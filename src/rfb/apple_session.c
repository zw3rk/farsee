// SPDX-License-Identifier: Apache-2.0
//
// farsee — Apple post-auth session driver.
//
// Single-threaded plaintext state machine driven by apple_session_step().
// The caller removes and applies record protection. This module consumes
// cleartext prelude bytes or decrypted records and emits plaintext responses.
// It does not perform socket I/O or encrypt or decrypt records.

#include "farsee/apple_session.h"
#include "farsee/apple_postauth.h"
#include "farsee/apple_record.h"
#include "farsee/secret.h"

#include <string.h>

// ---------------------------------------------------------------------------
// Lifecycle.
// ---------------------------------------------------------------------------

void apple_session_init(apple_session *s, apple_record_layer *rl,
                        rfb_framebuffer *fb, rfb_allocator *alloc,
                        size_t fb_byte_limit)
{
    if (s == NULL) return;
    memset(s, 0, sizeof *s);
    s->phase = APPLE_SESSION_PRELUDE;
    s->rl = rl;
    s->fb = fb;
    s->alloc = alloc;
    s->fb_byte_limit = fb_byte_limit;
    s->mode = APPLE_MODE_FULL_QUALITY;
    s->last_error = "ok";
}

void apple_session_destroy(apple_session *s)
{
    if (s == NULL) return;
    // Release cursor cache (bounded, owned RGBA copies).
    for (size_t i = 0; i < APPLE_CURSOR_CACHE_MAX; i++) {
        apple_cursor_cache_entry *e = &s->cursor_cache[i];
        if (e->rgba != NULL && s->alloc != NULL) {
            rfb_secret_zero(e->rgba, e->rgba_len);
            s->alloc->free(s->alloc, e->rgba);
            e->rgba = NULL;
        }
        memset(e, 0, sizeof *e);
    }
    // Clear sensitive state (no keys live here; record layer is borrowed).
    memset(&s->server_init, 0, sizeof s->server_init);
    memset(&s->viewer_info, 0, sizeof s->viewer_info);
}

// ---------------------------------------------------------------------------
// Phase diagnostics (static literals; never remote-controlled text).
// ---------------------------------------------------------------------------

const char *apple_session_phase_name(apple_session_phase p)
{
    switch (p) {
        case APPLE_SESSION_PRELUDE:       return "prelude";
        case APPLE_SESSION_REKEY:         return "rekey";
        case APPLE_SESSION_DISPLAY_CONFIG:return "display-config";
        case APPLE_SESSION_ENCODINGS:     return "encodings";
        case APPLE_SESSION_ARMED:         return "armed";
        case APPLE_SESSION_STREAMING:     return "streaming";
        case APPLE_SESSION_RESIZE:        return "resize";
        case APPLE_SESSION_CLOSED:        return "closed";
        default:                          return "unknown";
    }
}

// ---------------------------------------------------------------------------
// Resize the borrowed framebuffer transactionally.
// ---------------------------------------------------------------------------

rfb_error apple_session_resize(apple_session *s, uint16_t width, uint16_t height)
{
    if (s == NULL || s->fb == NULL) return RFB_ERR_INTERNAL;
    rfb_error e = rfb_framebuffer_resize(s->fb, width, height, s->fb_byte_limit);
    if (e != RFB_OK) {
        s->last_error = rfb_strerror(e);
        return e;
    }
    s->resizes++;
    return RFB_OK;
}

// ---------------------------------------------------------------------------
// Cursor cache (fixed entry count).
// ---------------------------------------------------------------------------

rfb_error apple_session_cursor_store(apple_session *s, uint8_t index,
                                     uint16_t width, uint16_t height,
                                     uint16_t hotspot_x, uint16_t hotspot_y,
                                     const uint8_t *rgba, size_t rgba_len)
{
    if (s == NULL) return RFB_ERR_INTERNAL;
    if (rgba == NULL && rgba_len > 0u) return RFB_ERR_INTERNAL;
    if ((size_t)index >= APPLE_CURSOR_CACHE_MAX) return RFB_ERR_LIMIT;

    apple_cursor_cache_entry *e = &s->cursor_cache[index];

    // Free any prior entry at this index.
        if (e->rgba != NULL && s->alloc != NULL) {
            rfb_secret_zero(e->rgba, e->rgba_len);
            s->alloc->free(s->alloc, e->rgba);
        }
    memset(e, 0, sizeof *e);

    e->index = index;
    e->width = width;
    e->height = height;
    e->hotspot_x = hotspot_x;
    e->hotspot_y = hotspot_y;
    e->valid = true;
    e->rgba_len = rgba_len;

    if (rgba_len > 0u) {
        if (s->alloc == NULL) return RFB_ERR_INTERNAL;
        e->rgba = (uint8_t *)s->alloc->alloc(s->alloc, rgba_len);
        if (e->rgba == NULL) {
            e->valid = false;
            s->last_error = "cursor alloc failed";
            return RFB_ERR_NOMEM;
        }
        memcpy(e->rgba, rgba, rgba_len);
    }
    return RFB_OK;
}

rfb_error apple_session_cursor_select(apple_session *s, uint8_t index)
{
    if (s == NULL) return RFB_ERR_INTERNAL;
    if ((size_t)index >= APPLE_CURSOR_CACHE_MAX) return RFB_ERR_LIMIT;
    apple_cursor_cache_entry *e = &s->cursor_cache[index];
    if (!e->valid) {
        s->last_error = "cursor cache miss";
        return RFB_ERR_PROTOCOL;
    }
    s->active_cursor = index;
    return RFB_OK;
}

// ---------------------------------------------------------------------------
// AutoFrameBufferUpdate arm.
// ---------------------------------------------------------------------------

rfb_error apple_session_arm_auto_update(apple_session *s, uint16_t max_rate,
                                        uint8_t *out_bytes, size_t out_cap,
                                        size_t *out_len)
{
    if (s == NULL || out_bytes == NULL || out_len == NULL) return RFB_ERR_INTERNAL;
    rfb_error e = apple_postauth_serialize_auto_fbupdate(true, max_rate,
                                                         out_bytes, out_cap, out_len);
    if (e != RFB_OK) {
        s->last_error = rfb_strerror(e);
        return e;
    }
    s->auto_update_armed = true;
    s->auto_update_rate = max_rate;
    return RFB_OK;
}

// ---------------------------------------------------------------------------
// The main step function.
//
// Drives one plaintext step. Cleartext input handles ServerInit,
// SetEncryption, SetMode, and unknown message types. Decrypted input handles
// SetDisplayConfiguration, AutoFrameBufferUpdate state, cursor STORE/SELECT,
// and unknown message types. A successful display configuration resizes the
// borrowed framebuffer.
// ---------------------------------------------------------------------------

static rfb_error handle_cleartext(apple_session *s, const uint8_t *data, size_t len,
                                  uint8_t *out_bytes, size_t out_cap, size_t *out_len)
{
    *out_len = 0;
    if (len == 0u) return RFB_OK;

    // ServerInit has no type byte; other cleartext messages do. First attempt
    // ServerInit parsing for a full-size candidate, then dispatch remaining
    // input on its first byte.
    if (len >= APPLE_SERVER_INIT_HEADER_LEN) {
        // Accept the input as ServerInit only when parsing succeeds with 32 bits
        // per pixel, depth 24, and true-color set. Otherwise continue to typed
        // cleartext dispatch.
        apple_server_init si;
        rfb_error e = apple_postauth_parse_server_init(data, len, &si);
        if (e == RFB_OK && si.bits_per_pixel == 32u && si.depth == 24u &&
            si.true_color == 1u) {
            s->server_init = si;
            // Emit a ViewerInfo response with the client device name after
            // receiving ServerInit.
            apple_viewer_info vi;
            memset(&vi, 0, sizeof vi);
            static const char device[] = "MacBook Air";
            memcpy(vi.device_name, device, sizeof device - 1u);
            vi.name_len = sizeof device - 1u;
            e = apple_postauth_serialize_viewer_info(&vi, out_bytes, out_cap, out_len);
            if (e != RFB_OK) {
                s->last_error = rfb_strerror(e);
                return e;
            }
            return RFB_OK;
        }
    }

    // Dispatch on the type byte for other cleartext messages.
    uint8_t type = data[0];
    switch (type) {
        case APPLE_POSTAUTH_SET_ENCRYPTION:
            if (len < 2u) return RFB_ERR_PROTOCOL;
            s->encryption_enabled = (data[1] != 0u);
            return RFB_OK;
        case APPLE_POSTAUTH_SET_MODE:
            if (len < 2u) return RFB_ERR_PROTOCOL;
            // Reject adaptive mode even in the prelude.
            if (data[1] == APPLE_MODE_ADAPTIVE) return RFB_ERR_UNSUPPORTED;
            s->mode = data[1];
            return RFB_OK;
        default:
            // Tolerate an unknown cleartext message.
            s->unknown_messages_tolerated++;
            return RFB_OK;
    }
}

static rfb_error handle_encrypted(apple_session *s, const uint8_t *data, size_t len,
                                  uint8_t *out_bytes, size_t out_cap, size_t *out_len)
{
    (void)out_bytes; (void)out_cap;
    *out_len = 0;
    if (len == 0u) return RFB_OK;
    s->records_processed++;

    uint8_t type = data[0];
    switch (type) {
        case APPLE_POSTAUTH_SET_DISPLAY_CFG: {
            if (len < 1u + 6u) return RFB_ERR_PROTOCOL;
            apple_display_config dc;
            rfb_error e = apple_postauth_parse_display_config(data + 1, len - 1u, &dc);
            if (e != RFB_OK) { s->last_error = rfb_strerror(e); return e; }
            e = apple_session_resize(s, dc.width, dc.height);
            if (e != RFB_OK) return e;
            if (s->phase < APPLE_SESSION_STREAMING) s->phase = APPLE_SESSION_DISPLAY_CONFIG;
            return RFB_OK;
        }
        case APPLE_POSTAUTH_AUTO_FBUPDATE:
            if (len < 2u) return RFB_ERR_PROTOCOL;
            s->auto_update_armed = (data[1] != 0u);
            if (s->phase < APPLE_SESSION_STREAMING) s->phase = APPLE_SESSION_ARMED;
            return RFB_OK;
        case APPLE_POSTAUTH_CURSOR_STORE: {
            if (len < 10u) return RFB_ERR_PROTOCOL;
            uint8_t idx = data[1];
            uint16_t w = (uint16_t)((uint16_t)data[2] << 8 | data[3]);
            uint16_t h = (uint16_t)((uint16_t)data[4] << 8 | data[5]);
            uint16_t hx = (uint16_t)((uint16_t)data[6] << 8 | data[7]);
            uint16_t hy = (uint16_t)((uint16_t)data[8] << 8 | data[9]);
            size_t rgba_len = len - 10u;
            return apple_session_cursor_store(s, idx, w, h, hx, hy,
                                              data + 10u, rgba_len);
        }
        case APPLE_POSTAUTH_CURSOR_SELECT:
            if (len < 2u) return RFB_ERR_PROTOCOL;
            return apple_session_cursor_select(s, data[1]);
        default:
            // Unknown extension messages do not close the session.
            s->unknown_messages_tolerated++;
            return RFB_OK;
    }
}

rfb_error apple_session_step(apple_session *s, const apple_session_record *step,
                             uint8_t *out_bytes, size_t out_cap, size_t *out_len)
{
    if (s == NULL || step == NULL) return RFB_ERR_INTERNAL;
    if (out_len == NULL) return RFB_ERR_INTERNAL;
    *out_len = 0;
    if (s->phase == APPLE_SESSION_CLOSED) return RFB_ERR_STATE;

    rfb_error e;
    if (step->kind == APPLE_STEP_CLEARTEXT) {
        e = handle_cleartext(s, step->data, step->len, out_bytes, out_cap, out_len);
    } else {
        e = handle_encrypted(s, step->data, step->len, out_bytes, out_cap, out_len);
    }
    if (e != RFB_OK) {
        s->last_error = rfb_strerror(e);
    }
    return e;
}
