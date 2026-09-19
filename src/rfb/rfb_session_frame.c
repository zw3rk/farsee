// SPDX-License-Identifier: Apache-2.0
//
// RFB session framebuffer decode and display publication ownership.

#include "rfb/rfb_session_internal.h"

#include "farsee/apple_mvs_stream.h"
#include "farsee/buffer.h"
#include "farsee/farsee_display.h"
#include "farsee/framebuffer.h"
#include "farsee/pacing.h"
#include "farsee/rfb_server_engine.h"

#include <stdio.h>
#include <string.h>

// --- decode path (pure engine) ---------------------------------------------

// Sparse sample: true when more than 200 sampled pixels have a nonzero R, G,
// or B component. The sample visits every 16th x and y coordinate.
static bool fb_sample_nonblack(const rfb_framebuffer *fb)
{
    if (fb == NULL || fb->rgba == NULL || fb->width == 0u ||
        fb->height == 0u) {
        return false;
    }
    const uint32_t step = 16u;
    size_t nz = 0;
    size_t samples = 0;
    for (uint32_t y = 0; y < fb->height; y += step) {
        for (uint32_t x = 0; x < fb->width; x += step) {
            const uint8_t *p = rfb_framebuffer_pixel_c(fb, x, y);
            samples++;
            if (p[0] != 0u || p[1] != 0u || p[2] != 0u) {
                nz++;
            }
        }
    }
    // The fixed threshold is not a classification of desktop contents or
    // display state.
    (void)samples;
    return nz > 200u;
}

// Request another full paint and optionally queue one bounded wake-input
// sequence while Apple cleartext has not crossed the sampled non-black
// threshold. view-only suppresses all input; policy can disable key input.
void rfb_session_internal_apple_wake(rfb_session *s, bool with_key)
{
    // The dialect enables this retry path. view_only suppresses PointerEvent
    // and KeyEvent input but does not suppress the full-refresh request.
    if (s == NULL || !rfb_session_internal_is_apple_cleartext(s)) {
        return;
    }
    s->apple_wake_attempts++;

    // Pointer and key input is suppressed under view_only. The
    // non-incremental FBUR request below remains allowed.
    const bool allow_input =
        with_key && !s->cfg.apple_disable_wake_keys;
    {
        uint8_t msg[64];
        size_t n = 0u;
        if (rfb_format_apple_wake_input(msg, sizeof msg, &n,
                                        s->cfg.view_only, allow_input,
                                        s->apple_wake_attempts,
                                        s->fb_width, s->fb_height) == RFB_OK &&
            n > 0u) {
            (void)session_queue_bytes(s, msg, n);
        }
    }

    // Request another full paint. This is allowed under view_only, and the
    // release frontend does not suppress it.
    if (!s->wire_variants.suppress_fbur) {
        rfb_pacing_force_full_refresh(&s->pacing);
    }
}

rfb_error rfb_session_internal_publish_frame(rfb_session *s)
{
    if (s->fb.rgba == NULL) {
        return RFB_OK;
    }

    s->frames_published++;
    const bool nonblack = fb_sample_nonblack(&s->fb);
    const bool first_colour = nonblack && !s->apple_seen_nonblack;
    if (nonblack) {
        s->apple_seen_nonblack = true;
    }

    // Apple cleartext: while no sample has crossed the non-black threshold,
    // request a full refresh after the first paint and again after the third. The
    // wake after the third paint also permits key input when session policy allows it.
    if (rfb_session_internal_is_apple_cleartext(s) &&
        !s->apple_seen_nonblack) {
        if (!s->apple_bootstrap_done) {
            s->apple_bootstrap_done = true;
            rfb_session_internal_apple_wake(s, /*with_key=*/false);
        } else if (s->apple_wake_attempts < 2u && s->frames_published == 3u) {
            rfb_session_internal_apple_wake(s, /*with_key=*/true);
        }
    }
    // Emit the threshold diagnostic once. Its text identifies whether the
    // AES-CBC record layer is active.
    {
        const rfb_black_hint_kind hint = rfb_black_hint_kind_for(
            rfb_session_internal_is_apple_cleartext(s),
            s->apple_records_active,
            s->apple_seen_nonblack, s->frames_published);
        if (hint != RFB_BLACK_HINT_NONE) {
            fprintf(stderr, "farsee: %u completed frames without crossing "
                            "the sampled non-black threshold (%ux%u). %s\n",
                    (unsigned)s->frames_published, (unsigned)s->fb.width,
                    (unsigned)s->fb.height, rfb_black_hint_text(hint));
            (void)fflush(stderr);
        }
    }
    const uint64_t now = rfb_io_mono_ms();
    // Rate-limit publishes. Always force the first several paints and the
    // first paint that crosses the sampled non-black threshold. Apple
    // cleartext paints below the threshold can be withheld from the slot;
    // full-refresh and wake handling above still run. Explicit capture sets
    // cfg.publish_black_frames so the slot also receives below-threshold
    // paints.
    if (rfb_session_should_withhold_black_publish(
            rfb_session_internal_is_apple_cleartext(s), nonblack,
            s->cfg.publish_black_frames || s->cursor.valid)) {
        return RFB_OK;
    }

    const bool force_publish =
        (s->frames_published <= 8u) || first_colour;
    const bool due =
        force_publish || rfb_pacing_can_present(&s->pacing, now);

    // Publish only. The app owns open/present/close for its presenter. When
    // slot is NULL, skip publication.
    if (due && s->cfg.slot != NULL) {
        const farsee_cursor cursor = {
            .hotspot_x = s->cursor.hotspot_x,
            .hotspot_y = s->cursor.hotspot_y,
            .width = s->cursor.width,
            .height = s->cursor.height,
            .format = FARSEE_PIXEL_RGBA8888,
            .data = s->cursor.rgba,
            .visible = s->cursor.valid,
            .pos_x = (int32_t)s->last_ptr_x,
            .pos_y = (int32_t)s->last_ptr_y,
        };
        const farsee_frame_publish_result publish_result =
            farsee_frame_slot_publish_composited_ex(
            s->cfg.slot, s->fb.rgba, s->fb.width, s->fb.height,
            (uint32_t)s->fb.stride, FARSEE_PIXEL_RGBA8888,
            s->cursor.valid ? &cursor : NULL);
        if (publish_result == FARSEE_FRAME_PUBLISH_RESOURCE_BUSY) {
            // Producer contention is an allowed latest-wins drop. Do not
            // account it as a presentation or advance the cadence.
            return RFB_OK;
        }
        if (publish_result != FARSEE_FRAME_PUBLISH_OK) {
            s->last_error =
                publish_result == FARSEE_FRAME_PUBLISH_OUT_OF_MEMORY
                    ? RFB_ERR_NOMEM
                    : RFB_ERR_STATE;
            return s->last_error;
        }
        rfb_pacing_presented(&s->pacing, now, s->eng.rects_decoded, 0);
    }
    return RFB_OK;
}

// Session hooks into the pure demux engine (product side-effects only).
static rfb_error session_eng_on_publish(void *hook_ctx)
{
    rfb_session *s = (rfb_session *)hook_ctx;
    if (s == NULL) {
        return RFB_ERR_INTERNAL;
    }
    if (s->capture_enabled) {
        rfb_error e = rfb_capture_scheduler_fbu_complete(
            &s->capture, rfb_session_internal_capture_now(s));
        if (e != RFB_OK) {
            s->last_error = e;
        }
        return e;
    }
    return rfb_session_internal_publish_frame(s);
}

static rfb_error session_eng_on_fbu_begin(void *hook_ctx, uint16_t nrects)
{
    rfb_session *s = (rfb_session *)hook_ctx;
    if (s == NULL) {
        return RFB_ERR_INTERNAL;
    }
    if (s->capture_enabled) {
        s->capture_frame_progress = true;
        rfb_error e = rfb_capture_scheduler_fbu_begin_at(
            &s->capture, nrects, rfb_session_internal_capture_now(s));
        if (e != RFB_OK) {
            s->last_error = e;
            return e;
        }
    }
    return RFB_OK;
}

static rfb_error session_eng_on_rect_decoded(
    void *hook_ctx, const rfb_rect_header *rect, const uint8_t *payload,
    size_t payload_len)
{
    rfb_session *s = (rfb_session *)hook_ctx;
    if (s == NULL || !s->capture_enabled) {
        return s == NULL ? RFB_ERR_INTERNAL : RFB_OK;
    }
    rfb_error e = rfb_capture_scheduler_record_rect(
        &s->capture, rect, payload, payload_len);
    if (e != RFB_OK) {
        s->last_error = e;
    }
    return e;
}

// DesktopSize: engine has already resized fb / *fb_width/*fb_height.
// Product live shells poll session geometry or the published frame size.
// Saved coefficients must zero — geometry slots no longer match.
static void session_eng_on_desktop_size(void *hook_ctx, uint16_t width,
                                        uint16_t height)
{
    rfb_session *s = (rfb_session *)hook_ctx;
    if (s == NULL) {
        return;
    }
    s->fb_width = width;
    s->fb_height = height;
    if (width > 0u && height > 0u) {
        if (apple_mvs_coeff_store_ensure_with_allocator(
                &s->mvs_coeffs, width, height, s->alloc)) {
            apple_mvs_coeff_store_clear(&s->mvs_coeffs);
        } else {
            apple_mvs_coeff_store_free(&s->mvs_coeffs);
        }
    } else {
        apple_mvs_coeff_store_free(&s->mvs_coeffs);
    }
}

// Returns:
//   RFB_OK            — progress or need more input
//   RFB_ERR_*         — hard failure
// Sets *progress when bytes were consumed.
rfb_error rfb_session_internal_process_in(rfb_session *s, bool *progress)
{
    // Modern AES-CBC path: demux cipher records before the pure engine sees
    // bytes. Engine dialect is CLASSIC for decrypted RFB (typed Apple msgs
    // already filtered); avoid cleartext u16be-control skip on plain stream.
    if (s->apple_records_active) {
        rfb_error de =
            rfb_session_internal_decrypt_apple_records(s, progress);
        if (de != RFB_OK) {
            return de;
        }
    }

    rfb_server_engine_ctx ctx;
    memset(&ctx, 0, sizeof ctx);
    ctx.eng = &s->eng;
    ctx.in = s->apple_records_active ? &s->apple_plain : &s->in;
    ctx.fb = &s->fb;
    ctx.pf = &s->pf;
    ctx.zstream = s->zstream;
    ctx.cursor = &s->cursor;
    ctx.alloc = s->alloc;
    ctx.pacing = &s->pacing;
    // Decrypted stream is classic RFB (or empty). Cleartext Apple demux
    // skip must not apply to plain messages after CBC open.
    ctx.dialect = s->apple_records_active ? RFB_SESSION_DIALECT_CLASSIC
                                          : s->dialect;
    ctx.fb_width = &s->fb_width;
    ctx.fb_height = &s->fb_height;
    // Product decoding is strict. The private soft-skip variant can be set
    // only on the private in-memory session fixture.
    ctx.mvs_skip_unknown = s->wire_variants.mvs_skip_unknown;
    if (s->mvs_have_qt) {
        ctx.mvs_qt0 = s->mvs_qt0;
        ctx.mvs_qt1 = s->mvs_qt1;
    }
    ctx.mvs_coeff_store = &s->mvs_coeffs;
    ctx.hooks.hook_ctx = s;
    ctx.hooks.on_publish = session_eng_on_publish;
    ctx.hooks.on_bell = NULL; // terminal bell is presenter-owned
    ctx.hooks.on_cut_text = NULL; // clipboard path not yet session-wired
    ctx.hooks.on_fbu_begin = session_eng_on_fbu_begin;
    ctx.hooks.on_rect_decoded = session_eng_on_rect_decoded;
    ctx.hooks.on_desktop_size = session_eng_on_desktop_size;

    bool eng_progress = false;
    rfb_error e = rfb_server_engine_process_in(&ctx, &eng_progress);
    if (eng_progress) {
        *progress = true;
    }
    if (e != RFB_OK) {
        s->last_error = e;
    }
    if (s->capture_enabled &&
        s->capture.state == RFB_CAPTURE_SCHEDULER_FAILED) {
        s->last_error = s->capture.error;
        return s->capture.error;
    }
    return e;
}
