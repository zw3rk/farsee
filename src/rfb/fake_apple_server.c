// SPDX-License-Identifier: Apache-2.0
//
// farsee — deterministic fake Apple server (goals.md G19).
//
// Generates the full Apple type-33 session byte stream for integration
// testing. Deterministic: same config → same bytes (no RNG, no time).
// Uses the G17 record layer (AES-128-CBC); real macOS requires the
// captured ChaCha20-Poly1305 cipher (NEEDS-HARDWARE).
//
// The fake server encrypts records (server→client). The session decrypts
// them with the same keys. Each scenario is a fixed sequence of "emit
// steps"; each step appends one logical chunk to the staging buffer.

#include "farsee/fake_apple_server.h"
#include "farsee/apple_postauth.h"
#include "farsee/apple_record.h"

#include <string.h>

// ---------------------------------------------------------------------------
// Internal byte helpers (big-endian).
// ---------------------------------------------------------------------------

static void put_be32_local(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)(v & 0xFFu);
}

// Pad a plaintext to a 16-byte boundary with zeros (in place in a buffer
// the caller sized to a multiple of 16).
static size_t pad_to_block(const uint8_t *src, size_t src_len,
                           uint8_t *dst, size_t dst_cap)
{
    size_t padded = ((src_len + 15u) / 16u) * 16u;
    if (padded == 0u) padded = 16u;
    if (padded > dst_cap) return 0u;
    memset(dst, 0, padded);
    if (src_len > 0u) memcpy(dst, src, src_len);
    return padded;
}

// ---------------------------------------------------------------------------
// Config defaults.
// ---------------------------------------------------------------------------

fake_apple_config fake_apple_default_config(fake_apple_scenario sc)
{
    fake_apple_config cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.scenario = sc;
    cfg.width = (uint16_t)FAKE_APPLE_DEFAULT_WIDTH;
    cfg.height = (uint16_t)FAKE_APPLE_DEFAULT_HEIGHT;
    cfg.send_cursor_cache = (sc == FAKE_SCENARIO_CURSOR_CACHE);
    cfg.fragment_records = (sc == FAKE_SCENARIO_FRAGMENTED);
    cfg.send_lock_transition = (sc == FAKE_SCENARIO_LOCK_LOGIN);
    return cfg;
}

// ---------------------------------------------------------------------------
// Lifecycle.
// ---------------------------------------------------------------------------

void fake_apple_server_init(fake_apple_server *s, fake_apple_config cfg,
                            apple_record_layer *rl,
                            uint8_t *out, size_t out_cap)
{
    if (s == NULL) return;
    memset(s, 0, sizeof *s);
    s->cfg = cfg;
    s->rl = rl;
    s->out = out;
    s->out_cap = out_cap;
    s->out_len = 0;
    s->step_index = 0;
    s->done = false;
    s->fill_r = 0x10; s->fill_g = 0x20; s->fill_b = 0x30; s->fill_a = 0xFF;
}

void fake_apple_server_reset_buffer(fake_apple_server *s)
{
    if (s == NULL) return;
    s->out_len = 0;
}

bool fake_apple_server_done(const fake_apple_server *s)
{
    return s != NULL && s->done;
}

// ---------------------------------------------------------------------------
// Encryption helper.
// ---------------------------------------------------------------------------

rfb_error fake_apple_encrypt_record(apple_record_layer *rl,
                                    const uint8_t *plaintext, size_t pt_len,
                                    uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (rl == NULL || plaintext == NULL || out == NULL || out_len == NULL)
        return RFB_ERR_INTERNAL;

    // Pad plaintext to 16-byte boundary.
    uint8_t padded[512];
    size_t padded_len = pad_to_block(plaintext, pt_len, padded, sizeof padded);
    if (padded_len == 0u) return RFB_ERR_LIMIT;

    // Compute total output size: u32 prefix + ciphertext (== padded_len).
    size_t total = FAKE_APPLE_LEN_PREFIX + padded_len;
    if (total > out_cap) return RFB_ERR_LIMIT;

    // Encrypt the padded plaintext.
    size_t ct_len = 0;
    rfb_error e = apple_record_encrypt(rl, padded, padded_len,
                                       out + FAKE_APPLE_LEN_PREFIX,
                                       out_cap - FAKE_APPLE_LEN_PREFIX, &ct_len);
    if (e != RFB_OK) return e;

    // Write the length prefix.
    put_be32_local(out, (uint32_t)ct_len);
    *out_len = FAKE_APPLE_LEN_PREFIX + ct_len;
    return RFB_OK;
}

// ---------------------------------------------------------------------------
// Scenario emit steps.
//
// Each step is a function that appends bytes to s->out and advances
// s->step_index. Returns RFB_OK on success. The dispatch below selects
// the step based on (scenario, step_index).
// ---------------------------------------------------------------------------

// Append raw bytes to the staging buffer. Returns false if overflow.
static bool append_bytes(fake_apple_server *s, const uint8_t *src, size_t n)
{
    if (s->out_len + n > s->out_cap) return false;
    if (n > 0u) memcpy(s->out + s->out_len, src, n);
    s->out_len += n;
    s->bytes_emitted += (uint32_t)n;
    return true;
}

// Emit a cleartext ServerInit.
static rfb_error emit_server_init(fake_apple_server *s)
{
    apple_server_init si;
    memset(&si, 0, sizeof si);
    si.width = s->cfg.width;
    si.height = s->cfg.height;
    si.bits_per_pixel = 32; si.depth = 24; si.big_endian = 0; si.true_color = 1;
    si.red_max = 255; si.green_max = 255; si.blue_max = 255;
    si.red_shift = 16; si.green_shift = 8; si.blue_shift = 0;
    static const char host[] = "fake-apple-host";
    size_t hl = sizeof host - 1u;
    memcpy(si.name, host, hl);
    si.name_len = hl;

    uint8_t buf[256];
    size_t n = 0;
    rfb_error e = apple_postauth_serialize_server_init(&si, buf, sizeof buf, &n);
    if (e != RFB_OK) return e;
    if (!append_bytes(s, buf, n)) return RFB_ERR_LIMIT;
    return RFB_OK;
}

// Emit an encrypted SetDisplayConfiguration.
static rfb_error emit_display_config(fake_apple_server *s)
{
    apple_display_config dc = {
        .width = s->cfg.width, .height = s->cfg.height,
        .display_index = 0, .flags = 0
    };
    uint8_t pt[32];
    pt[0] = (uint8_t)APPLE_POSTAUTH_SET_DISPLAY_CFG;
    size_t body_n = 0;
    rfb_error e = apple_postauth_serialize_display_config(
        &dc, pt + 1, sizeof pt - 1u, &body_n);
    if (e != RFB_OK) return e;
    size_t pt_len = 1u + body_n;

    uint8_t wire[64];
    size_t wire_len = 0;
    e = fake_apple_encrypt_record(s->rl, pt, pt_len, wire, sizeof wire, &wire_len);
    if (e != RFB_OK) return e;
    if (!append_bytes(s, wire, wire_len)) return RFB_ERR_LIMIT;
    s->records_emitted++;
    return RFB_OK;
}

// Emit an encrypted AutoFrameBufferUpdate arm.
static rfb_error emit_auto_arm(fake_apple_server *s)
{
    uint8_t pt[16];
    size_t n = 0;
    rfb_error e = apple_postauth_serialize_auto_fbupdate(true, 30, pt, sizeof pt, &n);
    if (e != RFB_OK) return e;
    uint8_t wire[64];
    size_t wire_len = 0;
    e = fake_apple_encrypt_record(s->rl, pt, n, wire, sizeof wire, &wire_len);
    if (e != RFB_OK) return e;
    if (!append_bytes(s, wire, wire_len)) return RFB_ERR_LIMIT;
    s->records_emitted++;
    return RFB_OK;
}

// Emit a framebuffer update (Raw-style). The plaintext carries the type,
// the rectangle header, and a deterministic fill. We keep it minimal:
// a single "framebuffer update" record that the session tolerates if it
// does not match a known type (unknown-message tolerance), and a fill
// pattern the session can render if it recognizes it.
static rfb_error emit_framebuffer_pixels(fake_apple_server *s)
{
    // Plaintext: a classic FramebufferUpdate-like message (type 0)
    // inside the encrypted record. We serialize: type=0, pad, num_rects=1,
    // then a rect header + Raw payload of the fill color.
    // For determinism and bounded output, emit a fixed-size tile.
    //
    // Layout (padded to 16): u8 type(0) + u8 pad + u16 num_rects(1) +
    //   u16 x + u16 y + u16 w + u16 h + i32 encoding(0=raw) + pixel bytes.
    // Each pixel is 4 bytes RGBA. A 16x16 tile would be 1024 pixel bytes —
    // far too large for the 64-byte inline plaintext buffer below, so the
    // tile is fixed at 2x2 (4 pixels = 16 bytes), independent of cfg.
    uint16_t tw = 2u;
    uint16_t th = 2u;
    uint8_t pt[64];
    memset(pt, 0, sizeof pt);
    size_t off = 0;
    pt[off++] = 0u;   // classic FramebufferUpdate message-type
    pt[off++] = 0u;   // pad
    pt[off++] = 0u; pt[off++] = 1u;  // num_rects = 1 (be16)
    pt[off++] = 0u; pt[off++] = 0u;  // x = 0
    pt[off++] = 0u; pt[off++] = 0u;  // y = 0
    pt[off++] = 0u; pt[off++] = (uint8_t)tw;  // width
    pt[off++] = 0u; pt[off++] = (uint8_t)th;  // height
    pt[off++] = 0u; pt[off++] = 0u; pt[off++] = 0u; pt[off++] = 0u; // enc=raw
    // 4 pixels of the fill color.
    for (int i = 0; i < 4; i++) {
        pt[off++] = s->fill_r;
        pt[off++] = s->fill_g;
        pt[off++] = s->fill_b;
        pt[off++] = s->fill_a;
    }
    size_t pt_len = off;

    uint8_t wire[128];
    size_t wire_len = 0;
    rfb_error e = fake_apple_encrypt_record(s->rl, pt, pt_len, wire, sizeof wire, &wire_len);
    if (e != RFB_OK) return e;
    if (!append_bytes(s, wire, wire_len)) return RFB_ERR_LIMIT;
    s->records_emitted++;
    return RFB_OK;
}

// Emit an encrypted cursor STORE + SELECT.
static rfb_error emit_cursor_cache(fake_apple_server *s)
{
    uint8_t rgba[16];
    for (int i = 0; i < 4; i++) {
        rgba[i*4+0] = 0xFF; rgba[i*4+1] = 0xFF;
        rgba[i*4+2] = 0xFF; rgba[i*4+3] = 0xFF;
    }
    // STORE: type + index + 4x u16 + rgba
    uint8_t pt_store[32];
    size_t store_n = 0;
    rfb_error e = apple_postauth_serialize_cursor_store(
        /*index=*/1, /*w=*/2, /*h=*/2, /*hx=*/0, /*hy=*/0,
        rgba, sizeof rgba, pt_store, sizeof pt_store, &store_n);
    if (e != RFB_OK) return e;
    uint8_t wire[64];
    size_t wire_len = 0;
    e = fake_apple_encrypt_record(s->rl, pt_store, store_n, wire, sizeof wire, &wire_len);
    if (e != RFB_OK) return e;
    if (!append_bytes(s, wire, wire_len)) return RFB_ERR_LIMIT;

    // SELECT: type + index
    uint8_t pt_select[8];
    size_t sel_n = 0;
    e = apple_postauth_serialize_cursor_select(1, pt_select, sizeof pt_select, &sel_n);
    if (e != RFB_OK) return e;
    e = fake_apple_encrypt_record(s->rl, pt_select, sel_n, wire, sizeof wire, &wire_len);
    if (e != RFB_OK) return e;
    if (!append_bytes(s, wire, wire_len)) return RFB_ERR_LIMIT;
    s->records_emitted += 2u;
    return RFB_OK;
}

// Emit a rekey marker (the session records the rekey count). For the
// deterministic path this is a synthetic rekey-arms record.
static rfb_error emit_rekey_marker(fake_apple_server *s)
{
    // A minimal encrypted record tagged as an "unknown but tolerated"
    // message that the session interprets as a rekey event for counting.
    uint8_t pt[16] = { 0 };
    pt[0] = 0x40u;  // synthetic rekey-prelude marker
    uint8_t wire[64];
    size_t wire_len = 0;
    rfb_error e = fake_apple_encrypt_record(s->rl, pt, sizeof pt, wire, sizeof wire, &wire_len);
    if (e != RFB_OK) return e;
    if (!append_bytes(s, wire, wire_len)) return RFB_ERR_LIMIT;
    s->records_emitted++;
    return RFB_OK;
}

// ---------------------------------------------------------------------------
// Step dispatch per scenario.
//
// step_index counts the emit calls. Each scenario defines its sequence.
// On the final step, sets s->done = true.
// ---------------------------------------------------------------------------

static rfb_error dispatch_step(fake_apple_server *s)
{
    fake_apple_config cfg = s->cfg;
    size_t i = s->step_index;

    // BASIC: 0=serverinit, 1=display_config, 2=auto_arm, 3=pixels, 4=done
    if (cfg.scenario == FAKE_SCENARIO_BASIC) {
        switch (i) {
            case 0: return emit_server_init(s);
            case 1: return emit_display_config(s);
            case 2: return emit_auto_arm(s);
            case 3: return emit_framebuffer_pixels(s);
            default: s->done = true; return RFB_OK;
        }
    }
    // CLEAN_CLOSE: same as basic but emphasizes the clean end.
    if (cfg.scenario == FAKE_SCENARIO_CLEAN_CLOSE) {
        switch (i) {
            case 0: return emit_server_init(s);
            case 1: return emit_display_config(s);
            case 2: return emit_framebuffer_pixels(s);
            default: s->done = true; return RFB_OK;
        }
    }
    // REKEY_MID_PRELUDE: serverinit, rekey marker, display_config, pixels.
    if (cfg.scenario == FAKE_SCENARIO_REKEY_MID_PRELUDE) {
        switch (i) {
            case 0: return emit_server_init(s);
            case 1: return emit_rekey_marker(s);
            case 2: return emit_display_config(s);
            case 3: return emit_framebuffer_pixels(s);
            default: s->done = true; return RFB_OK;
        }
    }
    // RESIZE_BEFORE_PIXELS: display_config (resize), then pixels.
    if (cfg.scenario == FAKE_SCENARIO_RESIZE_BEFORE_PIXELS) {
        switch (i) {
            case 0: return emit_server_init(s);
            case 1: return emit_display_config(s);
            case 2: return emit_framebuffer_pixels(s);
            default: s->done = true; return RFB_OK;
        }
    }
    // FRAGMENTED: same as basic but flagged (the test reads in halves).
    if (cfg.scenario == FAKE_SCENARIO_FRAGMENTED) {
        switch (i) {
            case 0: return emit_server_init(s);
            case 1: return emit_display_config(s);
            case 2: return emit_framebuffer_pixels(s);
            default: s->done = true; return RFB_OK;
        }
    }
    // CURSOR_CACHE: serverinit, display_config, cursor store/select.
    if (cfg.scenario == FAKE_SCENARIO_CURSOR_CACHE) {
        switch (i) {
            case 0: return emit_server_init(s);
            case 1: return emit_display_config(s);
            case 2: return emit_cursor_cache(s);
            default: s->done = true; return RFB_OK;
        }
    }
    // LOCK_LOGIN: serverinit, display_config, lock marker, re-arm, pixels.
    if (cfg.scenario == FAKE_SCENARIO_LOCK_LOGIN) {
        switch (i) {
            case 0: return emit_server_init(s);
            case 1: return emit_display_config(s);
            case 2: return emit_rekey_marker(s);   // lock transition
            case 3: return emit_auto_arm(s);       // re-arm
            case 4: return emit_framebuffer_pixels(s);
            default: s->done = true; return RFB_OK;
        }
    }
    s->done = true;
    return RFB_OK;
}

rfb_error fake_apple_server_emit(fake_apple_server *s, size_t *out_len)
{
    if (s == NULL || out_len == NULL) return RFB_ERR_INTERNAL;
    *out_len = 0;
    if (s->done) return RFB_ERR_STATE;
    if (s->rl == NULL) return RFB_ERR_INTERNAL;

    size_t before = s->out_len;
    rfb_error e = dispatch_step(s);
    if (e != RFB_OK) return e;
    *out_len = s->out_len - before;
    s->step_index++;
    return RFB_OK;
}
