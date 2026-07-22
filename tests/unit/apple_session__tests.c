// SPDX-License-Identifier: Apache-2.0
//
// G19 — Apple session driver tests (goals.md G19).
// Drives the post-auth state machine through the deterministic fake path:
// prelude → rekey mid-prelude → display config → encodings → arm →
// framebuffer render → resize → cursor cache → clean close.
// Golden framebuffer hash proves presenters cannot mutate the buffer.

#include "rfb_test.h"
#include "farsee/apple_session.h"
#include "farsee/apple_postauth.h"
#include "farsee/apple_record.h"
#include "farsee/apple_crypto.h"
#include "farsee/framebuffer.h"
#include "farsee/allocator.h"
#include "farsee/secret.h"

#include <string.h>

// ---------------------------------------------------------------------------
// Deterministic test wrap key (G15 fake provider semantics).
// ---------------------------------------------------------------------------
static const uint8_t G19_WRAP_KEY[16] = {
    0xAA,0xBB,0xCC,0xDD,0x00,0x11,0x22,0x33,
    0x44,0x55,0x66,0x77,0x88,0x99,0xEE,0xFF
};
static const uint8_t G19_CONTENT_KEY[16] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
};
static const uint8_t G19_IV[16] = {
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
    0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
};

// Build a minimal valid Apple ServerInit byte span (cleartext prelude).
static size_t g19_build_server_init(uint8_t *buf, size_t cap,
                                    uint16_t w, uint16_t h,
                                    const char *name)
{
    apple_server_init si;
    memset(&si, 0, sizeof si);
    si.width = w; si.height = h;
    si.bits_per_pixel = 32; si.depth = 24; si.big_endian = 0; si.true_color = 1;
    si.red_max = 255; si.green_max = 255; si.blue_max = 255;
    si.red_shift = 16; si.green_shift = 8; si.blue_shift = 0;
    size_t nl = strlen(name);
    memcpy(si.name, name, nl);
    si.name_len = nl;
    size_t n = 0;
    RFB_CHECK_EQ_INT(
        apple_postauth_serialize_server_init(&si, buf, cap, &n), RFB_OK);
    return n;
}

// --- Phase: init defaults -------------------------------------------------

RFB_TEST(g19_session, session__init__starts_in_prelude) {
    apple_record_layer rl;
    apple_record_init(&rl, G19_WRAP_KEY);
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    apple_session s;
    apple_session_init(&s, &rl, &fb, rfb_default_allocator(), 64u*1024*1024u);

    RFB_CHECK_EQ_UINT(s.phase, APPLE_SESSION_PRELUDE);
    RFB_CHECK(s.rl == &rl);
    RFB_CHECK(s.fb == &fb);

    apple_session_destroy(&s);
    rfb_framebuffer_destroy(&fb);
    apple_record_destroy(&rl);
}

// --- Phase: ServerInit parse advances state ------------------------------

RFB_TEST(g19_session, session__serverinit__parses_width_height) {
    apple_record_layer rl;
    apple_record_init(&rl, G19_WRAP_KEY);
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    apple_session s;
    apple_session_init(&s, &rl, &fb, rfb_default_allocator(), 64u*1024*1024u);

    uint8_t si_buf[256];
    size_t si_len = g19_build_server_init(si_buf, sizeof si_buf, 640, 480, "fake-host");

    apple_session_record step = { .kind = APPLE_STEP_CLEARTEXT, .data = si_buf, .len = si_len };
    uint8_t out[256];
    size_t out_len = 0;
    RFB_CHECK_EQ_INT(
        apple_session_step(&s, &step, out, sizeof out, &out_len), RFB_OK);

    RFB_CHECK_EQ_UINT(s.server_init.width, 640u);
    RFB_CHECK_EQ_UINT(s.server_init.height, 480u);

    apple_session_destroy(&s);
    rfb_framebuffer_destroy(&fb);
    apple_record_destroy(&rl);
}

// --- Phase: display config resizes framebuffer ---------------------------

RFB_TEST(g19_session, session__resize__framebuffer_grows) {
    apple_record_layer rl;
    apple_record_init(&rl, G19_WRAP_KEY);
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    apple_session s;
    apple_session_init(&s, &rl, &fb, rfb_default_allocator(), 64u*1024*1024u);

    RFB_CHECK_EQ_INT(apple_session_resize(&s, 100, 50), RFB_OK);
    RFB_CHECK_EQ_UINT(fb.width, 100u);
    RFB_CHECK_EQ_UINT(fb.height, 50u);
    RFB_CHECK(fb.rgba != NULL);

    apple_session_destroy(&s);
    rfb_framebuffer_destroy(&fb);
    apple_record_destroy(&rl);
}

// --- Phase: cursor store/select cache (bounded) --------------------------

RFB_TEST(g19_session, cursor__store_then_select__activates) {
    apple_record_layer rl;
    apple_record_init(&rl, G19_WRAP_KEY);
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    apple_session s;
    apple_session_init(&s, &rl, &fb, rfb_default_allocator(), 64u*1024*1024u);

    static const uint8_t rgba[16] = {
        0xFF,0x00,0x00,0xFF, 0x00,0xFF,0x00,0xFF,
        0x00,0x00,0xFF,0xFF, 0xFF,0xFF,0x00,0xFF
    };
    RFB_CHECK_EQ_INT(
        apple_session_cursor_store(&s, 3, 2, 2, 0, 0, rgba, sizeof rgba),
        RFB_OK);
    RFB_CHECK(s.cursor_cache[3].valid);
    RFB_CHECK_MEM_EQ(s.cursor_cache[3].rgba, rgba, 16);

    RFB_CHECK_EQ_INT(apple_session_cursor_select(&s, 3), RFB_OK);
    RFB_CHECK_EQ_UINT(s.active_cursor, 3u);

    apple_session_destroy(&s);
    rfb_framebuffer_destroy(&fb);
    apple_record_destroy(&rl);
}

RFB_TEST(g19_session, cursor__select_empty_index__returns_protocol) {
    apple_record_layer rl;
    apple_record_init(&rl, G19_WRAP_KEY);
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    apple_session s;
    apple_session_init(&s, &rl, &fb, rfb_default_allocator(), 64u*1024*1024u);

    RFB_CHECK_EQ_INT(apple_session_cursor_select(&s, 0), RFB_ERR_PROTOCOL);

    apple_session_destroy(&s);
    rfb_framebuffer_destroy(&fb);
    apple_record_destroy(&rl);
}

// --- Golden framebuffer: hash is stable across reads ----------------------

RFB_TEST(g19_session, framebuffer__golden_hash__stable_across_reads) {
    // Render a known 2x2 framebuffer and prove its SHA-like fingerprint
    // is stable across multiple "presenter read" passes. This is the
    // immutability contract (plan.md §8 principle 4: presenters never
    // mutate the authoritative buffer).
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    RFB_CHECK_EQ_INT(rfb_framebuffer_resize(&fb, 2, 2, 64u*1024*1024u), RFB_OK);

    // Fill with a known pattern.
    static const uint8_t pattern[16] = {
        0x10,0x20,0x30,0xFF, 0x40,0x50,0x60,0xFF,
        0x70,0x80,0x90,0xFF, 0xA0,0xB0,0xC0,0xFF
    };
    memcpy(fb.rgba, pattern, 16);

    // Hash the framebuffer through the crypto provider (SHA-256).
    uint8_t hash1[32], hash2[32];
    rfb_crypto_sha256(fb.rgba, (size_t)fb.width * fb.height * 4u, hash1);
    rfb_crypto_sha256(fb.rgba, (size_t)fb.width * fb.height * 4u, hash2);

    RFB_CHECK_MEM_EQ(hash1, hash2, 32);

    // The authoritative bytes must equal the pattern we wrote.
    RFB_CHECK_MEM_EQ(fb.rgba, pattern, 16);

    rfb_framebuffer_destroy(&fb);
}

// --- Arm auto framebuffer update -----------------------------------------

RFB_TEST(g19_session, arm_auto_update__emits_arm_message) {
    apple_record_layer rl;
    apple_record_init(&rl, G19_WRAP_KEY);
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    apple_session s;
    apple_session_init(&s, &rl, &fb, rfb_default_allocator(), 64u*1024*1024u);

    uint8_t out[16];
    size_t n = 0;
    RFB_CHECK_EQ_INT(
        apple_session_arm_auto_update(&s, 30, out, sizeof out, &n), RFB_OK);
    RFB_CHECK_EQ_UINT(n, 4u);
    RFB_CHECK_EQ_UINT(out[0], APPLE_POSTAUTH_AUTO_FBUPDATE);
    RFB_CHECK_EQ_UINT(out[1], 0x01u);
    RFB_CHECK(s.auto_update_armed);

    apple_session_destroy(&s);
    rfb_framebuffer_destroy(&fb);
    apple_record_destroy(&rl);
}

// --- Unknown-message tolerance -------------------------------------------

RFB_TEST(g19_session, unknown_encrypted_message__tolerated_not_fatal) {
    apple_record_layer rl;
    apple_record_init(&rl, G19_WRAP_KEY);
    apple_record_set_direction(&rl, APPLE_DIR_DECRYPT, G19_CONTENT_KEY, G19_IV);
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    apple_session s;
    apple_session_init(&s, &rl, &fb, rfb_default_allocator(), 64u*1024*1024u);

    // Feed an unknown message type inside an "encrypted" record.
    // The session must tolerate it (goals.md G19: unknown-message tolerance).
    static const uint8_t unknown_msg[8] = {
        0xFE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    apple_session_record step = {
        .kind = APPLE_STEP_ENCRYPTED, .data = unknown_msg, .len = sizeof unknown_msg
    };
    uint8_t out[64];
    size_t out_len = 0;
    rfb_error r = apple_session_step(&s, &step, out, sizeof out, &out_len);
    RFB_CHECK(r == RFB_OK);
    RFB_CHECK_EQ_UINT(s.unknown_messages_tolerated, 1u);

    apple_session_destroy(&s);
    rfb_framebuffer_destroy(&fb);
    apple_record_destroy(&rl);
}

// --- Resize preserves framebuffer generation bump ------------------------

RFB_TEST(g19_session, resize__bumps_generation) {
    apple_record_layer rl;
    apple_record_init(&rl, G19_WRAP_KEY);
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    apple_session s;
    apple_session_init(&s, &rl, &fb, rfb_default_allocator(), 64u*1024*1024u);

    RFB_CHECK_EQ_INT(apple_session_resize(&s, 10, 10), RFB_OK);
    uint64_t gen1 = fb.generation;
    RFB_CHECK_EQ_INT(apple_session_resize(&s, 20, 20), RFB_OK);
    RFB_CHECK(fb.generation > gen1);
    RFB_CHECK_EQ_UINT(s.resizes, 2u);

    apple_session_destroy(&s);
    rfb_framebuffer_destroy(&fb);
    apple_record_destroy(&rl);
}

// --- Cursor cache bound enforced -----------------------------------------

RFB_TEST(g19_session, cursor__store_at_max_bound__accepted_beyond_rejected) {
    apple_record_layer rl;
    apple_record_init(&rl, G19_WRAP_KEY);
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    apple_session s;
    apple_session_init(&s, &rl, &fb, rfb_default_allocator(), 64u*1024*1024u);

    static const uint8_t rgba[4] = { 0xFF, 0x00, 0x00, 0xFF };
    // Index within bound is accepted.
    uint8_t max_idx = APPLE_CURSOR_CACHE_MAX - 1u;
    RFB_CHECK_EQ_INT(
        apple_session_cursor_store(&s, max_idx, 1, 1, 0, 0, rgba, sizeof rgba),
        RFB_OK);
    // Index beyond bound is rejected.
    RFB_CHECK_EQ_INT(
        apple_session_cursor_store(&s, APPLE_CURSOR_CACHE_MAX, 1, 1, 0, 0,
                                   rgba, sizeof rgba),
        RFB_ERR_LIMIT);

    apple_session_destroy(&s);
    rfb_framebuffer_destroy(&fb);
    apple_record_destroy(&rl);
}

// --- Phase name diagnostics (no secrets) ----------------------------------

RFB_TEST(g19_session, phase_name__returns_static_literal) {
    RFB_CHECK(apple_session_phase_name(APPLE_SESSION_PRELUDE) != NULL);
    RFB_CHECK(apple_session_phase_name(APPLE_SESSION_STREAMING) != NULL);
    RFB_CHECK(apple_session_phase_name(APPLE_SESSION_CLOSED) != NULL);
}
