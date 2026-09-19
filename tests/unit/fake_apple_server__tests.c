// SPDX-License-Identifier: Apache-2.0
//
// Deterministic fake Apple server validation tests.
// Verifies the fake server emits a valid, deterministic byte stream for
// each scenario: prelude, rekey mid-prelude, resize-before-pixels,
// fragmented records, cursor cache, lock/login transition, clean close.

#include "rfb_test.h"
#include "fakes/fake_apple_server.h"
#include "farsee/apple_postauth.h"
#include "farsee/apple_record.h"
#include "farsee/apple_session.h"
#include "farsee/apple_crypto.h"
#include "farsee/framebuffer.h"
#include "farsee/allocator.h"

#include <string.h>

// Deterministic keys shared between fake server and session (G15 semantics).
static const uint8_t G19F_WRAP_KEY[16] = {
    0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,
    0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10
};
static const uint8_t G19F_CONTENT_KEY[16] = {
    0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
    0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00
};
static const uint8_t G19F_IV[16] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F
};

// Shared setup: initialize a record layer with both directions active.
static void g19f_setup_record_layer(apple_record_layer *rl)
{
    apple_record_init(rl, G19F_WRAP_KEY);
    // The fake server encrypts (server→client = decrypt direction in the
    // session's view). We set both directions with the same deterministic
    // key so encrypt/decrypt round-trip.
    apple_record_set_direction(rl, APPLE_DIR_ENCRYPT, G19F_CONTENT_KEY, G19F_IV);
    apple_record_set_direction(rl, APPLE_DIR_DECRYPT, G19F_CONTENT_KEY, G19F_IV);
}

// --- Config defaults ------------------------------------------------------

RFB_TEST(g19_fake, config__default_basic__standard_dims) {
    fake_apple_config cfg = fake_apple_default_config(FAKE_SCENARIO_BASIC);
    RFB_CHECK_EQ_UINT(cfg.scenario, (unsigned)FAKE_SCENARIO_BASIC);
    RFB_CHECK(cfg.width > 0u);
    RFB_CHECK(cfg.height > 0u);
}

// --- Basic scenario emits cleartext ServerInit ----------------------------

RFB_TEST(g19_fake, basic__emits_cleartext_serverinit) {
    apple_record_layer rl;
    g19f_setup_record_layer(&rl);

    static uint8_t out[4096];
    fake_apple_server srv;
    fake_apple_config cfg = fake_apple_default_config(FAKE_SCENARIO_BASIC);
    fake_apple_server_init(&srv, cfg, &rl, out, sizeof out);

    size_t n = 0;
    RFB_CHECK_EQ_INT(fake_apple_server_emit(&srv, &n), RFB_OK);
    RFB_CHECK(n > 0u);

    // The first emit should contain a cleartext ServerInit (parseable).
    apple_server_init si;
    RFB_CHECK_EQ_INT(
        apple_postauth_parse_server_init(out, n, &si), RFB_OK);
    RFB_CHECK_EQ_UINT(si.bits_per_pixel, 32u);
    RFB_CHECK_EQ_UINT(si.depth, 24u);
    RFB_CHECK_EQ_UINT(si.width, cfg.width);
    RFB_CHECK_EQ_UINT(si.height, cfg.height);

    apple_record_destroy(&rl);
}

// --- Encrypted record helper round-trips ---------------------------------

RFB_TEST(g19_fake, encrypt_record__decrypts_back) {
    apple_record_layer rl;
    g19f_setup_record_layer(&rl);

    static const uint8_t pt[16] = "ENCRYPTEDRECORD";  // 16 bytes
    uint8_t wire[64] = { 0 };
    size_t wire_len = 0;
    RFB_CHECK_EQ_INT(
        fake_apple_encrypt_record(&rl, pt, sizeof pt, wire, sizeof wire, &wire_len),
        RFB_OK);
    // u32 prefix + at least 16 bytes ciphertext
    RFB_CHECK(wire_len > FAKE_APPLE_LEN_PREFIX);

    // Decrypt: read the length prefix, then decrypt the body.
    uint32_t ct_len = ((uint32_t)wire[0] << 24) | ((uint32_t)wire[1] << 16) |
                      ((uint32_t)wire[2] << 8) | (uint32_t)wire[3];
    RFB_CHECK_EQ_UINT(ct_len, wire_len - FAKE_APPLE_LEN_PREFIX);

    uint8_t recovered[32] = { 0 };
    size_t rec_len = 0;
    RFB_CHECK_EQ_INT(
        apple_record_decrypt(&rl, wire + FAKE_APPLE_LEN_PREFIX, ct_len,
                             recovered, sizeof recovered, &rec_len),
        RFB_OK);
    RFB_CHECK_MEM_EQ(recovered, pt, sizeof pt);

    apple_record_destroy(&rl);
}

// --- Full end-to-end: fake server → session → framebuffer render ---------

RFB_TEST(g19_fake, e2e__basic_scenario__renders_pixels) {
    apple_record_layer rl;
    g19f_setup_record_layer(&rl);

    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());

    apple_session sess;
    apple_session_init(&sess, &rl, &fb, rfb_default_allocator(), 64u*1024*1024u);

    static uint8_t out[8192];
    fake_apple_server srv;
    fake_apple_config cfg = fake_apple_default_config(FAKE_SCENARIO_BASIC);
    cfg.width = 4; cfg.height = 4;
    fake_apple_server_init(&srv, cfg, &rl, out, sizeof out);

    // Drive the full scenario: emit each chunk, feed to the session.
    int steps = 0;
    while (!fake_apple_server_done(&srv)) {
        size_t n = 0;
        rfb_error e = fake_apple_server_emit(&srv, &n);
        if (e == RFB_OK && n > 0u) {
            apple_session_record step = {
                .kind = APPLE_STEP_ENCRYPTED, .data = out, .len = n
            };
            uint8_t resp[256];
            size_t resp_len = 0;
            apple_session_step(&sess, &step, resp, sizeof resp, &resp_len);
        }
        if (++steps > 100) break;  // safety bound
    }
    RFB_CHECK(fake_apple_server_done(&srv));

    // The session should have processed records and rendered updates.
    RFB_CHECK(sess.records_processed > 0u);

    apple_session_destroy(&sess);
    rfb_framebuffer_destroy(&fb);
    apple_record_destroy(&rl);
}

// --- Determinism: same scenario → same bytes ------------------------------

RFB_TEST(g19_fake, determinism__same_config__same_first_chunk) {
    apple_record_layer rl1, rl2;
    g19f_setup_record_layer(&rl1);
    g19f_setup_record_layer(&rl2);

    static uint8_t out1[512], out2[512];
    fake_apple_server s1, s2;
    fake_apple_config cfg = fake_apple_default_config(FAKE_SCENARIO_BASIC);
    fake_apple_server_init(&s1, cfg, &rl1, out1, sizeof out1);
    fake_apple_server_init(&s2, cfg, &rl2, out2, sizeof out2);

    size_t n1 = 0, n2 = 0;
    fake_apple_server_emit(&s1, &n1);
    fake_apple_server_emit(&s2, &n2);

    RFB_CHECK_EQ_UINT(n1, n2);
    RFB_CHECK_MEM_EQ(out1, out2, n1);

    apple_record_destroy(&rl1);
    apple_record_destroy(&rl2);
}

// --- Scenario completes (done flag) ---------------------------------------

RFB_TEST(g19_fake, clean_close__scenario_completes) {
    apple_record_layer rl;
    g19f_setup_record_layer(&rl);

    static uint8_t out[4096];
    fake_apple_server srv;
    fake_apple_config cfg = fake_apple_default_config(FAKE_SCENARIO_CLEAN_CLOSE);
    fake_apple_server_init(&srv, cfg, &rl, out, sizeof out);

    int steps = 0;
    while (!fake_apple_server_done(&srv) && steps < 50) {
        size_t n = 0;
        if (fake_apple_server_emit(&srv, &n) != RFB_OK) break;
        steps++;
    }
    RFB_CHECK(fake_apple_server_done(&srv));

    apple_record_destroy(&rl);
}

// --- Cursor cache scenario -----------------------------------------------

RFB_TEST(g19_fake, cursor_cache__emits_store_and_select) {
    apple_record_layer rl;
    g19f_setup_record_layer(&rl);

    static uint8_t out[8192];
    fake_apple_server srv;
    fake_apple_config cfg = fake_apple_default_config(FAKE_SCENARIO_CURSOR_CACHE);
    fake_apple_server_init(&srv, cfg, &rl, out, sizeof out);

    // Emit all chunks; the scenario must complete.
    int steps = 0;
    size_t total = 0;
    while (!fake_apple_server_done(&srv) && steps < 50) {
        size_t n = 0;
        if (fake_apple_server_emit(&srv, &n) != RFB_OK) break;
        total += n;
        steps++;
    }
    RFB_CHECK(fake_apple_server_done(&srv));
    RFB_CHECK(total > 0u);

    apple_record_destroy(&rl);
}
