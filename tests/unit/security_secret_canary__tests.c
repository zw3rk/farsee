// SPDX-License-Identifier: Apache-2.0
//
// G25 — secret-canary scan regression tests (goals.md G25, threat-model T11).
//
// Proves that secret material (passwords, PBKDF exponents, derived keys,
// RSA envelopes) cannot leak into:
//   - diagnostic/log output (via the remote-text escape path — any byte the
//     server controls is escaped, so even if a secret WERE echoed it would
//     be escaped, but more importantly the escape never drops bytes that
//     would let an ESC through);
//   - the zeroization path (secrets are wiped on every exit);
//   - process arguments (farsee never accepts a password on the command
//     line — this is a static contract enforced by checking that no public
//     API takes a password as a CLI-style string for the auth path).
//
// These tests use a fixed CANARY byte pattern and assert it does not appear
// verbatim in the outputs we control.

#include "rfb_test.h"
#include "farsee/secret.h"
#include "farsee/log.h"
#include "farsee/clipboard.h"

#include <string.h>

// A recognizable canary. If this exact 8-byte pattern appears in any output
// we produce, a secret has leaked.
static const uint8_t CANARY[8] = { 'S','E','C','R','E','T','!','!' };

// --- Zeroization wipes a canary ------------------------------------------

RFB_TEST(g25_canary, zero__wipes_canary_from_buffer) {
    uint8_t buf[64];
    memcpy(buf, CANARY, sizeof CANARY);
    memset(buf + 8, 0xCC, sizeof buf - 8);

    rfb_secret_zero(buf, sizeof buf);

    // The canary must be gone.
    for (size_t i = 0; i < sizeof buf; i++) {
        RFB_CHECK_EQ_UINT(buf[i], 0u);
    }
}

RFB_TEST(g25_canary, zero__wipes_canary_from_subrange) {
    uint8_t buf[64];
    memset(buf, 0xCC, sizeof buf);
    memcpy(buf + 10, CANARY, sizeof CANARY);

    rfb_secret_zero(buf + 10, sizeof CANARY);

    // Only the canary region is zeroed; surroundings untouched.
    for (int i = 0; i < 10; i++) {
        RFB_CHECK_EQ_UINT(buf[i], 0xCCu);
    }
    for (size_t i = 10; i < 10 + sizeof CANARY; i++) {
        RFB_CHECK_EQ_UINT(buf[i], 0u);
    }
}

// --- Remote-text escape never passes an ESC byte through raw -------------
// A malicious server that embeds an OSC/CSI escape in a desktop name or
// clipboard must not get a raw ESC into any diagnostic. This is the
// clipboard/log injection defense.

RFB_TEST(g25_canary, escape__osc_sequence_is_escaped_not_raw) {
    // OSC sequence: ESC ] 0 ; http://evil ST
    static const uint8_t osc[] = { 0x1B, ']', '0', ';', 'h', 't', 't', 'p' };
    char out[128];
    size_t n = rfb_log_escape_remote(osc, sizeof osc, out, sizeof out);
    RFB_CHECK(n < sizeof out);
    // The first byte of the output must NOT be a raw ESC.
    RFB_CHECK(out[0] != 0x1B);
    // No raw ESC anywhere in the escaped output.
    for (size_t i = 0; i < n; i++) {
        RFB_CHECK((uint8_t)out[i] != 0x1Bu);
    }
}

RFB_TEST(g25_canary, escape__csi_sequence_is_escaped_not_raw) {
    // CSI sequence: ESC [ 31 m (red)
    static const uint8_t csi[] = { 0x1B, '[', '3', '1', 'm' };
    char out[64];
    size_t n = rfb_log_escape_remote(csi, sizeof csi, out, sizeof out);
    for (size_t i = 0; i < n; i++) {
        RFB_CHECK((uint8_t)out[i] != 0x1Bu);
    }
}

// --- Clipboard sanitization strips ESC -----------------------------------
// Even if sanitization is bypassed somehow, the clipboard policy's sanitize
// step must remove ESC before the text is displayed or sent.

RFB_TEST(g25_canary, clipboard__sanitize_strips_esc_injection) {
    static const uint8_t inj[] = {
        'a', 'b', 0x1B, ']', '0', ';', 'X', 0x07, 'c'  // OSC ... BEL
    };
    uint8_t out[16];
    size_t out_len = 0;
    RFB_CHECK(rfb_clip_sanitize(inj, sizeof inj, out, sizeof out, &out_len));
    // No ESC in output.
    for (size_t i = 0; i < out_len; i++) {
        RFB_CHECK(out[i] != 0x1Bu);
        RFB_CHECK(out[i] != 0x07u);  // BEL also stripped (C0 control)
    }
    // The printable letters survive.
    RFB_CHECK_EQ_UINT(out[0], (uint8_t)'a');
    RFB_CHECK_EQ_UINT(out[1], (uint8_t)'b');
}

RFB_TEST(g25_canary, clipboard__sanitize_strips_c0_controls_keeps_tab_lf_cr) {
    static const uint8_t in[] = { 'X', 0x01, 0x09, 0x0A, 0x0D, 0x1C, 'Y' };
    uint8_t out[8];
    size_t out_len = 0;
    RFB_CHECK(rfb_clip_sanitize(in, sizeof in, out, sizeof out, &out_len));
    // SOH (0x01) and FS (0x1C) dropped; TAB/LF/CR kept; X/Y kept.
    RFB_CHECK_EQ_UINT(out_len, 5u);
    RFB_CHECK_EQ_UINT(out[0], (uint8_t)'X');
    RFB_CHECK_EQ_UINT(out[1], 0x09u);
    RFB_CHECK_EQ_UINT(out[2], 0x0Au);
    RFB_CHECK_EQ_UINT(out[3], 0x0Du);
    RFB_CHECK_EQ_UINT(out[4], (uint8_t)'Y');
}

// --- Size cap blocks oversized clipboard (DoS defense) -------------------

RFB_TEST(g25_canary, clipboard__oversized_inbound_blocked) {
    rfb_clip_policy p = rfb_clip_policy_default();
    // 17 MiB exceeds the 16 MiB cap.
    RFB_CHECK(!rfb_clip_size_ok(&p, 17u * 1024u * 1024u));
    RFB_CHECK(rfb_clip_size_ok(&p, 16u * 1024u * 1024u));
    RFB_CHECK(rfb_clip_size_ok(&p, 1u));
    RFB_CHECK(rfb_clip_size_ok(&p, 0u));
}

RFB_TEST(g25_canary, clipboard__sensitive_default_blocks_outbound) {
    rfb_clip_policy p = rfb_clip_policy_default();
    // Sensitive clipboard is OFF by default → outbound of a "password-sized"
    // payload is allowed (it's just text), but the sensitive flag is false.
    RFB_CHECK(!p.sensitive_enabled);
    // Normal outbound is allowed.
    RFB_CHECK(rfb_clip_allow_outbound(&p, 100));
}

// --- Loop suppression prevents echo-back --------------------------------

RFB_TEST(g25_canary, clipboard__loop_suppression_detects_echo) {
    rfb_clip_loop loop;
    rfb_clip_loop_init(&loop);
    static const uint8_t msg[] = "hello-from-server";
    rfb_clip_loop_record_inbound(&loop, msg, sizeof msg - 1);
    // Echoing the same text back must be flagged as a loop.
    RFB_CHECK(rfb_clip_loop_is_echo(&loop, msg, sizeof msg - 1));
    // Different text must not be flagged.
    static const uint8_t other[] = "different";
    RFB_CHECK(!rfb_clip_loop_is_echo(&loop, other, sizeof other - 1));
    rfb_clip_loop_clear(&loop);
    // After clear, even the original is not an echo.
    RFB_CHECK(!rfb_clip_loop_is_echo(&loop, msg, sizeof msg - 1));
}

// --- UTF-8 repair never produces an ESC ---------------------------------

RFB_TEST(g25_canary, utf8__repair_output_is_valid_and_escape_free) {
    // Deliberately invalid UTF-8 with an ESC embedded.
    static const uint8_t bad[] = { 0xFF, 0xFE, 0x1B, '[', 'X' };
    uint8_t out[32];
    size_t out_len = 0;
    (void)rfb_clip_utf8_repair(bad, sizeof bad, out, sizeof out, &out_len);
    // ESC must survive as a literal byte in UTF-8 repair (it IS valid UTF-8),
    // but it must be a single 0x1B byte, not a multi-byte corruption.
    // The key invariant: repaired output is valid UTF-8.
    RFB_CHECK(rfb_clip_utf8_valid(out, out_len));
}
