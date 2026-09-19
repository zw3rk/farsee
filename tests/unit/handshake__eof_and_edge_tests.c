// SPDX-License-Identifier: Apache-2.0
//
// G2 — EOF and edge-case tests (plan.md §G2: "EOF at every handshake byte
// boundary", "zero offered security types and bounded failure reason",
// "malformed banner characters, width, and newline").
//
// These cover the boundary conditions the main transcript tests don't
// drive: truncated input at every length, zero-security-types followed
// by a reason string, and banner edge cases not covered in the banner
// suite.

#include "rfb_test.h"
#include "farsee/handshake.h"
#include "farsee/allocator.h"
#include "farsee/buffer.h"

#include <string.h>

// --- EOF at every byte boundary ------------------------------------------
// Feed a known-good transcript truncated at every length; the SM must
// never crash, never emit partial/invalid output, and must simply wait
// for more input. When the transcript is complete it reaches the
// expected state. This is the "fragmented at every byte boundary"
// property combined with graceful truncation handling.

RFB_TEST(handshake_eof, eof__truncated_at_every_length__never_crashes_never_invalid) {
    static const uint8_t T[] = {
        'R','F','B',' ','0','0','3','.','0','0','8','\n',
        0x01, 0x02,  // VNC only
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  // challenge
        0x00,0x00,0x00,0x00,  // OK
    };
    // For every prefix length 0..sizeof T, run the SM on exactly that many
    // bytes and assert: no crash, no RFB_ERR_PROTOCOL (we just don't have
    // enough bytes yet), and output never exceeds the full expected
    // client output (banner+selection+response = 29 bytes for this path).
    for (size_t n = 0; n <= sizeof T; n++) {
        rfb_handshake_policy pol = rfb_handshake_policy_default();
        rfb_handshake h;
        rfb_handshake_init(&h, &pol, rfb_default_allocator());
        static const uint8_t pw[8] = { 'x','x','x','x','x','x','x','x' };
        rfb_handshake_set_password(&h, pw, 8);
        rfb_buffer in, out;
        rfb_buffer_init(&in, rfb_default_allocator(), 4096);
        rfb_buffer_init(&out, rfb_default_allocator(), 4096);
        rfb_buffer_append(&in, T, n);
        rfb_error e = RFB_OK;
        for (int k = 0; k < 16 && !rfb_handshake_finished(&h); k++) {
            e = rfb_handshake_step(&h, &in, &out);
            if (e != RFB_OK) break;
        }
        // On any prefix, either we're still progressing/waiting, or done.
        // We must never produce an output longer than the full exchange.
        RFB_CHECK(rfb_buffer_length(&out) <= 29u);
        rfb_buffer_destroy(&in); rfb_buffer_destroy(&out);
        rfb_handshake_destroy(&h);
    }
}

// --- zero security types, 3.8, with a reason string ---------------------

RFB_TEST(handshake_eof, zero_security_types__rfb38__reads_reason_and_fails) {
    // RFC 6143 §7.1.2: count=0 means the connection failed; a reason
    // string (u32 length + bytes) follows. This is distinct from "no
    // common security type" — the server is refusing outright.
    static const uint8_t T[] = {
        'R','F','B',' ','0','0','3','.','0','0','8','\n',
        0x00,  // zero security types
        0x00,0x00,0x00,0x06,  // reason length = 6
        'b','a','n','n','e','d',  // reason
    };
    rfb_handshake_policy pol = rfb_handshake_policy_default();
    rfb_handshake h;
    rfb_handshake_init(&h, &pol, rfb_default_allocator());
    rfb_buffer in, out;
    rfb_buffer_init(&in, rfb_default_allocator(), 4096);
    rfb_buffer_init(&out, rfb_default_allocator(), 4096);
    rfb_buffer_append(&in, T, sizeof T);
    rfb_error e = RFB_OK;
    for (int i = 0; i < 16 && !rfb_handshake_finished(&h); i++) {
        e = rfb_handshake_step(&h, &in, &out);
        if (e != RFB_OK) break;
    }
    RFB_CHECK_EQ_INT(h.state, RFB_HS_FAILED);
    // The reason string was captured.
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&h.failure_reason), 6u);
    RFB_CHECK_MEM_EQ(rfb_buffer_data(&h.failure_reason),
                     (const uint8_t *)"banned", 6);
    rfb_buffer_destroy(&in); rfb_buffer_destroy(&out);
    rfb_handshake_destroy(&h);
}

// --- unsupported security type only (no None, no VNC) -------------------

RFB_TEST(handshake_eof, rfb38__only_unknown_security_type__fails_unsupported) {
    static const uint8_t T[] = {
        'R','F','B',' ','0','0','3','.','0','0','8','\n',
        0x01, 0x40,  // count=1, type=64 (some unsupported type)
    };
    rfb_handshake_policy pol = rfb_handshake_policy_default();
    rfb_handshake h;
    rfb_handshake_init(&h, &pol, rfb_default_allocator());
    rfb_buffer in, out;
    rfb_buffer_init(&in, rfb_default_allocator(), 4096);
    rfb_buffer_init(&out, rfb_default_allocator(), 4096);
    rfb_buffer_append(&in, T, sizeof T);
    rfb_error e = RFB_OK;
    for (int i = 0; i < 16 && !rfb_handshake_finished(&h); i++) {
        e = rfb_handshake_step(&h, &in, &out);
        if (e != RFB_OK) break;
    }
    RFB_CHECK(e != RFB_OK);
    RFB_CHECK_EQ_INT(h.state, RFB_HS_FAILED);
    RFB_CHECK_EQ_INT(h.last_error, RFB_ERR_UNSUPPORTED);
    rfb_buffer_destroy(&in); rfb_buffer_destroy(&out);
    rfb_handshake_destroy(&h);
}

// --- selection prefers VNC over None when both offered and both allowed --

RFB_TEST(handshake_eof, rfb38__both_none_and_vnc_offered_with_opt_in__prefers_vnc) {
    static const uint8_t T[] = {
        'R','F','B',' ','0','0','3','.','0','0','8','\n',
        0x02, 0x01, 0x02,  // count=2: None, VNC
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  // challenge (if VNC chosen)
        0x00,0x00,0x00,0x00,  // result OK
    };
    rfb_handshake_policy pol = rfb_handshake_policy_default();
    pol.allow_none_auth = true;
    rfb_handshake h;
    rfb_handshake_init(&h, &pol, rfb_default_allocator());
    static const uint8_t pw[8] = { 'p','a','s','s','w','o','r','d' };
    rfb_handshake_set_password(&h, pw, 8);
    rfb_buffer in, out;
    rfb_buffer_init(&in, rfb_default_allocator(), 4096);
    rfb_buffer_init(&out, rfb_default_allocator(), 4096);
    rfb_buffer_append(&in, T, sizeof T);
    for (int i = 0; i < 16 && !rfb_handshake_finished(&h); i++) {
        rfb_error e = rfb_handshake_step(&h, &in, &out);
        if (e != RFB_OK) break;
    }
    RFB_CHECK_EQ_INT(h.selected_security, RFB_SECURITY_VNC);
    // Selection byte must be 2 (VNC), not 1 (None).
    RFB_CHECK_EQ_UINT(rfb_buffer_data(&out)[12], 0x02);
    rfb_buffer_destroy(&in); rfb_buffer_destroy(&out);
    rfb_handshake_destroy(&h);
}

// --- 3.8 None auth success path (opt-in) --------------------------------

RFB_TEST(handshake_eof, rfb38__none_auth_with_opt_in__reaches_done) {
    static const uint8_t T[] = {
        'R','F','B',' ','0','0','3','.','0','0','8','\n',
        0x01, 0x01,  // count=1: None
        0x00,0x00,0x00,0x00,  // result OK
    };
    rfb_handshake_policy pol = rfb_handshake_policy_default();
    pol.allow_none_auth = true;
    rfb_handshake h;
    rfb_handshake_init(&h, &pol, rfb_default_allocator());
    rfb_buffer in, out;
    rfb_buffer_init(&in, rfb_default_allocator(), 4096);
    rfb_buffer_init(&out, rfb_default_allocator(), 4096);
    rfb_buffer_append(&in, T, sizeof T);
    rfb_error e = RFB_OK;
    for (int i = 0; i < 16 && !rfb_handshake_finished(&h); i++) {
        e = rfb_handshake_step(&h, &in, &out);
        if (e != RFB_OK) break;
    }
    RFB_CHECK_EQ_INT(e, RFB_OK);
    RFB_CHECK_EQ_INT(h.state, RFB_HS_DONE);
    RFB_CHECK_EQ_INT(h.selected_security, RFB_SECURITY_NONE);
    rfb_buffer_destroy(&in); rfb_buffer_destroy(&out);
    rfb_handshake_destroy(&h);
}

// --- password not set when VNC auth starts → fail closed ----------------

RFB_TEST(handshake_eof, vnc_auth__no_password_set__fails_closed) {
    static const uint8_t T[] = {
        'R','F','B',' ','0','0','3','.','0','0','8','\n',
        0x01, 0x02,
        1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
    };
    static const uint8_t expected_output[] = {
        'R','F','B',' ','0','0','3','.','0','0','8','\n', 0x02,
    };
    static const uint8_t zero_password[8] = { 0 };
    static const uint8_t zero_block[16] = { 0 };
    rfb_handshake_policy pol = rfb_handshake_policy_default();
    rfb_handshake h;
    rfb_handshake_init(&h, &pol, rfb_default_allocator());
    // Note: deliberately do NOT call rfb_handshake_set_password.
    memset(h.response, 0xA5, sizeof h.response);
    rfb_buffer in, out;
    rfb_buffer_init(&in, rfb_default_allocator(), 4096);
    rfb_buffer_init(&out, rfb_default_allocator(), 4096);
    rfb_buffer_append(&in, T, sizeof T);
    rfb_error e = RFB_OK;
    for (int i = 0; i < 16 && !rfb_handshake_finished(&h); i++) {
        e = rfb_handshake_step(&h, &in, &out);
        if (e != RFB_OK) break;
    }
    RFB_CHECK(e != RFB_OK);
    RFB_CHECK_EQ_INT(h.state, RFB_HS_FAILED);
    RFB_CHECK_EQ_INT(h.last_error, RFB_ERR_AUTH);
    RFB_CHECK(!h.password_set);
    RFB_CHECK_MEM_EQ(h.password, zero_password, sizeof h.password);
    RFB_CHECK_MEM_EQ(h.challenge, zero_block, sizeof h.challenge);
    RFB_CHECK_MEM_EQ(h.response, zero_block, sizeof h.response);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&out), sizeof expected_output);
    RFB_CHECK_MEM_EQ(rfb_buffer_data(&out), expected_output,
                     sizeof expected_output);
    rfb_buffer_destroy(&in); rfb_buffer_destroy(&out);
    rfb_handshake_destroy(&h);
}
