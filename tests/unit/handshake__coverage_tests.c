// SPDX-License-Identifier: Apache-2.0
//
// G2 — handshake coverage completion tests. These drive the NULL-guard
// branches and the 3.3-specific error paths not covered by the main
// transcript tests, so plan.md §15.5's "RFB handshake/security state
// machine: at least 95% line and 90% branch" target is met.

#include "rfb_test.h"
#include "farsee/handshake.h"
#include "farsee/buffer.h"

#include <string.h>

// --- NULL guards on the public API --------------------------------------

RFB_TEST(hs_cov, handshake_init__null__is_safe_noop) {
    rfb_handshake_init(NULL, NULL, NULL);
    rfb_handshake_destroy(NULL);
    rfb_handshake_set_password(NULL, (const uint8_t *)"x", 1);
    rfb_handshake_set_des_provider(NULL, NULL);
    RFB_CHECK(true);  // reached here without crashing
}

RFB_TEST(hs_cov, handshake_step__null_args__returns_internal) {
    rfb_handshake_policy pol = rfb_handshake_policy_default();
    rfb_handshake h;
    rfb_handshake_init(&h, &pol, rfb_default_allocator());
    rfb_buffer b;
    rfb_buffer_init(&b, rfb_default_allocator(), 64);
    RFB_CHECK_EQ_INT(rfb_handshake_step(NULL, &b, &b), RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(rfb_handshake_step(&h, NULL, &b), RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(rfb_handshake_step(&h, &b, NULL), RFB_ERR_INTERNAL);
    rfb_buffer_destroy(&b);
    rfb_handshake_destroy(&h);
}

RFB_TEST(hs_cov, format_banner__null_out__returns_internal) {
    RFB_CHECK_EQ_INT(rfb_format_banner(RFB_VERSION_3_8, NULL, 12), RFB_ERR_INTERNAL);
}

RFB_TEST(hs_cov, format_banner__too_small_cap__returns_limit) {
    uint8_t out[11] = { 0 };
    RFB_CHECK_EQ_INT(rfb_format_banner(RFB_VERSION_3_8, out, sizeof out), RFB_ERR_LIMIT);
}

RFB_TEST(hs_cov, format_banner__unknown_version__returns_protocol) {
    uint8_t out[12] = { 0 };
    RFB_CHECK_EQ_INT(rfb_format_banner(RFB_VERSION_UNKNOWN, out, sizeof out), RFB_ERR_PROTOCOL);
}

// --- 3.3 error paths -----------------------------------------------------

RFB_TEST(hs_cov, rfb33__security_type_none_without_opt_in__fails) {
    static const uint8_t T[] = {
        'R','F','B',' ','0','0','3','.','0','0','3','\n',
        0x00,0x00,0x00,0x01,  // security type = 1 (None)
    };
    rfb_handshake_policy pol = rfb_handshake_policy_default();  // allow_none=false
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
    RFB_CHECK_EQ_INT(e, RFB_ERR_UNSUPPORTED);
    RFB_CHECK_EQ_INT(h.state, RFB_HS_FAILED);
    rfb_buffer_destroy(&in); rfb_buffer_destroy(&out);
    rfb_handshake_destroy(&h);
}

RFB_TEST(hs_cov, rfb33__security_type_none_with_opt_in__done) {
    static const uint8_t T[] = {
        'R','F','B',' ','0','0','3','.','0','0','3','\n',
        0x00,0x00,0x00,0x01,  // None
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

RFB_TEST(hs_cov, rfb33__security_type_vnc_disabled__fails) {
    static const uint8_t T[] = {
        'R','F','B',' ','0','0','3','.','0','0','3','\n',
        0x00,0x00,0x00,0x02,  // VNC
    };
    rfb_handshake_policy pol = rfb_handshake_policy_default();
    pol.allow_vnc_auth = false;  // policy disables VNC
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
    RFB_CHECK_EQ_INT(e, RFB_ERR_UNSUPPORTED);
    RFB_CHECK_EQ_INT(h.state, RFB_HS_FAILED);
    rfb_buffer_destroy(&in); rfb_buffer_destroy(&out);
    rfb_handshake_destroy(&h);
}

RFB_TEST(hs_cov, rfb33__security_type_unknown__fails) {
    static const uint8_t T[] = {
        'R','F','B',' ','0','0','3','.','0','0','3','\n',
        0x00,0x00,0x00,0x40,  // unknown type 64
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
    RFB_CHECK_EQ_INT(e, RFB_ERR_UNSUPPORTED);
    RFB_CHECK_EQ_INT(h.state, RFB_HS_FAILED);
    rfb_buffer_destroy(&in); rfb_buffer_destroy(&out);
    rfb_handshake_destroy(&h);
}

RFB_TEST(hs_cov, rfb33__security_type_zero__fails_auth) {
    static const uint8_t T[] = {
        'R','F','B',' ','0','0','3','.','0','0','3','\n',
        0x00,0x00,0x00,0x00,  // 3.3 zero = connection failed
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
    RFB_CHECK_EQ_INT(e, RFB_ERR_AUTH);
    RFB_CHECK_EQ_INT(h.state, RFB_HS_FAILED);
    rfb_buffer_destroy(&in); rfb_buffer_destroy(&out);
    rfb_handshake_destroy(&h);
}

RFB_TEST(hs_cov, rfb33__security_type_above_u8__fails_protocol) {
    static const uint8_t T[] = {
        'R','F','B',' ','0','0','3','.','0','0','3','\n',
        0x00,0x01,0x00,0x00,  // 0x10000 — exceeds the valid u8 range
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
    RFB_CHECK_EQ_INT(e, RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(h.state, RFB_HS_FAILED);
    rfb_buffer_destroy(&in); rfb_buffer_destroy(&out);
    rfb_handshake_destroy(&h);
}

// --- banner parse failure inside step -----------------------------------

RFB_TEST(hs_cov, step__malformed_banner__fails_protocol) {
    static const uint8_t T[] = {
        'R','F','B',' ','0','0','3','.','0','0','8','X',  // bad last byte
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
    RFB_CHECK_EQ_INT(e, RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(h.state, RFB_HS_FAILED);
    rfb_buffer_destroy(&in); rfb_buffer_destroy(&out);
    rfb_handshake_destroy(&h);
}

RFB_TEST(hs_cov, step__unknown_vendor_banner__fails_unsupported) {
    static const uint8_t T[] = {
        'R','F','B',' ','0','0','3','.','8','8','9','\n',  // Apple-observed, unmapped
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
    RFB_CHECK_EQ_INT(e, RFB_ERR_UNSUPPORTED);
    rfb_buffer_destroy(&in); rfb_buffer_destroy(&out);
    rfb_handshake_destroy(&h);
}

// --- 3.8 None auth failure (result nonzero) -----------------------------

RFB_TEST(hs_cov, rfb38__none_auth_failure_result__fails) {
    static const uint8_t T[] = {
        'R','F','B',' ','0','0','3','.','0','0','8','\n',
        0x01, 0x01,  // None
        0x00,0x00,0x00,0x01,  // failed
        0x00,0x00,0x00,0x03, 'b','a','d',
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
    RFB_CHECK_EQ_INT(e, RFB_ERR_AUTH);
    RFB_CHECK_EQ_INT(h.state, RFB_HS_FAILED);
    rfb_buffer_destroy(&in); rfb_buffer_destroy(&out);
    rfb_handshake_destroy(&h);
}

// --- oversized reason string rejected -----------------------------------

RFB_TEST(hs_cov, rfb38__oversized_failure_reason__fails_limit) {
    static const uint8_t T[] = {
        'R','F','B',' ','0','0','3','.','0','0','8','\n',
        0x01, 0x02,  // VNC
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  // challenge
        0x00,0x00,0x00,0x01,  // failed
        0x00,0x10,0x00,0x01,  // reason length = 1 MiB + 1 (over the cap)
    };
    rfb_handshake_policy pol = rfb_handshake_policy_default();
    rfb_handshake h;
    rfb_handshake_init(&h, &pol, rfb_default_allocator());
    static const uint8_t pw[8] = { 'p','a','s','s','w','o','r','d' };
    rfb_handshake_set_password(&h, pw, 8);
    rfb_buffer in, out;
    rfb_buffer_init(&in, rfb_default_allocator(), 4096);
    rfb_buffer_init(&out, rfb_default_allocator(), 4096);
    rfb_buffer_append(&in, T, sizeof T);
    rfb_error e = RFB_OK;
    for (int i = 0; i < 16 && !rfb_handshake_finished(&h); i++) {
        e = rfb_handshake_step(&h, &in, &out);
        if (e != RFB_OK) break;
    }
    RFB_CHECK_EQ_INT(e, RFB_ERR_LIMIT);
    RFB_CHECK_EQ_INT(h.state, RFB_HS_FAILED);
    rfb_buffer_destroy(&in); rfb_buffer_destroy(&out);
    rfb_handshake_destroy(&h);
}

// --- 3.7 None auth: straight to DONE (no result u32) --------------------

RFB_TEST(hs_cov, rfb37__none_auth_with_opt_in__straight_to_done) {
    static const uint8_t T[] = {
        'R','F','B',' ','0','0','3','.','0','0','7','\n',
        0x01, 0x01,  // None
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

// --- output queue full mid-handshake -------------------------------------

RFB_TEST(hs_cov, handshake__output_queue_too_small_for_banner__returns_error) {
    // Give the output buffer only 4 bytes so the 12-byte banner append fails.
    static const uint8_t T[] = {
        'R','F','B',' ','0','0','3','.','0','0','8','\n',
        0x01, 0x02,
    };
    rfb_handshake_policy pol = rfb_handshake_policy_default();
    rfb_handshake h;
    rfb_handshake_init(&h, &pol, rfb_default_allocator());
    rfb_buffer in, out;
    rfb_buffer_init(&in, rfb_default_allocator(), 4096);
    rfb_buffer_init(&out, rfb_default_allocator(), 4);  // too small for banner
    rfb_buffer_append(&in, T, sizeof T);
    rfb_error e = rfb_handshake_step(&h, &in, &out);
    RFB_CHECK(e != RFB_OK);  // append failed (LIMIT)
    rfb_buffer_destroy(&in); rfb_buffer_destroy(&out);
    rfb_handshake_destroy(&h);
}

// --- 3.8 VNC auth with bad challenge read (truncated mid-challenge) -----
// Already covered by fragmentation tests, but add an explicit short-
// challenge-after-successful-list case to drive the "need more input"
// path inside step_read_vnc_challenge.

RFB_TEST(hs_cov, vnc_auth__challenge_only_partially_arrives__waits) {
    static const uint8_t T[] = {
        'R','F','B',' ','0','0','3','.','0','0','8','\n',
        0x01, 0x02,
        0,0,0,0,0,0,0,0,  // only 8 of 16 challenge bytes
    };
    rfb_handshake_policy pol = rfb_handshake_policy_default();
    rfb_handshake h;
    rfb_handshake_init(&h, &pol, rfb_default_allocator());
    static const uint8_t pw[8] = { 'p','a','s','s','w','o','r','d' };
    rfb_handshake_set_password(&h, pw, 8);
    rfb_buffer in, out;
    rfb_buffer_init(&in, rfb_default_allocator(), 4096);
    rfb_buffer_init(&out, rfb_default_allocator(), 4096);
    rfb_buffer_append(&in, T, sizeof T);
    // Step until stable; the SM should be waiting for more challenge bytes.
    for (int i = 0; i < 16 && !rfb_handshake_finished(&h); i++) {
        rfb_error e = rfb_handshake_step(&h, &in, &out);
        if (e != RFB_OK) break;
    }
    RFB_CHECK_EQ_INT(h.state, RFB_HS_READ_VNC_CHALLENGE);  // still waiting
    rfb_buffer_destroy(&in); rfb_buffer_destroy(&out);
    rfb_handshake_destroy(&h);
}
