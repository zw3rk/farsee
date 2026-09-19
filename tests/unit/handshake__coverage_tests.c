// SPDX-License-Identifier: Apache-2.0
//
// G2 — handshake tests for public NULL guards, 3.3 security paths,
// malformed input, failure reasons, allocator failure, and short output.
// The repository coverage gate measures the aggregate target separately.

#include "rfb_test.h"
#include "farsee/handshake.h"
#include "farsee/buffer.h"

#include <string.h>

static void *hs_always_fail_alloc(rfb_allocator *allocator, size_t size)
{
    (void)allocator;
    (void)size;
    return NULL;
}

static void hs_noop_free(rfb_allocator *allocator, void *pointer)
{
    (void)allocator;
    (void)pointer;
}

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
    // RFC 6143 §7.1.3: 3.3 zero = connection failed, and a u32-length
    // reason follows. An empty reason still routes
    // through the failure-reason reader and ends FAILED/AUTH.
    static const uint8_t T[] = {
        'R','F','B',' ','0','0','3','.','0','0','3','\n',
        0x00,0x00,0x00,0x00,  // 3.3 zero = connection failed
        0x00,0x00,0x00,0x00,  // reason length = 0
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
        'R','F','B',' ','0','0','3','.','8','8','9','\n',  // extension, unmapped
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

RFB_TEST(hs_cov, rfb38__long_failure_reason__retains_exact_prefix) {
    enum { reason_len = 4097 };
    uint8_t transcript[12u + 2u + 4u + 4u + reason_len];
    size_t pos = 0u;
    static const uint8_t banner[] = "RFB 003.008\n";
    memcpy(transcript + pos, banner, sizeof banner - 1u);
    pos += sizeof banner - 1u;
    transcript[pos++] = 1u;
    transcript[pos++] = RFB_SECURITY_NONE;
    transcript[pos++] = 0u;
    transcript[pos++] = 0u;
    transcript[pos++] = 0u;
    transcript[pos++] = 1u;
    transcript[pos++] = 0u;
    transcript[pos++] = 0u;
    transcript[pos++] = 0x10u;
    transcript[pos++] = 0x01u;
    for (size_t i = 0u; i < reason_len; i++) {
        transcript[pos++] = (uint8_t)('a' + (i % 26u));
    }

    rfb_handshake_policy pol = rfb_handshake_policy_default();
    pol.allow_none_auth = true;
    rfb_handshake h;
    rfb_handshake_init(&h, &pol, rfb_default_allocator());
    rfb_buffer in;
    rfb_buffer out;
    rfb_buffer_init(&in, rfb_default_allocator(), sizeof transcript);
    rfb_buffer_init(&out, rfb_default_allocator(), 4096u);
    RFB_CHECK_EQ_INT(rfb_buffer_append(&in, transcript, sizeof transcript),
                     RFB_OK);

    rfb_error e = RFB_OK;
    for (int i = 0; i < 16 && !rfb_handshake_finished(&h); i++) {
        e = rfb_handshake_step(&h, &in, &out);
        if (e != RFB_OK) {
            break;
        }
    }
    RFB_CHECK_EQ_INT(e, RFB_ERR_AUTH);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&h.failure_reason), 4096u);
    if (rfb_buffer_length(&h.failure_reason) == 4096u) {
        RFB_CHECK_MEM_EQ(rfb_buffer_data(&h.failure_reason),
                         transcript + sizeof transcript - reason_len, 4096u);
    }
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&in), 0u);

    rfb_buffer_destroy(&in);
    rfb_buffer_destroy(&out);
    rfb_handshake_destroy(&h);
}

RFB_TEST(hs_cov, rfb38__failure_reason_allocation_error__is_propagated) {
    static const uint8_t transcript[] = {
        'R','F','B',' ','0','0','3','.','0','0','8','\n',
        1u, RFB_SECURITY_NONE,
        0u, 0u, 0u, 1u,
        0u, 0u, 0u, 3u, 'b', 'a', 'd',
    };
    rfb_allocator fail_allocator = {
        .alloc = hs_always_fail_alloc,
        .free = hs_noop_free,
        .user = NULL,
    };
    rfb_handshake_policy policy = rfb_handshake_policy_default();
    policy.allow_none_auth = true;
    rfb_handshake h;
    rfb_handshake_init(&h, &policy, &fail_allocator);
    rfb_buffer in;
    rfb_buffer out;
    rfb_buffer_init(&in, rfb_default_allocator(), sizeof transcript);
    rfb_buffer_init(&out, rfb_default_allocator(), 4096u);
    RFB_CHECK_EQ_INT(rfb_buffer_append(&in, transcript, sizeof transcript),
                     RFB_OK);

    rfb_error error = RFB_OK;
    for (int i = 0; i < 16 && !rfb_handshake_finished(&h); i++) {
        error = rfb_handshake_step(&h, &in, &out);
        if (error != RFB_OK) {
            break;
        }
    }
    RFB_CHECK_EQ_INT(error, RFB_ERR_NOMEM);
    RFB_CHECK_EQ_INT(h.last_error, RFB_ERR_NOMEM);
    RFB_CHECK_EQ_INT(h.state, RFB_HS_FAILED);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&h.failure_reason), 0u);

    rfb_buffer_destroy(&in);
    rfb_buffer_destroy(&out);
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

RFB_TEST(hs_cov, init_null_policy_and_empty_passwords__use_safe_defaults)
{
    rfb_handshake h;
    rfb_handshake_init(&h, NULL, rfb_default_allocator());
    RFB_CHECK(!h.policy.allow_none_auth);
    RFB_CHECK(h.policy.allow_vnc_auth);
    RFB_CHECK(h.policy.shared_flag);

    rfb_handshake_set_password(&h, NULL, 1u);
    RFB_CHECK(h.password_set);
    static const uint8_t zero[8] = {0u};
    RFB_CHECK_MEM_EQ(h.password, zero, sizeof zero);
    rfb_handshake_set_password(&h, (const uint8_t *)"x", 0u);
    RFB_CHECK_MEM_EQ(h.password, zero, sizeof zero);
    rfb_handshake_destroy(&h);
}

RFB_TEST(hs_cov, banner_digits_below_zero_and_bad_minor__fail_protocol)
{
    static const uint8_t below_zero[] = "RFB 00/.008\n";
    static const uint8_t bad_minor[] = "RFB 003.0a8\n";
    rfb_version version = RFB_VERSION_UNKNOWN;
    RFB_CHECK_EQ_INT(
        rfb_parse_banner(below_zero, 12u, &version), RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(
        rfb_parse_banner(bad_minor, 12u, &version), RFB_ERR_PROTOCOL);
}

RFB_TEST(hs_cov, rfb38_vnc_only_with_vnc_disabled__fails_unsupported)
{
    static const uint8_t transcript[] = {
        'R','F','B',' ','0','0','3','.','0','0','8','\n',
        1u, RFB_SECURITY_VNC,
    };
    rfb_handshake_policy policy = rfb_handshake_policy_default();
    policy.allow_vnc_auth = false;
    rfb_handshake h;
    rfb_handshake_init(&h, &policy, rfb_default_allocator());
    rfb_buffer input;
    rfb_buffer output;
    rfb_buffer_init(&input, rfb_default_allocator(), sizeof transcript);
    rfb_buffer_init(&output, rfb_default_allocator(), 64u);
    RFB_CHECK_EQ_INT(
        rfb_buffer_append(&input, transcript, sizeof transcript), RFB_OK);
    RFB_CHECK_EQ_INT(rfb_handshake_step(&h, &input, &output), RFB_OK);
    RFB_CHECK_EQ_INT(rfb_handshake_step(&h, &input, &output),
                     RFB_ERR_UNSUPPORTED);
    RFB_CHECK_EQ_INT(h.state, RFB_HS_FAILED);
    rfb_buffer_destroy(&input);
    rfb_buffer_destroy(&output);
    rfb_handshake_destroy(&h);
}

RFB_TEST(hs_cov, security_selection_output_limit__is_reported)
{
    static const uint8_t transcript[] = {
        'R','F','B',' ','0','0','3','.','0','0','8','\n',
        1u, RFB_SECURITY_VNC,
    };
    rfb_handshake_policy policy = rfb_handshake_policy_default();
    rfb_handshake h;
    rfb_handshake_init(&h, &policy, rfb_default_allocator());
    rfb_buffer input;
    rfb_buffer output;
    rfb_buffer_init(&input, rfb_default_allocator(), sizeof transcript);
    rfb_buffer_init(&output, rfb_default_allocator(), 12u);
    RFB_CHECK_EQ_INT(
        rfb_buffer_append(&input, transcript, sizeof transcript), RFB_OK);
    RFB_CHECK_EQ_INT(rfb_handshake_step(&h, &input, &output), RFB_OK);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&output), 12u);
    RFB_CHECK_EQ_INT(rfb_handshake_step(&h, &input, &output), RFB_ERR_LIMIT);
    rfb_buffer_destroy(&input);
    rfb_buffer_destroy(&output);
    rfb_handshake_destroy(&h);
}

RFB_TEST(hs_cov, vnc_password_with_null_provider__fails_auth)
{
    static const uint8_t transcript[] = {
        'R','F','B',' ','0','0','3','.','0','0','8','\n',
        1u, RFB_SECURITY_VNC,
        1u,2u,3u,4u,5u,6u,7u,8u,9u,10u,11u,12u,13u,14u,15u,16u,
    };
    static const uint8_t expected_output[] = {
        'R','F','B',' ','0','0','3','.','0','0','8','\n', RFB_SECURITY_VNC,
    };
    static const uint8_t zero_password[8] = { 0 };
    static const uint8_t zero_block[16] = { 0 };
    rfb_handshake_policy policy = rfb_handshake_policy_default();
    rfb_handshake h;
    rfb_handshake_init(&h, &policy, rfb_default_allocator());
    rfb_handshake_set_password(&h, (const uint8_t *)"password", 8u);
    rfb_handshake_set_des_provider(&h, NULL);
    memset(h.response, 0xA5, sizeof h.response);
    rfb_buffer input;
    rfb_buffer output;
    rfb_buffer_init(&input, rfb_default_allocator(), sizeof transcript);
    rfb_buffer_init(&output, rfb_default_allocator(), 64u);
    RFB_CHECK_EQ_INT(
        rfb_buffer_append(&input, transcript, sizeof transcript), RFB_OK);
    RFB_CHECK_EQ_INT(rfb_handshake_step(&h, &input, &output), RFB_OK);
    RFB_CHECK_EQ_INT(rfb_handshake_step(&h, &input, &output), RFB_OK);
    RFB_CHECK_EQ_INT(rfb_handshake_step(&h, &input, &output), RFB_ERR_AUTH);
    RFB_CHECK_EQ_INT(h.state, RFB_HS_FAILED);
    RFB_CHECK_EQ_INT(h.last_error, RFB_ERR_AUTH);
    RFB_CHECK(!h.password_set);
    RFB_CHECK_MEM_EQ(h.password, zero_password, sizeof h.password);
    RFB_CHECK_MEM_EQ(h.challenge, zero_block, sizeof h.challenge);
    RFB_CHECK_MEM_EQ(h.response, zero_block, sizeof h.response);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&output), sizeof expected_output);
    RFB_CHECK_MEM_EQ(rfb_buffer_data(&output), expected_output,
                     sizeof expected_output);
    rfb_buffer_destroy(&input);
    rfb_buffer_destroy(&output);
    rfb_handshake_destroy(&h);
}

RFB_TEST(hs_cov, invalid_state__fails_internal)
{
    rfb_handshake h;
    rfb_handshake_init(&h, NULL, rfb_default_allocator());
    h.state = (rfb_hs_state)127;
    rfb_buffer input;
    rfb_buffer output;
    rfb_buffer_init(&input, rfb_default_allocator(), 1u);
    rfb_buffer_init(&output, rfb_default_allocator(), 1u);
    RFB_CHECK_EQ_INT(rfb_handshake_step(&h, &input, &output),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(h.state, RFB_HS_FAILED);
    rfb_buffer_destroy(&input);
    rfb_buffer_destroy(&output);
    rfb_handshake_destroy(&h);
}
