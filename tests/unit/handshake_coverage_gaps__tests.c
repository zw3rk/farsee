// SPDX-License-Identifier: Apache-2.0
//
// Additional handshake tests for NULL guards, partial input, output limits,
// provider failure, and terminal/write-state dispatch. One explicit
// placeholder below does not exercise a 3.7 authentication failure.

#include "rfb_test.h"
#include "farsee/handshake.h"
#include "farsee/buffer.h"
#include "farsee/allocator.h"
#include "farsee/error.h"
#include <string.h>

static bool hs_stub_des(const uint8_t key[8], const uint8_t in[8], uint8_t out[8])
{
    for (int i = 0; i < 8; i++) out[i] = (uint8_t)(in[i] ^ key[i]);
    return true;
}

static bool hs_failing_des(const uint8_t key[8], const uint8_t in[8], uint8_t out[8])
{
    (void)key;
    (void)in;
    memset(out, 0xA5, 8);
    return false;
}

static rfb_error run_steps(rfb_handshake *h, rfb_buffer *in, rfb_buffer *out, int max)
{
    rfb_error e = RFB_OK;
    for (int i = 0; i < max && !rfb_handshake_finished(h); i++) {
        e = rfb_handshake_step(h, in, out);
        if (e != RFB_OK) break;
    }
    return e;
}

// --- banner parse: NULL input → PROTOCOL (line 124) ----------------------
RFB_TEST(hs_cov2, banner__null_input__protocol) {
    rfb_version v;
    RFB_CHECK_EQ_INT(rfb_parse_banner(NULL, 12, &v), RFB_ERR_PROTOCOL);
}

// --- step: format_banner failure (unknown version banner parsed by step) --
RFB_TEST(hs_cov2, step__unknown_banner__fails_unsupported) {
    static const uint8_t T[] = "RFB 003.999\n";
    rfb_handshake_policy pol = rfb_handshake_policy_default();
    rfb_handshake h; rfb_handshake_init(&h, &pol, rfb_default_allocator());
    rfb_buffer in, out;
    rfb_buffer_init(&in, rfb_default_allocator(), 4096);
    rfb_buffer_init(&out, rfb_default_allocator(), 4096);
    rfb_buffer_append(&in, T, 12);
    rfb_error e = run_steps(&h, &in, &out, 8);
    RFB_CHECK_EQ_INT(e, RFB_ERR_UNSUPPORTED);
    RFB_CHECK_EQ_INT(h.state, RFB_HS_FAILED);
    rfb_buffer_destroy(&in); rfb_buffer_destroy(&out);
    rfb_handshake_destroy(&h);
}

// --- output queue too small for banner → error (line 239/382) -----------
RFB_TEST(hs_cov2, output_too_small_for_banner__returns_error) {
    static const uint8_t T[] = "RFB 003.008\n";
    rfb_handshake_policy pol = rfb_handshake_policy_default();
    rfb_handshake h; rfb_handshake_init(&h, &pol, rfb_default_allocator());
    rfb_buffer in, out;
    rfb_buffer_init(&in, rfb_default_allocator(), 4096);
    rfb_buffer_init(&out, rfb_default_allocator(), 4);  // tiny
    rfb_buffer_append(&in, T, 12);
    rfb_error e = rfb_handshake_step(&h, &in, &out);
    RFB_CHECK(e != RFB_OK);
    rfb_buffer_destroy(&in); rfb_buffer_destroy(&out);
    rfb_handshake_destroy(&h);
}

// --- 3.3: truncated security type (need more input) (line 258) ----------
RFB_TEST(hs_cov2, rfb33_truncated_sec_type__needs_more_input) {
    static const uint8_t T[] = "RFB 003.003\n";
    rfb_handshake_policy pol = rfb_handshake_policy_default();
    rfb_handshake h; rfb_handshake_init(&h, &pol, rfb_default_allocator());
    rfb_buffer in, out;
    rfb_buffer_init(&in, rfb_default_allocator(), 4096);
    rfb_buffer_init(&out, rfb_default_allocator(), 4096);
    rfb_buffer_append(&in, T, 12);
    // Only banner, no security type bytes yet.
    run_steps(&h, &in, &out, 8);
    RFB_CHECK_EQ_INT(h.state, RFB_HS_READ_SECURITY_TYPES);
    rfb_buffer_destroy(&in); rfb_buffer_destroy(&out);
    rfb_handshake_destroy(&h);
}

// --- 3.3 VNC challenge truncated (need more input) (line 317 area) -------
RFB_TEST(hs_cov2, rfb33_vnc_challenge_truncated__needs_input) {
    static const uint8_t T[] = {
        'R','F','B',' ','0','0','3','.','0','0','3','\n',
        0x00,0x00,0x00,0x02, // VNC
        0,0,0,0,0,0,0,0,     // only 8 of 16 challenge bytes
    };
    rfb_handshake_policy pol = rfb_handshake_policy_default();
    rfb_handshake h; rfb_handshake_init(&h, &pol, rfb_default_allocator());
    rfb_handshake_set_des_provider(&h, hs_stub_des);
    rfb_handshake_set_password(&h, (const uint8_t*)"pass", 4);
    rfb_buffer in, out;
    rfb_buffer_init(&in, rfb_default_allocator(), 4096);
    rfb_buffer_init(&out, rfb_default_allocator(), 4096);
    rfb_buffer_append(&in, T, sizeof T);
    run_steps(&h, &in, &out, 16);
    RFB_CHECK_EQ_INT(h.state, RFB_HS_READ_VNC_CHALLENGE);
    rfb_buffer_destroy(&in); rfb_buffer_destroy(&out);
    rfb_handshake_destroy(&h);
}

// --- 3.8 security result truncated (need more input) (line 342 area) -----
RFB_TEST(hs_cov2, rfb38_result_truncated__needs_input) {
    static const uint8_t T[] = {
        'R','F','B',' ','0','0','3','.','0','0','8','\n',
        0x01, 0x02, // VNC
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, // challenge
        // No result bytes yet
    };
    rfb_handshake_policy pol = rfb_handshake_policy_default();
    rfb_handshake h; rfb_handshake_init(&h, &pol, rfb_default_allocator());
    rfb_handshake_set_des_provider(&h, hs_stub_des);
    rfb_handshake_set_password(&h, (const uint8_t*)"pass", 4);
    rfb_buffer in, out;
    rfb_buffer_init(&in, rfb_default_allocator(), 4096);
    rfb_buffer_init(&out, rfb_default_allocator(), 4096);
    rfb_buffer_append(&in, T, sizeof T);
    run_steps(&h, &in, &out, 16);
    RFB_CHECK_EQ_INT(h.state, RFB_HS_READ_SECURITY_RESULT);
    rfb_buffer_destroy(&in); rfb_buffer_destroy(&out);
    rfb_handshake_destroy(&h);
}

// --- VNC auth: DES failure (line 422-424) -------------------------------
RFB_TEST(hs_cov2, vnc_auth_des_fails__internal_error) {
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
    rfb_handshake h; rfb_handshake_init(&h, &pol, rfb_default_allocator());
    rfb_handshake_set_des_provider(&h, hs_failing_des);
    rfb_handshake_set_password(&h, (const uint8_t*)"pass", 4);
    rfb_buffer in, out;
    rfb_buffer_init(&in, rfb_default_allocator(), 4096);
    rfb_buffer_init(&out, rfb_default_allocator(), 4096);
    rfb_buffer_append(&in, T, sizeof T);
    rfb_error e = run_steps(&h, &in, &out, 16);
    RFB_CHECK_EQ_INT(e, RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(h.state, RFB_HS_FAILED);
    RFB_CHECK_EQ_INT(h.last_error, RFB_ERR_INTERNAL);
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

// --- output queue too small for VNC response -----------------------------
RFB_TEST(hs_cov2, vnc_auth_response_output_limit__cleans_secrets) {
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
    rfb_handshake h; rfb_handshake_init(&h, &pol, rfb_default_allocator());
    rfb_handshake_set_des_provider(&h, hs_stub_des);
    rfb_handshake_set_password(&h, (const uint8_t *)"pass", 4);
    rfb_buffer in, out;
    rfb_buffer_init(&in, rfb_default_allocator(), 4096);
    rfb_buffer_init(&out, rfb_default_allocator(), 20);
    rfb_buffer_append(&in, T, sizeof T);
    rfb_error e = run_steps(&h, &in, &out, 16);
    RFB_CHECK_EQ_INT(e, RFB_ERR_LIMIT);
    RFB_CHECK_EQ_INT(h.state, RFB_HS_FAILED);
    RFB_CHECK_EQ_INT(h.last_error, RFB_ERR_LIMIT);
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

// --- truncated failure reason waits for more input -----------------------
RFB_TEST(hs_cov2, rfb38_failure_reason_truncated__needs_input) {
    static const uint8_t T[] = {
        'R','F','B',' ','0','0','3','.','0','0','8','\n',
        0x01, 0x02,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0x00,0x00,0x00,0x01, // failed
        0x00,0x00,0x00,0x05, // reason length 5
        'a','b','c',         // only 3 of 5 reason bytes
    };
    rfb_handshake_policy pol = rfb_handshake_policy_default();
    rfb_handshake h; rfb_handshake_init(&h, &pol, rfb_default_allocator());
    rfb_handshake_set_des_provider(&h, hs_stub_des);
    rfb_handshake_set_password(&h, (const uint8_t*)"pass", 4);
    rfb_buffer in, out;
    rfb_buffer_init(&in, rfb_default_allocator(), 4096);
    rfb_buffer_init(&out, rfb_default_allocator(), 4096);
    rfb_buffer_append(&in, T, sizeof T);
    (void)run_steps(&h, &in, &out, 16);
    // Should be waiting for more reason bytes, not failed yet.
    RFB_CHECK_EQ_INT(h.state, RFB_HS_READ_SECURITY_FAILURE_REASON);
    rfb_buffer_destroy(&in); rfb_buffer_destroy(&out);
    rfb_handshake_destroy(&h);
}

// --- explicit coverage placeholder ---------------------------------------
RFB_TEST(hs_cov2, rfb37_vnc_auth_failure__placeholder_only) {
    // This placeholder feeds no transcript and does not test authentication.
    RFB_CHECK(true);
}

// --- rfb_handshake_finished true cases in dispatch (lines 551/554) -------
RFB_TEST(hs_cov2, step__on_done_returns_ok) {
    rfb_handshake_policy pol = rfb_handshake_policy_default();
    rfb_handshake h; rfb_handshake_init(&h, &pol, rfb_default_allocator());
    h.state = RFB_HS_DONE;
    rfb_buffer in, out;
    rfb_buffer_init(&in, rfb_default_allocator(), 64);
    rfb_buffer_init(&out, rfb_default_allocator(), 64);
    RFB_CHECK_EQ_INT(rfb_handshake_step(&h, &in, &out), RFB_OK);
    rfb_buffer_destroy(&in); rfb_buffer_destroy(&out);
    rfb_handshake_destroy(&h);
}

RFB_TEST(hs_cov2, step__on_failed_returns_ok) {
    rfb_handshake_policy pol = rfb_handshake_policy_default();
    rfb_handshake h; rfb_handshake_init(&h, &pol, rfb_default_allocator());
    h.state = RFB_HS_FAILED;
    rfb_buffer in, out;
    rfb_buffer_init(&in, rfb_default_allocator(), 64);
    rfb_buffer_init(&out, rfb_default_allocator(), 64);
    RFB_CHECK_EQ_INT(rfb_handshake_step(&h, &in, &out), RFB_OK);
    rfb_buffer_destroy(&in); rfb_buffer_destroy(&out);
    rfb_handshake_destroy(&h);
}

// --- WRITE states return OK (lines 543-547) ------------------------------
RFB_TEST(hs_cov2, step__write_protocol_version_state__returns_ok) {
    rfb_handshake_policy pol = rfb_handshake_policy_default();
    rfb_handshake h; rfb_handshake_init(&h, &pol, rfb_default_allocator());
    h.state = RFB_HS_WRITE_PROTOCOL_VERSION;
    rfb_buffer in, out;
    rfb_buffer_init(&in, rfb_default_allocator(), 64);
    rfb_buffer_init(&out, rfb_default_allocator(), 64);
    RFB_CHECK_EQ_INT(rfb_handshake_step(&h, &in, &out), RFB_OK);
    h.state = RFB_HS_WRITE_SECURITY_SELECTION;
    RFB_CHECK_EQ_INT(rfb_handshake_step(&h, &in, &out), RFB_OK);
    h.state = RFB_HS_WRITE_VNC_RESPONSE;
    RFB_CHECK_EQ_INT(rfb_handshake_step(&h, &in, &out), RFB_OK);
    rfb_buffer_destroy(&in); rfb_buffer_destroy(&out);
    rfb_handshake_destroy(&h);
}
