// SPDX-License-Identifier: Apache-2.0
//
// G2 — VNC Authentication negotiation tests (plan.md §G2, RFC 6143
// §7.2.2). They cover 3.8 success and rejection, 3.3/3.7
// SecurityResult handling, password cleanup, and one-byte challenge feeds.
// The response checks use the deterministic XOR stub below; the crypto
// provider known-answer test is separate. These tests stop before
// ClientInit and ServerInit, so they are not full connection handshakes.

#include "rfb_test.h"
#include "farsee/handshake.h"
#include "farsee/allocator.h"
#include "farsee/buffer.h"

#include <string.h>

// A stub DES is used so we don't depend on a real provider here; the real
// KAT is covered by crypto_kat__tests.c. The stub XORs the key into each
// block so the response is deterministic and inspectable.
static bool handshake_stub_des(const uint8_t key[8], const uint8_t in[8], uint8_t out[8])
{
    for (int i = 0; i < 8; i++) {
        out[i] = (uint8_t)(in[i] ^ key[i]);
    }
    return true;
}

// Run the SM until it finishes or fails. Returns the last error.
static rfb_error handshake_run_to_finish(rfb_handshake *h, rfb_buffer *in, rfb_buffer *out)
{
    rfb_error e = RFB_OK;
    for (int i = 0; i < 32 && !rfb_handshake_finished(h); i++) {
        e = rfb_handshake_step(h, in, out);
        if (e != RFB_OK) break;
    }
    return e;
}

RFB_TEST(handshake_auth, set_password__classic_boundary_copies_first_eight)
{
    static const uint8_t full_password[] = "password-RDP-and-Apple-tail";
    static const uint8_t expected[] = "password";
    rfb_handshake_policy policy = rfb_handshake_policy_default();
    rfb_handshake handshake;
    rfb_handshake_init(&handshake, &policy, rfb_default_allocator());

    rfb_handshake_set_password(&handshake, full_password,
                               sizeof full_password - 1u);

    RFB_CHECK(handshake.password_set);
    RFB_CHECK_MEM_EQ(handshake.password, expected, sizeof expected - 1u);
    rfb_handshake_destroy(&handshake);
}

// --- 3.8 + VNC auth, success --------------------------------------------

RFB_TEST(handshake_auth, vnc_auth__rfb38_success__emits_response_and_reaches_done) {
    static const uint8_t T[] = {
        // banner
        'R','F','B',' ','0','0','3','.','0','0','8','\n',
        // security list: count=1, type=2 (VNC)
        0x01, 0x02,
        // 16-byte challenge (all zeros for inspectability)
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        // security result = 0 (OK)
        0x00,0x00,0x00,0x00,
    };
    rfb_handshake_policy pol = rfb_handshake_policy_default();
    rfb_handshake h;
    rfb_handshake_init(&h, &pol, rfb_default_allocator());
    rfb_handshake_set_des_provider(&h, handshake_stub_des);
    static const uint8_t pw[8] = { 'p','a','s','s','w','o','r','d' };
    rfb_handshake_set_password(&h, pw, 8);
    rfb_buffer in, out;
    rfb_buffer_init(&in, rfb_default_allocator(), 4096);
    rfb_buffer_init(&out, rfb_default_allocator(), 4096);
    rfb_buffer_append(&in, T, sizeof T);

    rfb_error e = handshake_run_to_finish(&h, &in, &out);
    RFB_CHECK_EQ_INT(e, RFB_OK);
    RFB_CHECK_EQ_INT(h.state, RFB_HS_DONE);
    RFB_CHECK_EQ_INT(h.selected_security, RFB_SECURITY_VNC);

    // Client output: banner (12) + selection (1) + response (16) = 29.
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&out), 29u);
    // Selection byte = 2 (VNC).
    RFB_CHECK_EQ_UINT(rfb_buffer_data(&out)[12], 0x02);
    // Response is challenge XOR scheduled-key. Password "password" -> key
    // {0x0e,0x86,0xce,0xce,0xee,0xf6,0x4e,0x26} repeated for both blocks.
    static const uint8_t exp_key[8] = {0x0e,0x86,0xce,0xce,0xee,0xf6,0x4e,0x26};
    const uint8_t *resp = rfb_buffer_data(&out) + 13;
    for (int i = 0; i < 16; i++) {
        RFB_CHECK_EQ_UINT(resp[i], (uint8_t)(0x00u ^ exp_key[i % 8]));
    }
    rfb_buffer_destroy(&in); rfb_buffer_destroy(&out);
    rfb_handshake_destroy(&h);
}

// --- 3.8 + VNC auth, wrong password → failure + reason ------------------

RFB_TEST(handshake_auth, vnc_auth__rfb38_failure__records_reason_string) {
    static const uint8_t T[] = {
        'R','F','B',' ','0','0','3','.','0','0','8','\n',
        0x01, 0x02,  // VNC only
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  // challenge
        0x00,0x00,0x00,0x01,  // result = 1 (failed)
        // reason string: u32 length = 13, then "auth rejected"
        0x00,0x00,0x00,0x0D,
        'a','u','t','h',' ','r','e','j','e','c','t','e','d',
    };
    rfb_handshake_policy pol = rfb_handshake_policy_default();
    rfb_handshake h;
    rfb_handshake_init(&h, &pol, rfb_default_allocator());
    rfb_handshake_set_des_provider(&h, handshake_stub_des);
    static const uint8_t pw[8] = { 'b','a','d','p','a','s','s','!' };
    rfb_handshake_set_password(&h, pw, 8);
    rfb_buffer in, out;
    rfb_buffer_init(&in, rfb_default_allocator(), 4096);
    rfb_buffer_init(&out, rfb_default_allocator(), 4096);
    rfb_buffer_append(&in, T, sizeof T);

    rfb_error e = handshake_run_to_finish(&h, &in, &out);
    RFB_CHECK_EQ_INT(e, RFB_ERR_AUTH);
    RFB_CHECK_EQ_INT(h.state, RFB_HS_FAILED);
    RFB_CHECK_EQ_INT(h.last_error, RFB_ERR_AUTH);
    // The reason string was captured.
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&h.failure_reason), 13u);
    RFB_CHECK_MEM_EQ(rfb_buffer_data(&h.failure_reason),
                     (const uint8_t *)"auth rejected", 13);
    rfb_buffer_destroy(&in); rfb_buffer_destroy(&out);
    rfb_handshake_destroy(&h);
}

// --- 3.3 + VNC auth (SecurityResult required; only None skips it) ------

RFB_TEST(handshake_auth, vnc_auth__rfb33__selects_vnc_and_reads_challenge) {
    static const uint8_t T[] = {
        'R','F','B',' ','0','0','3','.','0','0','3','\n',
        0x00,0x00,0x00,0x02,  // 3.3 single security type = VNC
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  // challenge
        0,0,0,0,  // SecurityResult = 0 (success); required on 3.3 VNC Auth
    };
    rfb_handshake_policy pol = rfb_handshake_policy_default();
    rfb_handshake h;
    rfb_handshake_init(&h, &pol, rfb_default_allocator());
    rfb_handshake_set_des_provider(&h, handshake_stub_des);
    static const uint8_t pw[8] = { 'p','a','s','s','w','o','r','d' };
    rfb_handshake_set_password(&h, pw, 8);
    rfb_buffer in, out;
    rfb_buffer_init(&in, rfb_default_allocator(), 4096);
    rfb_buffer_init(&out, rfb_default_allocator(), 4096);
    rfb_buffer_append(&in, T, sizeof T);

    rfb_error e = handshake_run_to_finish(&h, &in, &out);
    RFB_CHECK_EQ_INT(e, RFB_OK);
    RFB_CHECK_EQ_INT(h.state, RFB_HS_DONE);
    RFB_CHECK_EQ_INT(h.selected_security, RFB_SECURITY_VNC);
    // Client output: banner (12) + response (16) = 28. No selection byte.
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&out), 28u);
    // All input including SecurityResult consumed (stream aligned for ServerInit).
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&in), 0u);
    rfb_buffer_destroy(&in); rfb_buffer_destroy(&out);
    rfb_handshake_destroy(&h);
}

// + fragmented 3.3 VNC SecurityResult still reaches DONE
RFB_TEST(handshake_auth, vnc_auth__rfb33_security_result_fragmented__done) {
    static const uint8_t prefix[] = {
        'R','F','B',' ','0','0','3','.','0','0','3','\n',
        0x00,0x00,0x00,0x02,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    };
    static const uint8_t result[] = { 0, 0, 0, 0 };
    rfb_handshake_policy pol = rfb_handshake_policy_default();
    rfb_handshake h;
    rfb_handshake_init(&h, &pol, rfb_default_allocator());
    rfb_handshake_set_des_provider(&h, handshake_stub_des);
    static const uint8_t pw[8] = { 'p','a','s','s','w','o','r','d' };
    rfb_handshake_set_password(&h, pw, 8);
    rfb_buffer in, out;
    rfb_buffer_init(&in, rfb_default_allocator(), 4096);
    rfb_buffer_init(&out, rfb_default_allocator(), 4096);
    rfb_buffer_append(&in, prefix, sizeof prefix);
    // Run until waiting on SecurityResult.
    for (int i = 0; i < 16 && !rfb_handshake_finished(&h); i++) {
        rfb_error e = rfb_handshake_step(&h, &in, &out);
        RFB_CHECK_EQ_INT(e, RFB_OK);
        if (h.state == RFB_HS_READ_SECURITY_RESULT) {
            break;
        }
    }
    RFB_CHECK_EQ_INT(h.state, RFB_HS_READ_SECURITY_RESULT);
    // Feed result one byte at a time.
    for (size_t i = 0; i < sizeof result; i++) {
        rfb_buffer_append(&in, &result[i], 1u);
        rfb_error e = rfb_handshake_step(&h, &in, &out);
        RFB_CHECK_EQ_INT(e, RFB_OK);
    }
    RFB_CHECK_EQ_INT(h.state, RFB_HS_DONE);
    rfb_buffer_destroy(&in); rfb_buffer_destroy(&out);
    rfb_handshake_destroy(&h);
}

// − 3.3 VNC SecurityResult reject (no reason string on 3.3)
RFB_TEST(handshake_auth, vnc_auth__rfb33_security_result_reject__fails_auth) {
    static const uint8_t T[] = {
        'R','F','B',' ','0','0','3','.','0','0','3','\n',
        0x00,0x00,0x00,0x02,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,1,  // SecurityResult = 1 (failed)
    };
    rfb_handshake_policy pol = rfb_handshake_policy_default();
    rfb_handshake h;
    rfb_handshake_init(&h, &pol, rfb_default_allocator());
    rfb_handshake_set_des_provider(&h, handshake_stub_des);
    static const uint8_t pw[8] = { 'p','a','s','s','w','o','r','d' };
    rfb_handshake_set_password(&h, pw, 8);
    rfb_buffer in, out;
    rfb_buffer_init(&in, rfb_default_allocator(), 4096);
    rfb_buffer_init(&out, rfb_default_allocator(), 4096);
    rfb_buffer_append(&in, T, sizeof T);

    rfb_error e = handshake_run_to_finish(&h, &in, &out);
    RFB_CHECK_EQ_INT(e, RFB_ERR_AUTH);
    RFB_CHECK_EQ_INT(h.state, RFB_HS_FAILED);
    rfb_buffer_destroy(&in); rfb_buffer_destroy(&out);
    rfb_handshake_destroy(&h);
}

// − truncated SecurityResult after VNC response waits (not DONE)
RFB_TEST(handshake_auth, vnc_auth__rfb33_security_result_truncated__waits) {
    static const uint8_t T[] = {
        'R','F','B',' ','0','0','3','.','0','0','3','\n',
        0x00,0x00,0x00,0x02,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,  // only 2 of 4 result bytes
    };
    rfb_handshake_policy pol = rfb_handshake_policy_default();
    rfb_handshake h;
    rfb_handshake_init(&h, &pol, rfb_default_allocator());
    rfb_handshake_set_des_provider(&h, handshake_stub_des);
    static const uint8_t pw[8] = { 'p','a','s','s','w','o','r','d' };
    rfb_handshake_set_password(&h, pw, 8);
    rfb_buffer in, out;
    rfb_buffer_init(&in, rfb_default_allocator(), 4096);
    rfb_buffer_init(&out, rfb_default_allocator(), 4096);
    rfb_buffer_append(&in, T, sizeof T);

    rfb_error e = handshake_run_to_finish(&h, &in, &out);
    RFB_CHECK_EQ_INT(e, RFB_OK);
    RFB_CHECK_EQ_INT(h.state, RFB_HS_READ_SECURITY_RESULT);
    RFB_CHECK(!rfb_handshake_finished(&h));
    rfb_buffer_destroy(&in); rfb_buffer_destroy(&out);
    rfb_handshake_destroy(&h);
}

// --- 3.7 + VNC auth (sends security-result u32, same as 3.8) -----------

RFB_TEST(handshake_auth, vnc_auth__rfb37__selects_vnc_and_reads_challenge) {
    static const uint8_t T[] = {
        'R','F','B',' ','0','0','3','.','0','0','7','\n',
        0x01, 0x02,  // list: count=1, VNC
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  // challenge
        0,0,0,0,  // 3.7 SecurityResult = 0 (success)
    };
    rfb_handshake_policy pol = rfb_handshake_policy_default();
    rfb_handshake h;
    rfb_handshake_init(&h, &pol, rfb_default_allocator());
    rfb_handshake_set_des_provider(&h, handshake_stub_des);
    static const uint8_t pw[8] = { 'p','a','s','s','w','o','r','d' };
    rfb_handshake_set_password(&h, pw, 8);
    rfb_buffer in, out;
    rfb_buffer_init(&in, rfb_default_allocator(), 4096);
    rfb_buffer_init(&out, rfb_default_allocator(), 4096);
    rfb_buffer_append(&in, T, sizeof T);

    rfb_error e = handshake_run_to_finish(&h, &in, &out);
    RFB_CHECK_EQ_INT(e, RFB_OK);
    RFB_CHECK_EQ_INT(h.state, RFB_HS_DONE);
    RFB_CHECK_EQ_INT(h.selected_security, RFB_SECURITY_VNC);
    rfb_buffer_destroy(&in); rfb_buffer_destroy(&out);
    rfb_handshake_destroy(&h);
}

// --- password zeroized on destroy ---------------------------------------

RFB_TEST(handshake_auth, password__zeroized_on_destroy) {
    rfb_handshake_policy pol = rfb_handshake_policy_default();
    rfb_handshake h;
    rfb_handshake_init(&h, &pol, rfb_default_allocator());
    static const uint8_t pw[8] = { 's','e','c','r','e','t','1','2' };
    rfb_handshake_set_password(&h, pw, 8);
    // Snapshot where the password lives in the struct.
    uint8_t before[8];
    memcpy(before, h.password, 8);
    RFB_CHECK(before[0] != 0);  // password is set
    rfb_handshake_destroy(&h);
    for (int i = 0; i < 8; i++) {
        RFB_CHECK_EQ_UINT(h.password[i], 0u);
    }
}

// --- challenge fragmented at every byte → same response ----------------

RFB_TEST(handshake_auth, vnc_auth__challenge_fragmented_one_byte_at_a_time__same_response) {
    static const uint8_t T[] = {
        'R','F','B',' ','0','0','3','.','0','0','8','\n',
        0x01, 0x02,
        0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
        0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00,
        0x00,0x00,0x00,0x00,
    };

    // Whole-feed run.
    rfb_handshake_policy pol = rfb_handshake_policy_default();
    rfb_handshake hw;
    rfb_handshake_init(&hw, &pol, rfb_default_allocator());
    rfb_handshake_set_des_provider(&hw, handshake_stub_des);
    static const uint8_t pw[8] = { 'p','a','s','s','w','o','r','d' };
    rfb_handshake_set_password(&hw, pw, 8);
    rfb_buffer inw, outw;
    rfb_buffer_init(&inw, rfb_default_allocator(), 4096);
    rfb_buffer_init(&outw, rfb_default_allocator(), 4096);
    rfb_buffer_append(&inw, T, sizeof T);
    (void)handshake_run_to_finish(&hw, &inw, &outw);

    // Fragmented run.
    rfb_handshake hf;
    rfb_handshake_init(&hf, &pol, rfb_default_allocator());
    rfb_handshake_set_des_provider(&hf, handshake_stub_des);
    rfb_handshake_set_password(&hf, pw, 8);
    rfb_buffer inf, outf;
    rfb_buffer_init(&inf, rfb_default_allocator(), 4096);
    rfb_buffer_init(&outf, rfb_default_allocator(), 4096);
    for (size_t i = 0; i < sizeof T; i++) {
        rfb_buffer_append(&inf, &T[i], 1);
        for (int k = 0; k < 16; k++) {
            size_t bi = rfb_buffer_length(&inf);
            size_t bo = rfb_buffer_length(&outf);
            rfb_error e = rfb_handshake_step(&hf, &inf, &outf);
            if (e != RFB_OK) break;
            if (rfb_buffer_length(&inf) == bi && rfb_buffer_length(&outf) == bo) break;
            if (rfb_handshake_finished(&hf)) break;
        }
    }
    RFB_CHECK_EQ_INT(hf.state, hw.state);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&outf), rfb_buffer_length(&outw));
    RFB_CHECK_MEM_EQ(rfb_buffer_data(&outf), rfb_buffer_data(&outw),
                     rfb_buffer_length(&outw));
    rfb_buffer_destroy(&inw); rfb_buffer_destroy(&outw);
    rfb_buffer_destroy(&inf); rfb_buffer_destroy(&outf);
    rfb_handshake_destroy(&hw); rfb_handshake_destroy(&hf);
}
