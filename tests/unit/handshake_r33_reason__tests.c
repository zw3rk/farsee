// SPDX-License-Identifier: Apache-2.0
//
// RFB 3.3 security-type-zero failure reason regressions.
//
// RFC 6143 §7.1.3: in RFB 3.3 the server sends a single u32 security type;
// zero means "connection failed" and a u32-length reason string follows.
// The 3.3 branch drains the reason into failure_reason before reporting the
// terminal error, matching the 3.7/3.8 count==0 behavior.

#include "rfb_test.h"
#include "farsee/handshake.h"
#include "farsee/allocator.h"
#include "farsee/buffer.h"
#include "farsee/error.h"

#include <string.h>

// 3.3 zero-security + reason string: the reason must be captured and the
// input fully drained before the terminal failure.
RFB_TEST(handshake_r33_reason, rfb33__zero_security_with_reason__drains_and_reports)
{
    static const uint8_t T[] = {
        'R','F','B',' ','0','0','3','.','0','0','3','\n',
        0x00, 0x00, 0x00, 0x00,  // security type 0 = connection failed
        0x00, 0x00, 0x00, 0x0C,  // reason length = 12
        'b','u','s','y',',',' ','t','r','y',' ','l','a',
    };
    rfb_handshake_policy pol = rfb_handshake_policy_default();
    rfb_handshake h;
    rfb_handshake_init(&h, &pol, rfb_default_allocator());
    rfb_buffer in, out;
    rfb_buffer_init(&in, rfb_default_allocator(), 4096);
    rfb_buffer_init(&out, rfb_default_allocator(), 4096);
    RFB_CHECK_EQ_INT(rfb_buffer_append(&in, T, sizeof T), RFB_OK);
    rfb_error e = RFB_OK;
    for (int i = 0; i < 8 && !rfb_handshake_finished(&h); i++) {
        e = rfb_handshake_step(&h, &in, &out);
        if (e != RFB_OK) break;
    }
    RFB_CHECK_EQ_INT(e, RFB_ERR_AUTH);
    RFB_CHECK_EQ_INT(h.state, RFB_HS_FAILED);
    // The reason string must surface in failure_reason.
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&h.failure_reason), 12u);
    // Guard: RFB_CHECK records and continues, and rfb_buffer_data of an
    // empty buffer is NULL — only compare bytes when the length matched.
    if (rfb_buffer_length(&h.failure_reason) == 12u) {
        RFB_CHECK_MEM_EQ(rfb_buffer_data(&h.failure_reason), T + 20u, 12u);
    }
    // The reason bytes must be drained from the input.
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&in), 0u);
    rfb_buffer_destroy(&in); rfb_buffer_destroy(&out);
    rfb_handshake_destroy(&h);
}

// Truncated reason (length word only): the handshake must WAIT for the
// full reason, not fail early.
RFB_TEST(handshake_r33_reason, rfb33__zero_security_reason_truncated__needs_input)
{
    static const uint8_t T[] = {
        'R','F','B',' ','0','0','3','.','0','0','3','\n',
        0x00, 0x00, 0x00, 0x00,  // security type 0
        0x00, 0x00, 0x00, 0x0C,  // reason length = 12 …but no bytes yet
    };
    rfb_handshake_policy pol = rfb_handshake_policy_default();
    rfb_handshake h;
    rfb_handshake_init(&h, &pol, rfb_default_allocator());
    rfb_buffer in, out;
    rfb_buffer_init(&in, rfb_default_allocator(), 4096);
    rfb_buffer_init(&out, rfb_default_allocator(), 4096);
    RFB_CHECK_EQ_INT(rfb_buffer_append(&in, T, sizeof T), RFB_OK);
    rfb_error e = RFB_OK;
    for (int i = 0; i < 8 && !rfb_handshake_finished(&h); i++) {
        e = rfb_handshake_step(&h, &in, &out);
        if (e != RFB_OK) break;
    }
    // Not finished: wait for the reason bytes.
    RFB_CHECK_EQ_INT(e, RFB_OK);
    RFB_CHECK_EQ_INT(h.state, RFB_HS_READ_SECURITY_FAILURE_REASON);
    // The u32 length word stays buffered until the reason bytes arrive.
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&in), 4u);
    rfb_buffer_destroy(&in); rfb_buffer_destroy(&out);
    rfb_handshake_destroy(&h);
}

// Empty reason (length 0): still routed through the reason reader and
// fails closed with AUTH.
RFB_TEST(handshake_r33_reason, rfb33__zero_security_empty_reason__fails_auth)
{
    static const uint8_t T[] = {
        'R','F','B',' ','0','0','3','.','0','0','3','\n',
        0x00, 0x00, 0x00, 0x00,  // security type 0
        0x00, 0x00, 0x00, 0x00,  // reason length = 0
    };
    rfb_handshake_policy pol = rfb_handshake_policy_default();
    rfb_handshake h;
    rfb_handshake_init(&h, &pol, rfb_default_allocator());
    rfb_buffer in, out;
    rfb_buffer_init(&in, rfb_default_allocator(), 4096);
    rfb_buffer_init(&out, rfb_default_allocator(), 4096);
    RFB_CHECK_EQ_INT(rfb_buffer_append(&in, T, sizeof T), RFB_OK);
    rfb_error e = RFB_OK;
    for (int i = 0; i < 8 && !rfb_handshake_finished(&h); i++) {
        e = rfb_handshake_step(&h, &in, &out);
        if (e != RFB_OK) break;
    }
    RFB_CHECK_EQ_INT(e, RFB_ERR_AUTH);
    RFB_CHECK_EQ_INT(h.state, RFB_HS_FAILED);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&h.failure_reason), 0u);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&in), 0u);
    rfb_buffer_destroy(&in); rfb_buffer_destroy(&out);
    rfb_handshake_destroy(&h);
}
