// SPDX-License-Identifier: Apache-2.0
//
// ViewerInfo acknowledgement peek without consume-then-append-to-tail.
// Pure classification of whether leading bytes form a complete ack.

#include "rfb_test.h"
#include "farsee/apple_type33_connect.h"
#include "farsee/apple_postauth.h"
#include "farsee/buffer.h"
#include "farsee/allocator.h"

#include <string.h>

// − peer skips ack, delivers classic FBU [00 00 …] → leave in buffer
RFB_TEST(type33_ack, fbu_prefix__consume_len_zero)
{
    static const uint8_t fbu[] = { 0x00, 0x00, 0x00, 0x01, 0x00, 0x00 };
    RFB_CHECK_EQ_UINT(apple_viewer_info_live_ack_consume_len(fbu, sizeof fbu),
                      0u);
    RFB_CHECK_EQ_UINT(apple_viewer_info_live_ack_consume_len(fbu, 2u), 0u);
}

// − partial header only
RFB_TEST(type33_ack, partial_header__consume_len_zero)
{
    static const uint8_t one[] = { 0x00 };
    RFB_CHECK_EQ_UINT(apple_viewer_info_live_ack_consume_len(one, 1u), 0u);
    RFB_CHECK_EQ_UINT(apple_viewer_info_live_ack_consume_len(NULL, 0u), 0u);
}

// − complete header but incomplete body
RFB_TEST(type33_ack, incomplete_body__consume_len_zero)
{
    // body_len = 0x4a, only 4 bytes present of 2+0x4a
    static const uint8_t partial[] = { 0x00, 0x4a, 0x11, 0x22 };
    RFB_CHECK_EQ_UINT(
        apple_viewer_info_live_ack_consume_len(partial, sizeof partial), 0u);
}

// − body_len out of range
RFB_TEST(type33_ack, oversize_body_len__consume_len_zero)
{
    uint8_t hdr[2];
    hdr[0] = 0x01;  // body_len = 0x0100 = 256 > MAX(256)? MAX is 256, so 257
    hdr[1] = 0x01;  // 0x0101 = 257
    RFB_CHECK_EQ_UINT(apple_viewer_info_live_ack_consume_len(hdr, 2u), 0u);
    // body_len 0
    hdr[0] = 0x00;
    hdr[1] = 0x00;  // also FBU shape
    RFB_CHECK_EQ_UINT(apple_viewer_info_live_ack_consume_len(hdr, 2u), 0u);
}

// + normal 0x4a ack then remaining FBU stays after consume
RFB_TEST(type33_ack, full_ack_4a__consume_exact_then_fbu_untouched)
{
    uint8_t stream[2u + 0x4au + 4u];
    memset(stream, 0xAB, sizeof stream);
    stream[0] = 0x00;
    stream[1] = 0x4a;
    // Trailing classic FBU-looking prefix after ack body.
    stream[2u + 0x4au + 0u] = 0x00;
    stream[2u + 0x4au + 1u] = 0x00;
    stream[2u + 0x4au + 2u] = 0x00;
    stream[2u + 0x4au + 3u] = 0x01;

    const size_t ack = apple_viewer_info_live_ack_consume_len(
        stream, sizeof stream);
    RFB_CHECK_EQ_UINT(ack, 2u + 0x4au);

    // Simulate correct connect-path consume (front only, no re-append).
    rfb_buffer in;
    rfb_buffer_init(&in, rfb_default_allocator(), 4096);
    RFB_CHECK_EQ_INT(rfb_buffer_append(&in, stream, sizeof stream), RFB_OK);
    rfb_buffer_consume(&in, ack);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&in), 4u);
    RFB_CHECK_EQ_UINT(rfb_buffer_data(&in)[0], 0x00u);
    RFB_CHECK_EQ_UINT(rfb_buffer_data(&in)[1], 0x00u);
    RFB_CHECK_EQ_UINT(rfb_buffer_data(&in)[3], 0x01u);
    rfb_buffer_destroy(&in);
}

// + 0x50 acknowledgement body
RFB_TEST(type33_ack, full_ack_50__consume_exact)
{
    uint8_t stream[2u + 0x50u];
    memset(stream, 0xCD, sizeof stream);
    stream[0] = 0x00;
    stream[1] = 0x50;
    RFB_CHECK_EQ_UINT(
        apple_viewer_info_live_ack_consume_len(stream, sizeof stream),
        2u + 0x50u);
}

// − FBU delivered in one buffer with extra payload after 00 00: still 0
RFB_TEST(type33_ack, fbu_with_payload__never_consume)
{
    static const uint8_t fbu[] = {
        0x00, 0x00, 0x00, 0x01,  // type,pad,nrects=1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x10,  // rect
    };
    RFB_CHECK_EQ_UINT(apple_viewer_info_live_ack_consume_len(fbu, sizeof fbu),
                      0u);
}
