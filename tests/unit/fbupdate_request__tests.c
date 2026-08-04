// SPDX-License-Identifier: Apache-2.0
//
// FramebufferUpdateRequest encoder tests (RFC 6143 §7.5.3).

#include "rfb_test.h"
#include "farsee/input.h"
#include "farsee/bytes.h"
#include "farsee/error.h"

// Wire layout: u8 type=3, u8 incremental, u16 x, u16 y, u16 w, u16 h (BE).

RFB_TEST(fbupdate_request, fbur__non_incremental_full_screen__exact_bytes)
{
    uint8_t out[10] = { 0 };
    rfb_writer w = rfb_writer_make(out, sizeof out);
    RFB_CHECK_EQ_INT(
        rfb_format_framebuffer_update_request(&w, false, 0, 0, 800, 600),
        RFB_OK);
    RFB_CHECK_EQ_UINT(w.length, 10u);
    RFB_CHECK_EQ_UINT(out[0], 3u);     // message-type
    RFB_CHECK_EQ_UINT(out[1], 0u);     // incremental=0
    RFB_CHECK_EQ_UINT(out[2], 0u);     // x BE
    RFB_CHECK_EQ_UINT(out[3], 0u);
    RFB_CHECK_EQ_UINT(out[4], 0u);     // y BE
    RFB_CHECK_EQ_UINT(out[5], 0u);
    RFB_CHECK_EQ_UINT(out[6], 0x03u);  // w=800 → 0x0320
    RFB_CHECK_EQ_UINT(out[7], 0x20u);
    RFB_CHECK_EQ_UINT(out[8], 0x02u);  // h=600 → 0x0258
    RFB_CHECK_EQ_UINT(out[9], 0x58u);
}

RFB_TEST(fbupdate_request, fbur__incremental_region__exact_bytes)
{
    uint8_t out[10] = { 0 };
    rfb_writer w = rfb_writer_make(out, sizeof out);
    RFB_CHECK_EQ_INT(
        rfb_format_framebuffer_update_request(&w, true, 10, 20, 30, 40),
        RFB_OK);
    RFB_CHECK_EQ_UINT(out[0], 3u);
    RFB_CHECK_EQ_UINT(out[1], 1u);     // incremental=1
    RFB_CHECK_EQ_UINT(out[2], 0u);
    RFB_CHECK_EQ_UINT(out[3], 10u);    // x=10
    RFB_CHECK_EQ_UINT(out[4], 0u);
    RFB_CHECK_EQ_UINT(out[5], 20u);    // y=20
    RFB_CHECK_EQ_UINT(out[6], 0u);
    RFB_CHECK_EQ_UINT(out[7], 30u);    // w=30
    RFB_CHECK_EQ_UINT(out[8], 0u);
    RFB_CHECK_EQ_UINT(out[9], 40u);    // h=40
}

RFB_TEST(fbupdate_request, fbur__null_writer__fails_internal)
{
    RFB_CHECK_EQ_INT(
        rfb_format_framebuffer_update_request(NULL, false, 0, 0, 1, 1),
        RFB_ERR_INTERNAL);
}

RFB_TEST(fbupdate_request, fbur__buffer_too_small__fails_limit)
{
    uint8_t out[9] = { 0 };
    rfb_writer w = rfb_writer_make(out, sizeof out);
    // 10-byte message cannot fit in 9; encoder pre-checks capacity and
    // fails with LIMIT without writing a partial message.
    RFB_CHECK_EQ_INT(
        rfb_format_framebuffer_update_request(&w, false, 0, 0, 1, 1),
        RFB_ERR_LIMIT);
    RFB_CHECK_EQ_UINT(w.length, 0u);
}

RFB_TEST(fbupdate_request, fbur__max_coords__exact_bytes)
{
    uint8_t out[10] = { 0 };
    rfb_writer w = rfb_writer_make(out, sizeof out);
    RFB_CHECK_EQ_INT(
        rfb_format_framebuffer_update_request(&w, true,
                                              0xFFFFu, 0xFFFFu,
                                              0xFFFFu, 0xFFFFu),
        RFB_OK);
    RFB_CHECK_EQ_UINT(out[2], 0xFFu);
    RFB_CHECK_EQ_UINT(out[3], 0xFFu);
    RFB_CHECK_EQ_UINT(out[4], 0xFFu);
    RFB_CHECK_EQ_UINT(out[5], 0xFFu);
    RFB_CHECK_EQ_UINT(out[6], 0xFFu);
    RFB_CHECK_EQ_UINT(out[7], 0xFFu);
    RFB_CHECK_EQ_UINT(out[8], 0xFFu);
    RFB_CHECK_EQ_UINT(out[9], 0xFFu);
}
