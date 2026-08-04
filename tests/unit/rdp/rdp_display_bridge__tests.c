// SPDX-License-Identifier: Apache-2.0
//
// R3 — RDP display/frame bridge tests (§15.8).

#ifdef FARSEE_WITH_RDP

#include "protocol/rdp/rdp_display_bridge.h"
#include "tests/test_framework/rfb_test.h"

#include <string.h>

RFB_TEST(rdp_frame, validate__valid_dimensions_and_rects)
{
    rdp_backend_rect rects[] = {{0,0,4,4},{2,2,2,2}};
    RFB_CHECK(rdp_frame_validate(8, 8, 32, 256, 16384, rects, 2) == 2);
    // No damage rects -> 0 (full frame).
    RFB_CHECK(rdp_frame_validate(8, 8, 32, 256, 16384, NULL, 0) == 0);
}

RFB_TEST(rdp_frame, validate__rejects_bad_dimensions)
{
    RFB_CHECK(rdp_frame_validate(0, 8, 0, 0, 16384, NULL, 0) < 0);  // zero w
    RFB_CHECK(rdp_frame_validate(8, 0, 0, 0, 16384, NULL, 0) < 0);  // zero h
    RFB_CHECK(rdp_frame_validate(20000, 8, 80000, 0, 16384, NULL, 0) < 0); // >max
    RFB_CHECK(rdp_frame_validate(8, 8, 16, 256, 16384, NULL, 0) < 0); // short stride
    RFB_CHECK(rdp_frame_validate(8, 8, 32, 999, 16384, NULL, 0) < 0); // bad data_size
}

RFB_TEST(rdp_frame, validate__rejects_out_of_bounds_rect)
{
    rdp_backend_rect over[] = {{6,0,4,4}};  // 6+4 > 8
    RFB_CHECK(rdp_frame_validate(8, 8, 32, 256, 16384, over, 1) < 0);
    rdp_backend_rect neg[] = {{-1,0,4,4}};
    RFB_CHECK(rdp_frame_validate(8, 8, 32, 256, 16384, neg, 1) < 0);
    rdp_backend_rect zero[] = {{0,0,0,4}};
    RFB_CHECK(rdp_frame_validate(8, 8, 32, 256, 16384, zero, 1) < 0);
}

RFB_TEST(rdp_frame, clip_rect__partial_negative_clipped)
{
    rdp_backend_rect in = {-2,-2,6,6};  // covers top-left, extends past 0
    farsee_rect out;
    RFB_CHECK(rdp_frame_clip_rect(&in, 8, 8, &out));
    RFB_CHECK_EQ_UINT(out.x, 0u);
    RFB_CHECK_EQ_UINT(out.y, 0u);
    RFB_CHECK_EQ_UINT(out.width, 4u);
    RFB_CHECK_EQ_UINT(out.height, 4u);
}

RFB_TEST(rdp_frame, clip_rect__entirely_outside_rejected)
{
    rdp_backend_rect in = {100,100,4,4};
    farsee_rect out;
    RFB_CHECK(rdp_frame_clip_rect(&in, 8, 8, &out) == false);
}

RFB_TEST(rdp_frame, build_surface_view__valid_and_bgra)
{
    uint8_t buf[128];  // 8x4 BGRA = 128 bytes
    memset(buf, 0, sizeof buf);
    farsee_surface_view v;
    RFB_CHECK(rdp_frame_build_surface_view(&v, 1, 8, 4, 32, buf, 128, 16384, 7));
    RFB_CHECK(v.format == FARSEE_PIXEL_BGRA8888);
    RFB_CHECK_EQ_UINT(v.width, 8u);
    RFB_CHECK_EQ_UINT(v.height, 4u);
    RFB_CHECK(v.data == buf);
    RFB_CHECK_EQ_UINT((unsigned)v.generation, 7u);
    // Invalid -> false.
    RFB_CHECK(rdp_frame_build_surface_view(&v, 1, 0, 4, 0, buf, 0, 16384, 0) == false);
}

#endif  // FARSEE_WITH_RDP
