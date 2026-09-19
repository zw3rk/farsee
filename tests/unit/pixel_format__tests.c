// SPDX-License-Identifier: Apache-2.0
//
// G3 — pixel format validation tests (plan.md §G3, §12.3).
//
// Covers the legal/illegal format combinations the support policy must
// distinguish: bpp/depth, true-color, zero maxima, overlapping masks.

#include "rfb_test.h"
#include "farsee/pixel_format.h"

static rfb_pixel_format make_pf(uint8_t bpp, uint8_t depth, uint8_t tc,
                                uint16_t rmax, uint16_t gmax, uint16_t bmax,
                                uint8_t rs, uint8_t gs, uint8_t bs)
{
    rfb_pixel_format pf;
    pf.bits_per_pixel = bpp;
    pf.depth = depth;
    pf.big_endian = 0;
    pf.true_color = tc;
    pf.red_max = rmax;
    pf.green_max = gmax;
    pf.blue_max = bmax;
    pf.red_shift = rs;
    pf.green_shift = gs;
    pf.blue_shift = bs;
    return pf;
}

RFB_TEST(pixel_format, pf__canonical_request__is_valid_and_canonical) {
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();
    RFB_CHECK(rfb_pixel_format_valid(&pf));
    RFB_CHECK(rfb_pixel_format_is_canonical(&pf));
}

RFB_TEST(pixel_format, pf__canonical_is_32bpp_depth24_truecolor_8bit_maxima) {
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();
    RFB_CHECK_EQ_UINT(pf.bits_per_pixel, 32);
    RFB_CHECK_EQ_UINT(pf.depth, 24);
    RFB_CHECK_EQ_UINT(pf.true_color, 1);
    RFB_CHECK_EQ_UINT(pf.red_max, 255);
    RFB_CHECK_EQ_UINT(pf.green_max, 255);
    RFB_CHECK_EQ_UINT(pf.blue_max, 255);
}

RFB_TEST(pixel_format, pf__valid_16bpp__accepted) {
    rfb_pixel_format pf = make_pf(16, 16, 1, 31, 63, 31, 11, 5, 0);
    RFB_CHECK(rfb_pixel_format_valid(&pf));
}

RFB_TEST(pixel_format, pf__valid_8bpp__accepted) {
    rfb_pixel_format pf = make_pf(8, 8, 1, 7, 7, 3, 5, 2, 0);
    RFB_CHECK(rfb_pixel_format_valid(&pf));
}

// --- rejections (plan.md §12.3) -----------------------------------------

RFB_TEST(pixel_format, pf__depth_greater_than_bpp__rejected) {
    rfb_pixel_format pf = make_pf(16, 24, 1, 255, 255, 255, 0, 8, 16);
    RFB_CHECK(!rfb_pixel_format_valid(&pf));
}

RFB_TEST(pixel_format, pf__zero_red_max__rejected) {
    rfb_pixel_format pf = make_pf(32, 24, 1, 0, 255, 255, 0, 8, 16);
    RFB_CHECK(!rfb_pixel_format_valid(&pf));
}

RFB_TEST(pixel_format, pf__zero_green_max__rejected) {
    rfb_pixel_format pf = make_pf(32, 24, 1, 255, 0, 255, 0, 8, 16);
    RFB_CHECK(!rfb_pixel_format_valid(&pf));
}

RFB_TEST(pixel_format, pf__zero_blue_max__rejected) {
    rfb_pixel_format pf = make_pf(32, 24, 1, 255, 255, 0, 0, 8, 16);
    RFB_CHECK(!rfb_pixel_format_valid(&pf));
}

RFB_TEST(pixel_format, pf__not_true_color__rejected) {
    rfb_pixel_format pf = make_pf(32, 24, 0, 255, 255, 255, 0, 8, 16);
    RFB_CHECK(!rfb_pixel_format_valid(&pf));
}

RFB_TEST(pixel_format, pf__overlapping_masks__rejected) {
    // red and green both claim bits 8..15.
    rfb_pixel_format pf = make_pf(32, 24, 1, 255, 255, 255, 8, 8, 0);
    RFB_CHECK(!rfb_pixel_format_valid(&pf));
}

RFB_TEST(pixel_format, pf__unsupported_bpp_24__rejected) {
    rfb_pixel_format pf = make_pf(24, 24, 1, 255, 255, 255, 0, 8, 16);
    RFB_CHECK(!rfb_pixel_format_valid(&pf));
}

RFB_TEST(pixel_format, pf__null__rejected) {
    RFB_CHECK(!rfb_pixel_format_valid(NULL));
}

RFB_TEST(pixel_format, pf__eq__identical_canonical__true) {
    rfb_pixel_format a = rfb_pixel_format_canonical_request();
    rfb_pixel_format b = rfb_pixel_format_canonical_request();
    RFB_CHECK(rfb_pixel_format_eq(&a, &b));
}

RFB_TEST(pixel_format, pf__eq__differ_in_bpp__false) {
    rfb_pixel_format a = rfb_pixel_format_canonical_request();
    rfb_pixel_format b = a;
    b.bits_per_pixel = 16;
    RFB_CHECK(!rfb_pixel_format_eq(&a, &b));
}
