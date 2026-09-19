// SPDX-License-Identifier: Apache-2.0
//
// Pixel-format shift validation regressions.
//
// rfb_pixel_format_valid() computes channel masks (mask << shift) on raw
// wire bytes. A hostile red_shift >= 32 (for example, 200) would make
// 0xFFu << 200 undefined under C11 6.5.7p3. These tests require rejection
// before the shift and acceptance at the valid boundary.

#include "rfb_test.h"
#include "farsee/pixel_format.h"

static rfb_pixel_format pixel_shift_format(uint8_t bpp, uint8_t depth, uint8_t tc,
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

// A raw wire shift byte >= 32 must be rejected without evaluating any
// mask<<shift expression, which is undefined and traps under UBSan with
// -fno-sanitize-recover=all).
RFB_TEST(pixel_format_shift, pf__red_shift_200__rejected_without_ub_shift)
{
    rfb_pixel_format pf =
        pixel_shift_format(32, 24, 1, 255, 255, 255, 200, 8, 0);
    RFB_CHECK(!rfb_pixel_format_valid(&pf));
}

RFB_TEST(pixel_format_shift, pf__red_shift_exactly_32__rejected)
{
    rfb_pixel_format pf =
        pixel_shift_format(32, 24, 1, 255, 255, 255, 32, 8, 0);
    RFB_CHECK(!rfb_pixel_format_valid(&pf));
}

RFB_TEST(pixel_format_shift, pf__all_shifts_255__rejected)
{
    rfb_pixel_format pf =
        pixel_shift_format(32, 24, 1, 255, 255, 255, 255, 255, 255);
    RFB_CHECK(!rfb_pixel_format_valid(&pf));
}

// The shift plus channel width must fit within bpp. With
// shift < 32 the mask math is defined, so this is the plain semantic
// rejection the later gate already implements — pinned here so the
// reordering cannot lose it.
RFB_TEST(pixel_format_shift, pf__shift_plus_width_exceeds_bpp__rejected)
{
    // red_max=255 → width 8; shift 16 + 8 = 24 > bpp 16.
    rfb_pixel_format pf =
        pixel_shift_format(16, 16, 1, 255, 63, 31, 16, 5, 0);
    RFB_CHECK(!rfb_pixel_format_valid(&pf));
}

RFB_TEST(pixel_format_shift, pf__green_shift_200__rejected)
{
    rfb_pixel_format pf =
        pixel_shift_format(32, 24, 1, 255, 255, 255, 16, 200, 0);
    RFB_CHECK(!rfb_pixel_format_valid(&pf));
}

RFB_TEST(pixel_format_shift, pf__blue_shift_200__rejected)
{
    rfb_pixel_format pf =
        pixel_shift_format(32, 24, 1, 255, 255, 255, 16, 8, 200);
    RFB_CHECK(!rfb_pixel_format_valid(&pf));
}

// Boundary sanity: the largest legal canonical-style layout still passes.
RFB_TEST(pixel_format_shift, pf__shift_24_width_8_bpp32__accepted)
{
    // red at bits 24..31, green 16..23, blue 8..15 — all within 32 bpp.
    rfb_pixel_format pf =
        pixel_shift_format(32, 32, 1, 255, 255, 255, 24, 16, 8);
    RFB_CHECK(rfb_pixel_format_valid(&pf));
}
