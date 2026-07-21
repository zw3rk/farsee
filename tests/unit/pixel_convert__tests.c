// SPDX-License-Identifier: Apache-2.0
//
// G3/G4 — wire-pixel → RGBA8 conversion tests (plan.md §12.3). RED step.
//
// Covers: channel extremes, non-255 maxima scaling, endianness, non-
// standard shifts, small-maxima exhaustive round-half-up, run conversion.

#include "rfb_test.h"
#include "farsee/pixel_convert.h"
#include "farsee/pixel_format.h"

#include <string.h>

static rfb_pixel_format make_pf_conv(uint8_t bpp, uint8_t depth, uint8_t be,
                                uint16_t rmax, uint16_t gmax, uint16_t bmax,
                                uint8_t rs, uint8_t gs, uint8_t bs)
{
    rfb_pixel_format pf;
    pf.bits_per_pixel = bpp;
    pf.depth = depth;
    pf.big_endian = be;
    pf.true_color = 1;
    pf.red_max = rmax;
    pf.green_max = gmax;
    pf.blue_max = bmax;
    pf.red_shift = rs;
    pf.green_shift = gs;
    pf.blue_shift = bs;
    return pf;
}

// --- canonical 32bpp: 1:1 mapping (max=255) -----------------------------

RFB_TEST(pixel_convert, convert__canonical_32bpp_le_white__ffffffff) {
    // Canonical request: bpp=32, LE, shifts R=16,G=8,B=0, max=255.
    // Wire pixel 0x00FFFFFF (LE bytes FF FF FF 00) = white.
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();
    uint8_t src[4] = { 0xFF, 0xFF, 0xFF, 0x00 };
    uint8_t out[4] = { 0 };
    rfb_pixel_to_rgba8(&pf, src, out);
    RFB_CHECK_EQ_UINT(out[0], 0xFFu);  // R
    RFB_CHECK_EQ_UINT(out[1], 0xFFu);  // G
    RFB_CHECK_EQ_UINT(out[2], 0xFFu);  // B
    RFB_CHECK_EQ_UINT(out[3], 0xFFu);  // A (always 255)
}

RFB_TEST(pixel_convert, convert__canonical_32bpp_le_red__ff0000ff) {
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();
    // Wire pixel with red=255, green=0, blue=0: 0x00FF0000 LE = 00 00 FF 00
    uint8_t src[4] = { 0x00, 0x00, 0xFF, 0x00 };
    uint8_t out[4] = { 0 };
    rfb_pixel_to_rgba8(&pf, src, out);
    RFB_CHECK_EQ_UINT(out[0], 0xFFu);
    RFB_CHECK_EQ_UINT(out[1], 0x00u);
    RFB_CHECK_EQ_UINT(out[2], 0x00u);
    RFB_CHECK_EQ_UINT(out[3], 0xFFu);
}

// --- endianness: big-endian 32bpp ---------------------------------------

RFB_TEST(pixel_convert, convert__32bpp_be_white__ffffffff) {
    // BE 32bpp, shifts R=16,G=8,B=0, max=255. White = 0xFFFFFFnn.
    // Wire bytes (BE): FF FF FF FF (all four bytes set so every channel is 255).
    rfb_pixel_format pf = make_pf_conv(32, 24, 1, 255, 255, 255, 16, 8, 0);
    uint8_t src[4] = { 0xFF, 0xFF, 0xFF, 0xFF };
    uint8_t out[4] = { 0 };
    rfb_pixel_to_rgba8(&pf, src, out);
    RFB_CHECK_EQ_UINT(out[0], 0xFFu);
    RFB_CHECK_EQ_UINT(out[1], 0xFFu);
    RFB_CHECK_EQ_UINT(out[2], 0xFFu);
}

// --- 16bpp RGB565 little-endian -----------------------------------------

RFB_TEST(pixel_convert, convert__16bpp_rgb565_le_red__scaled_to_255) {
    // RGB565: red in bits 11..15 (max 31), green 5..10 (max 63), blue 0..4 (max 31).
    rfb_pixel_format pf = make_pf_conv(16, 16, 0, 31, 63, 31, 11, 5, 0);
    // Pure red: red=31 (all red bits set). Wire value = 31 << 11 = 0xF800.
    // LE bytes: 0x00 0xF8.
    uint8_t src[2] = { 0x00, 0xF8 };
    uint8_t out[4] = { 0 };
    rfb_pixel_to_rgba8(&pf, src, out);
    RFB_CHECK_EQ_UINT(out[0], 0xFFu);  // 31 scales to 255
    RFB_CHECK_EQ_UINT(out[1], 0x00u);
    RFB_CHECK_EQ_UINT(out[2], 0x00u);
}

RFB_TEST(pixel_convert, convert__16bpp_rgb565_le_green__scaled_to_255) {
    rfb_pixel_format pf = make_pf_conv(16, 16, 0, 31, 63, 31, 11, 5, 0);
    // Pure green: green=63. Wire value = 63 << 5 = 0x07E0. LE: 0xE0 0x07.
    uint8_t src[2] = { 0xE0, 0x07 };
    uint8_t out[4] = { 0 };
    rfb_pixel_to_rgba8(&pf, src, out);
    RFB_CHECK_EQ_UINT(out[0], 0x00u);
    RFB_CHECK_EQ_UINT(out[1], 0xFFu);  // 63 scales to 255
    RFB_CHECK_EQ_UINT(out[2], 0x00u);
}

// --- non-255 maxima scaling (plan.md §12.3: "non-255 channel maxima") ----

RFB_TEST(pixel_convert, convert__8bpp_3bit_red_max7__mid_scales) {
    // red max=7. Value 4 should scale to (4*255 + 3)/7 = 1023/7 = 146 (round-half-up).
    rfb_pixel_format pf = make_pf_conv(8, 8, 0, 7, 7, 7, 5, 2, 0);
    // Pixel value with red=4, green=0, blue=0. Shifts red=5 so byte = 4<<5 = 0x80.
    uint8_t src[1] = { 0x80 };
    uint8_t out[4] = { 0 };
    rfb_pixel_to_rgba8(&pf, src, out);
    RFB_CHECK_EQ_UINT(out[0], 146u);
}

// --- exhaustive small-maxima round-half-up (plan §12.3) ------------------
// For max=3, every channel value 0..3 must scale by (v*255+1)/3.
//   0 -> 0, 1 -> 85, 2 -> 170 (rounds 170.5 down to 170 with +max/2=1),
//   3 -> 255.

RFB_TEST(pixel_convert, convert__max3_exhaustive__matches_formula) {
    // 8bpp, red max=3 at shift 6, green max=3 at shift 4, blue max=3 at shift 0.
    // (These shifts are arbitrary; just need distinct non-overlapping masks.)
    rfb_pixel_format pf = make_pf_conv(8, 8, 0, 3, 3, 3, 6, 4, 0);
    for (uint16_t r = 0; r <= 3; r++) {
        uint8_t byte = (uint8_t)((r << 6) | (0 << 4) | (0 << 0));
        uint8_t src[1] = { byte };
        uint8_t out[4] = { 0 };
        rfb_pixel_to_rgba8(&pf, src, out);
        uint16_t expect = (uint16_t)((r * 255 + 1) / 3);
        RFB_CHECK_EQ_UINT(out[0], expect);
    }
}

// --- run conversion: a 4-pixel row ---------------------------------------

RFB_TEST(pixel_convert, convert_run__4_pixels__each_converted) {
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();
    // 4 pixels: red, green, blue, white. Each 4 bytes LE.
    static const uint8_t src[16] = {
        0x00, 0x00, 0xFF, 0x00,  // red
        0x00, 0xFF, 0x00, 0x00,  // green
        0xFF, 0x00, 0x00, 0x00,  // blue
        0xFF, 0xFF, 0xFF, 0x00,  // white
    };
    uint8_t dst[16] = { 0 };
    rfb_convert_run(&pf, src, dst, 4);
    RFB_CHECK_EQ_UINT(dst[0], 0xFFu);  // R red
    RFB_CHECK_EQ_UINT(dst[4], 0x00u);  // R green = 0
    RFB_CHECK_EQ_UINT(dst[5], 0xFFu);  // G green
    RFB_CHECK_EQ_UINT(dst[10], 0xFFu); // B blue
    RFB_CHECK_EQ_UINT(dst[15], 0xFFu); // A white
}
