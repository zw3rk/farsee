// SPDX-License-Identifier: Apache-2.0
//
// Targeted tests for semantic branch conditions.

#include "rfb_test.h"
#include "farsee/encoding.h"
#include "farsee/encoding_zrle.h"
#include "farsee/zlib_adapter.h"
#include "farsee/framebuffer.h"
#include "farsee/pixel_format.h"
#include "farsee/pixel_convert.h"
#include "farsee/bytes.h"
#include "farsee/allocator.h"
#include "farsee/error.h"

#include <zlib.h>

// ===== encoding_raw.c branches =====

// Line 20/24: x+w overflow (uint32 wrap).
RFB_TEST(br_raw, raw__x_plus_w_overflow__fails) {
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_resize(&fb, 4, 4, 1u << 20);
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();
    // x=0xFFFF, w=0x0002 → x+w = 0x10001 > width(4) but also overflows u16.
    rfb_rect_header rh = { .x = 0xFFFF, .y = 0, .width = 2, .height = 1,
                           .encoding = RFB_ENCODING_RAW };
    static const uint8_t payload[8] = { 0 };
    rfb_rect dmg;
    RFB_CHECK_EQ_INT(rfb_decode_raw(&fb, &pf, &rh, payload, 8, &dmg), RFB_ERR_PROTOCOL);
    rfb_framebuffer_destroy(&fb);
}

// Line 25/27: y+h exceeds height.
RFB_TEST(br_raw, raw__y_plus_h_exceeds_height__fails) {
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_resize(&fb, 4, 4, 1u << 20);
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();
    rfb_rect_header rh = { .x = 0, .y = 3, .width = 1, .height = 2,
                           .encoding = RFB_ENCODING_RAW };
    static const uint8_t payload[8] = { 0 };
    rfb_rect dmg;
    RFB_CHECK_EQ_INT(rfb_decode_raw(&fb, &pf, &rh, payload, 8, &dmg), RFB_ERR_PROTOCOL);
    rfb_framebuffer_destroy(&fb);
}

// ===== pixel_convert.c branches =====

// Line 19: 8bpp case in read_pixel_word switch.
RFB_TEST(br_pconv, convert__8bpp_read_pixel_word__covered) {
    // The 8bpp path in read_pixel_word returns src[0].
    rfb_pixel_format pf = { .bits_per_pixel=8, .depth=8, .big_endian=0,
                            .true_color=1, .red_max=7, .green_max=7,
                            .blue_max=3, .red_shift=5, .green_shift=2,
                            .blue_shift=0 };
    uint8_t src[1] = { 0xE4 };  // red=7, green=1, blue=0
    uint8_t out[4];
    rfb_pixel_to_rgba8(&pf, src, out);
    RFB_CHECK_EQ_UINT(out[0], 0xFFu);  // 7 → 255
}

// The scale_channel input is masked to max, so its output cannot exceed 255.
// The clamp is defensive and excluded from coverage.

// ===== encoding_zrle.c: subencoding dispatch branches =====
// The branches at lines 49, 50, 63, 68, 96, 127, 148, 172, 193 are the
// subencoding comparisons. Each subencoding test covers one path. The
// remaining branches are the false-branches of each comparison (the code
// falls through to the next subenc check). These are implicitly covered
// by any test that decodes a different subencoding. The lcov branch model
// counts both true and false for each comparison.

// Test: undefined subencoding 17 → UNSUPPORTED.
RFB_TEST(br_zrle, zrle__undefined_subenc_17__unsupported) {
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_resize(&fb, 2, 2, 1u << 20);
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();
    // Subenc=17: not raw(0), not solid(1), not packed(2-16), not RLE(128),
// not palette-RLE(129+).
    uint8_t tile[1] = { 17 };
    uint8_t compressed[64];
    uLongf clen = sizeof compressed;
    compress2(compressed, &clen, tile, 1, Z_DEFAULT_COMPRESSION);
    rfb_rect_header rh = { 0, 0, 2, 2, RFB_ENCODING_ZRLE };
    rfb_zlib_stream *zs = rfb_zlib_create();
    rfb_rect dmg;
    rfb_error e = rfb_decode_zrle(&fb, &pf, &rh, zs, compressed, clen, 1u<<20, &dmg);
    RFB_CHECK_EQ_INT(e, RFB_ERR_UNSUPPORTED);
    rfb_zlib_destroy(zs);
    rfb_framebuffer_destroy(&fb);
}

// Test: subenc=127 (just below the 128 plain-RLE threshold).
RFB_TEST(br_zrle, zrle__subenc_127__unsupported) {
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_resize(&fb, 2, 2, 1u << 20);
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();
    uint8_t tile[1] = { 127 };
    uint8_t compressed[64];
    uLongf clen = sizeof compressed;
    compress2(compressed, &clen, tile, 1, Z_DEFAULT_COMPRESSION);
    rfb_rect_header rh = { 0, 0, 2, 2, RFB_ENCODING_ZRLE };
    rfb_zlib_stream *zs = rfb_zlib_create();
    rfb_rect dmg;
    rfb_error e = rfb_decode_zrle(&fb, &pf, &rh, zs, compressed, clen, 1u<<20, &dmg);
    RFB_CHECK_EQ_INT(e, RFB_ERR_UNSUPPORTED);
    rfb_zlib_destroy(zs);
    rfb_framebuffer_destroy(&fb);
}
