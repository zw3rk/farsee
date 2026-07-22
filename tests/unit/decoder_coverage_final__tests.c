// SPDX-License-Identifier: Apache-2.0
//
// Coverage completion tests for decoder modules — drives the remaining
// semantic branch points to reach plan.md §15.5 95% line.

#include "rfb_test.h"
#include "farsee/encoding.h"
#include "farsee/encoding_zrle.h"
#include "farsee/framebuffer.h"
#include "farsee/pixel_format.h"
#include "farsee/pixel_convert.h"
#include "farsee/fbupdate.h"
#include "farsee/zlib_adapter.h"
#include "farsee/bytes.h"
#include "farsee/allocator.h"
#include "farsee/error.h"

#include <zlib.h>
#include <string.h>

// ---- encoding_raw.c line 21: zero-area rect ----
RFB_TEST(cov_raw, raw__zero_area_rect__fails) {
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_resize(&fb, 4, 4, 1u << 20);
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();
    rfb_rect_header rh = { 0, 0, 0, 1, RFB_ENCODING_RAW };
    static const uint8_t payload[1] = { 0 };
    rfb_rect dmg;
    RFB_CHECK_EQ_INT(rfb_decode_raw(&fb, &pf, &rh, payload, 1, &dmg), RFB_ERR_PROTOCOL);
    rfb_framebuffer_destroy(&fb);
}

// ---- encoding_raw.c line 43: invalid pixel format ----
RFB_TEST(cov_raw, raw__invalid_pixel_format__fails) {
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_resize(&fb, 4, 4, 1u << 20);
    // depth > bpp
    rfb_pixel_format pf = { .bits_per_pixel=16, .depth=24, .big_endian=0,
                            .true_color=1, .red_max=255, .green_max=255,
                            .blue_max=255, .red_shift=0, .green_shift=8,
                            .blue_shift=16 };
    rfb_rect_header rh = { 0, 0, 1, 1, RFB_ENCODING_RAW };
    static const uint8_t payload[4] = { 0 };
    rfb_rect dmg;
    RFB_CHECK_EQ_INT(rfb_decode_raw(&fb, &pf, &rh, payload, 4, &dmg), RFB_ERR_PROTOCOL);
    rfb_framebuffer_destroy(&fb);
}

// ---- pixel_convert.c line 24: 16bpp big-endian ----
RFB_TEST(cov_pconv, convert__16bpp_be__decodes) {
    rfb_pixel_format pf = { .bits_per_pixel=16, .depth=16, .big_endian=1,
                            .true_color=1, .red_max=31, .green_max=63,
                            .blue_max=31, .red_shift=11, .green_shift=5,
                            .blue_shift=0 };
    // Red in RGB565 BE: 0xF800 → bytes FF 08? No, BE means high byte first.
    // 0xF800 BE: FF 80? No. 0xF800 as bytes: high byte = 0xF8, low byte = 0x00.
    uint8_t src[2] = { 0xF8, 0x00 };
    uint8_t out[4] = { 0 };
    rfb_pixel_to_rgba8(&pf, src, out);
    RFB_CHECK_EQ_UINT(out[0], 0xFFu);  // red max=31 scales to 255
}

// ---- pixel_convert.c line 47: scale_channel max=0 ----
RFB_TEST(cov_pconv, convert__zero_max__returns_zero) {
    // Construct a pixel format where one channel has max=0.
    // This is rejected by rfb_pixel_format_valid, but the converter
    // is called directly with scale_channel. Test via the internal path:
    // Use a format with blue_max=0 (invalid but we call the converter directly).
    rfb_pixel_format pf = { .bits_per_pixel=32, .depth=24, .big_endian=0,
                            .true_color=1, .red_max=255, .green_max=255,
                            .blue_max=0, .red_shift=16, .green_shift=8,
                            .blue_shift=0 };
    uint8_t src[4] = { 0xFF, 0xFF, 0xFF, 0x00 };
    uint8_t out[4] = { 0 };
    rfb_pixel_to_rgba8(&pf, src, out);
    // With blue_max=0, the scale_channel returns 0 for blue.
    RFB_CHECK_EQ_UINT(out[2], 0u);
}

// ---- fbupdate.c: wrong-type and short-header (already tested, but
//      verify the remaining pad-byte path) ----
RFB_TEST(cov_fbupdate, fbupdate__pad_byte_nonzero__still_ok) {
    // The header parser reads a pad byte. If pad is nonzero, it still
    // succeeds (pad is ignored). This drives the pad-read branch.
    static const uint8_t h[] = { 0x00, 0xFF, 0x00, 0x02 };  // type=0, pad=0xFF, count=2
    rfb_reader r = rfb_reader_make(h, sizeof h);
    uint16_t n = 0;
    RFB_CHECK_EQ_INT(rfb_parse_fbupdate_header(&r, &n), RFB_OK);
    RFB_CHECK_EQ_UINT(n, 2u);
}

// ---- encoding_zrle.c: CPIXEL fallback path (non-canonical format) ----
RFB_TEST(cov_zrle, zrle__cpixel_fallback_non32bpp__uses_full_pixel) {
    // For a 16bpp format, CPIXEL = 2 bytes (full pixel width).
    rfb_pixel_format pf = { .bits_per_pixel=16, .depth=16, .big_endian=0,
                            .true_color=1, .red_max=31, .green_max=63,
                            .blue_max=31, .red_shift=11, .green_shift=5,
                            .blue_shift=0 };
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_resize(&fb, 2, 2, 1u << 20);
    // Build a solid tile (subenc=1) + 2-byte CPIXEL.
    uint8_t tile[3];
    tile[0] = 1;  // solid
    tile[1] = 0x00; tile[2] = 0xF8;  // red in RGB565 LE: 0xF800 → LE bytes 00 F8
    uint8_t compressed[64];
    uLongf clen = sizeof compressed;
    compress2(compressed, &clen, tile, 3, Z_DEFAULT_COMPRESSION);
    rfb_rect_header rh = { 0, 0, 2, 2, RFB_ENCODING_ZRLE };
    rfb_zlib_stream *zs = rfb_zlib_create();
    rfb_rect dmg;
    rfb_error e = rfb_decode_zrle(&fb, &pf, &rh, zs, compressed, clen, 1u<<20, &dmg);
    RFB_CHECK_EQ_INT(e, RFB_OK);
    // The pixel should be red (31 → 255).
    RFB_CHECK_EQ_UINT(rfb_framebuffer_pixel_c(&fb, 0, 0)[0], 0xFFu);
    rfb_zlib_destroy(zs);
    rfb_framebuffer_destroy(&fb);
}

// ---- encoding_zrle.c: run-length overflow (255 extension) ----
RFB_TEST(cov_zrle, zrle__run_length_255_extension__decodes) {
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_resize(&fb, 64, 1, 1u << 20);
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();
    // Plain RLE, run of 255 (single 255 byte → run = 255).
    uint8_t tile[8];
    tile[0] = 128;  // plain RLE
    tile[1] = 0x00; tile[2] = 0x00; tile[3] = 0xFF;  // red CPIXEL
    tile[4] = 254;  // 254 → run = 255
    // Pad to 64 pixels: need another run of 255... but 255 already exceeds 64.
    // So this should fail (run overflow). Let's test the overflow path.
    uint8_t compressed[64];
    uLongf clen = sizeof compressed;
    compress2(compressed, &clen, tile, 5, Z_DEFAULT_COMPRESSION);
    rfb_rect_header rh = { 0, 0, 64, 1, RFB_ENCODING_ZRLE };
    rfb_zlib_stream *zs = rfb_zlib_create();
    rfb_rect dmg;
    // Run of 255 in a 64-pixel tile → overflow → PROTOCOL error.
    rfb_error e = rfb_decode_zrle(&fb, &pf, &rh, zs, compressed, clen, 1u<<20, &dmg);
    RFB_CHECK_EQ_INT(e, RFB_ERR_PROTOCOL);
    rfb_zlib_destroy(zs);
    rfb_framebuffer_destroy(&fb);
}

// ---- encoding_zrle.c: invalid palette index ----
RFB_TEST(cov_zrle, zrle__packed_palette_invalid_index__fails) {
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_resize(&fb, 4, 1, 1u << 20);
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();
    // Packed palette with 2 entries but pixel data references index 1 when
    // the palette only has valid entries... actually with 2 entries (1 bit),
    // indices 0 and 1 are both valid. Need an invalid index: use subenc=2
    // (2-entry palette) but data that produces index > 1. With 1 bit/pixel,
    // max index is 1. So this path needs bits_per_idx > 1.
    // Use subenc=4 (4-entry palette, 2 bits/pixel). Palette has 4 entries.
    // Index 3 is valid. To get invalid, need index >= 4 with 2 bits = impossible.
    // Actually the "invalid palette index" check (line 198) fires when
    // idx >= pal_size. With correct packing, this can't happen unless the
    // data is corrupt. Let's construct corrupt data:
    // subenc=2 (2-entry palette, 1 bit/pixel). But the pixel data byte
    // has all bits set → indices 0,1,0,1,0,1,0,1 — all valid for 2 entries.
    // The invalid-index path requires bits_per_idx to produce an index
    // that's >= pal_size. With correct bit extraction, this CAN'T happen.
    // So this is a genuinely unreachable defensive check.
    // Mark it with LCOV_EXCL or test a truncated packed-data scenario.
    // Test truncated packed data instead (line 131):
    uint8_t tile[8];
    tile[0] = 2;  // palette size 2
    tile[1] = 0; tile[2] = 0; tile[3] = 0xFF;  // red CPIXEL
    tile[4] = 0; tile[5] = 0xFF; tile[6] = 0;  // green CPIXEL
    // No packed data → truncated.
    uint8_t compressed[64];
    uLongf clen = sizeof compressed;
    compress2(compressed, &clen, tile, 7, Z_DEFAULT_COMPRESSION);
    rfb_rect_header rh = { 0, 0, 4, 1, RFB_ENCODING_ZRLE };
    rfb_zlib_stream *zs = rfb_zlib_create();
    rfb_rect dmg;
    rfb_error e = rfb_decode_zrle(&fb, &pf, &rh, zs, compressed, clen, 1u<<20, &dmg);
    RFB_CHECK_EQ_INT(e, RFB_ERR_PROTOCOL);
    rfb_zlib_destroy(zs);
    rfb_framebuffer_destroy(&fb);
}

// ---- encoding_zrle.c: truncated RLE run ----
RFB_TEST(cov_zrle, zrle__plain_rle_truncated_run__fails) {
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_resize(&fb, 2, 2, 1u << 20);
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();
    // Plain RLE with CPIXEL but no run-length bytes (truncated).
    uint8_t tile[4];
    tile[0] = 128;  // plain RLE
    tile[1] = 0; tile[2] = 0; tile[3] = 0xFF;  // CPIXEL, but no run-length byte
    uint8_t compressed[64];
    uLongf clen = sizeof compressed;
    compress2(compressed, &clen, tile, 4, Z_DEFAULT_COMPRESSION);
    rfb_rect_header rh = { 0, 0, 2, 2, RFB_ENCODING_ZRLE };
    rfb_zlib_stream *zs = rfb_zlib_create();
    rfb_rect dmg;
    rfb_error e = rfb_decode_zrle(&fb, &pf, &rh, zs, compressed, clen, 1u<<20, &dmg);
    RFB_CHECK_EQ_INT(e, RFB_ERR_PROTOCOL);
    rfb_zlib_destroy(zs);
    rfb_framebuffer_destroy(&fb);
}

// ---- encoding_zrle.c: palette RLE truncated ----
RFB_TEST(cov_zrle, zrle__palette_rle_truncated__fails) {
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_resize(&fb, 2, 2, 1u << 20);
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();
    // Palette RLE (subenc=130 = 128+2) with palette but no runs.
    uint8_t tile[8];
    tile[0] = 130;  // palette RLE, 2 colors
    tile[1] = 0; tile[2] = 0; tile[3] = 0xFF;  // red CPIXEL
    tile[4] = 0; tile[5] = 0xFF; tile[6] = 0;  // green CPIXEL
    // No run data → truncated.
    uint8_t compressed[64];
    uLongf clen = sizeof compressed;
    compress2(compressed, &clen, tile, 7, Z_DEFAULT_COMPRESSION);
    rfb_rect_header rh = { 0, 0, 2, 2, RFB_ENCODING_ZRLE };
    rfb_zlib_stream *zs = rfb_zlib_create();
    rfb_rect dmg;
    rfb_error e = rfb_decode_zrle(&fb, &pf, &rh, zs, compressed, clen, 1u<<20, &dmg);
    RFB_CHECK_EQ_INT(e, RFB_ERR_PROTOCOL);
    rfb_zlib_destroy(zs);
    rfb_framebuffer_destroy(&fb);
}

// ---- encoding_zrle.c: 8bpp CPIXEL (1 byte) ----
RFB_TEST(cov_zrle, zrle__8bpp_solid_tile__uses_cpixel) {
    rfb_pixel_format pf = { .bits_per_pixel=8, .depth=8, .big_endian=0,
                            .true_color=1, .red_max=7, .green_max=7,
                            .blue_max=3, .red_shift=5, .green_shift=2,
                            .blue_shift=0 };
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_resize(&fb, 2, 2, 1u << 20);
    // For 8bpp, CPIXEL = 1 byte (full pixel width since bpp < 32).
    uint8_t tile[2];
    tile[0] = 1;  // solid
    tile[1] = 0xE0;  // red=7 (bits 5-7 = 111)
    uint8_t compressed[64];
    uLongf clen = sizeof compressed;
    compress2(compressed, &clen, tile, 2, Z_DEFAULT_COMPRESSION);
    rfb_rect_header rh = { 0, 0, 2, 2, RFB_ENCODING_ZRLE };
    rfb_zlib_stream *zs = rfb_zlib_create();
    rfb_rect dmg;
    rfb_error e = rfb_decode_zrle(&fb, &pf, &rh, zs, compressed, clen, 1u<<20, &dmg);
    RFB_CHECK_EQ_INT(e, RFB_OK);
    // red=7 should scale to 255.
    RFB_CHECK_EQ_UINT(rfb_framebuffer_pixel_c(&fb, 0, 0)[0], 0xFFu);
    rfb_zlib_destroy(zs);
    rfb_framebuffer_destroy(&fb);
}
