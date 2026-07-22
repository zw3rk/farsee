// SPDX-License-Identifier: Apache-2.0
//
// G8 — ZRLE RLE subencoding tests (plan.md §G8, RFC 6143 §7.7.6). RED step.
//
// Tests: packed-palette (subenc 2..16), plain RLE (subenc 128), palette
// RLE (subenc 129+). Each test constructs a valid zlib-compressed ZRLE
// payload, feeds it to the decoder, and verifies the framebuffer pixels.

#include "rfb_test.h"
#include "farsee/encoding_zrle.h"
#include "farsee/encoding.h"
#include "farsee/framebuffer.h"
#include "farsee/pixel_format.h"
#include "farsee/zlib_adapter.h"
#include "farsee/allocator.h"
#include "farsee/error.h"
#include "farsee/limits.h"

#include <zlib.h>
#include <string.h>

static size_t zrle_rle_compress(const uint8_t *src, size_t src_len,
                        uint8_t *dst, size_t dst_cap)
{
    uLongf out_len = dst_cap;
    if (compress2(dst, &out_len, src, src_len, Z_DEFAULT_COMPRESSION) != Z_OK) {
        return 0;
    }
    return (size_t)out_len;
}

// Helper: check every pixel in a tile matches expected RGBA.
static void check_tile_rgba(rfb_framebuffer *fb,
                            uint32_t ox, uint32_t oy,
                            uint32_t w, uint32_t h,
                            const uint8_t expected_rgba[])
{
    for (uint32_t row = 0; row < h; row++) {
        for (uint32_t col = 0; col < w; col++) {
            const uint8_t *p = rfb_framebuffer_pixel_c(fb, ox + col, oy + row);
            size_t idx = (size_t)(row * w + col) * 4u;
            RFB_CHECK_EQ_UINT(p[0], expected_rgba[idx]);
            RFB_CHECK_EQ_UINT(p[1], expected_rgba[idx + 1]);
            RFB_CHECK_EQ_UINT(p[2], expected_rgba[idx + 2]);
            RFB_CHECK_EQ_UINT(p[3], expected_rgba[idx + 3]);
        }
    }
}

// --- packed-palette (subenc 2): 2-entry palette, 1 bit/pixel -----------
// A 4x2 tile with alternating red/green pixels.
// Palette: [0]=red, [1]=green. Pixel data: 1 bit/pixel packed MSB-first.

RFB_TEST(zrle_rle, zrle__packed_palette_2_colors_4x2__decodes_correctly) {
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_resize(&fb, 4, 2, 1u << 20);
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();

    // Build ZRLE tile data for subencoding 2 (2-color packed palette).
    // Subencoding byte = 2 (palette size).
    // Palette: 2 pixels in CPIXEL format (canonical 32bpp → CPIXEL may be 1 byte
    // if the pixel fits; for simplicity use full 4-byte pixels).
    // For canonical format with shifts R=16,G=8,B=0 and max=255, a CPIXEL
    // where all channels fit in byte 0 uses 3 bytes (RGB without the alpha
    // byte). Actually ZRLE CPIXEL for 32bpp depth-24 with max=255 uses 3 bytes
    // (drops the zero high byte). Let's use 3-byte CPIXEL.
    // Red CPIXEL: 0x00FF0000 → bytes (LE) 00 00 FF. But CPIXEL drops the
    // unused high byte... This is getting complex. Let's use the simplest
    // valid encoding: for a 32bpp true-color with max=255 and shifts
    // R=16,G=8,B=0, the CPIXEL is 3 bytes: the low 3 bytes of the pixel
    // word (since byte 3 is always 0).
    // Red pixel word LE: 00 00 FF 00 → CPIXEL = 00 00 FF (3 bytes).
    // Green pixel word LE: 00 FF 00 00 → CPIXEL = 00 FF 00 (3 bytes).

    uint8_t tile[32];
    int pos = 0;
    tile[pos++] = 2;  // subencoding = palette size 2
    // Palette entries (CPIXEL, 3 bytes each for canonical 32bpp).
    tile[pos++] = 0x00; tile[pos++] = 0x00; tile[pos++] = 0xFF;  // red
    tile[pos++] = 0x00; tile[pos++] = 0xFF; tile[pos++] = 0x00;  // green
    // Pixel data: 1 bit/pixel, MSB first, row-padded (RFC 6143 §7.7.6).
    // Width 4 → row_bytes = 1. Alternating R(0),G(1) each row → 0x50
    // (bits 0101 + pad). Two rows → two bytes.
    tile[pos++] = 0x50;
    tile[pos++] = 0x50;

    uint8_t compressed[64];
    size_t comp_len = zrle_rle_compress(tile, (size_t)pos, compressed, sizeof compressed);
    RFB_CHECK(comp_len > 0);

    rfb_rect_header rh = { .x = 0, .y = 0, .width = 4, .height = 2,
                           .encoding = RFB_ENCODING_ZRLE };
    rfb_zlib_stream *zs = rfb_zlib_create();
    rfb_rect dmg = { 0 };
    RFB_CHECK_EQ_INT(
        rfb_decode_zrle(&fb, &pf, &rh, zs, compressed, comp_len, 1u << 20, &dmg),
        RFB_OK);
    rfb_zlib_destroy(zs);

    // Expected: alternating red/green per row (R,G,R,G / R,G,R,G).
    const uint8_t exp[] = {
        0xFF,0x00,0x00,0xFF, 0x00,0xFF,0x00,0xFF,
        0xFF,0x00,0x00,0xFF, 0x00,0xFF,0x00,0xFF,
        0xFF,0x00,0x00,0xFF, 0x00,0xFF,0x00,0xFF,
        0xFF,0x00,0x00,0xFF, 0x00,0xFF,0x00,0xFF,
    };
    check_tile_rgba(&fb, 0, 0, 4, 2, exp);
    rfb_framebuffer_destroy(&fb);
}

// Multi-row edge width: 3×2, 1 bit/pixel — row pad differs from flat stream.
// Flat bitstream of 6 bits would fit in 1 byte; row-padded needs 2 bytes.
RFB_TEST(zrle_rle, zrle__packed_palette_1bit_3x2_row_pad__decodes) {
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_resize(&fb, 3, 2, 1u << 20);
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();

    uint8_t tile[32];
    int pos = 0;
    tile[pos++] = 2;
    tile[pos++] = 0x00; tile[pos++] = 0x00; tile[pos++] = 0xFF;  // red=0
    tile[pos++] = 0x00; tile[pos++] = 0xFF; tile[pos++] = 0x00;  // green=1
    // Row0: R G R → bits 0,1,0 + pad → 0x40 (0100 0000)
    // Row1: G R G → bits 1,0,1 + pad → 0xA0 (1010 0000)
    tile[pos++] = 0x40;
    tile[pos++] = 0xA0;

    uint8_t compressed[64];
    size_t comp_len = zrle_rle_compress(tile, (size_t)pos, compressed, sizeof compressed);
    RFB_CHECK(comp_len > 0);

    rfb_rect_header rh = { .x = 0, .y = 0, .width = 3, .height = 2,
                           .encoding = RFB_ENCODING_ZRLE };
    rfb_zlib_stream *zs = rfb_zlib_create();
    rfb_rect dmg = { 0 };
    RFB_CHECK_EQ_INT(
        rfb_decode_zrle(&fb, &pf, &rh, zs, compressed, comp_len, 1u << 20, &dmg),
        RFB_OK);
    rfb_zlib_destroy(zs);

    const uint8_t exp[] = {
        // row0: R G R
        0xFF,0x00,0x00,0xFF, 0x00,0xFF,0x00,0xFF, 0xFF,0x00,0x00,0xFF,
        // row1: G R G
        0x00,0xFF,0x00,0xFF, 0xFF,0x00,0x00,0xFF, 0x00,0xFF,0x00,0xFF,
    };
    check_tile_rgba(&fb, 0, 0, 3, 2, exp);
    rfb_framebuffer_destroy(&fb);
}

// 2-bit palette, width 3 (row_bytes = 1): multi-row edge case.
RFB_TEST(zrle_rle, zrle__packed_palette_2bit_3x2_row_pad__decodes) {
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_resize(&fb, 3, 2, 1u << 20);
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();

    uint8_t tile[48];
    int pos = 0;
    tile[pos++] = 3;  // 3-color palette → 2 bits/index
    // pal[0]=red, pal[1]=green, pal[2]=blue
    tile[pos++] = 0x00; tile[pos++] = 0x00; tile[pos++] = 0xFF;
    tile[pos++] = 0x00; tile[pos++] = 0xFF; tile[pos++] = 0x00;
    tile[pos++] = 0xFF; tile[pos++] = 0x00; tile[pos++] = 0x00;
    // Row: 3 pixels × 2 bits = 6 bits → 1 byte. Indices 0,1,2 → 00 01 10 xx
    // = 0x18 (000110xx with pad 00 → 00011000 = 0x18)
    tile[pos++] = 0x18;
    // Row1: 2,0,1 → 10 00 01 xx = 0x84
    tile[pos++] = 0x84;

    uint8_t compressed[64];
    size_t comp_len = zrle_rle_compress(tile, (size_t)pos, compressed, sizeof compressed);
    RFB_CHECK(comp_len > 0);

    rfb_rect_header rh = { .x = 0, .y = 0, .width = 3, .height = 2,
                           .encoding = RFB_ENCODING_ZRLE };
    rfb_zlib_stream *zs = rfb_zlib_create();
    rfb_rect dmg = { 0 };
    RFB_CHECK_EQ_INT(
        rfb_decode_zrle(&fb, &pf, &rh, zs, compressed, comp_len, 1u << 20, &dmg),
        RFB_OK);
    rfb_zlib_destroy(zs);

    const uint8_t exp[] = {
        // R G B
        0xFF,0x00,0x00,0xFF, 0x00,0xFF,0x00,0xFF, 0x00,0x00,0xFF,0xFF,
        // B R G
        0x00,0x00,0xFF,0xFF, 0xFF,0x00,0x00,0xFF, 0x00,0xFF,0x00,0xFF,
    };
    check_tile_rgba(&fb, 0, 0, 3, 2, exp);
    rfb_framebuffer_destroy(&fb);
}

// --- plain RLE (subenc 128): 4x2 with runs -----------------------------
// Run = pixel (CPIXEL) followed by u8 length-1 (run of 1..256).
// Layout: pixel1, len1-1, pixel2, len2-1, ...

RFB_TEST(zrle_rle, zrle__plain_rle_4x2__decodes_correctly) {
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_resize(&fb, 4, 2, 1u << 20);
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();

    // 4x2 tile: 4 red, then 2 green, then 2 blue.
    // Plain RLE: subenc=128, then runs.
    // Run 1: red CPIXEL (3 bytes: 00 00 FF) + len-1=3 (4 pixels).
    // Run 2: green CPIXEL (3 bytes: 00 FF 00) + len-1=1 (2 pixels).
    // Run 3: blue CPIXEL (3 bytes: FF 00 00) + len-1=1 (2 pixels).
    uint8_t tile[32];
    int pos = 0;
    tile[pos++] = 128;  // plain RLE
    // Run 1: red, 4 pixels
    tile[pos++] = 0x00; tile[pos++] = 0x00; tile[pos++] = 0xFF;
    tile[pos++] = 3;  // run length - 1 = 3 (4 pixels)
    // Run 2: green, 2 pixels
    tile[pos++] = 0x00; tile[pos++] = 0xFF; tile[pos++] = 0x00;
    tile[pos++] = 1;  // 2 pixels
    // Run 3: blue, 2 pixels
    tile[pos++] = 0xFF; tile[pos++] = 0x00; tile[pos++] = 0x00;
    tile[pos++] = 1;  // 2 pixels

    uint8_t compressed[64];
    size_t comp_len = zrle_rle_compress(tile, (size_t)pos, compressed, sizeof compressed);
    RFB_CHECK(comp_len > 0);

    rfb_rect_header rh = { .x = 0, .y = 0, .width = 4, .height = 2,
                           .encoding = RFB_ENCODING_ZRLE };
    rfb_zlib_stream *zs = rfb_zlib_create();
    rfb_rect dmg = { 0 };
    RFB_CHECK_EQ_INT(
        rfb_decode_zrle(&fb, &pf, &rh, zs, compressed, comp_len, 1u << 20, &dmg),
        RFB_OK);
    rfb_zlib_destroy(zs);

    // Expected: RRRR GG BB
    const uint8_t exp[] = {
        0xFF,0x00,0x00,0xFF, 0xFF,0x00,0x00,0xFF,
        0xFF,0x00,0x00,0xFF, 0xFF,0x00,0x00,0xFF,
        0x00,0xFF,0x00,0xFF, 0x00,0xFF,0x00,0xFF,
        0x00,0x00,0xFF,0xFF, 0x00,0x00,0xFF,0xFF,
    };
    check_tile_rgba(&fb, 0, 0, 4, 2, exp);
    rfb_framebuffer_destroy(&fb);
}

// --- palette RLE (subenc 129+): RFC 6143 §7.7.6 --------------------------
// subenc = 128 + palette_size. Each run starts with an index byte:
//   bit7 clear → run length 1, index = low 7 bits
//   bit7 set   → run length follows (plain-RLE encoding), index = low 7 bits

RFB_TEST(zrle_rle, zrle__palette_rle_2_colors_4x2__decodes_correctly) {
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_resize(&fb, 4, 2, 1u << 20);
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();

    // Palette RLE with 2-color palette: subenc = 128 + 2 = 130.
    // Palette: [0]=red, [1]=green.
    // Run 1: index 0 (red), length 4  → 0x80 | 0, then run-1=3
    // Run 2: index 1 (green), length 2 → 0x80 | 1, then run-1=1
    // Run 3: index 0 (red), length 1   → 0x00 (no length byte)
    // Run 4: index 1 (green), length 1 → 0x01
    // Total = 4+2+1+1 = 8 pixels (4x2).
    uint8_t tile[32];
    int pos = 0;
    tile[pos++] = 130;  // palette RLE, 2-color palette
    // Palette entries (CPIXEL, 3 bytes each).
    tile[pos++] = 0x00; tile[pos++] = 0x00; tile[pos++] = 0xFF;  // red
    tile[pos++] = 0x00; tile[pos++] = 0xFF; tile[pos++] = 0x00;  // green
    tile[pos++] = (uint8_t)(0x80u | 0u);  // index 0 + length follows
    tile[pos++] = 3;                      // run length - 1 = 3 (4 pixels)
    tile[pos++] = (uint8_t)(0x80u | 1u);  // index 1 + length follows
    tile[pos++] = 1;                      // run length - 1 = 1 (2 pixels)
    tile[pos++] = 0;                      // index 0, run length 1
    tile[pos++] = 1;                      // index 1, run length 1

    uint8_t compressed[64];
    size_t comp_len = zrle_rle_compress(tile, (size_t)pos, compressed, sizeof compressed);
    RFB_CHECK(comp_len > 0);

    rfb_rect_header rh = { .x = 0, .y = 0, .width = 4, .height = 2,
                           .encoding = RFB_ENCODING_ZRLE };
    rfb_zlib_stream *zs = rfb_zlib_create();
    rfb_rect dmg = { 0 };
    RFB_CHECK_EQ_INT(
        rfb_decode_zrle(&fb, &pf, &rh, zs, compressed, comp_len, 1u << 20, &dmg),
        RFB_OK);
    rfb_zlib_destroy(zs);

    // Expected: RRRR GG R G
    const uint8_t exp[] = {
        0xFF,0x00,0x00,0xFF, 0xFF,0x00,0x00,0xFF,
        0xFF,0x00,0x00,0xFF, 0xFF,0x00,0x00,0xFF,
        0x00,0xFF,0x00,0xFF, 0x00,0xFF,0x00,0xFF,
        0xFF,0x00,0x00,0xFF, 0x00,0xFF,0x00,0xFF,
    };
    check_tile_rgba(&fb, 0, 0, 4, 2, exp);
    rfb_framebuffer_destroy(&fb);
}

// --- run overflow: length > 255 uses extended encoding -----------------
// In ZRLE RLE, a run length is encoded as: pixel/index, then a sequence
// of bytes where 255 means "add 255 and continue reading", and a final
// byte < 255 means "add that many + 1". So a run of 256 = 255, 0.
// A run of 300 = 255, 44.

// --- run within a single tile exceeding 64 pixels (edge tiles) --------

RFB_TEST(zrle_rle, zrle__plain_rle_two_tiles_65x1__decodes_correctly) {
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_resize(&fb, 65, 1, 1u << 20);
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();

    // 65x1 rectangle = two tiles: 64x1 + 1x1.
    uint8_t tile[32];
    int pos = 0;
    // Tile 1: 64x1 all red, plain RLE run of 64.
    tile[pos++] = 128;
    tile[pos++] = 0x00; tile[pos++] = 0x00; tile[pos++] = 0xFF;
    tile[pos++] = 63;   // run = 64
    // Tile 2: 1x1 red.
    tile[pos++] = 128;
    tile[pos++] = 0x00; tile[pos++] = 0x00; tile[pos++] = 0xFF;
    tile[pos++] = 0;    // run = 1

    uint8_t compressed[64];
    size_t comp_len = zrle_rle_compress(tile, (size_t)pos, compressed, sizeof compressed);
    RFB_CHECK(comp_len > 0);

    rfb_rect_header rh = { .x = 0, .y = 0, .width = 65, .height = 1,
                           .encoding = RFB_ENCODING_ZRLE };
    rfb_zlib_stream *zs = rfb_zlib_create();
    rfb_rect dmg = { 0 };
    RFB_CHECK_EQ_INT(
        rfb_decode_zrle(&fb, &pf, &rh, zs, compressed, comp_len, 1u << 20, &dmg),
        RFB_OK);
    rfb_zlib_destroy(zs);

    for (uint32_t x = 0; x < 65; x++) {
        RFB_CHECK_EQ_UINT(rfb_framebuffer_pixel_c(&fb, x, 0)[0], 0xFFu);
    }
    rfb_framebuffer_destroy(&fb);
}

// RFC 6143: palette sizes 5–8 use 4 bits/index (not ceil(log2)=3).
RFB_TEST(zrle_rle, zrle__packed_palette_5_colors_2x2__4bit_indices) {
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_resize(&fb, 2, 2, 1u << 20);
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();

    uint8_t tile[64];
    int pos = 0;
    tile[pos++] = 5;  // palette size 5 → must use 4 bits/index
    // pal[0]=red,1=green,2=blue,3=white,4=black (CPIXEL 3 bytes each)
    tile[pos++] = 0x00; tile[pos++] = 0x00; tile[pos++] = 0xFF;
    tile[pos++] = 0x00; tile[pos++] = 0xFF; tile[pos++] = 0x00;
    tile[pos++] = 0xFF; tile[pos++] = 0x00; tile[pos++] = 0x00;
    tile[pos++] = 0xFF; tile[pos++] = 0xFF; tile[pos++] = 0xFF;
    tile[pos++] = 0x00; tile[pos++] = 0x00; tile[pos++] = 0x00;
    // 2×2, 4 bits/px → row_bytes = 1. Indices 0,1 then 2,3.
    // Row0: 0000 0001 → 0x01
    // Row1: 0010 0011 → 0x23
    tile[pos++] = 0x01;
    tile[pos++] = 0x23;

    uint8_t compressed[64];
    size_t comp_len = zrle_rle_compress(tile, (size_t)pos, compressed, sizeof compressed);
    RFB_CHECK(comp_len > 0);

    rfb_rect_header rh = { .x = 0, .y = 0, .width = 2, .height = 2,
                           .encoding = RFB_ENCODING_ZRLE };
    rfb_zlib_stream *zs = rfb_zlib_create();
    rfb_rect dmg = { 0 };
    RFB_CHECK_EQ_INT(
        rfb_decode_zrle(&fb, &pf, &rh, zs, compressed, comp_len, 1u << 20, &dmg),
        RFB_OK);
    rfb_zlib_destroy(zs);

    const uint8_t exp[] = {
        // R G
        0xFF,0x00,0x00,0xFF, 0x00,0xFF,0x00,0xFF,
        // B W
        0x00,0x00,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,
    };
    check_tile_rgba(&fb, 0, 0, 2, 2, exp);
    rfb_framebuffer_destroy(&fb);
}

// RFC 6143: palette size 8 also forces 4 bits/index (not 3).
RFB_TEST(zrle_rle, zrle__packed_palette_8_colors_4x1__4bit_indices) {
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_resize(&fb, 4, 1, 1u << 20);
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();

    uint8_t tile[96];
    int pos = 0;
    tile[pos++] = 8;  // palette size 8 → 4 bits/index
    // 8 CPIXEL entries: greyscale 0..7 * 32 in R
    for (int i = 0; i < 8; i++) {
        uint8_t v = (uint8_t)(i * 32);
        tile[pos++] = v; tile[pos++] = v; tile[pos++] = v;
    }
    // 4x1, 4 bits → 2 bytes: indices 0,1,2,3 → 0x01 0x23
    tile[pos++] = 0x01;
    tile[pos++] = 0x23;

    uint8_t compressed[128];
    size_t comp_len = zrle_rle_compress(tile, (size_t)pos, compressed, sizeof compressed);
    RFB_CHECK(comp_len > 0);

    rfb_rect_header rh = { .x = 0, .y = 0, .width = 4, .height = 1,
                           .encoding = RFB_ENCODING_ZRLE };
    rfb_zlib_stream *zs = rfb_zlib_create();
    rfb_rect dmg = { 0 };
    RFB_CHECK_EQ_INT(
        rfb_decode_zrle(&fb, &pf, &rh, zs, compressed, comp_len, 1u << 20, &dmg),
        RFB_OK);
    rfb_zlib_destroy(zs);

    for (uint32_t x = 0; x < 4; x++) {
        uint8_t exp = (uint8_t)(x * 32);
        const uint8_t *px = rfb_framebuffer_pixel_c(&fb, x, 0);
        RFB_CHECK_EQ_UINT(px[0], exp);
        RFB_CHECK_EQ_UINT(px[1], exp);
        RFB_CHECK_EQ_UINT(px[2], exp);
    }
    rfb_framebuffer_destroy(&fb);
}

// Multirow 3x2 with pal_size=6: two rows of 4-bit packed indices + pad.
RFB_TEST(zrle_rle, zrle__packed_palette_6_colors_3x2__multirow_4bit) {
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_resize(&fb, 3, 2, 1u << 20);
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();

    uint8_t tile[96];
    int pos = 0;
    tile[pos++] = 6;
    // pal: R,G,B,W,K,Y (CPIXEL BGR order as other tests)
    tile[pos++] = 0x00; tile[pos++] = 0x00; tile[pos++] = 0xFF; // 0 red
    tile[pos++] = 0x00; tile[pos++] = 0xFF; tile[pos++] = 0x00; // 1 green
    tile[pos++] = 0xFF; tile[pos++] = 0x00; tile[pos++] = 0x00; // 2 blue
    tile[pos++] = 0xFF; tile[pos++] = 0xFF; tile[pos++] = 0xFF; // 3 white
    tile[pos++] = 0x00; tile[pos++] = 0x00; tile[pos++] = 0x00; // 4 black
    tile[pos++] = 0x00; tile[pos++] = 0xFF; tile[pos++] = 0xFF; // 5 yellow
    // row_bytes = (3*4+7)/8 = 2. Indices row0: 0,1,2 → 0x01 0x20 (pad nibble 0)
    // row1: 3,4,5 → 0x34 0x50
    tile[pos++] = 0x01; tile[pos++] = 0x20;
    tile[pos++] = 0x34; tile[pos++] = 0x50;

    uint8_t compressed[128];
    size_t comp_len = zrle_rle_compress(tile, (size_t)pos, compressed, sizeof compressed);
    RFB_CHECK(comp_len > 0);

    rfb_rect_header rh = { .x = 0, .y = 0, .width = 3, .height = 2,
                           .encoding = RFB_ENCODING_ZRLE };
    rfb_zlib_stream *zs = rfb_zlib_create();
    rfb_rect dmg = { 0 };
    RFB_CHECK_EQ_INT(
        rfb_decode_zrle(&fb, &pf, &rh, zs, compressed, comp_len, 1u << 20, &dmg),
        RFB_OK);
    rfb_zlib_destroy(zs);

    const uint8_t exp[] = {
        0xFF,0x00,0x00,0xFF, 0x00,0xFF,0x00,0xFF, 0x00,0x00,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF, 0x00,0x00,0x00,0xFF, 0xFF,0xFF,0x00,0xFF,
    };
    check_tile_rgba(&fb, 0, 0, 3, 2, exp);
    rfb_framebuffer_destroy(&fb);
}

// post-t11 T2: 32bpp depth-32 plain RLE unit runs need 1+5*4096 scratch.
RFB_TEST(zrle_rle, zrle__plain_rle_cpixel4_unit_runs_64x1__ok)
{
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_resize(&fb, 64, 1, 1u << 20);
    // Depth-32 / max>255 so CPIXEL is full 4 bytes.
    rfb_pixel_format pf;
    memset(&pf, 0, sizeof pf);
    pf.bits_per_pixel = 32;
    pf.depth = 32;
    pf.big_endian = 0;
    pf.true_color = 1;
    pf.red_max = 255;
    pf.green_max = 255;
    pf.blue_max = 255;
    pf.red_shift = 16;
    pf.green_shift = 8;
    pf.blue_shift = 0;
    // Force non-compact: red_max still 255 but depth 32 → check cpixel_size
    // path: typically depth<=24 triggers 3-byte. Set red_max > 255 if needed.
    // From encoding_zrle cpixel_size: 32bpp depth<=24 max<=255 → 3. So depth 32 → 4.
    uint8_t tile[1 + 64 * 5];
    int pos = 0;
    tile[pos++] = 128; // plain RLE
    for (int i = 0; i < 64; i++) {
        tile[pos++] = 0x11; tile[pos++] = 0x22; tile[pos++] = 0x33; tile[pos++] = 0x44;
        tile[pos++] = 0; // run length 1
    }
    uint8_t compressed[512];
    size_t clen = zrle_rle_compress(tile, (size_t)pos, compressed,
                                    sizeof compressed);
    RFB_CHECK(clen > 0);
    rfb_zlib_stream *zs = rfb_zlib_create();
    rfb_rect_header rh = { 0, 0, 64, 1, RFB_ENCODING_ZRLE };
    rfb_rect dmg = { 0 };
    RFB_CHECK_EQ_INT(
        rfb_decode_zrle(&fb, &pf, &rh, zs, compressed, clen, 1u << 20, &dmg),
        RFB_OK);
    // Full 64x64 tile bound for cs=4 is 1+4096*5 = 20481; 64x1 is smaller
    // but must exceed the old 1+4096*4 per-tile under-estimate for unit runs
    // when height grows — at least cap grew for cs+1.
    RFB_CHECK(rfb_zlib_scratch_cap(zs) >= (size_t)(1 + 64 * 5));
    rfb_zlib_destroy(zs);
    rfb_framebuffer_destroy(&fb);
}

// multi-review 2026-08-03 T1: consecutive ZRLE rects reuse zlib scratch
// (no 256 MiB per-rect alloc).
RFB_TEST(zrle_rle, zrle__scratch_reused_across_two_rects)
{
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_resize(&fb, 2, 2, 1u << 20);
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();

    uint8_t tile[16];
    int pos = 0;
    tile[pos++] = 1; // solid
    tile[pos++] = 0x00; tile[pos++] = 0x00; tile[pos++] = 0xFF;
    uint8_t compressed[64];
    size_t clen = zrle_rle_compress(tile, (size_t)pos, compressed,
                                    sizeof compressed);
    RFB_CHECK(clen > 0);

    rfb_zlib_stream *zs = rfb_zlib_create();
    RFB_CHECK(zs != NULL);
    rfb_rect_header rh = { 0, 0, 2, 2, RFB_ENCODING_ZRLE };
    rfb_rect dmg = { 0 };
    RFB_CHECK_EQ_INT(
        rfb_decode_zrle(&fb, &pf, &rh, zs, compressed, clen, 1u << 20, &dmg),
        RFB_OK);
    const size_t cap1 = rfb_zlib_scratch_cap(zs);
    RFB_CHECK(cap1 > 0u);
    RFB_CHECK(cap1 < (1u << 20)); // far below policy 256 MiB
    RFB_CHECK_EQ_INT(
        rfb_decode_zrle(&fb, &pf, &rh, zs, compressed, clen, 1u << 20, &dmg),
        RFB_OK);
    RFB_CHECK_EQ_UINT(rfb_zlib_scratch_cap(zs), cap1); // reused, not grown needlessly
    rfb_zlib_destroy(zs);
    rfb_framebuffer_destroy(&fb);
}

// multi-review 2026-07-31 T1: plain RLE long 0xFF chain must fail closed
// before uint32 wrap (cap at tile max 4096). Production inflate budget.
RFB_TEST(zrle_rle, zrle__plain_rle_run_length_wrap_chain__protocol) {
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_resize(&fb, 64, 64, 1u << 20);
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();

    // 17×0xFF would accumulate 17*255 = 4335 > 4096 tile max → PROTOCOL
    // in read_run_length (before any stack fill).
    uint8_t tile[64];
    int pos = 0;
    tile[pos++] = 128; // plain RLE
    tile[pos++] = 0x00; tile[pos++] = 0x00; tile[pos++] = 0xFF; // red CPIXEL
    for (int i = 0; i < 17; i++) {
        tile[pos++] = 255;
    }
    tile[pos++] = 0xFE; // would terminate if chain were allowed

    uint8_t compressed[128];
    size_t comp_len = zrle_rle_compress(tile, (size_t)pos, compressed,
                                        sizeof compressed);
    RFB_CHECK(comp_len > 0);

    rfb_rect_header rh = { .x = 0, .y = 0, .width = 64, .height = 64,
                           .encoding = RFB_ENCODING_ZRLE };
    rfb_zlib_stream *zs = rfb_zlib_create();
    rfb_rect dmg = { 0 };
    // Production-scale byte_limit (256 MiB) — unit suites used 1 MiB.
    rfb_error e = rfb_decode_zrle(&fb, &pf, &rh, zs, compressed, comp_len,
                                  RFB_LIMIT_COMPRESSED_RECT_BYTES, &dmg);
    RFB_CHECK_EQ_INT(e, RFB_ERR_PROTOCOL);
    rfb_zlib_destroy(zs);
    rfb_framebuffer_destroy(&fb);
}

// T1 −: palette RLE (subenc 129+) same wrap-proof on extended run.
RFB_TEST(zrle_rle, zrle__palette_rle_run_length_wrap_chain__protocol) {
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_resize(&fb, 64, 64, 1u << 20);
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();

    uint8_t tile[64];
    int pos = 0;
    tile[pos++] = 129; // palette size 1 + RLE
    tile[pos++] = 0x00; tile[pos++] = 0x00; tile[pos++] = 0xFF; // pal[0]
    tile[pos++] = 0x80; // index 0, bit7 set → run length follows
    for (int i = 0; i < 17; i++) {
        tile[pos++] = 255;
    }
    tile[pos++] = 0xFE;

    uint8_t compressed[128];
    size_t comp_len = zrle_rle_compress(tile, (size_t)pos, compressed,
                                        sizeof compressed);
    RFB_CHECK(comp_len > 0);

    rfb_rect_header rh = { .x = 0, .y = 0, .width = 64, .height = 64,
                           .encoding = RFB_ENCODING_ZRLE };
    rfb_zlib_stream *zs = rfb_zlib_create();
    rfb_rect dmg = { 0 };
    rfb_error e = rfb_decode_zrle(&fb, &pf, &rh, zs, compressed, comp_len,
                                  RFB_LIMIT_COMPRESSED_RECT_BYTES, &dmg);
    RFB_CHECK_EQ_INT(e, RFB_ERR_PROTOCOL);
    rfb_zlib_destroy(zs);
    rfb_framebuffer_destroy(&fb);
}

// T1 +: exact tile pixel count run is OK; tile_pixels+1 fails.
RFB_TEST(zrle_rle, zrle__plain_rle_exact_tile_run__ok_and_plus_one_fails) {
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();

    // 2×2 tile, run of 4 (= byte 3) → OK
    {
        rfb_framebuffer fb;
        rfb_framebuffer_init(&fb, rfb_default_allocator());
        rfb_framebuffer_resize(&fb, 2, 2, 1u << 20);
        uint8_t tile[16];
        int pos = 0;
        tile[pos++] = 128;
        tile[pos++] = 0x00; tile[pos++] = 0x00; tile[pos++] = 0xFF;
        tile[pos++] = 3; // run = 4
        uint8_t compressed[64];
        size_t clen = zrle_rle_compress(tile, (size_t)pos, compressed,
                                        sizeof compressed);
        RFB_CHECK(clen > 0);
        rfb_rect_header rh = { 0, 0, 2, 2, RFB_ENCODING_ZRLE };
        rfb_zlib_stream *zs = rfb_zlib_create();
        rfb_rect dmg = { 0 };
        RFB_CHECK_EQ_INT(
            rfb_decode_zrle(&fb, &pf, &rh, zs, compressed, clen,
                            RFB_LIMIT_COMPRESSED_RECT_BYTES, &dmg),
            RFB_OK);
        rfb_zlib_destroy(zs);
        RFB_CHECK_EQ_UINT(rfb_framebuffer_pixel_c(&fb, 0, 0)[0], 0xFFu);
        rfb_framebuffer_destroy(&fb);
    }
    // run of 5 on 2×2 → PROTOCOL
    {
        rfb_framebuffer fb;
        rfb_framebuffer_init(&fb, rfb_default_allocator());
        rfb_framebuffer_resize(&fb, 2, 2, 1u << 20);
        uint8_t tile[16];
        int pos = 0;
        tile[pos++] = 128;
        tile[pos++] = 0x00; tile[pos++] = 0x00; tile[pos++] = 0xFF;
        tile[pos++] = 4; // run = 5 > 4
        uint8_t compressed[64];
        size_t clen = zrle_rle_compress(tile, (size_t)pos, compressed,
                                        sizeof compressed);
        RFB_CHECK(clen > 0);
        rfb_rect_header rh = { 0, 0, 2, 2, RFB_ENCODING_ZRLE };
        rfb_zlib_stream *zs = rfb_zlib_create();
        rfb_rect dmg = { 0 };
        RFB_CHECK_EQ_INT(
            rfb_decode_zrle(&fb, &pf, &rh, zs, compressed, clen,
                            RFB_LIMIT_COMPRESSED_RECT_BYTES, &dmg),
            RFB_ERR_PROTOCOL);
        rfb_zlib_destroy(zs);
        rfb_framebuffer_destroy(&fb);
    }
}

// Two-tile 65×2: solid + pal5 second tile; wrong bit width would desync tile2.
RFB_TEST(zrle_rle, zrle__packed_palette_5_two_tiles_65x2__no_desync) {
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_resize(&fb, 65, 2, 1u << 20);
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();

    // Tile0 (64x2): solid red subenc=1 + CPIXEL
    // Tile1 (1x2): palette size 5 with 4-bit indices
    uint8_t raw[256];
    int pos = 0;
    raw[pos++] = 1; // solid
    raw[pos++] = 0x00; raw[pos++] = 0x00; raw[pos++] = 0xFF; // red CPIXEL

    raw[pos++] = 5; // pal size 5 on second tile
    raw[pos++] = 0x00; raw[pos++] = 0x00; raw[pos++] = 0xFF; //0 red
    raw[pos++] = 0x00; raw[pos++] = 0xFF; raw[pos++] = 0x00; //1 green
    raw[pos++] = 0xFF; raw[pos++] = 0x00; raw[pos++] = 0x00; //2 blue
    raw[pos++] = 0xFF; raw[pos++] = 0xFF; raw[pos++] = 0xFF; //3 white
    raw[pos++] = 0x00; raw[pos++] = 0x00; raw[pos++] = 0x00; //4 black
    // 1x2 tile: 4 bits/px, row_bytes=1 each row. idx 1 then 2 → 0x10, 0x20
    raw[pos++] = 0x10;
    raw[pos++] = 0x20;

    uint8_t compressed[256];
    size_t comp_len = zrle_rle_compress(raw, (size_t)pos, compressed, sizeof compressed);
    RFB_CHECK(comp_len > 0);

    rfb_rect_header rh = { .x = 0, .y = 0, .width = 65, .height = 2,
                           .encoding = RFB_ENCODING_ZRLE };
    rfb_zlib_stream *zs = rfb_zlib_create();
    rfb_rect dmg = { 0 };
    RFB_CHECK_EQ_INT(
        rfb_decode_zrle(&fb, &pf, &rh, zs, compressed, comp_len, 1u << 20, &dmg),
        RFB_OK);
    rfb_zlib_destroy(zs);

    // Left tile solid red
    RFB_CHECK_EQ_UINT(rfb_framebuffer_pixel_c(&fb, 0, 0)[0], 0xFFu);
    RFB_CHECK_EQ_UINT(rfb_framebuffer_pixel_c(&fb, 63, 1)[0], 0xFFu);
    // Right tile column 64: green then blue
    RFB_CHECK_EQ_UINT(rfb_framebuffer_pixel_c(&fb, 64, 0)[1], 0xFFu); // green G
    RFB_CHECK_EQ_UINT(rfb_framebuffer_pixel_c(&fb, 64, 1)[2], 0xFFu); // blue B
    rfb_framebuffer_destroy(&fb);
}
