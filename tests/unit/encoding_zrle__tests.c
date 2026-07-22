// SPDX-License-Identifier: Apache-2.0
//
// G8 — ZRLE decoder tests (plan.md §G8, RFC 6143 §7.7.6). RED step.
//
// Tests: solid tile, raw tile, and the 64×64 tile traversal. Each test
// constructs a valid zlib-compressed ZRLE payload, feeds it to the
// decoder, and verifies the framebuffer pixels are correct.

#include "rfb_test.h"
#include "farsee/encoding_zrle.h"
#include "farsee/encoding.h"
#include "farsee/framebuffer.h"
#include "farsee/pixel_format.h"
#include "farsee/pixel_convert.h"
#include "farsee/zlib_adapter.h"
#include "farsee/allocator.h"
#include "farsee/error.h"

#include <zlib.h>
#include <string.h>

// Compress raw bytes with zlib.
static size_t zcompress(const uint8_t *src, size_t src_len,
                        uint8_t *dst, size_t dst_cap)
{
    uLongf out_len = dst_cap;
    if (compress2(dst, &out_len, src, src_len, Z_DEFAULT_COMPRESSION) != Z_OK) {
        return 0;
    }
    return (size_t)out_len;
}

// --- ZRLE solid tile (subencoding 1): 2x2 all-red ----------------------
// A solid tile is: u32 subencoding=1, then u32 pixel (the solid color).
// For a canonical 32bpp format, the pixel is 4 bytes LE.
// The entire tile payload (for the whole rectangle) is zlib-compressed.

RFB_TEST(zrle, zrle__solid_tile_2x2_red__fills_solid) {
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_resize(&fb, 2, 2, 1u << 20);
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();

    // Build the uncompressed ZRLE tile data for a 2x2 rect (one 2x2 tile).
    // Subencoding byte = 1 (solid), then the single pixel in wire format.
    // Canonical 32bpp LE: red = 0x00FF0000 → bytes 00 00 FF 00.
    uint8_t tile_data[5];
    tile_data[0] = 1;  // solid tile subencoding
    tile_data[1] = 0x00; tile_data[2] = 0x00; tile_data[3] = 0xFF; tile_data[4] = 0x00;

    // Compress.
    uint8_t compressed[64];
    size_t comp_len = zcompress(tile_data, sizeof tile_data, compressed, sizeof compressed);
    RFB_CHECK(comp_len > 0);

    rfb_rect_header rh = { .x = 0, .y = 0, .width = 2, .height = 2,
                           .encoding = RFB_ENCODING_ZRLE };
    rfb_zlib_stream *zs = rfb_zlib_create();
    rfb_rect dmg = { 0 };
    RFB_CHECK_EQ_INT(
        rfb_decode_zrle(&fb, &pf, &rh, zs, compressed, comp_len, 1u << 20, &dmg),
        RFB_OK);
    rfb_zlib_destroy(zs);

    // Every pixel should be red.
    for (uint32_t y = 0; y < 2; y++) {
        for (uint32_t x = 0; x < 2; x++) {
            const uint8_t *p = rfb_framebuffer_pixel_c(&fb, x, y);
            RFB_CHECK_EQ_UINT(p[0], 0xFFu);
            RFB_CHECK_EQ_UINT(p[1], 0x00u);
            RFB_CHECK_EQ_UINT(p[2], 0x00u);
            RFB_CHECK_EQ_UINT(p[3], 0xFFu);
        }
    }
    rfb_framebuffer_destroy(&fb);
}

// --- ZRLE raw tile (subencoding 0): 2x2 checkerboard -------------------
// RFC 6143 §7.7.6: raw tiles are CPIXEL sequences (3 bytes for 32bpp/24).

RFB_TEST(zrle, zrle__raw_tile_2x2_checkerboard__each_pixel_correct) {
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_resize(&fb, 2, 2, 1u << 20);
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();

    // Raw tile: subencoding 0 + 4 × CPIXEL (B,G,R for LE R=16 G=8 B=0).
    uint8_t tile_data[1 + 12];
    tile_data[0] = 0;  // raw tile
    // red, green, blue, white as 3-byte CPIXEL (B G R)
    static const uint8_t pixels[12] = {
        0x00, 0x00, 0xFF,  // red
        0x00, 0xFF, 0x00,  // green
        0xFF, 0x00, 0x00,  // blue
        0xFF, 0xFF, 0xFF,  // white
    };
    memcpy(tile_data + 1, pixels, 12);

    uint8_t compressed[64];
    size_t comp_len = zcompress(tile_data, sizeof tile_data, compressed, sizeof compressed);
    RFB_CHECK(comp_len > 0);

    rfb_rect_header rh = { .x = 0, .y = 0, .width = 2, .height = 2,
                           .encoding = RFB_ENCODING_ZRLE };
    rfb_zlib_stream *zs = rfb_zlib_create();
    rfb_rect dmg = { 0 };
    RFB_CHECK_EQ_INT(
        rfb_decode_zrle(&fb, &pf, &rh, zs, compressed, comp_len, 1u << 20, &dmg),
        RFB_OK);
    rfb_zlib_destroy(zs);

    RFB_CHECK_EQ_UINT(rfb_framebuffer_pixel_c(&fb, 0, 0)[0], 0xFFu);  // red
    RFB_CHECK_EQ_UINT(rfb_framebuffer_pixel_c(&fb, 1, 0)[1], 0xFFu);  // green
    RFB_CHECK_EQ_UINT(rfb_framebuffer_pixel_c(&fb, 0, 1)[2], 0xFFu);  // blue
    RFB_CHECK_EQ_UINT(rfb_framebuffer_pixel_c(&fb, 1, 1)[3], 0xFFu);  // white alpha
    rfb_framebuffer_destroy(&fb);
}

// --- ZRLE tile traversal: 65x1 (two tiles: 64x1 + 1x1) -----------------

RFB_TEST(zrle, zrle__65x1_two_tiles__all_solid_red) {
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_resize(&fb, 65, 1, 1u << 20);
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();

    // Tile 1: 64x1 solid red. Tile 2: 1x1 solid red.
    // Each tile: subencoding=1 + CPIXEL (3 bytes for canonical 32bpp).
    uint8_t tile_data[8];
    tile_data[0] = 1;  // solid
    tile_data[1] = 0x00; tile_data[2] = 0x00; tile_data[3] = 0xFF;  // red CPIXEL
    tile_data[4] = 1;  // solid (second tile)
    tile_data[5] = 0x00; tile_data[6] = 0x00; tile_data[7] = 0xFF;

    uint8_t compressed[64];
    size_t comp_len = zcompress(tile_data, sizeof tile_data, compressed, sizeof compressed);
    RFB_CHECK(comp_len > 0);

    rfb_rect_header rh = { .x = 0, .y = 0, .width = 65, .height = 1,
                           .encoding = RFB_ENCODING_ZRLE };
    rfb_zlib_stream *zs = rfb_zlib_create();
    rfb_rect dmg = { 0 };
    RFB_CHECK_EQ_INT(
        rfb_decode_zrle(&fb, &pf, &rh, zs, compressed, comp_len, 1u << 20, &dmg),
        RFB_OK);
    rfb_zlib_destroy(zs);

    // All 65 pixels should be red.
    for (uint32_t x = 0; x < 65; x++) {
        RFB_CHECK_EQ_UINT(rfb_framebuffer_pixel_c(&fb, x, 0)[0], 0xFFu);
    }
    rfb_framebuffer_destroy(&fb);
}

// --- ZRLE bounds check: rectangle outside framebuffer ------------------

RFB_TEST(zrle, zrle__rect_outside_framebuffer__fails_without_write) {
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_resize(&fb, 2, 2, 1u << 20);
    rfb_framebuffer_fill(&fb, 9, 9, 9, 9);
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();
    rfb_rect_header rh = { .x = 1, .y = 0, .width = 2, .height = 1,
                           .encoding = RFB_ENCODING_ZRLE };
    uint8_t compressed[4] = { 0 };
    rfb_zlib_stream *zs = rfb_zlib_create();
    rfb_rect dmg = { 0 };
    RFB_CHECK_EQ_INT(
        rfb_decode_zrle(&fb, &pf, &rh, zs, compressed, sizeof compressed, 1u << 20, &dmg),
        RFB_ERR_PROTOCOL);
    rfb_zlib_destroy(zs);
    RFB_CHECK_EQ_UINT(rfb_framebuffer_pixel_c(&fb, 0, 0)[0], 9u);  // untouched
    rfb_framebuffer_destroy(&fb);
}

// full2 T4: LE BGR-swapped shifts (B at 16, R at 0) — CPIXEL wire [R,G,B]
// as low 3 LE bytes of word with R at shift 0 → pixel = R|G<<8|B<<16.
RFB_TEST(zrle, zrle__solid_cpixel__swapped_rb_shifts__matches_raw_convert)
{
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_resize(&fb, 2, 2, 1u << 20);
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();
    // Swap R/B shifts relative to canonical (R=16,B=0 → R=0,B=16).
    pf.red_shift = 0;
    pf.blue_shift = 16;
    pf.green_shift = 8;
    RFB_CHECK(rfb_pixel_format_valid(&pf));

    // Solid red in this PF: channel R=255 at shift 0 → LE wire CPIXEL
    // low 3 bytes of word 0x0000FF = bytes FF 00 00 (then high 0).
    // CPIXEL LE = [0xFF, 0x00, 0x00].
    uint8_t tile[1 + 3];
    tile[0] = 1; // solid
    tile[1] = 0xFF; tile[2] = 0x00; tile[3] = 0x00;

    uint8_t compressed[64];
    size_t comp_len = zcompress(tile, sizeof tile, compressed, sizeof compressed);
    RFB_CHECK(comp_len > 0);

    rfb_rect_header rh = { .x = 0, .y = 0, .width = 2, .height = 2,
                           .encoding = RFB_ENCODING_ZRLE };
    rfb_zlib_stream *zs = rfb_zlib_create();
    rfb_rect dmg = { 0 };
    RFB_CHECK_EQ_INT(
        rfb_decode_zrle(&fb, &pf, &rh, zs, compressed, comp_len, 1u << 20, &dmg),
        RFB_OK);
    rfb_zlib_destroy(zs);

    // Same wire as Raw 4-byte LE [FF,00,00,00] must yield same RGBA.
    uint8_t raw_rgba[4];
    uint8_t raw_px[4] = { 0xFF, 0x00, 0x00, 0x00 };
    rfb_pixel_to_rgba8(&pf, raw_px, raw_rgba);
    const uint8_t *p = rfb_framebuffer_pixel_c(&fb, 0, 0);
    RFB_CHECK_EQ_UINT(p[0], raw_rgba[0]);
    RFB_CHECK_EQ_UINT(p[1], raw_rgba[1]);
    RFB_CHECK_EQ_UINT(p[2], raw_rgba[2]);
    RFB_CHECK_EQ_UINT(p[3], 0xFFu);
    // With R at shift 0, word 0xFF → red channel 255.
    RFB_CHECK_EQ_UINT(p[0], 0xFFu);
    rfb_framebuffer_destroy(&fb);
}

// full2 T4: big-endian CPIXEL omits most-significant byte → pad 0 at front.
RFB_TEST(zrle, zrle__solid_cpixel__big_endian__matches_raw_convert)
{
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_resize(&fb, 2, 2, 1u << 20);
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();
    pf.big_endian = 1;
    RFB_CHECK(rfb_pixel_format_valid(&pf));

    // BE RGB888: PIXEL [0,R,G,B]; CPIXEL omits MSB → [R,G,B].
    // Solid red R=255: CPIXEL = FF 00 00; full PIXEL = 00 FF 00 00.
    uint8_t tile[1 + 3];
    tile[0] = 1;
    tile[1] = 0xFF; tile[2] = 0x00; tile[3] = 0x00;

    uint8_t compressed[64];
    size_t comp_len = zcompress(tile, sizeof tile, compressed, sizeof compressed);
    RFB_CHECK(comp_len > 0);

    rfb_rect_header rh = { .x = 0, .y = 0, .width = 2, .height = 2,
                           .encoding = RFB_ENCODING_ZRLE };
    rfb_zlib_stream *zs = rfb_zlib_create();
    rfb_rect dmg = { 0 };
    RFB_CHECK_EQ_INT(
        rfb_decode_zrle(&fb, &pf, &rh, zs, compressed, comp_len, 1u << 20, &dmg),
        RFB_OK);
    rfb_zlib_destroy(zs);

    uint8_t raw_rgba[4];
    uint8_t raw_px[4] = { 0x00, 0xFF, 0x00, 0x00 }; // BE full PIXEL for red
    rfb_pixel_to_rgba8(&pf, raw_px, raw_rgba);
    const uint8_t *p = rfb_framebuffer_pixel_c(&fb, 0, 0);
    RFB_CHECK_EQ_UINT(p[0], raw_rgba[0]);
    RFB_CHECK_EQ_UINT(p[1], raw_rgba[1]);
    RFB_CHECK_EQ_UINT(p[2], raw_rgba[2]);
    RFB_CHECK_EQ_UINT(p[0], 0xFFu); // red
    rfb_framebuffer_destroy(&fb);
}
