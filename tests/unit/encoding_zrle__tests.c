// SPDX-License-Identifier: Apache-2.0
//
// G8 — ZRLE decoder tests (plan.md §G8, RFC 6143 §7.7.6).
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
#include <stdlib.h>
#include <string.h>

typedef struct zrle_fault_allocator {
    size_t calls;
    size_t fail_at;
} zrle_fault_allocator;

static void *zrle_fault_alloc(farsee_allocator *allocator, size_t size)
{
    zrle_fault_allocator *fault =
        (zrle_fault_allocator *)allocator->user;
    fault->calls++;
    return fault->calls == fault->fail_at ? NULL : malloc(size);
}

static void zrle_fault_free(farsee_allocator *allocator, void *allocation)
{
    (void)allocator;
    free(allocation);
}

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
// A solid tile contains a one-byte subencoding followed by one CPIXEL.
// For canonical 32bpp/depth-24 little-endian color, CPIXEL omits the
// unused high byte and contains the low three bytes of the pixel value.
// The entire tile payload (for the whole rectangle) is zlib-compressed.

RFB_TEST(zrle, zrle__solid_tile_2x2_red__fills_solid) {
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_resize(&fb, 2, 2, 1u << 20);
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();

    // Build the uncompressed ZRLE tile data for a 2x2 rect (one 2x2 tile).
    // Subencoding byte = 1 (solid), then the single pixel in wire format.
    // Canonical 32bpp/depth-24 LE: red = 0x00FF0000, so CPIXEL is 00 00 FF.
    uint8_t tile_data[4];
    tile_data[0] = 1;  // solid tile subencoding
    tile_data[1] = 0x00; tile_data[2] = 0x00; tile_data[3] = 0xFF;

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

// With LE BGR-swapped shifts (B at 16, R at 0), CPIXEL wire is [R,G,B]
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

// Big-endian CPIXEL omits the most-significant byte, so pad 0 at the front.
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

RFB_TEST(zrle, zero_area_rectangles__fail_before_inflate)
{
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    RFB_CHECK_EQ_INT(rfb_framebuffer_resize(&fb, 1u, 1u, 1u << 20), RFB_OK);
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();
    static const uint8_t payload[1] = {0u};
    rfb_rect damage;
    memset(&damage, 0, sizeof damage);
    rfb_zlib_stream *stream = rfb_zlib_create();
    RFB_CHECK(stream != NULL);

    rfb_rect_header width_zero = {0, 0, 0, 1, RFB_ENCODING_ZRLE};
    RFB_CHECK_EQ_INT(
        rfb_decode_zrle(&fb, &pf, &width_zero, stream, payload,
                        sizeof payload, 1u << 20, &damage),
        RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_UINT(rfb_zlib_scratch_cap(stream), 0u);
    rfb_rect_header height_zero = {0, 0, 1, 0, RFB_ENCODING_ZRLE};
    RFB_CHECK_EQ_INT(
        rfb_decode_zrle(&fb, &pf, &height_zero, stream, payload,
                        sizeof payload, 1u << 20, &damage),
        RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_UINT(rfb_zlib_scratch_cap(stream), 0u);

    rfb_zlib_destroy(stream);
    rfb_framebuffer_destroy(&fb);
}

RFB_TEST(zrle, zrle_null_operands__return_internal_error)
{
    rfb_framebuffer fb;
    memset(&fb, 0, sizeof fb);
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();
    rfb_rect_header rh = {0, 0, 1, 1, RFB_ENCODING_ZRLE};
    static const uint8_t payload[1] = {0u};
    rfb_rect damage;
    memset(&damage, 0, sizeof damage);
    rfb_zlib_stream *stream = rfb_zlib_create();
    RFB_CHECK(stream != NULL);

    RFB_CHECK_EQ_INT(
        rfb_decode_zrle(NULL, &pf, &rh, stream, payload, sizeof payload,
                        1u << 20, &damage),
        RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(
        rfb_decode_zrle(&fb, NULL, &rh, stream, payload, sizeof payload,
                        1u << 20, &damage),
        RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(
        rfb_decode_zrle(&fb, &pf, NULL, stream, payload, sizeof payload,
                        1u << 20, &damage),
        RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(
        rfb_decode_zrle(&fb, &pf, &rh, NULL, payload, sizeof payload,
                        1u << 20, &damage),
        RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(
        rfb_decode_zrle(&fb, &pf, &rh, stream, NULL, sizeof payload,
                        1u << 20, &damage),
        RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(
        rfb_decode_zrle(&fb, &pf, &rh, stream, payload, sizeof payload,
                        1u << 20, NULL),
        RFB_ERR_INTERNAL);

    rfb_zlib_destroy(stream);
}

RFB_TEST(zrle, invalid_pixel_format__fails_before_inflate)
{
    rfb_framebuffer fb;
    memset(&fb, 0, sizeof fb);
    fb.width = 1u;
    fb.height = 1u;
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();
    pf.true_color = 0u;
    rfb_rect_header rh = {0, 0, 1, 1, RFB_ENCODING_ZRLE};
    static const uint8_t payload[1] = {0u};
    rfb_rect damage;
    memset(&damage, 0, sizeof damage);
    rfb_zlib_stream *stream = rfb_zlib_create();
    RFB_CHECK(stream != NULL);
    RFB_CHECK_EQ_INT(
        rfb_decode_zrle(&fb, &pf, &rh, stream, payload, sizeof payload,
                        1u << 20, &damage),
        RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_UINT(rfb_zlib_scratch_cap(stream), 0u);
    rfb_zlib_destroy(stream);
}

RFB_TEST(zrle, depth32_solid_tile__uses_full_four_byte_pixel)
{
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    RFB_CHECK_EQ_INT(rfb_framebuffer_resize(&fb, 1u, 1u, 1u << 20), RFB_OK);
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();
    pf.depth = 32u;
    RFB_CHECK(rfb_pixel_format_valid(&pf));

    static const uint8_t tile[5] = {1u, 0u, 0u, 0xffu, 0u};
    uint8_t compressed[64];
    const size_t compressed_len =
        zcompress(tile, sizeof tile, compressed, sizeof compressed);
    RFB_CHECK(compressed_len > 0u);
    rfb_rect_header rh = {0, 0, 1, 1, RFB_ENCODING_ZRLE};
    rfb_rect damage;
    memset(&damage, 0, sizeof damage);
    rfb_zlib_stream *stream = rfb_zlib_create();
    RFB_CHECK(stream != NULL);
    RFB_CHECK_EQ_INT(
        rfb_decode_zrle(&fb, &pf, &rh, stream, compressed, compressed_len,
                        1u << 20, &damage),
        RFB_OK);
    RFB_CHECK_EQ_UINT(rfb_framebuffer_pixel_c(&fb, 0u, 0u)[0], 0xffu);
    rfb_zlib_destroy(stream);
    rfb_framebuffer_destroy(&fb);
}

RFB_TEST(zrle, scratch_allocation_failure__returns_nomem_without_damage)
{
    zrle_fault_allocator fault = {.calls = 0u, .fail_at = 2u};
    farsee_allocator allocator = {
        .alloc = zrle_fault_alloc,
        .free = zrle_fault_free,
        .user = &fault,
    };
    rfb_zlib_stream *stream = rfb_zlib_create_with_allocator(&allocator);
    RFB_CHECK(stream != NULL);

    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    RFB_CHECK_EQ_INT(rfb_framebuffer_resize(&fb, 1u, 1u, 1u << 20), RFB_OK);
    rfb_framebuffer_fill(&fb, 9u, 8u, 7u, 6u);
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();
    rfb_rect_header rh = {0, 0, 1, 1, RFB_ENCODING_ZRLE};
    static const uint8_t payload[1] = {0u};
    rfb_rect damage = {.x = 11u, .y = 12u, .width = 13u, .height = 14u};
    static const uint8_t expected_pixel[4] = {9u, 8u, 7u, 6u};
    RFB_CHECK_EQ_INT(
        rfb_decode_zrle(&fb, &pf, &rh, stream, payload, sizeof payload,
                        1u << 20, &damage),
        RFB_ERR_NOMEM);
    RFB_CHECK_MEM_EQ(rfb_framebuffer_pixel_c(&fb, 0u, 0u), expected_pixel,
                     sizeof expected_pixel);
    RFB_CHECK_EQ_UINT(damage.x, 11u);
    RFB_CHECK_EQ_UINT(damage.y, 12u);
    RFB_CHECK_EQ_UINT(damage.width, 13u);
    RFB_CHECK_EQ_UINT(damage.height, 14u);

    rfb_zlib_destroy(stream);
    rfb_framebuffer_destroy(&fb);
}

RFB_TEST(zrle, staging_allocation_failure__returns_nomem_without_damage)
{
    static const uint8_t tile[4] = {1u, 0u, 0u, 0xffu};
    uint8_t compressed[64];
    const size_t compressed_len =
        zcompress(tile, sizeof tile, compressed, sizeof compressed);
    RFB_CHECK(compressed_len > 0u);

    zrle_fault_allocator fault = {.calls = 0u, .fail_at = 0u};
    farsee_allocator allocator = {
        .alloc = zrle_fault_alloc,
        .free = zrle_fault_free,
        .user = &fault,
    };
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, &allocator);
    RFB_CHECK_EQ_INT(rfb_framebuffer_resize(&fb, 1u, 1u, 1u << 20), RFB_OK);
    rfb_framebuffer_fill(&fb, 9u, 8u, 7u, 6u);
    // The framebuffer and its pixels keep one allocator for their lifetime.
    // Fail that allocator's next request, which is the rectangle staging
    // surface allocated by rfb_decode_zrle.
    fault.fail_at = fault.calls + 1u;

    rfb_pixel_format pf = rfb_pixel_format_canonical_request();
    rfb_rect_header rh = {0, 0, 1, 1, RFB_ENCODING_ZRLE};
    rfb_rect damage = {.x = 11u, .y = 12u, .width = 13u, .height = 14u};
    static const uint8_t expected_pixel[4] = {9u, 8u, 7u, 6u};
    rfb_zlib_stream *stream = rfb_zlib_create();
    RFB_CHECK(stream != NULL);
    RFB_CHECK_EQ_INT(
        rfb_decode_zrle(&fb, &pf, &rh, stream, compressed, compressed_len,
                        1u << 20, &damage),
        RFB_ERR_NOMEM);
    RFB_CHECK_MEM_EQ(rfb_framebuffer_pixel_c(&fb, 0u, 0u), expected_pixel,
                     sizeof expected_pixel);
    RFB_CHECK_EQ_UINT(damage.x, 11u);
    RFB_CHECK_EQ_UINT(damage.y, 12u);
    RFB_CHECK_EQ_UINT(damage.width, 13u);
    RFB_CHECK_EQ_UINT(damage.height, 14u);

    rfb_zlib_destroy(stream);
    rfb_framebuffer_destroy(&fb);
}
