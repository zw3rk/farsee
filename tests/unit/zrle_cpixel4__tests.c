// SPDX-License-Identifier: Apache-2.0
//
// ZRLE CPIXEL size rule (RFC 6143 §7.7.5/§7.7.6).
//
// A CPIXEL is 3 bytes only when the top byte of the pixel word is always
// zero, i.e. every channel's (max << shift) fits in the least-significant
// 3 bytes. Formats whose red channel sits in the top byte use a 4-byte CPIXEL
// and decode without desynchronizing the tile stream.

#include "rfb_test.h"
#include "farsee/encoding_zrle.h"
#include "farsee/encoding.h"
#include "farsee/framebuffer.h"
#include "farsee/pixel_format.h"
#include "farsee/zlib_adapter.h"
#include "farsee/allocator.h"
#include "farsee/error.h"

#include <zlib.h>
#include <string.h>

// Valid-per-validator 32bpp depth-24 format with red in the TOP byte:
// R=8 bits @24, G=8 @16, B=8 @8. Top byte of the pixel word is NOT always
// zero → CPIXEL must be 4 bytes (RFC 6143 §7.7.5).
static rfb_pixel_format cpixel4_top_byte_format(void)
{
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();
    pf.red_shift = 24;
    pf.green_shift = 16;
    pf.blue_shift = 8;
    return pf;
}

static size_t cpixel4_compress(const uint8_t *src, size_t src_len,
                              uint8_t *dst, size_t dst_cap)
{
    uLongf out_len = dst_cap;
    if (compress2(dst, &out_len, src, src_len, Z_DEFAULT_COMPRESSION) != Z_OK) {
        return 0;
    }
    return (size_t)out_len;
}

// Single 1x1 raw tile encoded with a 4-byte CPIXEL.
RFB_TEST(zrle_cpixel4, cpixel__red_shift_24_raw_tile__uses_4_bytes)
{
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    RFB_CHECK_EQ_INT(rfb_framebuffer_resize(&fb, 1, 1, 1u << 20), RFB_OK);
    rfb_pixel_format pf = cpixel4_top_byte_format();
    RFB_CHECK(rfb_pixel_format_valid(&pf));

    // Pixel r=0x11 g=0x22 b=0x33 → word 0x11223300 → LE bytes 00 33 22 11.
    uint8_t tile[1 + 4];
    tile[0] = 0;  // raw tile
    tile[1] = 0x00; tile[2] = 0x33; tile[3] = 0x22; tile[4] = 0x11;

    uint8_t stream[64];
    size_t comp_len = cpixel4_compress(tile, sizeof tile, stream,
                                      sizeof stream);
    RFB_CHECK(comp_len > 0);

    rfb_rect_header rh = { .x = 0, .y = 0, .width = 1, .height = 1,
                           .encoding = RFB_ENCODING_ZRLE };
    rfb_zlib_stream *zs = rfb_zlib_create();
    rfb_rect dmg;
    memset(&dmg, 0, sizeof dmg);
    RFB_CHECK_EQ_INT(
        rfb_decode_zrle(&fb, &pf, &rh, zs, stream, comp_len, 1u << 20, &dmg),
        RFB_OK);
    rfb_zlib_destroy(zs);

    const uint8_t *p = rfb_framebuffer_pixel_c(&fb, 0, 0);
    RFB_CHECK_EQ_UINT(p[0], 0x11u);  // red (in the top byte on the wire)
    RFB_CHECK_EQ_UINT(p[1], 0x22u);
    RFB_CHECK_EQ_UINT(p[2], 0x33u);
    RFB_CHECK_EQ_UINT(p[3], 0xFFu);
    rfb_framebuffer_destroy(&fb);
}

// Two tiles (65x1): the second tile starts exactly at byte 1 + 64*4.
RFB_TEST(zrle_cpixel4, cpixel__red_shift_24_two_tiles__no_desync)
{
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    RFB_CHECK_EQ_INT(rfb_framebuffer_resize(&fb, 65, 1, 1u << 20), RFB_OK);
    rfb_pixel_format pf = cpixel4_top_byte_format();
    RFB_CHECK(rfb_pixel_format_valid(&pf));

    // Tile 0 (64x1): raw, 64 × 4-byte CPIXEL, all pixels r=g=b=0x77
    // (word 0x77777700 → LE bytes 00 77 77 77).
    // Tile 1 (1x1): raw, one 4-byte CPIXEL r=0xAA g=0xBB b=0xCC
    // (word 0xAABBCC00 → LE bytes 00 CC BB AA).
    uint8_t tile[1 + 64u * 4u + 1 + 4u];
    size_t n = 0;
    tile[n++] = 0;
    for (uint32_t i = 0; i < 64u; i++) {
        tile[n++] = 0x00; tile[n++] = 0x77; tile[n++] = 0x77; tile[n++] = 0x77;
    }
    tile[n++] = 0;
    tile[n++] = 0x00; tile[n++] = 0xCC; tile[n++] = 0xBB; tile[n++] = 0xAA;
    RFB_CHECK_EQ_UINT(n, sizeof tile);

    uint8_t stream[384];
    size_t comp_len = cpixel4_compress(tile, sizeof tile, stream,
                                      sizeof stream);
    RFB_CHECK(comp_len > 0);

    rfb_rect_header rh = { .x = 0, .y = 0, .width = 65, .height = 1,
                           .encoding = RFB_ENCODING_ZRLE };
    rfb_zlib_stream *zs = rfb_zlib_create();
    rfb_rect dmg;
    memset(&dmg, 0, sizeof dmg);
    RFB_CHECK_EQ_INT(
        rfb_decode_zrle(&fb, &pf, &rh, zs, stream, comp_len, 1u << 20, &dmg),
        RFB_OK);
    rfb_zlib_destroy(zs);

    for (uint32_t x = 0; x < 64u; x++) {
        const uint8_t *p = rfb_framebuffer_pixel_c(&fb, x, 0);
        RFB_CHECK_EQ_UINT(p[0], 0x77u);
        RFB_CHECK_EQ_UINT(p[1], 0x77u);
        RFB_CHECK_EQ_UINT(p[2], 0x77u);
    }
    const uint8_t *last = rfb_framebuffer_pixel_c(&fb, 64, 0);
    RFB_CHECK_EQ_UINT(last[0], 0xAAu);
    RFB_CHECK_EQ_UINT(last[1], 0xBBu);
    RFB_CHECK_EQ_UINT(last[2], 0xCCu);
    RFB_CHECK_EQ_UINT(last[3], 0xFFu);
    rfb_framebuffer_destroy(&fb);
}

// A solid tile in the same format: the single CPIXEL must be 4 bytes too.
RFB_TEST(zrle_cpixel4, cpixel__red_shift_24_solid_tile__uses_4_bytes)
{
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    RFB_CHECK_EQ_INT(rfb_framebuffer_resize(&fb, 2, 2, 1u << 20), RFB_OK);
    rfb_pixel_format pf = cpixel4_top_byte_format();
    RFB_CHECK(rfb_pixel_format_valid(&pf));

    // Solid tile: subenc 1 + one 4-byte CPIXEL r=0x12 g=0x34 b=0x56
    // (word 0x12345600 → LE bytes 00 56 34 12).
    uint8_t tile[1 + 4];
    tile[0] = 1;
    tile[1] = 0x00; tile[2] = 0x56; tile[3] = 0x34; tile[4] = 0x12;

    uint8_t stream[64];
    size_t comp_len = cpixel4_compress(tile, sizeof tile, stream,
                                      sizeof stream);
    RFB_CHECK(comp_len > 0);

    rfb_rect_header rh = { .x = 0, .y = 0, .width = 2, .height = 2,
                           .encoding = RFB_ENCODING_ZRLE };
    rfb_zlib_stream *zs = rfb_zlib_create();
    rfb_rect dmg;
    memset(&dmg, 0, sizeof dmg);
    RFB_CHECK_EQ_INT(
        rfb_decode_zrle(&fb, &pf, &rh, zs, stream, comp_len, 1u << 20, &dmg),
        RFB_OK);
    rfb_zlib_destroy(zs);

    for (uint32_t y = 0; y < 2; y++) {
        for (uint32_t x = 0; x < 2; x++) {
            const uint8_t *p = rfb_framebuffer_pixel_c(&fb, x, y);
            RFB_CHECK_EQ_UINT(p[0], 0x12u);
            RFB_CHECK_EQ_UINT(p[1], 0x34u);
            RFB_CHECK_EQ_UINT(p[2], 0x56u);
            RFB_CHECK_EQ_UINT(p[3], 0xFFu);
        }
    }
    rfb_framebuffer_destroy(&fb);
}

// The canonical low-three-bytes format keeps its 3-byte CPIXEL.
RFB_TEST(zrle_cpixel4, cpixel__canonical_format__uses_3_bytes)
{
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    RFB_CHECK_EQ_INT(rfb_framebuffer_resize(&fb, 1, 1, 1u << 20), RFB_OK);
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();

    // A raw tile uses a 3-byte CPIXEL red (B,G,R = 00 00 FF). This fixture
    // must decode correctly.
    uint8_t tile[1 + 3];
    tile[0] = 0;
    tile[1] = 0x00; tile[2] = 0x00; tile[3] = 0xFF;

    uint8_t stream[64];
    size_t comp_len = cpixel4_compress(tile, sizeof tile, stream,
                                      sizeof stream);
    RFB_CHECK(comp_len > 0);

    rfb_rect_header rh = { .x = 0, .y = 0, .width = 1, .height = 1,
                           .encoding = RFB_ENCODING_ZRLE };
    rfb_zlib_stream *zs = rfb_zlib_create();
    rfb_rect dmg;
    memset(&dmg, 0, sizeof dmg);
    RFB_CHECK_EQ_INT(
        rfb_decode_zrle(&fb, &pf, &rh, zs, stream, comp_len, 1u << 20, &dmg),
        RFB_OK);
    rfb_zlib_destroy(zs);

    const uint8_t *p = rfb_framebuffer_pixel_c(&fb, 0, 0);
    RFB_CHECK_EQ_UINT(p[0], 0xFFu);
    RFB_CHECK_EQ_UINT(p[1], 0x00u);
    RFB_CHECK_EQ_UINT(p[2], 0x00u);
    RFB_CHECK_EQ_UINT(p[3], 0xFFu);
    rfb_framebuffer_destroy(&fb);
}
