// SPDX-License-Identifier: Apache-2.0
//
// ZRLE rectangle-level atomicity regressions.
//
// encoding.h G4: "No damage is emitted for a partially-decoded rectangle."
// On any tile failure, the framebuffer remains byte-identical to its
// pre-decode state and no damage is reported.

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

static size_t zrle_atomic_compress(const uint8_t *src, size_t src_len,
                                uint8_t *dst, size_t dst_cap)
{
    uLongf out_len = dst_cap;
    if (compress2(dst, &out_len, src, src_len, Z_DEFAULT_COMPRESSION) != Z_OK) {
        return 0;
    }
    return (size_t)out_len;
}

// Sentinel fill that no test pixel equals.
static const uint8_t zrle_atomic_sentinel[4] = { 9u, 8u, 7u, 6u };

static bool zrle_atomic_fb_all_sentinel(const rfb_framebuffer *fb)
{
    for (uint32_t y = 0; y < fb->height; y++) {
        for (uint32_t x = 0; x < fb->width; x++) {
            const uint8_t *p = rfb_framebuffer_pixel_c(fb, x, y);
            if (memcmp(p, zrle_atomic_sentinel, 4u) != 0) {
                return false;
            }
        }
    }
    return true;
}

// A rectangle owns exactly its decompressed tile stream. Accepting a
// valid tile prefix plus trailing bytes would silently discard bytes inside
// the persistent ZRLE stream and hide a malformed peer message.
RFB_TEST(zrle_rect_atomicity, zrle__exact_tile_stream__commits)
{
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    RFB_CHECK_EQ_INT(rfb_framebuffer_resize(&fb, 1, 1, 1u << 20), RFB_OK);
    rfb_framebuffer_fill(&fb, zrle_atomic_sentinel[0], zrle_atomic_sentinel[1],
                         zrle_atomic_sentinel[2], zrle_atomic_sentinel[3]);
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();
    const uint8_t tile[] = { 1u, 0u, 0u, 0xFFu };
    uint8_t stream[64];
    size_t stream_len = zrle_atomic_compress(tile, sizeof tile, stream,
                                          sizeof stream);
    RFB_CHECK(stream_len > 0u);

    rfb_rect_header rh = { .x = 0, .y = 0, .width = 1, .height = 1,
                           .encoding = RFB_ENCODING_ZRLE };
    rfb_zlib_stream *zs = rfb_zlib_create();
    rfb_rect dmg = { 0 };
    RFB_CHECK_EQ_INT(rfb_decode_zrle(&fb, &pf, &rh, zs, stream, stream_len,
                                     1u << 20, &dmg), RFB_OK);
    RFB_CHECK_EQ_UINT(rfb_framebuffer_pixel_c(&fb, 0, 0)[0], 0xFFu);
    RFB_CHECK_EQ_UINT(dmg.width, 1u);
    RFB_CHECK_EQ_UINT(dmg.height, 1u);
    rfb_zlib_destroy(zs);
    rfb_framebuffer_destroy(&fb);
}

RFB_TEST(zrle_rect_atomicity, zrle__trailing_decompressed_byte__rejects_atomically)
{
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    RFB_CHECK_EQ_INT(rfb_framebuffer_resize(&fb, 1, 1, 1u << 20), RFB_OK);
    rfb_framebuffer_fill(&fb, zrle_atomic_sentinel[0], zrle_atomic_sentinel[1],
                         zrle_atomic_sentinel[2], zrle_atomic_sentinel[3]);
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();
    const uint8_t tile_with_tail[] = { 1u, 0u, 0u, 0xFFu, 0xA5u };
    uint8_t stream[64];
    size_t stream_len = zrle_atomic_compress(tile_with_tail,
                                          sizeof tile_with_tail,
                                          stream, sizeof stream);
    RFB_CHECK(stream_len > 0u);

    rfb_rect_header rh = { .x = 0, .y = 0, .width = 1, .height = 1,
                           .encoding = RFB_ENCODING_ZRLE };
    rfb_zlib_stream *zs = rfb_zlib_create();
    const rfb_rect damage_before = {
        .x = 7u, .y = 8u, .width = 9u, .height = 10u,
    };
    rfb_rect dmg = damage_before;
    RFB_CHECK_EQ_INT(rfb_decode_zrle(&fb, &pf, &rh, zs, stream, stream_len,
                                     1u << 20, &dmg), RFB_ERR_PROTOCOL);
    RFB_CHECK(zrle_atomic_fb_all_sentinel(&fb));
    RFB_CHECK_MEM_EQ(&dmg, &damage_before, sizeof dmg);
    rfb_zlib_destroy(zs);
    rfb_framebuffer_destroy(&fb);
}

// Atomicity core: a 128x1 rect has two tiles. Tile 0 is valid solid red; the
// final tile is truncated (raw subencoding with zero pixel bytes). The
// decode must fail AND leave the framebuffer untouched with no damage.
RFB_TEST(zrle_rect_atomicity, zrle__last_tile_truncated__framebuffer_unchanged)
{
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    RFB_CHECK_EQ_INT(rfb_framebuffer_resize(&fb, 128, 1, 1u << 20), RFB_OK);
    rfb_framebuffer_fill(&fb, zrle_atomic_sentinel[0], zrle_atomic_sentinel[1],
                         zrle_atomic_sentinel[2], zrle_atomic_sentinel[3]);
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();

    // Tile 0 (64x1): solid red — subencoding 1 + 3-byte CPIXEL red.
    // Tile 1 (64x1): raw subencoding byte with no pixel data → truncated.
    uint8_t all[5 + 1];
    all[0] = 1;                                // solid
    all[1] = 0x00; all[2] = 0x00;              // red CPIXEL (B,G,R)
    all[3] = 0xFF; all[4] = 0x00;
    all[5] = 0;                                // truncated final tile

    uint8_t stream[64];
    size_t comp_len = zrle_atomic_compress(all, sizeof all, stream,
                                        sizeof stream);
    RFB_CHECK(comp_len > 0);

    rfb_rect_header rh = { .x = 0, .y = 0, .width = 128, .height = 1,
                           .encoding = RFB_ENCODING_ZRLE };
    rfb_zlib_stream *zs = rfb_zlib_create();
    rfb_rect dmg;
    memset(&dmg, 0, sizeof dmg);
    RFB_CHECK_EQ_INT(
        rfb_decode_zrle(&fb, &pf, &rh, zs, stream, comp_len, 1u << 20, &dmg),
        RFB_ERR_PROTOCOL);
    rfb_zlib_destroy(zs);

    // Rect-level contract: nothing written, nothing reported damaged.
    RFB_CHECK(zrle_atomic_fb_all_sentinel(&fb));
    RFB_CHECK_EQ_UINT(dmg.width, 0u);
    RFB_CHECK_EQ_UINT(dmg.height, 0u);
    rfb_framebuffer_destroy(&fb);
}

// Failure in a LATER tile-row band: a 64x65 rect has one full 64x64 tile
// plus a 64x1 edge tile below it. The full tile decodes; the edge tile is
// a solid subencoding with a truncated CPIXEL. The whole rect must roll
// back to untouched.
RFB_TEST(zrle_rect_atomicity, zrle__last_tile_solid_truncated__framebuffer_unchanged)
{
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    RFB_CHECK_EQ_INT(rfb_framebuffer_resize(&fb, 64, 65, 1u << 20), RFB_OK);
    rfb_framebuffer_fill(&fb, zrle_atomic_sentinel[0], zrle_atomic_sentinel[1],
                         zrle_atomic_sentinel[2], zrle_atomic_sentinel[3]);
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();

    // Tile 0 (64x64): solid red. Tile 1 (64x1): solid subencoding byte
    // with no CPIXEL bytes → truncated.
    uint8_t all[5];
    all[0] = 1; all[1] = 0x00; all[2] = 0x00;  // solid red CPIXEL
    all[3] = 0xFF; all[4] = 0x00;
    uint8_t extra[1];
    extra[0] = 1;  // truncated solid tile header only

    uint8_t stream[64];
    uint8_t joined[6];
    memcpy(joined, all, sizeof all);
    memcpy(joined + sizeof all, extra, sizeof extra);
    size_t comp_len = zrle_atomic_compress(joined, sizeof joined, stream,
                                        sizeof stream);
    RFB_CHECK(comp_len > 0);

    rfb_rect_header rh = { .x = 0, .y = 0, .width = 64, .height = 65,
                           .encoding = RFB_ENCODING_ZRLE };
    rfb_zlib_stream *zs = rfb_zlib_create();
    rfb_rect dmg;
    memset(&dmg, 0, sizeof dmg);
    RFB_CHECK_EQ_INT(
        rfb_decode_zrle(&fb, &pf, &rh, zs, stream, comp_len, 1u << 20, &dmg),
        RFB_ERR_PROTOCOL);
    rfb_zlib_destroy(zs);

    RFB_CHECK(zrle_atomic_fb_all_sentinel(&fb));
    RFB_CHECK_EQ_UINT(dmg.width, 0u);
    RFB_CHECK_EQ_UINT(dmg.height, 0u);
    rfb_framebuffer_destroy(&fb);
}

// Positive control: a fully valid multi-tile rect still commits everything
// and reports full-rect damage through the staging path.
RFB_TEST(zrle_rect_atomicity, zrle__two_valid_tiles__commits_and_damages_full_rect)
{
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    RFB_CHECK_EQ_INT(rfb_framebuffer_resize(&fb, 128, 1, 1u << 20), RFB_OK);
    rfb_framebuffer_fill(&fb, zrle_atomic_sentinel[0], zrle_atomic_sentinel[1],
                         zrle_atomic_sentinel[2], zrle_atomic_sentinel[3]);
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();

    uint8_t all[8];
    all[0] = 1; all[1] = 0x00; all[2] = 0x00; all[3] = 0xFF;  // tile 0 red
    all[4] = 1; all[5] = 0x00; all[6] = 0x00; all[7] = 0xFF;  // tile 1 red
    uint8_t stream[64];
    size_t comp_len = zrle_atomic_compress(all, sizeof all, stream,
                                        sizeof stream);
    RFB_CHECK(comp_len > 0);

    rfb_rect_header rh = { .x = 0, .y = 0, .width = 128, .height = 1,
                           .encoding = RFB_ENCODING_ZRLE };
    rfb_zlib_stream *zs = rfb_zlib_create();
    rfb_rect dmg;
    memset(&dmg, 0, sizeof dmg);
    RFB_CHECK_EQ_INT(
        rfb_decode_zrle(&fb, &pf, &rh, zs, stream, comp_len, 1u << 20, &dmg),
        RFB_OK);
    rfb_zlib_destroy(zs);

    for (uint32_t x = 0; x < 128; x++) {
        const uint8_t *p = rfb_framebuffer_pixel_c(&fb, x, 0);
        RFB_CHECK_EQ_UINT(p[0], 0xFFu);
        RFB_CHECK_EQ_UINT(p[1], 0x00u);
        RFB_CHECK_EQ_UINT(p[2], 0x00u);
        RFB_CHECK_EQ_UINT(p[3], 0xFFu);
    }
    RFB_CHECK_EQ_UINT(dmg.width, 128u);
    RFB_CHECK_EQ_UINT(dmg.height, 1u);
    rfb_framebuffer_destroy(&fb);
}
