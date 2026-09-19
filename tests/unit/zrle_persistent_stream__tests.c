// SPDX-License-Identifier: Apache-2.0
//
// ZRLE sequential independent-stream and post-success failure tests.
//
// The first case decodes two independent Z_FINISH streams through one
// rfb_zlib_stream wrapper. The second decodes one finished stream, then
// supplies corrupt bytes through the reset wrapper.
//
// These cases verify reset-path reuse, sampled pixel values, failure reporting,
// and preservation of a sampled value committed by an earlier call. They do not
// exercise RFC 6143 §7.7.6 persistent state across rectangles.

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

// Build one continuous deflate stream to smoke-test fixture generation.
static void build_persistent_stream(const uint8_t *rect1, size_t len1,
                                    const uint8_t *rect2, size_t len2,
                                    uint8_t *out, size_t out_cap,
                                    size_t *out_len)
{
    z_stream zs;
    memset(&zs, 0, sizeof zs);
    deflateInit(&zs, Z_DEFAULT_COMPRESSION);
    zs.next_out = out;
    zs.avail_out = (uInt)out_cap;
    zs.next_in = (Bytef *)(uintptr_t)rect1;
    zs.avail_in = (uInt)len1;
    deflate(&zs, Z_SYNC_FLUSH);
    zs.next_in = (Bytef *)(uintptr_t)rect2;
    zs.avail_in = (uInt)len2;
    deflate(&zs, Z_FINISH);
    *out_len = zs.total_out;
    deflateEnd(&zs);
}

// --- two independent finished streams through one wrapper ---------------

RFB_TEST(zrle_ps, zrle__two_rects_persistent_stream__both_decode_correctly) {
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_resize(&fb, 4, 2, 1u << 20);
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();

    // Rect 1: 2x2 solid red at (0,0).
    uint8_t tile1[4];
    tile1[0] = 1;  // solid
    tile1[1] = 0x00; tile1[2] = 0x00; tile1[3] = 0xFF;  // red CPIXEL

    // Rect 2: 2x2 solid green at (2,0).
    uint8_t tile2[4];
    tile2[0] = 1;  // solid
    tile2[1] = 0x00; tile2[2] = 0xFF; tile2[3] = 0x00;  // green CPIXEL

    // Smoke-test continuous fixture generation; these bytes are not decoded.
    uint8_t compressed[128];
    size_t comp_len = 0;
    build_persistent_stream(tile1, 4, tile2, 4, compressed, sizeof compressed, &comp_len);
    RFB_CHECK(comp_len > 0);

    // This case does not exercise RFC 6143 persistent-stream state. The
    // generated continuous stream above is not split into per-rectangle
    // payloads and is not passed to the decoder. It only checks that the
    // fixture builder can produce bytes.
    //
    // Instead, compress2 creates two independent Z_FINISH streams. The
    // decoder receives each complete stream in a separate call through one
    // rfb_zlib_stream wrapper. rfb_zlib_inflate observes Z_STREAM_END and
    // resets its inflate state before the next call.
    //
    // The legacy test identifier retains "persistent_stream"; this case checks
    // sequential decoding of independent finished streams into separate
    // framebuffer rectangles, followed by sampled pixel checks. It does not
    // cover shared dictionary or inflate state across rectangles.

    uint8_t comp1[64], comp2[64];
    uLongf len1 = sizeof comp1, len2 = sizeof comp2;
    compress2(comp1, &len1, tile1, 4, Z_DEFAULT_COMPRESSION);
    compress2(comp2, &len2, tile2, 4, Z_DEFAULT_COMPRESSION);

    rfb_zlib_stream *zs = rfb_zlib_create();

    // Decode independent finished stream 1: 2x2 at (0,0).
    rfb_rect_header rh1 = { .x = 0, .y = 0, .width = 2, .height = 2,
                            .encoding = RFB_ENCODING_ZRLE };
    rfb_rect dmg1 = { 0 };
    RFB_CHECK_EQ_INT(
        rfb_decode_zrle(&fb, &pf, &rh1, zs, comp1, len1, 1u << 20, &dmg1), RFB_OK);

    // Decode independent finished stream 2: 2x2 at (2,0).
    rfb_rect_header rh2 = { .x = 2, .y = 0, .width = 2, .height = 2,
                            .encoding = RFB_ENCODING_ZRLE };
    rfb_rect dmg2 = { 0 };
    RFB_CHECK_EQ_INT(
        rfb_decode_zrle(&fb, &pf, &rh2, zs, comp2, len2, 1u << 20, &dmg2), RFB_OK);

    rfb_zlib_destroy(zs);

    // Verify rect 1 is red.
    RFB_CHECK_EQ_UINT(rfb_framebuffer_pixel_c(&fb, 0, 0)[0], 0xFFu);
    RFB_CHECK_EQ_UINT(rfb_framebuffer_pixel_c(&fb, 0, 0)[1], 0x00u);
    // Verify rect 2 is green.
    RFB_CHECK_EQ_UINT(rfb_framebuffer_pixel_c(&fb, 2, 0)[1], 0xFFu);
    RFB_CHECK_EQ_UINT(rfb_framebuffer_pixel_c(&fb, 2, 0)[0], 0x00u);
    rfb_framebuffer_destroy(&fb);
}

// --- corrupt input after one successful finished stream -----------------

RFB_TEST(zrle_ps, zrle__corruption_after_valid_rect__second_fails_first_preserved) {
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_resize(&fb, 2, 2, 1u << 20);
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();

    // Rect 1: valid 2x2 solid red.
    uint8_t tile1[4] = { 1, 0x00, 0x00, 0xFF };
    uint8_t comp1[64];
    uLongf len1 = sizeof comp1;
    compress2(comp1, &len1, tile1, 4, Z_DEFAULT_COMPRESSION);

    rfb_zlib_stream *zs = rfb_zlib_create();

    // Decode finished stream 1; Z_STREAM_END resets the wrapper.
    rfb_rect_header rh1 = { .x = 0, .y = 0, .width = 2, .height = 2,
                            .encoding = RFB_ENCODING_ZRLE };
    rfb_rect dmg1 = { 0 };
    RFB_CHECK_EQ_INT(
        rfb_decode_zrle(&fb, &pf, &rh1, zs, comp1, len1, 1u << 20, &dmg1), RFB_OK);

    // Second call: corrupt bytes enter the reset inflater.
    static const uint8_t corrupt[8] = { 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00 };
    rfb_rect_header rh2 = { .x = 0, .y = 0, .width = 2, .height = 2,
                            .encoding = RFB_ENCODING_ZRLE };
    rfb_rect dmg2 = { 0 };
    rfb_error e2 = rfb_decode_zrle(&fb, &pf, &rh2, zs, corrupt, sizeof corrupt,
                                   1u << 20, &dmg2);
    RFB_CHECK(e2 != RFB_OK);  // should fail (corrupt zlib or protocol error)

    rfb_zlib_destroy(zs);

    // The sampled red value from the first call remains after the second fails.
    RFB_CHECK_EQ_UINT(rfb_framebuffer_pixel_c(&fb, 0, 0)[0], 0xFFu);  // still red
    rfb_framebuffer_destroy(&fb);
}
