// SPDX-License-Identifier: Apache-2.0
//
// G4 — FramebufferUpdate header + rect header + golden framebuffer tests
// (plan.md §G4, §14.7).

#include "rfb_test.h"
#include "farsee/fbupdate.h"
#include "farsee/encoding.h"
#include "farsee/framebuffer.h"
#include "farsee/pixel_format.h"
#include "farsee/bytes.h"
#include "farsee/allocator.h"
#include "farsee/error.h"

#include <string.h>

// --- header parse --------------------------------------------------------

RFB_TEST(fbupdate, fbupdate_header__type0_two_rects__parses_count) {
    static const uint8_t h[4] = { 0x00, 0x00, 0x00, 0x02 };  // type=0, pad, count=2
    rfb_reader r = rfb_reader_make(h, sizeof h);
    uint16_t n = 0;
    RFB_CHECK_EQ_INT(rfb_parse_fbupdate_header(&r, &n), RFB_OK);
    RFB_CHECK_EQ_UINT(n, 2u);
    RFB_CHECK_EQ_UINT(rfb_reader_remaining(&r), 0u);
}

RFB_TEST(fbupdate, fbupdate_header__wrong_type__fails_protocol) {
    static const uint8_t h[4] = { 0x02, 0x00, 0x00, 0x01 };  // type=2 (not FBUpdate)
    rfb_reader r = rfb_reader_make(h, sizeof h);
    uint16_t n = 999;
    RFB_CHECK_EQ_INT(rfb_parse_fbupdate_header(&r, &n), RFB_ERR_PROTOCOL);
}

RFB_TEST(fbupdate, fbupdate_header__short__fails_offset_unchanged) {
    static const uint8_t h[3] = { 0x00, 0x00, 0x00 };
    rfb_reader r = rfb_reader_make(h, sizeof h);
    uint16_t n = 0;
    RFB_CHECK_EQ_INT(rfb_parse_fbupdate_header(&r, &n), RFB_ERR_PROTOCOL);
}

// --- rect header parse ---------------------------------------------------

RFB_TEST(fbupdate, rect_header__raw_encoding__parses_fields) {
    static const uint8_t h[12] = {
        0x00, 0x01,  // x=1
        0x00, 0x02,  // y=2
        0x00, 0x03,  // w=3
        0x00, 0x04,  // h=4
        0x00, 0x00, 0x00, 0x00,  // encoding=0 (Raw)
    };
    rfb_reader r = rfb_reader_make(h, sizeof h);
    rfb_rect_header rh;
    RFB_CHECK_EQ_INT(rfb_parse_rect_header(&r, &rh), RFB_OK);
    RFB_CHECK_EQ_UINT(rh.x, 1u);
    RFB_CHECK_EQ_UINT(rh.y, 2u);
    RFB_CHECK_EQ_UINT(rh.width, 3u);
    RFB_CHECK_EQ_UINT(rh.height, 4u);
    RFB_CHECK_EQ_INT(rh.encoding, RFB_ENCODING_RAW);
}

RFB_TEST(fbupdate, rect_header__desktopsize_negative_encoding__parses) {
    // DesktopSize = -223 = 0xFFFFFF21 as u32 bits.
    static const uint8_t h[12] = {
        0,0, 0,0, 0,0x10, 0,0x10,
        0xFF, 0xFF, 0xFF, 0x21,
    };
    rfb_reader r = rfb_reader_make(h, sizeof h);
    rfb_rect_header rh;
    RFB_CHECK_EQ_INT(rfb_parse_rect_header(&r, &rh), RFB_OK);
    RFB_CHECK_EQ_INT(rh.encoding, RFB_ENCODING_DESKTOPSIZE);
    RFB_CHECK_EQ_UINT(rh.width, 16u);
}

// --- golden framebuffer: multi-rect update exact bytes ------------------
// Plan §14.7: "multiple rectangles in one update" + exact RGBA check.

RFB_TEST(fbupdate, golden__two_raw_rects__exact_final_rgba) {
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_resize(&fb, 4, 2, 1u << 20);
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();
    // Rect 1: (0,0,2,2) — all red.
    {
        rfb_rect_header rh = { 0, 0, 2, 2, RFB_ENCODING_RAW };
        static const uint8_t px[4] = { 0x00, 0x00, 0xFF, 0x00 };  // red, LE canonical
        uint8_t payload[16];
        for (int i = 0; i < 4; i++) memcpy(payload + i * 4, px, 4);
        rfb_rect dmg;
        RFB_CHECK_EQ_INT(rfb_decode_raw(&fb, &pf, &rh, payload, sizeof payload, &dmg), RFB_OK);
    }
    // Rect 2: (2,0,2,2) — all green.
    {
        rfb_rect_header rh = { 2, 0, 2, 2, RFB_ENCODING_RAW };
        static const uint8_t px[4] = { 0x00, 0xFF, 0x00, 0x00 };  // green
        uint8_t payload[16];
        for (int i = 0; i < 4; i++) memcpy(payload + i * 4, px, 4);
        rfb_rect dmg;
        RFB_CHECK_EQ_INT(rfb_decode_raw(&fb, &pf, &rh, payload, sizeof payload, &dmg), RFB_OK);
    }
    // Expected: left half red, right half green, all alpha 255.
    for (uint32_t y = 0; y < 2; y++) {
        for (uint32_t x = 0; x < 4; x++) {
            const uint8_t *p = rfb_framebuffer_pixel_c(&fb, x, y);
            if (x < 2) {
                RFB_CHECK_EQ_UINT(p[0], 0xFFu);  // red
                RFB_CHECK_EQ_UINT(p[1], 0x00u);
            } else {
                RFB_CHECK_EQ_UINT(p[1], 0xFFu);  // green
                RFB_CHECK_EQ_UINT(p[0], 0x00u);
            }
            RFB_CHECK_EQ_UINT(p[3], 0xFFu);  // alpha
        }
    }
    rfb_framebuffer_destroy(&fb);
}

// --- golden: color ramp (plan §14.7: "color ramps") ---------------------

RFB_TEST(fbupdate, golden__color_ramp_8x1__exact_scaling) {
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_resize(&fb, 8, 1, 1u << 20);
    // Use an 8bpp format with red max=7 so we can verify scaling exactly.
    // Shifts: red at 5, green at 2, blue at 0; but we only use red here.
    rfb_pixel_format pf = { .bits_per_pixel = 8, .depth = 8,
                            .big_endian = 0, .true_color = 1,
                            .red_max = 7, .green_max = 7, .blue_max = 3,
                            .red_shift = 5, .green_shift = 2, .blue_shift = 0 };
    rfb_rect_header rh = { 0, 0, 8, 1, RFB_ENCODING_RAW };
    // 8 pixels with red = 0..7. Red bits at shift 5: byte = (red << 5).
    uint8_t payload[8];
    for (int i = 0; i < 8; i++) {
        payload[i] = (uint8_t)((uint8_t)i << 5);
    }
    rfb_rect dmg;
    RFB_CHECK_EQ_INT(rfb_decode_raw(&fb, &pf, &rh, payload, sizeof payload, &dmg), RFB_OK);
    // Expected red channel: scale_channel(i, 7) = (i*255 + 3)/7.
    for (int i = 0; i < 8; i++) {
        uint8_t expect = (uint8_t)(((uint32_t)i * 255u + 3u) / 7u);
        RFB_CHECK_EQ_UINT(rfb_framebuffer_pixel_c(&fb, (uint32_t)i, 0)[0], expect);
    }
    rfb_framebuffer_destroy(&fb);
}

RFB_TEST(fbupdate, fbupdate_null_operands__return_internal_error)
{
    static const uint8_t bytes[12] = {0u};
    rfb_reader reader = rfb_reader_make(bytes, sizeof bytes);
    uint16_t count = 0u;
    rfb_rect_header rectangle;
    memset(&rectangle, 0, sizeof rectangle);

    RFB_CHECK_EQ_INT(rfb_parse_fbupdate_header(NULL, &count),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(rfb_parse_fbupdate_header(&reader, NULL),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(rfb_parse_rect_header(NULL, &rectangle),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(rfb_parse_rect_header(&reader, NULL),
                     RFB_ERR_INTERNAL);
}
