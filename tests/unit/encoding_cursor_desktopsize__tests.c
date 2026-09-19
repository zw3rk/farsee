// SPDX-License-Identifier: Apache-2.0
//
// G6 — Cursor and DesktopSize pseudo-encoding tests (plan.md §G6, RFC 6143
// §7.7.9, §7.7.10).

#include "rfb_test.h"
#include "farsee/encoding.h"
#include "farsee/framebuffer.h"
#include "farsee/pixel_format.h"
#include "farsee/allocator.h"
#include "farsee/error.h"

#include <string.h>

// --- Cursor: 2x2 with mask, canonical pixel format -----------------------

RFB_TEST(cursor, cursor__2x2_with_mask__rgba_alpha_from_mask) {
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();
    rfb_rect_header rh = { .x = 0, .y = 0, .width = 2, .height = 2,
                           .encoding = RFB_ENCODING_CURSOR };
    // Pixel payload: 4 pixels (2x2), canonical 32bpp LE. All red.
    static const uint8_t pixels[16] = {
        0x00,0x00,0xFF,0x00,  0x00,0x00,0xFF,0x00,
        0x00,0x00,0xFF,0x00,  0x00,0x00,0xFF,0x00,
    };
    // Mask: one padded byte per row. Each row has its left pixel visible
    // (bit 7) and right pixel transparent (bit 6), so both bytes are 0x80.
    static const uint8_t mask[2] = { 0x80, 0x80 };
    uint8_t payload[18];
    memcpy(payload, pixels, 16);
    memcpy(payload + 16, mask, 2);

    rfb_cursor c = { 0 };
    RFB_CHECK_EQ_INT(
        rfb_decode_cursor(&c, &pf, &rh, payload, sizeof payload,
                          rfb_default_allocator()), RFB_OK);
    RFB_CHECK_EQ_UINT(c.width, 2u);
    RFB_CHECK_EQ_UINT(c.height, 2u);
    RFB_CHECK(c.rgba != NULL);
    RFB_CHECK(c.valid);
    // Top-left (masked on): red, alpha=255.
    RFB_CHECK_EQ_UINT(c.rgba[0], 0xFFu);
    RFB_CHECK_EQ_UINT(c.rgba[3], 0xFFu);
    // Top-right (masked off): alpha=0.
    RFB_CHECK_EQ_UINT(c.rgba[7], 0x00u);
    // Bottom-left (masked on): alpha=255.
    RFB_CHECK_EQ_UINT(c.rgba[8 + 3], 0xFFu);
    // Bottom-right (masked off): alpha=0.
    RFB_CHECK_EQ_UINT(c.rgba[8 + 7], 0x00u);
    rfb_cursor_destroy(&c, rfb_default_allocator());
}

// --- Cursor: 1x1 minimum ------------------------------------------------

RFB_TEST(cursor, cursor__1x1_minimum__decodes) {
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();
    rfb_rect_header rh = { .x = 0, .y = 0, .width = 1, .height = 1,
                           .encoding = RFB_ENCODING_CURSOR };
    static const uint8_t pixels[4] = { 0x00,0xFF,0x00,0x00 }; // green
    static const uint8_t mask[1] = { 0x80 };  // pixel visible
    uint8_t payload[5];
    memcpy(payload, pixels, 4);
    memcpy(payload + 4, mask, 1);
    rfb_cursor c = { 0 };
    RFB_CHECK_EQ_INT(
        rfb_decode_cursor(&c, &pf, &rh, payload, sizeof payload,
                          rfb_default_allocator()), RFB_OK);
    RFB_CHECK_EQ_UINT(c.width, 1u);
    RFB_CHECK_EQ_UINT(c.rgba[1], 0xFFu);  // green
    RFB_CHECK_EQ_UINT(c.rgba[3], 0xFFu);  // alpha
    rfb_cursor_destroy(&c, rfb_default_allocator());
}

// --- Cursor: payload too short → fail ------------------------------------

RFB_TEST(cursor, cursor__truncated_payload__fails_protocol) {
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();
    rfb_rect_header rh = { .x = 0, .y = 0, .width = 2, .height = 2,
                           .encoding = RFB_ENCODING_CURSOR };
    static const uint8_t too_short[10] = { 0 };  // need 18
    rfb_cursor c = { 0 };
    RFB_CHECK_EQ_INT(
        rfb_decode_cursor(&c, &pf, &rh, too_short, sizeof too_short,
                          rfb_default_allocator()),
        RFB_ERR_PROTOCOL);
    RFB_CHECK(!c.valid);
}

// --- Cursor: zero-area → fail --------------------------------------------

RFB_TEST(cursor, cursor__zero_width__fails_protocol) {
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();
    rfb_rect_header rh = { .x = 0, .y = 0, .width = 0, .height = 2,
                           .encoding = RFB_ENCODING_CURSOR };
    rfb_cursor c = { 0 };
    RFB_CHECK_EQ_INT(
        rfb_decode_cursor(&c, &pf, &rh, NULL, 0,
                          rfb_default_allocator()),
        RFB_ERR_PROTOCOL);
}

// --- DesktopSize: resize to 4x3 ------------------------------------------

RFB_TEST(desktopsize, desktopsize__resize_4x3__succeeds_generation_bumps) {
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_resize(&fb, 2, 2, 1u << 20);
    uint64_t gen_before = fb.generation;
    rfb_rect_header rh = { .x = 0, .y = 0, .width = 4, .height = 3,
                           .encoding = RFB_ENCODING_DESKTOPSIZE };
    rfb_rect dmg = { 0 };
    RFB_CHECK_EQ_INT(rfb_decode_desktopsize(&fb, &rh, 1u << 20, &dmg), RFB_OK);
    RFB_CHECK_EQ_UINT(fb.width, 4u);
    RFB_CHECK_EQ_UINT(fb.height, 3u);
    RFB_CHECK(fb.generation > gen_before);
    RFB_CHECK_EQ_UINT(dmg.width, 4u);
    RFB_CHECK_EQ_UINT(dmg.height, 3u);
    rfb_framebuffer_destroy(&fb);
}

// --- DesktopSize: over byte limit → fail, old preserved -----------------

RFB_TEST(desktopsize, desktopsize__over_limit__fails_preserves_old) {
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_resize(&fb, 2, 2, 1u << 20);
    rfb_rect_header rh = { .x = 0, .y = 0, .width = 1000, .height = 1000,
                           .encoding = RFB_ENCODING_DESKTOPSIZE };
    rfb_rect dmg = { 0 };
    RFB_CHECK_EQ_INT(rfb_decode_desktopsize(&fb, &rh, 100, &dmg), RFB_ERR_LIMIT);
    RFB_CHECK_EQ_UINT(fb.width, 2u);   // old preserved
    RFB_CHECK_EQ_UINT(fb.height, 2u);
    rfb_framebuffer_destroy(&fb);
}

// --- DesktopSize: zero dimension → fail ----------------------------------

RFB_TEST(desktopsize, desktopsize__zero_width__fails_protocol) {
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_rect_header rh = { .x = 0, .y = 0, .width = 0, .height = 3,
                           .encoding = RFB_ENCODING_DESKTOPSIZE };
    rfb_rect dmg = { 0 };
    RFB_CHECK_EQ_INT(rfb_decode_desktopsize(&fb, &rh, 1u << 20, &dmg), RFB_ERR_PROTOCOL);
    rfb_framebuffer_destroy(&fb);
}
