// SPDX-License-Identifier: Apache-2.0
//
// G4 — Raw decoder tests (plan.md §G4, RFC 6143 §7.7.1).

#include "rfb_test.h"
#include "farsee/encoding.h"
#include "farsee/framebuffer.h"
#include "farsee/pixel_format.h"
#include "farsee/allocator.h"
#include "farsee/error.h"

#include <string.h>

// --- 1x1 channel extremes -----------------------------------------------

RFB_TEST(raw, raw__1x1_red_canonical__writes_rgba_255_0_0_255) {
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_resize(&fb, 1, 1, 1u << 20);
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();
    rfb_rect_header rh = { .x = 0, .y = 0, .width = 1, .height = 1,
                           .encoding = RFB_ENCODING_RAW };
    // Canonical 32bpp LE, shifts R=16,G=8,B=0. Red = 0x00FF0000 LE.
    static const uint8_t payload[4] = { 0x00, 0x00, 0xFF, 0x00 };
    rfb_rect damage = { 0 };
    RFB_CHECK_EQ_INT(rfb_decode_raw(&fb, &pf, &rh, payload, sizeof payload, &damage), RFB_OK);
    const uint8_t *p = rfb_framebuffer_pixel_c(&fb, 0, 0);
    RFB_CHECK_EQ_UINT(p[0], 0xFFu);
    RFB_CHECK_EQ_UINT(p[1], 0x00u);
    RFB_CHECK_EQ_UINT(p[2], 0x00u);
    RFB_CHECK_EQ_UINT(p[3], 0xFFu);
    RFB_CHECK_EQ_UINT(damage.x, 0u);
    RFB_CHECK_EQ_UINT(damage.y, 0u);
    RFB_CHECK_EQ_UINT(damage.width, 1u);
    RFB_CHECK_EQ_UINT(damage.height, 1u);
    rfb_framebuffer_destroy(&fb);
}

// --- 2x2 multi-row -------------------------------------------------------

RFB_TEST(raw, raw__2x2_checkerboard__each_pixel_correct) {
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_resize(&fb, 2, 2, 1u << 20);
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();
    rfb_rect_header rh = { .x = 0, .y = 0, .width = 2, .height = 2,
                           .encoding = RFB_ENCODING_RAW };
    // 4 pixels: red, green / blue, white. Canonical LE.
    static const uint8_t payload[16] = {
        0x00,0x00,0xFF,0x00,  0x00,0xFF,0x00,0x00,
        0xFF,0x00,0x00,0x00,  0xFF,0xFF,0xFF,0x00,
    };
    rfb_rect damage = { 0 };
    RFB_CHECK_EQ_INT(rfb_decode_raw(&fb, &pf, &rh, payload, sizeof payload, &damage), RFB_OK);
    const uint8_t *p00 = rfb_framebuffer_pixel_c(&fb, 0, 0);
    const uint8_t *p10 = rfb_framebuffer_pixel_c(&fb, 1, 0);
    const uint8_t *p01 = rfb_framebuffer_pixel_c(&fb, 0, 1);
    const uint8_t *p11 = rfb_framebuffer_pixel_c(&fb, 1, 1);
    RFB_CHECK_EQ_UINT(p00[0], 0xFFu);  // red
    RFB_CHECK_EQ_UINT(p10[1], 0xFFu);  // green
    RFB_CHECK_EQ_UINT(p01[2], 0xFFu);  // blue
    RFB_CHECK_EQ_UINT(p11[3], 0xFFu);  // white alpha
    rfb_framebuffer_destroy(&fb);
}

// --- bounds rejection: rectangle outside framebuffer --------------------

RFB_TEST(raw, raw__rect_outside_framebuffer__fails_without_write) {
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_resize(&fb, 2, 2, 1u << 20);
    // Paint it a known color so we can confirm no write happened.
    rfb_framebuffer_fill(&fb, 9, 9, 9, 9);
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();
    rfb_rect_header rh = { .x = 1, .y = 0, .width = 2, .height = 1,
                           .encoding = RFB_ENCODING_RAW };
    static const uint8_t payload[8] = { 0 };
    rfb_rect damage = { 0 };
    RFB_CHECK_EQ_INT(rfb_decode_raw(&fb, &pf, &rh, payload, sizeof payload, &damage),
                     RFB_ERR_PROTOCOL);
    // No pixel was modified.
    const uint8_t *p = rfb_framebuffer_pixel_c(&fb, 0, 0);
    RFB_CHECK_EQ_UINT(p[0], 9u);
    rfb_framebuffer_destroy(&fb);
}

// --- payload length mismatch --------------------------------------------

RFB_TEST(raw, raw__payload_too_short__fails_without_write) {
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_resize(&fb, 2, 2, 1u << 20);
    rfb_framebuffer_fill(&fb, 9, 9, 9, 9);
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();
    rfb_rect_header rh = { .x = 0, .y = 0, .width = 2, .height = 2,
                           .encoding = RFB_ENCODING_RAW };
    static const uint8_t payload[4] = { 0 };  // need 16, have 4
    rfb_rect damage = { 0 };
    RFB_CHECK_EQ_INT(rfb_decode_raw(&fb, &pf, &rh, payload, sizeof payload, &damage),
                     RFB_ERR_PROTOCOL);
    const uint8_t *p = rfb_framebuffer_pixel_c(&fb, 0, 0);
    RFB_CHECK_EQ_UINT(p[0], 9u);  // untouched
    rfb_framebuffer_destroy(&fb);
}

// --- sub-rectangle placement (offset within a larger framebuffer) --------

RFB_TEST(raw, raw__1x1_at_1_1_in_3x3__writes_correct_pixel_only) {
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_resize(&fb, 3, 3, 1u << 20);
    rfb_framebuffer_fill(&fb, 0, 0, 0, 255);  // black
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();
    rfb_rect_header rh = { .x = 1, .y = 1, .width = 1, .height = 1,
                           .encoding = RFB_ENCODING_RAW };
    static const uint8_t payload[4] = { 0x00, 0x00, 0xFF, 0x00 };  // red
    rfb_rect damage = { 0 };
    RFB_CHECK_EQ_INT(rfb_decode_raw(&fb, &pf, &rh, payload, sizeof payload, &damage), RFB_OK);
    // Only (1,1) is red; everything else stays black.
    RFB_CHECK_EQ_UINT(rfb_framebuffer_pixel_c(&fb, 1, 1)[0], 0xFFu);
    RFB_CHECK_EQ_UINT(rfb_framebuffer_pixel_c(&fb, 0, 0)[0], 0x00u);
    RFB_CHECK_EQ_UINT(rfb_framebuffer_pixel_c(&fb, 2, 2)[0], 0x00u);
    RFB_CHECK_EQ_UINT(damage.x, 1u);
    RFB_CHECK_EQ_UINT(damage.y, 1u);
    rfb_framebuffer_destroy(&fb);
}

// --- odd width (row stride not a round number) ---------------------------

RFB_TEST(raw, raw__3x1_odd_width__each_pixel_correct) {
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_resize(&fb, 4, 1, 1u << 20);  // wider than the rect
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();
    rfb_rect_header rh = { .x = 0, .y = 0, .width = 3, .height = 1,
                           .encoding = RFB_ENCODING_RAW };
    static const uint8_t payload[12] = {
        0x00,0x00,0xFF,0x00, 0x00,0xFF,0x00,0x00, 0xFF,0x00,0x00,0x00,
    };
    rfb_rect damage = { 0 };
    RFB_CHECK_EQ_INT(rfb_decode_raw(&fb, &pf, &rh, payload, sizeof payload, &damage), RFB_OK);
    RFB_CHECK_EQ_UINT(rfb_framebuffer_pixel_c(&fb, 0, 0)[0], 0xFFu);  // red
    RFB_CHECK_EQ_UINT(rfb_framebuffer_pixel_c(&fb, 1, 0)[1], 0xFFu);  // green
    RFB_CHECK_EQ_UINT(rfb_framebuffer_pixel_c(&fb, 2, 0)[2], 0xFFu);  // blue
    RFB_CHECK_EQ_UINT(rfb_framebuffer_pixel_c(&fb, 3, 0)[0], 0x00u);  // untouched
    rfb_framebuffer_destroy(&fb);
}

RFB_TEST(raw, raw__zero_height__fails_without_write)
{
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    RFB_CHECK_EQ_INT(rfb_framebuffer_resize(&fb, 1u, 1u, 1u << 20), RFB_OK);
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();
    rfb_rect_header rh = {0, 0, 1, 0, RFB_ENCODING_RAW};
    static const uint8_t payload[1] = {0u};
    rfb_rect damage;
    memset(&damage, 0, sizeof damage);
    RFB_CHECK_EQ_INT(
        rfb_decode_raw(&fb, &pf, &rh, payload, sizeof payload, &damage),
        RFB_ERR_PROTOCOL);
    rfb_framebuffer_destroy(&fb);
}

RFB_TEST(raw, raw_null_operands__return_internal_error)
{
    rfb_framebuffer fb;
    memset(&fb, 0, sizeof fb);
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();
    rfb_rect_header rh = {0, 0, 1, 1, RFB_ENCODING_RAW};
    static const uint8_t payload[4] = {0u, 0u, 0u, 0u};
    rfb_rect damage;
    memset(&damage, 0, sizeof damage);

    RFB_CHECK_EQ_INT(
        rfb_decode_raw(NULL, &pf, &rh, payload, sizeof payload, &damage),
        RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(
        rfb_decode_raw(&fb, NULL, &rh, payload, sizeof payload, &damage),
        RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(
        rfb_decode_raw(&fb, &pf, NULL, payload, sizeof payload, &damage),
        RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(
        rfb_decode_raw(&fb, &pf, &rh, NULL, sizeof payload, &damage),
        RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(
        rfb_decode_raw(&fb, &pf, &rh, payload, sizeof payload, NULL),
        RFB_ERR_INTERNAL);
}
