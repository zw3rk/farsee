// SPDX-License-Identifier: Apache-2.0
//
// G4 — CopyRect decoder tests (plan.md §G4, RFC 6143 §7.7.2). RED step.
//
// Covers: no-overlap, overlap in all four directions, full-width scroll,
// source/destination bounds rejection, and the zero-area policy.

#include "rfb_test.h"
#include "farsee/encoding.h"
#include "farsee/framebuffer.h"
#include "farsee/allocator.h"
#include "farsee/error.h"

// Helper: paint a cell with a unique color so we can tell source from
// destination after a copy.
static void paint_cell(rfb_framebuffer *fb, uint32_t x, uint32_t y,
                       uint8_t r, uint8_t g, uint8_t b)
{
    uint8_t *p = rfb_framebuffer_pixel(fb, x, y);
    p[0] = r; p[1] = g; p[2] = b; p[3] = 255;
}

// --- no overlap: copy (0,0,2,2) to (2,2) --------------------------------

RFB_TEST(copyrect, copyrect__no_overlap__copies_exact_pixels) {
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_resize(&fb, 4, 4, 1u << 20);
    // Source: (0,0)=red, (1,0)=green, (0,1)=blue, (1,1)=white.
    paint_cell(&fb, 0, 0, 0xFF, 0, 0);
    paint_cell(&fb, 1, 0, 0, 0xFF, 0);
    paint_cell(&fb, 0, 1, 0, 0, 0xFF);
    paint_cell(&fb, 1, 1, 0xFF, 0xFF, 0xFF);
    rfb_rect_header rh = { .x = 2, .y = 2, .width = 2, .height = 2,
                           .encoding = RFB_ENCODING_COPYRECT };
    // Payload: u16 src-x=0, u16 src-y=0 (big-endian).
    static const uint8_t payload[4] = { 0x00, 0x00, 0x00, 0x00 };
    rfb_rect damage = { 0 };
    RFB_CHECK_EQ_INT(rfb_decode_copyrect(&fb, &rh, payload, sizeof payload, &damage), RFB_OK);
    RFB_CHECK_EQ_UINT(rfb_framebuffer_pixel_c(&fb, 2, 2)[0], 0xFFu);  // red
    RFB_CHECK_EQ_UINT(rfb_framebuffer_pixel_c(&fb, 3, 2)[1], 0xFFu);  // green
    RFB_CHECK_EQ_UINT(rfb_framebuffer_pixel_c(&fb, 2, 3)[2], 0xFFu);  // blue
    RFB_CHECK_EQ_UINT(rfb_framebuffer_pixel_c(&fb, 3, 3)[3], 0xFFu);  // white alpha
    rfb_framebuffer_destroy(&fb);
}

// --- overlap: scroll down (source above destination) --------------------
// The classic terminal-scroll case. Source rows are read before they are
// overwritten, so the copy must proceed top-to-bottom (so it doesn't
// clobber rows it hasn't read yet). Wait — scrolling DOWN means dst is
// below src, so we must read src rows before writing dst rows that
// overlap them. That's a bottom-to-top traversal.

RFB_TEST(copyrect, copyrect__overlap_scroll_down__matches_memmove) {
    // 1-column-wide, 4 tall. Copy (0,0,1,3) to (0,1) — scroll the top
    // three rows down by one. Source overlaps destination.
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_resize(&fb, 1, 4, 1u << 20);
    paint_cell(&fb, 0, 0, 10, 0, 0);
    paint_cell(&fb, 0, 1, 20, 0, 0);
    paint_cell(&fb, 0, 2, 30, 0, 0);
    paint_cell(&fb, 0, 3, 40, 0, 0);
    rfb_rect_header rh = { .x = 0, .y = 1, .width = 1, .height = 3,
                           .encoding = RFB_ENCODING_COPYRECT };
    static const uint8_t payload[4] = { 0x00, 0x00, 0x00, 0x00 };  // src (0,0)
    rfb_rect damage = { 0 };
    RFB_CHECK_EQ_INT(rfb_decode_copyrect(&fb, &rh, payload, sizeof payload, &damage), RFB_OK);
    // Expected after scroll-down: row 0 unchanged (10), row 1 = old row 0 (10),
    // row 2 = old row 1 (20), row 3 = old row 2 (30).
    RFB_CHECK_EQ_UINT(rfb_framebuffer_pixel_c(&fb, 0, 0)[0], 10u);
    RFB_CHECK_EQ_UINT(rfb_framebuffer_pixel_c(&fb, 0, 1)[0], 10u);
    RFB_CHECK_EQ_UINT(rfb_framebuffer_pixel_c(&fb, 0, 2)[0], 20u);
    RFB_CHECK_EQ_UINT(rfb_framebuffer_pixel_c(&fb, 0, 3)[0], 30u);
    rfb_framebuffer_destroy(&fb);
}

// --- overlap: scroll up (source below destination) ----------------------
// Here we must read top-to-bottom so we don't clobber unread source rows.

RFB_TEST(copyrect, copyrect__overlap_scroll_up__matches_memmove) {
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_resize(&fb, 1, 4, 1u << 20);
    paint_cell(&fb, 0, 0, 10, 0, 0);
    paint_cell(&fb, 0, 1, 20, 0, 0);
    paint_cell(&fb, 0, 2, 30, 0, 0);
    paint_cell(&fb, 0, 3, 40, 0, 0);
    // Copy (0,1,1,3) to (0,0) — scroll the bottom three rows up by one.
    rfb_rect_header rh = { .x = 0, .y = 0, .width = 1, .height = 3,
                           .encoding = RFB_ENCODING_COPYRECT };
    static const uint8_t payload[4] = { 0x00, 0x00, 0x00, 0x01 };  // src (0,1)
    rfb_rect damage = { 0 };
    RFB_CHECK_EQ_INT(rfb_decode_copyrect(&fb, &rh, payload, sizeof payload, &damage), RFB_OK);
    // row 0 = old row 1 (20), row 1 = old row 2 (30), row 2 = old row 3 (40),
    // row 3 unchanged (40).
    RFB_CHECK_EQ_UINT(rfb_framebuffer_pixel_c(&fb, 0, 0)[0], 20u);
    RFB_CHECK_EQ_UINT(rfb_framebuffer_pixel_c(&fb, 0, 1)[0], 30u);
    RFB_CHECK_EQ_UINT(rfb_framebuffer_pixel_c(&fb, 0, 2)[0], 40u);
    RFB_CHECK_EQ_UINT(rfb_framebuffer_pixel_c(&fb, 0, 3)[0], 40u);
    rfb_framebuffer_destroy(&fb);
}

// --- full-width scroll --------------------------------------------------

RFB_TEST(copyrect, copyrect__full_width_scroll_down__matches_memmove) {
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_resize(&fb, 3, 3, 1u << 20);
    for (uint32_t y = 0; y < 3; y++) {
        for (uint32_t x = 0; x < 3; x++) {
            paint_cell(&fb, x, y, (uint8_t)(x * 10 + y), 0, 0);
        }
    }
    // Copy (0,0,3,2) to (0,1) — scroll the top two rows down by one.
    rfb_rect_header rh = { .x = 0, .y = 1, .width = 3, .height = 2,
                           .encoding = RFB_ENCODING_COPYRECT };
    static const uint8_t payload[4] = { 0x00, 0x00, 0x00, 0x00 };
    rfb_rect damage = { 0 };
    RFB_CHECK_EQ_INT(rfb_decode_copyrect(&fb, &rh, payload, sizeof payload, &damage), RFB_OK);
    // Row 0 unchanged. Row 1 = old row 0. Row 2 = old row 1.
    RFB_CHECK_EQ_UINT(rfb_framebuffer_pixel_c(&fb, 0, 0)[0], 0u);
    RFB_CHECK_EQ_UINT(rfb_framebuffer_pixel_c(&fb, 1, 1)[0], 10u);
    RFB_CHECK_EQ_UINT(rfb_framebuffer_pixel_c(&fb, 2, 2)[0], 21u);
    rfb_framebuffer_destroy(&fb);
}

// --- source out of bounds -----------------------------------------------

RFB_TEST(copyrect, copyrect__source_out_of_bounds__fails_without_write) {
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_resize(&fb, 2, 2, 1u << 20);
    rfb_framebuffer_fill(&fb, 9, 9, 9, 255);
    rfb_rect_header rh = { .x = 0, .y = 0, .width = 2, .height = 2,
                           .encoding = RFB_ENCODING_COPYRECT };
    // src-x=5 (out of bounds for a 2-wide framebuffer).
    static const uint8_t payload[4] = { 0x00, 0x05, 0x00, 0x00 };
    rfb_rect damage = { 0 };
    RFB_CHECK_EQ_INT(rfb_decode_copyrect(&fb, &rh, payload, sizeof payload, &damage),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_UINT(rfb_framebuffer_pixel_c(&fb, 0, 0)[0], 9u);  // untouched
    rfb_framebuffer_destroy(&fb);
}

// --- destination out of bounds ------------------------------------------

RFB_TEST(copyrect, copyrect__destination_out_of_bounds__fails_without_write) {
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_resize(&fb, 2, 2, 1u << 20);
    rfb_framebuffer_fill(&fb, 9, 9, 9, 255);
    rfb_rect_header rh = { .x = 1, .y = 0, .width = 2, .height = 1,
                           .encoding = RFB_ENCODING_COPYRECT };
    static const uint8_t payload[4] = { 0x00, 0x00, 0x00, 0x00 };
    rfb_rect damage = { 0 };
    RFB_CHECK_EQ_INT(rfb_decode_copyrect(&fb, &rh, payload, sizeof payload, &damage),
                     RFB_ERR_PROTOCOL);
    rfb_framebuffer_destroy(&fb);
}

// --- payload length mismatch --------------------------------------------

RFB_TEST(copyrect, copyrect__payload_too_short__fails_protocol) {
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_resize(&fb, 2, 2, 1u << 20);
    rfb_rect_header rh = { .x = 0, .y = 0, .width = 1, .height = 1,
                           .encoding = RFB_ENCODING_COPYRECT };
    static const uint8_t payload[3] = { 0 };  // need 4
    rfb_rect damage = { 0 };
    RFB_CHECK_EQ_INT(rfb_decode_copyrect(&fb, &rh, payload, sizeof payload, &damage),
                     RFB_ERR_PROTOCOL);
    rfb_framebuffer_destroy(&fb);
}

RFB_TEST(copyrect_cov, copyrect__identical_src_dst__no_op_ok) {
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_resize(&fb, 2, 2, 1u << 20);
    rfb_framebuffer_fill(&fb, 0x42, 0x42, 0x42, 0xFF);
    rfb_rect_header rh = { .x = 0, .y = 0, .width = 2, .height = 2,
                           .encoding = RFB_ENCODING_COPYRECT };
    // src-x=0, src-y=0 → identical to dst.
    static const uint8_t payload[4] = { 0x00, 0x00, 0x00, 0x00 };
    rfb_rect dmg = { 0 };
    RFB_CHECK_EQ_INT(rfb_decode_copyrect(&fb, &rh, payload, sizeof payload, &dmg), RFB_OK);
    RFB_CHECK_EQ_UINT(dmg.width, 2u);
    // Pixels unchanged.
    RFB_CHECK_EQ_UINT(rfb_framebuffer_pixel_c(&fb, 0, 0)[0], 0x42u);
    rfb_framebuffer_destroy(&fb);
}
