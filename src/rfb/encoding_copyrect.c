// SPDX-License-Identifier: Apache-2.0
//
// farsee — CopyRect decoder (plan.md §G4, RFC 6143 §7.7.2).
//
// Copies a rectangle within the framebuffer. Overlap is handled with
// memmove-style row ordering: when source rows are above destination
// rows (scrolling down), iterate bottom-to-top so we don't clobber
// unread source rows; when source is below destination (scrolling up),
// iterate top-to-bottom. Column overlap (left/right shifts) is handled
// analogously within each row via memmove.

#include "farsee/encoding.h"
#include "farsee/bytes.h"
#include "farsee/checked.h"

#include <string.h>

static bool rect_in_bounds(const rfb_framebuffer *fb,
                           uint32_t x, uint32_t y, uint32_t w, uint32_t h)
{
    if (w == 0 || h == 0) {
        return false;
    }
    uint32_t x_end = 0, y_end = 0;
    if (!rfb_checked_add_u32(x, w, &x_end)) return false;
    if (!rfb_checked_add_u32(y, h, &y_end)) return false;
    return x_end <= fb->width && y_end <= fb->height;
}

rfb_error rfb_decode_copyrect(rfb_framebuffer *fb,
                              const rfb_rect_header *rh,
                              const uint8_t *payload, size_t payload_len,
                              rfb_rect *out_damage)
{
    // LCOV_EXCL_START
    if (fb == NULL || rh == NULL || payload == NULL || out_damage == NULL) {  // LCOV_EXCL_BR_LINE
        return RFB_ERR_INTERNAL;
    }
    // LCOV_EXCL_STOP
    if (payload_len != 4) {
        return RFB_ERR_PROTOCOL;
    }
    // Parse src-x, src-y (big-endian).
    rfb_reader r = rfb_reader_make(payload, payload_len);
    uint16_t src_x = 0, src_y = 0;
    if (!rfb_read_u16(&r, &src_x) || !rfb_read_u16(&r, &src_y)) {
        return RFB_ERR_PROTOCOL;
    }
    // Bounds: both source and destination rectangles must be in-bounds.
    if (!rect_in_bounds(fb, rh->x, rh->y, rh->width, rh->height)) {
        return RFB_ERR_PROTOCOL;
    }
    if (!rect_in_bounds(fb, src_x, src_y, rh->width, rh->height)) {
        return RFB_ERR_PROTOCOL;
    }
    // If source and destination are identical, this is a no-op.
    if (src_x == rh->x && src_y == rh->y) {
        out_damage->x = rh->x; out_damage->y = rh->y;
        out_damage->width = rh->width; out_damage->height = rh->height;
        return RFB_OK;
    }
    // memmove semantics: choose iteration order to avoid clobbering
    // source rows/columns that have not been read yet.
    int row_step = 1;
    uint32_t row_start = 0;
    if (src_y < rh->y) {
        // Source above destination: read bottom rows first.
        row_step = -1;
        row_start = rh->height - 1;
    }
    int col_step = 1;
    uint32_t col_start = 0;
    if (src_x < rh->x) {
        // Source left of destination: read right columns first.
        col_step = -1;
        col_start = rh->width - 1;
    }
    size_t row_bytes = (size_t)rh->width * 4u;
    // Iterate rows in the chosen order.
    for (uint32_t i = 0; i < rh->height; i++) {
        uint32_t row = (uint32_t)((int)row_start + (int)i * row_step);
        uint32_t dst_y = rh->y + row;
        uint32_t src_row_y = src_y + row;
        uint8_t *dst_row = rfb_framebuffer_pixel(fb, rh->x, dst_y);
        uint8_t *src_row = rfb_framebuffer_pixel(fb, src_x, src_row_y);
        // If there's column overlap, memmove within the row in the chosen
        // column order; otherwise memcpy is fine. We always use memmove
        // for simplicity and correctness.
        (void)col_start; (void)col_step;  // memmove handles overlap per-byte
        memmove(dst_row, src_row, row_bytes);
    }
    out_damage->x = rh->x;
    out_damage->y = rh->y;
    out_damage->width = rh->width;
    out_damage->height = rh->height;
    return RFB_OK;
}
