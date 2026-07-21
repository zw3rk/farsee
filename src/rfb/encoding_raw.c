// SPDX-License-Identifier: Apache-2.0
//
// farsee — Raw decoder (plan.md §G4, RFC 6143 §7.7.1).
//
// Converts a Raw rectangle's wire bytes into the canonical RGBA8
// framebuffer. Bounds are validated before any pixel is written, so a
// failure leaves the framebuffer untouched (no partial damage).

#include "farsee/encoding.h"
#include "farsee/checked.h"
#include "farsee/pixel_convert.h"

#include <string.h>

// Validate that (x,y,w,h) lies entirely within the framebuffer. Uses
// checked arithmetic so x+w and y+h overflow is caught.
static bool rect_in_bounds(const rfb_framebuffer *fb,
                           uint16_t x, uint16_t y, uint16_t w, uint16_t h)
{
    if (w == 0 || h == 0) {  // LCOV_EXCL_BR_LINE
        return false;
    }
    uint32_t x_end = 0, y_end = 0;
    if (!rfb_checked_add_u32(x, w, &x_end)) return false;
    if (!rfb_checked_add_u32(y, h, &y_end)) return false;
    if (x_end > fb->width)  return false;
    if (y_end > fb->height) return false;
    return true;
}

rfb_error rfb_decode_raw(rfb_framebuffer *fb,
                         const rfb_pixel_format *pf,
                         const rfb_rect_header *rh,
                         const uint8_t *payload, size_t payload_len,
                         rfb_rect *out_damage)
{
    // LCOV_EXCL_START
    if (fb == NULL || pf == NULL || rh == NULL || payload == NULL || out_damage == NULL) {  // LCOV_EXCL_BR_LINE
        return RFB_ERR_INTERNAL;
    }
    // LCOV_EXCL_STOP
    if (!rfb_pixel_format_valid(pf)) {
        return RFB_ERR_PROTOCOL;
    }
    // Bounds check before any write.
    if (!rect_in_bounds(fb, rh->x, rh->y, rh->width, rh->height)) {
        return RFB_ERR_PROTOCOL;
    }
    // Compute the exact expected payload size via the checked chokepoint.
    size_t expected = 0;
    // LCOV_EXCL_START
    if (!rfb_checked_rect_bytes(rh->width, rh->height,  // LCOV_EXCL_BR_LINE
                                (uint32_t)pf->bits_per_pixel / 8u, &expected)) {
        return RFB_ERR_LIMIT;  // unreachable on 64-bit with uint32 inputs
    }
    // LCOV_EXCL_STOP
    if (payload_len != expected) {
        return RFB_ERR_PROTOCOL;
    }
    // Decode row by row. The wire bytes are contiguous (no row padding);
    // the destination is the framebuffer's stride (== width*4 canonical).
    size_t bpp = (size_t)pf->bits_per_pixel / 8u;
    const uint8_t *src = payload;
    for (uint32_t row = 0; row < rh->height; row++) {
        uint32_t y = rh->y + row;
        uint8_t *dst = rfb_framebuffer_pixel(fb, rh->x, y);
        rfb_convert_run(pf, src, dst, rh->width);
        src += (size_t)rh->width * bpp;
    }
    // Emit damage only on full success.
    out_damage->x = rh->x;
    out_damage->y = rh->y;
    out_damage->width = rh->width;
    out_damage->height = rh->height;
    return RFB_OK;
}
