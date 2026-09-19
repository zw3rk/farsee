// SPDX-License-Identifier: Apache-2.0
//
// farsee — Cursor and DesktopSize pseudo-encoding decoders (plan.md §G6,
// RFC 6143 §7.7.9, §7.7.10).

#include "farsee/encoding.h"
#include "farsee/pixel_convert.h"
#include "farsee/checked.h"

#include <stdlib.h>
#include <string.h>

// --- Cursor (RFC 6143 §7.7.9) --------------------------------------------
// Payload: width*height pixels (in the negotiated format) followed by a
// monochrome bitmask: width bits per row (MSB first), padded to a byte
// boundary, height rows. A set bit means the cursor pixel is visible.

rfb_error rfb_decode_cursor(rfb_cursor *cursor,
                            const rfb_pixel_format *pf,
                            const rfb_rect_header *rh,
                            const uint8_t *payload, size_t payload_len,
                            rfb_allocator *alloc)
{
    if (cursor == NULL || pf == NULL || rh == NULL || alloc == NULL) {
        return RFB_ERR_INTERNAL;
    }
    memset(cursor, 0, sizeof *cursor);
    if (rh->width == 0 || rh->height == 0) {
        return RFB_ERR_PROTOCOL;
    }
    // Validate the pixel format.
    if (!rfb_pixel_format_valid(pf)) {
        return RFB_ERR_PROTOCOL;
    }
    // Compute the expected payload size.
    size_t pixel_bytes = 0;
    if (!rfb_checked_rect_bytes(rh->width, rh->height,
                                (uint32_t)pf->bits_per_pixel / 8u,
                                &pixel_bytes)) {
        return RFB_ERR_LIMIT;
    }
    // Mask: ceil(width/8) bytes per row, height rows.
    size_t mask_row_bytes = ((size_t)rh->width + 7u) / 8u;
    size_t mask_bytes = 0;
    if (!rfb_checked_mul_size(mask_row_bytes, rh->height, &mask_bytes)) {
        return RFB_ERR_LIMIT;
    }
    size_t expected = 0;
    if (!rfb_checked_add_size(pixel_bytes, mask_bytes, &expected)) {
        return RFB_ERR_LIMIT;
    }
    if (payload_len != expected) {
        return RFB_ERR_PROTOCOL;
    }
    // Allocate RGBA storage.
    size_t rgba_bytes = 0;
    if (!rfb_checked_rect_bytes(rh->width, rh->height, 4u, &rgba_bytes)) {
        return RFB_ERR_LIMIT;
    }
    cursor->rgba = (uint8_t *)alloc->alloc(alloc, rgba_bytes);
    if (cursor->rgba == NULL) {
        return RFB_ERR_NOMEM;
    }
    // Convert pixels.
    size_t bpp = (size_t)pf->bits_per_pixel / 8u;
    const uint8_t *src = payload;
    for (uint32_t row = 0; row < rh->height; row++) {
        for (uint32_t col = 0; col < rh->width; col++) {
            uint8_t rgba[4];
            rfb_pixel_to_rgba8(pf, src, rgba);
            size_t idx = ((size_t)row * rh->width + col) * 4u;
            cursor->rgba[idx]     = rgba[0];
            cursor->rgba[idx + 1] = rgba[1];
            cursor->rgba[idx + 2] = rgba[2];
            // Alpha comes from the mask, not the pixel.
            cursor->rgba[idx + 3] = 0;  // set below from mask
            src += bpp;
        }
    }
    // Apply mask. The mask is ceil(width/8) bytes per row, MSB first within
    // each byte (RFC 6143 §7.7.9).
    const uint8_t *mask = payload + pixel_bytes;
    for (uint32_t row = 0; row < rh->height; row++) {
        const uint8_t *mask_row = mask + (size_t)row * mask_row_bytes;
        for (uint32_t col = 0; col < rh->width; col++) {
            size_t byte_index = col / 8u;
            size_t bit_offset = 7u - (col % 8u);  // MSB first
            bool visible = (mask_row[byte_index] >> bit_offset) & 1u;
            size_t idx = ((size_t)row * rh->width + col) * 4u;
            cursor->rgba[idx + 3] = visible ? 255u : 0u;
        }
    }
    cursor->hotspot_x = rh->x;  // rectangle x/y is the hotspot
    cursor->hotspot_y = rh->y;
    cursor->width = rh->width;
    cursor->height = rh->height;
    cursor->valid = true;
    (void)mask_row_bytes;
    (void)mask_bytes;
    return RFB_OK;
}

void rfb_cursor_destroy(rfb_cursor *cursor, rfb_allocator *alloc)
{
    if (cursor == NULL || alloc == NULL) {
        return;
    }
    if (cursor->rgba != NULL) {
        alloc->free(alloc, cursor->rgba);
    }
    cursor->rgba = NULL;
    cursor->valid = false;
}

// --- DesktopSize (RFC 6143 §7.7.10) --------------------------------------
// No payload. The rectangle's width/height is the new framebuffer size.

rfb_error rfb_decode_desktopsize(rfb_framebuffer *fb,
                                 const rfb_rect_header *rh,
                                 size_t byte_limit,
                                 rfb_rect *out_damage)
{
    if (fb == NULL || rh == NULL || out_damage == NULL) {
        return RFB_ERR_INTERNAL;
    }
    rfb_error e = rfb_framebuffer_resize(fb, rh->width, rh->height, byte_limit);
    if (e != RFB_OK) {
        return e;  // transactional: old framebuffer preserved
    }
    out_damage->x = 0;
    out_damage->y = 0;
    out_damage->width = rh->width;
    out_damage->height = rh->height;
    return RFB_OK;
}
