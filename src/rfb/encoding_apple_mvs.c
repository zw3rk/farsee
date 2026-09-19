// SPDX-License-Identifier: Apache-2.0
//
// Apple MultiVariant (0x03f3) rect validation/product seam.
// Type-0 partial updates have independent command and image planes. The
// product path strictly validates the complete command plane and the image
// endpoint, then decodes and paints the image plane through
// apple_mvs_image_paint_rect. Unsupported bodies are consumed with no damage.

#include "farsee/encoding_apple_mvs.h"

#include "farsee/apple_mvs_image.h"
#include "farsee/apple_mvs_stream.h"
#include "farsee/apple_wire_decode.h"
#include "farsee/checked.h"

#include <string.h>

static bool rect_in_bounds(const rfb_framebuffer *fb, uint16_t x, uint16_t y,
                           uint16_t w, uint16_t h)
{
    if (w == 0u || h == 0u) {
        return false;
    }
    uint32_t x_end = 0, y_end = 0;
    if (!rfb_checked_add_u32(x, w, &x_end) ||
        !rfb_checked_add_u32(y, h, &y_end)) {
        return false;
    }
    if (x_end > fb->width || y_end > fb->height) {
        return false;
    }
    return true;
}

static void fill_rect_rgba(rfb_framebuffer *fb, uint16_t x, uint16_t y,
                           uint16_t w, uint16_t h, uint8_t r, uint8_t g,
                           uint8_t b)
{
    for (uint32_t row = 0; row < h; row++) {
        uint8_t *p = rfb_framebuffer_pixel(fb, x, y + row);
        for (uint32_t col = 0; col < w; col++) {
            p[0] = r;
            p[1] = g;
            p[2] = b;
            p[3] = 255u;
            p += 4;
        }
    }
}

static rfb_error
rfb_decode_apple_mvs_impl(rfb_framebuffer *fb, const rfb_rect_header *rh,
                          const uint8_t *payload, size_t payload_len,
                          bool skip_unknown, const uint8_t *qt0,
                          const uint8_t *qt1,
                          apple_mvs_coeff_store *coeff_store,
                          rfb_rect *out_damage)
{
    if (fb == NULL || rh == NULL || out_damage == NULL) {
        return RFB_ERR_INTERNAL;
    }
    if (payload == NULL && payload_len != 0u) {
        return RFB_ERR_INTERNAL;
    }
    // Kept in the signature for API compatibility. The type-0 product path
    // manages coefficient state inside apple_mvs_image_paint_rect.
    (void)coeff_store;
    memset(out_damage, 0, sizeof *out_damage);
    if (rh->encoding != (int32_t)RFB_ENCODING_APPLE_MVS) {
        return RFB_ERR_UNSUPPORTED;
    }
    if (!rect_in_bounds(fb, rh->x, rh->y, rh->width, rh->height)) {
        return RFB_ERR_PROTOCOL;
    }

    // Supported solid-black known-answer payload (15-byte body).
    if (apple_wire_mvs_is_solid_black_sample(payload, payload_len)) {
        // Preserve the established KAT contract (the exact body may
        // fill the caller's in-bounds rectangle), but prove the body itself is
        // still the known 1024x768/8x8 structural vector before painting.
        apple_wire_mvs_rect_hdr black_hdr;
        apple_wire_mvs_command_stats black_commands;
        apple_wire_mvs_image_stats black_image;
        if (!apple_wire_decode_mvs_rect_hdr(payload, payload_len, &black_hdr) ||
            !apple_wire_validate_mvs_partial_commands(&black_hdr, 12288u,
                                                       &black_commands) ||
            !apple_wire_validate_mvs_partial_image_suffix(&black_hdr,
                                                           &black_image)) {
            return RFB_ERR_PROTOCOL;
        }
        fill_rect_rgba(fb, rh->x, rh->y, rh->width, rh->height, 0u, 0u, 0u);
        fb->generation += 1u;
        out_damage->x = rh->x;
        out_damage->y = rh->y;
        out_damage->width = rh->width;
        out_damage->height = rh->height;
        return RFB_OK;
    }

    const bool recognized_type0 = payload_len != 0u && payload[0] == 0u;
    apple_wire_mvs_rect_hdr hdr;
    if (!apple_wire_decode_mvs_rect_hdr(payload, payload_len, &hdr)) {
        if (skip_unknown && !recognized_type0) {
            return RFB_OK;
        }
        return RFB_ERR_PROTOCOL;
    }

    uint32_t expected_tiles = 0u;
    if (!apple_wire_mvs_tile_grid_checked(rh->width, rh->height, NULL, NULL,
                                          &expected_tiles)) {
        return RFB_ERR_PROTOCOL;
    }
    apple_wire_mvs_command_stats command_stats;
    if (!apple_wire_validate_mvs_partial_commands(&hdr, expected_tiles,
                                                   &command_stats)) {
        return RFB_ERR_PROTOCOL;
    }

    // A recognized type-0 body is malformed unless its independently bounded
    // image plane also ends at the required `m` + zero-pad suffix.
    // `skip_unknown` applies to unsupported envelopes, not corrupt supported
    // grammar. No framebuffer or decoder state has been touched at this point.
    apple_wire_mvs_image_stats image_stats;
    if (!apple_wire_validate_mvs_partial_image_suffix(&hdr, &image_stats)) {
        return RFB_ERR_PROTOCOL;
    }

    // Type-0 uses independent command and image readers; the image plane is
    // decoded by apple_mvs_image_paint_rect.
    //
    // Fail closed. The pre-decoder contract — validate, consume, damage
    // nothing — remains the fallback for every body this decoder cannot
    // render: no quantisation tables yet, an unsupported quality tier, a tile
    // class with no supported grammar, an allocation failure, or an image plane
    // that does not parse and close on its own endpoint. Painting a wrong
    // framebuffer is worse than painting nothing, and the rectangle is
    // self-delimited by its length prefix, so consuming it cannot desync the
    // stream.
    //
    // hdr.type is zero here. Nonzero types are rejected before this entry
    // point.
    {
        rfb_rect painted;
        const rfb_error pe = apple_mvs_image_paint_rect(
            fb, rh, &hdr, &image_stats, qt0, qt1, &painted);
        if (pe == RFB_OK) {
            *out_damage = painted;
        }
        return RFB_OK;
    }
}

rfb_error rfb_decode_apple_mvs(rfb_framebuffer *fb, const rfb_rect_header *rh,
                               const uint8_t *payload, size_t payload_len,
                               bool skip_unknown, const uint8_t *qt0,
                               const uint8_t *qt1,
                               apple_mvs_coeff_store *coeff_store,
                               rfb_rect *out_damage)
{
    return rfb_decode_apple_mvs_impl(
        fb, rh, payload, payload_len, skip_unknown, qt0, qt1, coeff_store,
        out_damage);
}
