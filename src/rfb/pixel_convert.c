// SPDX-License-Identifier: Apache-2.0
//
// farsee — wire-pixel → RGBA8 conversion (plan.md §12, §G4).
//
// Integer-only scaling with round-half-up (plan.md §12.3). No floating
// point anywhere. The scaling formula for a channel value `v` in
// [0, max] is:
//     out = (v * 255 + max/2) / max
// This is equivalent to round(v * 255 / max) for the halfway case and is
// exhaustive-tested for small maxima (see pixel_convert__tests.c).

#include "farsee/pixel_convert.h"

#include <stdint.h>

// Assemble the raw pixel word (1, 2, or 4 bytes) honoring the PIXEL_FORMAT's
// big_endian flag. This is distinct from the network byte-order parsing in
// bytes.c (rfb_read_u16/u32) because RFB pixel words follow the peer's
// advertised byte order, not the network order. The two are intentionally
// separate code paths with different semantics (G13 audit note).
static uint32_t read_pixel_word(const rfb_pixel_format *pf, const uint8_t *src)
{
    switch (pf->bits_per_pixel) {
    case 8:
        return (uint32_t)src[0];
    case 16:
        if (pf->big_endian) {
            return ((uint32_t)src[0] << 8) | (uint32_t)src[1];
        }
        return ((uint32_t)src[1] << 8) | (uint32_t)src[0];
    case 32:
    default: {
        if (pf->big_endian) {
            return ((uint32_t)src[0] << 24)
                 | ((uint32_t)src[1] << 16)
                 | ((uint32_t)src[2] << 8)
                 | (uint32_t)src[3];
        }
        return ((uint32_t)src[3] << 24)
             | ((uint32_t)src[2] << 16)
             | ((uint32_t)src[1] << 8)
             | (uint32_t)src[0];
    }
    }
}

// Scale a channel value in [0, max] to [0, 255] with round-half-up.
static uint8_t scale_channel(uint32_t v, uint16_t max)
{
    if (max == 0) {
        return 0;
    }
    // The plan specifies round-half-up: (v*255 + max/2) / max.
    // v <= max <= 65535, so v*255 <= ~16.7M which fits in uint32_t.
    uint32_t scaled = (v * 255u + (uint32_t)max / 2u) / (uint32_t)max;
    if (scaled > 255u) {  // LCOV_EXCL_BR_LINE
        scaled = 255u;  // clamp (shouldn't happen for v <= max)
    }
    return (uint8_t)scaled;
}

void rfb_pixel_to_rgba8(const rfb_pixel_format *pf,
                        const uint8_t *src, uint8_t out[4])
{
    // Treat NULL/invalid defensively; the decoder validates the format
    // before calling, but we don't crash on bad input.
    // LCOV_EXCL_START
    if (pf == NULL || src == NULL || out == NULL) {  // LCOV_EXCL_BR_LINE
        return;
    }
    // LCOV_EXCL_STOP
    uint32_t word = read_pixel_word(pf, src);
    uint32_t r = (word >> pf->red_shift)   & (uint32_t)pf->red_max;
    uint32_t g = (word >> pf->green_shift) & (uint32_t)pf->green_max;
    uint32_t b = (word >> pf->blue_shift)  & (uint32_t)pf->blue_max;
    out[0] = scale_channel(r, pf->red_max);
    out[1] = scale_channel(g, pf->green_max);
    out[2] = scale_channel(b, pf->blue_max);
    out[3] = 255u;  // canonical framebuffer is opaque (ADR-0003)
}

void rfb_convert_run(const rfb_pixel_format *pf,
                     const uint8_t *src, uint8_t *dst, size_t count)
{
    // LCOV_EXCL_START
    if (pf == NULL || src == NULL || dst == NULL) {  // LCOV_EXCL_BR_LINE
        return;
    }
    // LCOV_EXCL_STOP
    size_t bytes_per_pixel = (size_t)pf->bits_per_pixel / 8u;
    for (size_t i = 0; i < count; i++) {
        rfb_pixel_to_rgba8(pf, src, dst);
        src += bytes_per_pixel;
        dst += 4;
    }
}
