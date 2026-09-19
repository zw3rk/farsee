// SPDX-License-Identifier: Apache-2.0
//
// farsee — RFB pixel format validation (plan.md §12, RFC 6143 §7.4).

#include "farsee/pixel_format.h"

#include <stdbool.h>
#include <string.h>

rfb_pixel_format rfb_pixel_format_canonical_request(void)
{
    // plan.md §12.2: 32 bpp, depth 24, true-color, 8-bit maxima. Shifts
    // chosen so the wire pixel matches a little-endian memory layout of
    // {B,G,R,0} on most hosts — but the canonical framebuffer is always
    // RGBA8 in memory regardless of the wire format (ADR-0003).
    rfb_pixel_format pf;
    pf.bits_per_pixel = 32;
    pf.depth = 24;
    pf.big_endian = 0;     // little-endian on the wire
    pf.true_color = 1;
    pf.red_max   = 255;
    pf.green_max = 255;
    pf.blue_max  = 255;
    pf.red_shift   = 16;
    pf.green_shift = 8;
    pf.blue_shift  = 0;
    return pf;
}

bool rfb_pixel_format_is_canonical(const rfb_pixel_format *pf)
{
    if (pf == NULL) {
        return false;
    }
    rfb_pixel_format c = rfb_pixel_format_canonical_request();
    return rfb_pixel_format_eq(pf, &c);
}

// Compute the bit-width of a channel given its max value.
static uint32_t channel_bit_width(uint16_t mx)
{
    if (mx == 0) return 0;
    uint32_t width = 0;
    uint32_t v = (uint32_t)mx;
    while (v > 0) {
        v >>= 1;
        width++;
    }
    return width;
}

// Compute the bit-mask of a channel given its max and shift. Returns the
// mask shifted into pixel position (0 is handled: max=0 => no bits).
static uint32_t channel_mask(uint16_t mx, uint8_t shift)
{
    if (mx == 0) {
        return 0;
    }
    uint32_t width = channel_bit_width(mx);
    // The mask covers `width` bits starting at `shift`.
    uint32_t mask = (width >= 32) ? 0xFFFFFFFFu : ((1u << width) - 1u);
    return mask << shift;
}

bool rfb_pixel_format_valid(const rfb_pixel_format *pf)
{
    if (pf == NULL) {
        return false;
    }
    // Supported bits-per-pixel values (plan.md §12.3).
    if (pf->bits_per_pixel != 8 && pf->bits_per_pixel != 16 &&
        pf->bits_per_pixel != 32) {
        return false;
    }
    // depth must not exceed bpp.
    if (pf->depth > pf->bits_per_pixel) {
        return false;
    }
    // We only support true-color formats (no color maps).
    if (pf->true_color == 0) {
        return false;
    }
    // Zero maxima are meaningless (plan.md §12.3).
    if (pf->red_max == 0 || pf->green_max == 0 || pf->blue_max == 0) {
        return false;
    }
    // Shift + channel width must fit within bits_per_pixel. This MUST run
    // before any mask is computed: red_shift is a raw wire byte, and
    // `mask << shift` with shift >= 32 is undefined behavior (C11 §6.5.7;
    // traps under asan-ubsan). bits_per_pixel is
    // already gated to <= 32 above, so shift + width <= bpp also proves
    // shift < 32 everywhere below (pixel_convert.c relies on this too).
    uint32_t rw = channel_bit_width(pf->red_max);
    uint32_t gw = channel_bit_width(pf->green_max);
    uint32_t bw = channel_bit_width(pf->blue_max);
    if ((uint32_t)pf->red_shift   + rw > pf->bits_per_pixel ||
        (uint32_t)pf->green_shift + gw > pf->bits_per_pixel ||
        (uint32_t)pf->blue_shift  + bw > pf->bits_per_pixel) {
        return false;
    }
    // Channel masks must not overlap (plan.md §12.3). Each shift is less
    // than 32, and each channel fits inside the pixel word.
    uint32_t r = channel_mask(pf->red_max,   pf->red_shift);
    uint32_t g = channel_mask(pf->green_max, pf->green_shift);
    uint32_t b = channel_mask(pf->blue_max,  pf->blue_shift);
    if ((r & g) != 0 || (r & b) != 0 || (g & b) != 0) {
        return false;
    }
    return true;
}

bool rfb_pixel_format_eq(const rfb_pixel_format *a, const rfb_pixel_format *b)
{
    if (a == NULL || b == NULL) {
        return a == b;
    }
    return a->bits_per_pixel == b->bits_per_pixel
        && a->depth == b->depth
        && a->big_endian == b->big_endian
        && a->true_color == b->true_color
        && a->red_max == b->red_max
        && a->green_max == b->green_max
        && a->blue_max == b->blue_max
        && a->red_shift == b->red_shift
        && a->green_shift == b->green_shift
        && a->blue_shift == b->blue_shift;
}
