// SPDX-License-Identifier: Apache-2.0
//
// farsee — wire-pixel → canonical RGBA8 conversion (plan.md §12, §G4).
//
// Converts a single pixel from any valid source PIXEL_FORMAT into the
// canonical RGBA8 memory layout (ADR-0003). Used by the Raw decoder and
// by ZRLE's plain-tile path. Integer-only; no floating point (plan.md
// §12.3). Channel scaling uses the documented round-half-up rule and is
// exhaustively tested for small maxima.

#ifndef FARSEE_INCLUDE_FARSEE_PIXEL_CONVERT_H
#define FARSEE_INCLUDE_FARSEE_PIXEL_CONVERT_H

#include "farsee/pixel_format.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Read a single wire pixel from `src` (at byte offset 0) using the given
// format, and write RGBA8 to out[4]. `src` must point to at least
// bits_per_pixel/8 bytes. The conversion:
//   1. assemble the raw pixel word (1, 2, or 4 bytes) with the format's
//      endianness;
//   2. mask+shift each channel to its 0..max value;
//   3. scale each channel to 0..255 using the integer formula
//      out = (channel * 255 + max/2) / max (round-half-up);
//   4. alpha is always 255 (the canonical framebuffer is opaque).
void rfb_pixel_to_rgba8(const rfb_pixel_format *pf,
                        const uint8_t *src, uint8_t out[4]);

// Convert a run of `count` contiguous wire pixels into `dst` RGBA8.
// `src` points at the first wire pixel (packed, no padding). `dst` points
// at the first output pixel (4 bytes each). Handles any valid source
// format. Used by the Raw decoder for the per-row inner loop.
void rfb_convert_run(const rfb_pixel_format *pf,
                     const uint8_t *src, uint8_t *dst, size_t count);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_PIXEL_CONVERT_H
