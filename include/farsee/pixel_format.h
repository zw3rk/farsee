// SPDX-License-Identifier: Apache-2.0
//
// farsee — RFB pixel format (plan.md §12, RFC 6143 §7.4).
//
// The PIXEL_FORMAT struct mirrors RFC 6143 §7.4.1's wire layout but is
// never overlaid on a network buffer (plan.md §6.3: no casting wire
// buffers to packed structs). It is parsed field-by-field from the
// reader.

#ifndef FARSEE_INCLUDE_FARSEE_PIXEL_FORMAT_H
#define FARSEE_INCLUDE_FARSEE_PIXEL_FORMAT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// RFB PIXEL_FORMAT (RFC 6143 §7.4.1). 16 bytes on the wire:
//   u8  bits-per-pixel
//   u8  depth
//   u8  big-endian-flag
//   u8  true-color-flag
//   u16 red-max
//   u16 green-max
//   u16 blue-max
//   u8  red-shift
//   u8  green-shift
//   u8  blue-shift
//   u8  padding[3]
typedef struct rfb_pixel_format {
    uint8_t  bits_per_pixel;
    uint8_t  depth;
    uint8_t  big_endian;
    uint8_t  true_color;
    uint16_t red_max;
    uint16_t green_max;
    uint16_t blue_max;
    uint8_t  red_shift;
    uint8_t  green_shift;
    uint8_t  blue_shift;
} rfb_pixel_format;

// The canonical wire format farsee requests after ServerInit
// (plan.md §12.2): 32 bpp, depth 24, true-color, 8-bit maxima, RGB shifts.
// Byte order is little-endian to minimize conversion on the common hosts;
// the canonical framebuffer is always RGBA8 in memory (ADR-0003).
rfb_pixel_format rfb_pixel_format_canonical_request(void);

// True iff the format is the canonical RGBA8 we requested (used to detect
// whether the server honored SetPixelFormat).
bool rfb_pixel_format_is_canonical(const rfb_pixel_format *pf);

// True iff the format is internally consistent (plan.md §12.3 conversion
// tests):
//   - bits_per_pixel in {8, 16, 32} (the values the decoders support);
//   - depth <= bits_per_pixel (plan §12.3: "depth greater than bits-per-
//     pixel rejection");
//   - true_color != 0 (we do not support color maps in the first release);
//   - red/green/blue max are all nonzero (plan §12.3: "zero-valued maxima
//     rejection");
//   - the three channel masks do not overlap given the shifts and maxes
//     (plan §12.3: "overlapping channel masks rejection").
bool rfb_pixel_format_valid(const rfb_pixel_format *pf);

// Equality (used to decide whether a re-issue of SetPixelFormat is needed).
bool rfb_pixel_format_eq(const rfb_pixel_format *a, const rfb_pixel_format *b);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_PIXEL_FORMAT_H
