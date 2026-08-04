// SPDX-License-Identifier: Apache-2.0
//
// farsee — checked arithmetic for wire-derived sizes (plan.md §10.2, §6.3,
// §15.3 "no unchecked width*height*bpp").
//
// Every size derived from network data flows through these helpers. They
// return false on overflow rather than wrapping, and the result is only
// written on success (transactional).

#ifndef FARSEE_INCLUDE_FARSEE_CHECKED_H
#define FARSEE_INCLUDE_FARSEE_CHECKED_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Checked size_t add: *out = a + b, or false on overflow.
bool rfb_checked_add_size(size_t a, size_t b, size_t *out);

// Checked size_t multiply: *out = a * b. Returns true with *out=0 when
// either operand is zero (callers should handle zero explicitly).
// Returns false only on overflow.
bool rfb_checked_mul_size(size_t a, size_t b, size_t *out);

// Checked rectangle byte size: *out = width * height * bytes_per_pixel,
// or false on overflow. All three operands are wire-derived; this is the
// single chokepoint for "no unchecked width*height*bpp" (plan.md §15.3).
// Returns false if width or height is zero (zero-area is a policy error,
// not an allocation size).
bool rfb_checked_rect_bytes(
    uint32_t width,
    uint32_t height,
    uint32_t bytes_per_pixel,
    size_t *out);

// Checked add for uint32_t (used by coordinate-bounds checks in G4).
bool rfb_checked_add_u32(uint32_t a, uint32_t b, uint32_t *out);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_CHECKED_H
