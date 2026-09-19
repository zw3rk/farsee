// SPDX-License-Identifier: Apache-2.0
//
// farsee — checked arithmetic implementation.
//
// Every wire-derived size flows through these helpers. The implementation
// is deliberately branchless-friendly and free of UB: we detect overflow
// before it happens, never by observing a wrap.

#include "farsee/checked.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool rfb_checked_add_size(size_t a, size_t b, size_t *out)
{
    if (out == NULL) {
        return false;
    }
    if (b > SIZE_MAX - a) {
        return false;  // a + b would overflow
    }
    *out = a + b;
    return true;
}

bool rfb_checked_mul_size(size_t a, size_t b, size_t *out)
{
    if (out == NULL) {
        return false;
    }
    if (a == 0 || b == 0) {
        *out = 0;
        return true;
    }
    if (a > SIZE_MAX / b) {
        return false;  // a * b would overflow
    }
    *out = a * b;
    return true;
}

bool rfb_checked_rect_bytes(
    uint32_t width,
    uint32_t height,
    uint32_t bytes_per_pixel,
    size_t *out)
{
    if (out == NULL) {
        return false;
    }
    // Zero-area rectangles are invalid allocation requests, not a
    // size we ever allocate.
    if (width == 0 || height == 0) {
        return false;
    }
    size_t pixels = 0;
    // On a 64-bit host the width*height product of two uint32_t values can
    // never overflow size_t (max is 2^64-1). This guard is exercised on
    // 32-bit hosts where it can. We keep it unconditionally for
    // portability and defense in depth. The failure branch is reachable on
    // 32-bit hosts only.
    if (!rfb_checked_mul_size((size_t)width, (size_t)height, &pixels)) {
        return false;
    }
    size_t bytes = 0;
    if (!rfb_checked_mul_size(pixels, (size_t)bytes_per_pixel, &bytes)) {
        return false;
    }
    *out = bytes;
    return true;
}

bool rfb_checked_add_u32(uint32_t a, uint32_t b, uint32_t *out)
{
    if (out == NULL) {
        return false;
    }
    if (b > UINT32_MAX - a) {
        return false;
    }
    *out = a + b;
    return true;
}
