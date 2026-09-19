// SPDX-License-Identifier: Apache-2.0
//
// Farsee display-scene helpers.
//
// Surface formats carry explicit channel order and byte size.
// farsee_surface_view_valid checks dimensions, stride, format, and buffer size.

#include "farsee/farsee_display.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

size_t farsee_pixel_format_bytes(farsee_pixel_format_kind fmt)
{
    switch (fmt) {
    case FARSEE_PIXEL_RGBA8888:
    case FARSEE_PIXEL_BGRA8888:
    case FARSEE_PIXEL_RGBX8888:
    case FARSEE_PIXEL_BGRX8888:
        return 4;
    case FARSEE_PIXEL_RGB888:
        return 3;
    }
    return 0;  // unknown / variable stride
}

bool farsee_rect_within(const farsee_rect *r, uint32_t w, uint32_t h)
{
    if (r == NULL || r->width == 0 || r->height == 0) {
        return false;
    }
    // Overflow-safe: x + width <= w without wrapping.
    if (r->x > w || r->width > w - r->x) {
        return false;
    }
    if (r->y > h || r->height > h - r->y) {
        return false;
    }
    return true;
}

bool farsee_surface_view_valid(const farsee_surface_view *v, uint32_t max_dim)
{
    if (v == NULL || v->data == NULL) {
        return false;
    }
    if (v->width == 0 || v->height == 0) {
        return false;
    }
    if (v->width > max_dim || v->height > max_dim) {
        return false;
    }
    size_t bpp = farsee_pixel_format_bytes(v->format);
    if (bpp == 0) {
        return false;
    }
    // Minimum stride = width * bpp.
    if (v->width > SIZE_MAX / bpp) {
        return false;
    }
    size_t min_stride = (size_t)v->width * bpp;
    if (v->stride < min_stride) {
        return false;
    }
    // stride * height must not overflow.
    if (v->height > SIZE_MAX / v->stride) {
        return false;
    }
    size_t total = v->stride * v->height;
    if (total != v->data_size) {
        return false;  // data_size must exactly describe the buffer
    }
    return true;
}
