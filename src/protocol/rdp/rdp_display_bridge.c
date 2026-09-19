// SPDX-License-Identifier: Apache-2.0
//
// Farsee RDP display/frame bridge implementation (R3 gate, §15.8).

#include "rdp_display_bridge.h"

#include <stddef.h>
#include <stdint.h>

// BGRA8888 is 4 bytes/pixel.
#define RDP_BGRA_BPP 4u

int rdp_frame_validate(uint32_t width, uint32_t height, size_t bgra_stride,
                       size_t data_size, uint32_t max_dim,
                       const rdp_backend_rect *rects, size_t rect_count)
{
    if (width == 0 || height == 0) {
        return -1;
    }
    if (width > max_dim || height > max_dim) {
        return -1;
    }
    // stride must be >= width*4 and not overflow when multiplied by height.
    if (bgra_stride < (size_t)width * RDP_BGRA_BPP) {
        return -1;
    }
    if (height > SIZE_MAX / bgra_stride) {
        return -1;
    }
    if (bgra_stride * height != data_size) {
        return -1;  // §15.8: byte count must match exactly
    }
    // Every damage rect must lie within the surface.
    for (size_t i = 0; i < rect_count; ++i) {
        const rdp_backend_rect *r = &rects[i];
        if (r->width <= 0 || r->height <= 0) {
            return -1;
        }
        // Reject negative-origin rects that would underflow when clipped;
        // rdp_frame_clip_rect handles partial-negative, but fully-negative
        // extent is invalid.
        if (r->x < 0 || r->y < 0) {
            return -1;
        }
        // x + width <= width(uint32) without overflow.
        if ((uint32_t)r->x > width ||
            (uint32_t)r->width > width - (uint32_t)r->x) {
            return -1;
        }
        if ((uint32_t)r->y > height ||
            (uint32_t)r->height > height - (uint32_t)r->y) {
            return -1;
        }
    }
    return (int)rect_count;
}

bool rdp_frame_clip_rect(const rdp_backend_rect *in, uint32_t width,
                         uint32_t height, farsee_rect *out)
{
    if (in == NULL || out == NULL || in->width <= 0 || in->height <= 0) {
        return false;
    }
    // Intersect [x, x+width) with [0, width).
    int64_t x0 = in->x;
    int64_t y0 = in->y;
    int64_t x1 = (int64_t)in->x + in->width;
    int64_t y1 = (int64_t)in->y + in->height;
    if (x0 < 0) {
        x0 = 0;
    }
    if (y0 < 0) {
        y0 = 0;
    }
    if (x1 > (int64_t)width) {
        x1 = (int64_t)width;
    }
    if (y1 > (int64_t)height) {
        y1 = (int64_t)height;
    }
    if (x0 >= x1 || y0 >= y1) {
        return false;  // entirely outside
    }
    out->x = (uint32_t)x0;
    out->y = (uint32_t)y0;
    out->width = (uint32_t)(x1 - x0);
    out->height = (uint32_t)(y1 - y0);
    return true;
}

bool rdp_frame_build_surface_view(farsee_surface_view *out,
                                  farsee_surface_id id,
                                  uint32_t width, uint32_t height,
                                  size_t bgra_stride,
                                  const uint8_t *data, size_t data_size,
                                  uint32_t max_dim, uint64_t generation)
{
    if (out == NULL || data == NULL) {
        return false;
    }
    if (rdp_frame_validate(width, height, bgra_stride, data_size, max_dim,
                           NULL, 0) < 0) {
        return false;
    }
    out->id = id;
    out->width = width;
    out->height = height;
    out->stride = bgra_stride;
    out->format = FARSEE_PIXEL_BGRA8888;  // FreeRDP software-GDI output
    out->data = data;
    out->data_size = data_size;
    out->generation = generation;
    return true;
}
