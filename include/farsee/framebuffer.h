// SPDX-License-Identifier: Apache-2.0
//
// farsee — canonical RGBA8 framebuffer (plan.md §10.3, §12.1, ADR-0003).
//
// One authoritative in-memory framebuffer. Decoders write into it;
// presenters read from it but never mutate it (plan.md §8 principle 4).
//
// Resize is transactional: the new buffer is allocated and validated
// before the old one is released, so a failed resize leaves the old
// framebuffer intact (plan.md §10.3, §G3).

#ifndef FARSEE_INCLUDE_FARSEE_FRAMEBUFFER_H
#define FARSEE_INCLUDE_FARSEE_FRAMEBUFFER_H

#include "farsee/allocator.h"
#include "farsee/error.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RFB_BPP_CANONICAL 4u  // RGBA8 = 4 bytes per pixel

typedef struct rfb_framebuffer {
    uint8_t *rgba;          // width*height*4 bytes, owned
    size_t   stride;        // bytes per row (== width * 4 for canonical)
    uint32_t width;
    uint32_t height;
    uint64_t generation;    // bumped on every successful resize/mutation
    rfb_allocator *alloc;
} rfb_framebuffer;

// Initialize an empty framebuffer (no allocation). Use rfb_framebuffer_resize
// to allocate storage.
void rfb_framebuffer_init(rfb_framebuffer *fb, rfb_allocator *alloc);

// Release the backing storage. Safe on a zero-initialized or failed-init fb.
void rfb_framebuffer_destroy(rfb_framebuffer *fb);

// Allocate storage for width*height RGBA8 pixels. Returns RFB_OK on
// success, RFB_ERR_LIMIT if width/height exceed the caps or the computed
// byte size exceeds the policy limit, RFB_ERR_NOMEM on allocation failure.
// On failure the prior contents (if any) are preserved (transactional).
// Initializes every pixel to (0,0,0,255) — black opaque (plan.md §G3:
// "initialize alpha to 255 and RGB to deterministic zero").
rfb_error rfb_framebuffer_resize(rfb_framebuffer *fb,
                                 uint32_t width, uint32_t height,
                                 size_t byte_limit);

// True iff (x,y) is inside the framebuffer.
static inline bool rfb_framebuffer_in_bounds(const rfb_framebuffer *fb,
                                             uint32_t x, uint32_t y)
{
    return fb != NULL && x < fb->width && y < fb->height;
}

// Pixel accessors. No bounds check — callers must validate first.
static inline uint8_t *rfb_framebuffer_pixel(rfb_framebuffer *fb,
                                             uint32_t x, uint32_t y)
{
    return fb->rgba + (size_t)y * fb->stride + (size_t)x * RFB_BPP_CANONICAL;
}
static inline const uint8_t *rfb_framebuffer_pixel_c(const rfb_framebuffer *fb,
                                                     uint32_t x, uint32_t y)
{
    return fb->rgba + (size_t)y * fb->stride + (size_t)x * RFB_BPP_CANONICAL;
}

// Fill the whole framebuffer with a solid RGBA color (used by tests and
// by the G4 Raw-solid optimization).
void rfb_framebuffer_fill(rfb_framebuffer *fb,
                          uint8_t r, uint8_t g, uint8_t b, uint8_t a);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_FRAMEBUFFER_H
