// SPDX-License-Identifier: Apache-2.0
//
// farsee — canonical RGBA8 framebuffer (ADR-0003).
//
// Resize is transactional: allocate+validate the new buffer before
// freeing the old one.

#include "farsee/framebuffer.h"
#include "farsee/checked.h"

#include <stdlib.h>
#include <string.h>

void rfb_framebuffer_init(rfb_framebuffer *fb, rfb_allocator *alloc)
{
    if (fb == NULL) {
        return;
    }
    memset(fb, 0, sizeof *fb);
    fb->alloc = alloc;
}

void rfb_framebuffer_destroy(rfb_framebuffer *fb)
{
    if (fb == NULL) {
        return;
    }
    if (fb->alloc != NULL && fb->alloc->free != NULL && fb->rgba != NULL) {
        fb->alloc->free(fb->alloc, fb->rgba);
    }
    fb->rgba = NULL;
    fb->stride = 0;
    fb->width = 0;
    fb->height = 0;
}

rfb_error rfb_framebuffer_resize(rfb_framebuffer *fb,
                                 uint32_t width, uint32_t height,
                                 size_t byte_limit)
{
    if (fb == NULL) {
        return RFB_ERR_INTERNAL;
    }
    // A zero-area framebuffer is a protocol error.
    if (width == 0 || height == 0) {
        return RFB_ERR_PROTOCOL;
    }
    // Check the allocation size at one chokepoint.
    size_t bytes = 0;
    if (!rfb_checked_rect_bytes(width, height, RFB_BPP_CANONICAL, &bytes)) {
        return RFB_ERR_LIMIT;
    }
    if (bytes > byte_limit) {
        return RFB_ERR_LIMIT;
    }
    // Allocate the new buffer BEFORE freeing the old one (transactional).
    if (fb->alloc == NULL || fb->alloc->alloc == NULL) {
        return RFB_ERR_INTERNAL;
    }
    uint8_t *new_rgba = (uint8_t *)fb->alloc->alloc(fb->alloc, bytes);
    if (new_rgba == NULL) {
        return RFB_ERR_NOMEM;  // old contents preserved
    }
    // Initialize the canonical buffer to opaque black.
    // Pack the fill word for speed: R=0, G=0, B=0, A=255.
    for (size_t i = 0; i < bytes; i += 4) {
        new_rgba[i]     = 0;    // R
        new_rgba[i + 1] = 0;    // G
        new_rgba[i + 2] = 0;    // B
        new_rgba[i + 3] = 255;  // A
    }
    // Commit: free old, swap in new.
    if (fb->rgba != NULL && fb->alloc->free != NULL) {
        fb->alloc->free(fb->alloc, fb->rgba);
    }
    fb->rgba   = new_rgba;
    fb->stride = (size_t)width * RFB_BPP_CANONICAL;
    fb->width  = width;
    fb->height = height;
    fb->generation += 1;
    return RFB_OK;
}

void rfb_framebuffer_fill(rfb_framebuffer *fb,
                          uint8_t r, uint8_t g, uint8_t b, uint8_t a)
{
    if (fb == NULL || fb->rgba == NULL) {
        return;
    }
    size_t total = (size_t)fb->height * fb->stride;
    for (size_t i = 0; i < total; i += 4) {
        fb->rgba[i]     = r;
        fb->rgba[i + 1] = g;
        fb->rgba[i + 2] = b;
        fb->rgba[i + 3] = a;
    }
    fb->generation += 1;
}
