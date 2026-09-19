// SPDX-License-Identifier: Apache-2.0
//
// farsee — damage accumulator with bounded rectangle storage (plan.md §G9, §10.4).
//
// Accumulates damage rectangles produced by FramebufferUpdate decoding.
// When the rectangle count exceeds a cap, the accumulator converts to
// full-frame damage rather than dropping pixels (plan.md §G9: "cap behavior
// converts to full-frame damage rather than dropping pixels").
//
// Rectangles are retained as received until the cap is exceeded; this
// component does not merge or alter their geometry.

#ifndef FARSEE_INCLUDE_FARSEE_DAMAGE_H
#define FARSEE_INCLUDE_FARSEE_DAMAGE_H

#include "farsee/presenter.h"
#include "farsee/error.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RFB_DAMAGE_MAX_RECTS 256u

typedef struct rfb_damage_accumulator {
    rfb_rect rects[RFB_DAMAGE_MAX_RECTS];
    size_t count;
    bool full_frame;
    uint32_t fb_width;
    uint32_t fb_height;
    uint64_t framebuffer_generation;
    size_t max_rects;  // configurable cap; default RFB_DAMAGE_MAX_RECTS
} rfb_damage_accumulator;

void rfb_damage_init(rfb_damage_accumulator *da,
                     uint32_t fb_width, uint32_t fb_height,
                     uint64_t generation);

// Resize the accumulator for a new framebuffer size/generation. Clears
// any pending damage (the old framebuffer's damage is stale).
void rfb_damage_resize(rfb_damage_accumulator *da,
                       uint32_t fb_width, uint32_t fb_height,
                       uint64_t generation);

// Add a damage rectangle. If the rectangle count exceeds max_rects,
// converts to full_frame=true and discards the individual rects.
void rfb_damage_add(rfb_damage_accumulator *da, const rfb_rect *r);

// Mark the entire framebuffer as damaged.
void rfb_damage_add_full(rfb_damage_accumulator *da);

// Produce a damage batch for presentation. The batch references the
// accumulator's rects (no copy). After produce, the accumulator is reset
// for the next frame.
rfb_damage_batch rfb_damage_produce(rfb_damage_accumulator *da);

// True if there is pending damage.
static inline bool rfb_damage_has_pending(const rfb_damage_accumulator *da)
{
    return da != NULL && (da->count > 0 || da->full_frame);
}

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_DAMAGE_H
