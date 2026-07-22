// SPDX-License-Identifier: Apache-2.0
//
// farsee — damage accumulator (plan.md §G9, §10.4).

#include "farsee/damage.h"

#include <string.h>

void rfb_damage_init(rfb_damage_accumulator *da,
                     uint32_t fb_width, uint32_t fb_height,
                     uint64_t generation)
{
    if (da == NULL) return;
    memset(da, 0, sizeof *da);
    da->fb_width = fb_width;
    da->fb_height = fb_height;
    da->framebuffer_generation = generation;
    da->max_rects = RFB_DAMAGE_MAX_RECTS;
}

void rfb_damage_resize(rfb_damage_accumulator *da,
                       uint32_t fb_width, uint32_t fb_height,
                       uint64_t generation)
{
    if (da == NULL) return;
    da->fb_width = fb_width;
    da->fb_height = fb_height;
    da->framebuffer_generation = generation;
    da->count = 0;
    da->full_frame = false;
}

void rfb_damage_add(rfb_damage_accumulator *da, const rfb_rect *r)
{
    if (da == NULL || r == NULL) return;
    if (da->full_frame) return;  // already full-frame; drop
    if (da->count >= da->max_rects) {
        // Cap exceeded: convert to full-frame (plan.md §G9).
        da->full_frame = true;
        da->count = 0;
        return;
    }
    da->rects[da->count++] = *r;
}

void rfb_damage_add_full(rfb_damage_accumulator *da)
{
    if (da == NULL) return;
    da->full_frame = true;
    da->count = 0;
}

rfb_damage_batch rfb_damage_produce(rfb_damage_accumulator *da)
{
    rfb_damage_batch b;
    if (da == NULL) {
        b.rects = NULL; b.count = 0; b.full_frame = false;
        b.framebuffer_generation = 0;
        return b;
    }
    b.rects = da->full_frame ? NULL : da->rects;
    b.count = da->full_frame ? 0 : da->count;
    b.full_frame = da->full_frame;
    b.framebuffer_generation = da->framebuffer_generation;
    // Reset for the next frame.
    da->count = 0;
    da->full_frame = false;
    return b;
}
