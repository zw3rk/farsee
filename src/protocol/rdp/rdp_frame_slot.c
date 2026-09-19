// SPDX-License-Identifier: Apache-2.0
//
// RDP thin wrappers over farsee_frame_slot (BGRA8888 publish).

#include "rdp_frame_slot.h"

#include "farsee/farsee_display.h"

bool rdp_frame_slot_init(rdp_frame_slot *s)
{
    return farsee_frame_slot_init(s);
}

bool rdp_frame_slot_init_with_allocator(rdp_frame_slot *s,
                                        farsee_allocator *allocator)
{
    return farsee_frame_slot_init_with_allocator(s, allocator);
}

void rdp_frame_slot_destroy(rdp_frame_slot *s)
{
    farsee_frame_slot_destroy(s);
}

bool rdp_frame_slot_publish(rdp_frame_slot *s, const uint8_t *bgra,
                            uint32_t w, uint32_t h, uint32_t stride)
{
    return rdp_frame_slot_publish_ex(s, bgra, w, h, stride) ==
           FARSEE_FRAME_PUBLISH_OK;
}

farsee_frame_publish_result rdp_frame_slot_publish_ex(
    rdp_frame_slot *s, const uint8_t *bgra, uint32_t w, uint32_t h,
    uint32_t stride)
{
    return farsee_frame_slot_publish_ex(s, bgra, w, h, stride,
                                        FARSEE_PIXEL_BGRA8888);
}

bool rdp_frame_slot_acquire(rdp_frame_slot *s, rdp_frame_view *out)
{
    return farsee_frame_slot_acquire(s, out);
}

bool rdp_frame_slot_acquire_wait(rdp_frame_slot *s, uint64_t after_gen,
                                 uint64_t deadline_monotonic_ms,
                                 farsee_atomic_int *stop,
                                 rdp_frame_view *out)
{
    return farsee_frame_slot_acquire_wait(s, after_gen, deadline_monotonic_ms,
                                          stop, out);
}

void rdp_frame_slot_release(rdp_frame_slot *s, const rdp_frame_view *v)
{
    farsee_frame_slot_release(s, v);
}

void rdp_frame_slot_kick(rdp_frame_slot *s)
{
    farsee_frame_slot_kick(s);
}
