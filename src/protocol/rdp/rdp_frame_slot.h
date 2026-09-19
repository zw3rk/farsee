// SPDX-License-Identifier: Apache-2.0
//
// RDP thin wrapper over the shared farsee_frame_slot.
// Public names stay rdp_* for main/callbacks; publish always uses BGRA8888.
// All concurrency, borrowed-allocator, acquired-view, cancellation, and
// destroy-after-quiescence rules are exactly those in farsee_frame_slot.h.

#ifndef FARSEE_SRC_PROTOCOL_RDP_RDP_FRAME_SLOT_H
#define FARSEE_SRC_PROTOCOL_RDP_RDP_FRAME_SLOT_H

#include "farsee/farsee_atomic.h"
#include "farsee/farsee_frame_slot.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RDP_FRAME_SLOT_N FARSEE_FRAME_SLOT_N

typedef farsee_frame_slot rdp_frame_slot;
typedef farsee_frame_view rdp_frame_view;

bool rdp_frame_slot_init(rdp_frame_slot *s);
bool rdp_frame_slot_init_with_allocator(rdp_frame_slot *s,
                                        farsee_allocator *allocator);
void rdp_frame_slot_destroy(rdp_frame_slot *s);

// Copy BGRA pixels into a free slot and publish as latest (BGRA8888).
bool rdp_frame_slot_publish(rdp_frame_slot *s, const uint8_t *bgra,
                            uint32_t w, uint32_t h, uint32_t stride);
farsee_frame_publish_result rdp_frame_slot_publish_ex(
    rdp_frame_slot *s, const uint8_t *bgra, uint32_t w, uint32_t h,
    uint32_t stride);

bool rdp_frame_slot_acquire(rdp_frame_slot *s, rdp_frame_view *out);

bool rdp_frame_slot_acquire_wait(rdp_frame_slot *s, uint64_t after_gen,
                                 uint64_t deadline_monotonic_ms,
                                 farsee_atomic_int *stop,
                                 rdp_frame_view *out);

void rdp_frame_slot_release(rdp_frame_slot *s, const rdp_frame_view *v);

void rdp_frame_slot_kick(rdp_frame_slot *s);

#ifdef __cplusplus
}
#endif

#endif /* FARSEE_SRC_PROTOCOL_RDP_RDP_FRAME_SLOT_H */
