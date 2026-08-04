// SPDX-License-Identifier: Apache-2.0
//
// Latest-wins triple buffer for multi-threaded present.
//
// Protocol thread publishes full frames (format-tagged); present thread
// takes the newest published slot without blocking the protocol path.
// Intermediate frames that are never taken are overwritten (latency
// preference). Protocol-neutral: RFB, RDP, and future engines share this.

#ifndef FARSEE_INCLUDE_FARSEE_FARSEE_FRAME_SLOT_H
#define FARSEE_INCLUDE_FARSEE_FARSEE_FRAME_SLOT_H

#include "farsee/farsee_atomic.h"
#include "farsee/farsee_display.h"
#include "farsee/farsee_thread.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FARSEE_FRAME_SLOT_N 3u

typedef struct farsee_frame_slot {
    farsee_mutex *mu;
    farsee_cond *cv;  // signaled on publish (optional wait)
    uint8_t *buf[FARSEE_FRAME_SLOT_N];
    size_t cap[FARSEE_FRAME_SLOT_N];
    uint32_t w;
    uint32_t h;
    uint32_t stride;  // bytes per row
    farsee_pixel_format_kind format;
    // Indices under mu:
    //   publish_idx — last fully published frame for present
    //   display_idx — -1 if present not holding; else slot present owns
    int publish_idx;  // -1 if none yet
    int display_idx;  // -1 if present not holding; else slot present owns
    uint64_t gen;     // increments on every successful publish
    uint64_t dropped; // publishes that overwrote a never-shown ready frame
    bool has_frame;
} farsee_frame_slot;

// Snapshot for present (valid until farsee_frame_slot_release).
typedef struct farsee_frame_view {
    const uint8_t *pixels;
    uint32_t w;
    uint32_t h;
    uint32_t stride;
    farsee_pixel_format_kind format;
    uint64_t gen;
    int slot_idx;  // private to slot; pass to release
} farsee_frame_view;

// Init empty slot (allocates mutex/cond). Returns false on OOM.
bool farsee_frame_slot_init(farsee_frame_slot *s);
void farsee_frame_slot_destroy(farsee_frame_slot *s);

// Copy pixels into a free slot and publish as latest. Drops any
// intermediate unpublished frame. Thread-safe.
// `stride` is bytes per row; must be >= w * bpp(format).
bool farsee_frame_slot_publish(farsee_frame_slot *s, const uint8_t *pixels,
                               uint32_t w, uint32_t h, uint32_t stride,
                               farsee_pixel_format_kind format);

// Acquire the latest published frame for reading. Returns false if none.
// Caller must farsee_frame_slot_release() when done presenting.
bool farsee_frame_slot_acquire(farsee_frame_slot *s, farsee_frame_view *out);

// Wait up to deadline for a frame with gen > after_gen, then acquire.
// Returns false on timeout / stop (if stop is set) / none.
bool farsee_frame_slot_acquire_wait(farsee_frame_slot *s, uint64_t after_gen,
                                    uint64_t deadline_monotonic_ms,
                                    farsee_atomic_int *stop,
                                    farsee_frame_view *out);

void farsee_frame_slot_release(farsee_frame_slot *s, const farsee_frame_view *v);

// Wake waiters (e.g. on stop).
void farsee_frame_slot_kick(farsee_frame_slot *s);

#ifdef __cplusplus
}
#endif

#endif /* FARSEE_INCLUDE_FARSEE_FARSEE_FRAME_SLOT_H */
