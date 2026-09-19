// SPDX-License-Identifier: Apache-2.0
//
// Latest-wins triple buffer for multi-threaded present.
//
// A protocol thread publishes format-tagged full frames; a present thread
// acquires the newest published slot. Intermediate frames not acquired can be
// overwritten.
// The slot contract is protocol-neutral.
//
// Concurrency and lifetime contract:
//   - publish/publish_ex, acquire/acquire_wait, release, and kick are safe to
//     call concurrently. init and destroy require exclusive access.
//   - The product topology is one protocol producer and one present consumer;
//     the slot also supports multiple concurrent publishers and readers.
//   - A successful acquire owns one reader reference. The caller must release
//     that exact, unchanged view exactly once before destroy. Several views may
//     name the same generation. At most three distinct slot generations can be
//     held at once; publication reports RESOURCE_BUSY when no storage is free.
//   - publish copies the defined pixels before it returns and never retains the
//     caller's pixel pointer. A view's pixel pointer remains valid until its
//     matching release.
//   - kick is only a wake-up. Cancellation is requested through the optional
//     stop flag passed to acquire_wait; kick alone does not make a wait fail.

#ifndef FARSEE_INCLUDE_FARSEE_FARSEE_FRAME_SLOT_H
#define FARSEE_INCLUDE_FARSEE_FARSEE_FRAME_SLOT_H

#include "farsee/farsee_atomic.h"
#include "farsee/farsee_allocator.h"
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
    farsee_allocator *alloc;
    farsee_mutex *mu;
    farsee_cond *cv;  // signaled on publish (optional wait)
    uint8_t *buf[FARSEE_FRAME_SLOT_N];
    size_t cap[FARSEE_FRAME_SLOT_N];
    uint32_t w;
    uint32_t h;
    uint32_t stride;  // bytes per row
    farsee_pixel_format_kind format;
    // State under mu. Each acquired view owns one reader reference on its
    // slot until release. A writer reserves a slot before copying so two
    // concurrent publishers cannot select or resize the same storage.
    int publish_idx;  // -1 if none yet
    unsigned readers[FARSEE_FRAME_SLOT_N];
    bool writing[FARSEE_FRAME_SLOT_N];
    uint64_t slot_gen[FARSEE_FRAME_SLOT_N];
    uint64_t gen;     // increments on every successful publish
    uint64_t dropped; // publishes that overwrote a ready frame not yet acquired
    bool publish_seen;
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

typedef enum farsee_frame_publish_result {
    FARSEE_FRAME_PUBLISH_OK = 0,
    FARSEE_FRAME_PUBLISH_INVALID,
    FARSEE_FRAME_PUBLISH_RESOURCE_BUSY,
    FARSEE_FRAME_PUBLISH_OUT_OF_MEMORY,
} farsee_frame_publish_result;

// Init empty slot (allocates mutex/cond). Returns false on OOM. After a
// successful init, destroy exactly once after all publishers/readers stop and
// all acquired views are released.
bool farsee_frame_slot_init(farsee_frame_slot *s);
// Test/embedding seam for deterministic frame-storage allocation failure.
// NULL allocator is rejected; the borrowed allocator must outlive the slot.
bool farsee_frame_slot_init_with_allocator(farsee_frame_slot *s,
                                           farsee_allocator *alloc);
void farsee_frame_slot_destroy(farsee_frame_slot *s);

// Copy defined pixel bytes into a free slot and publish it as latest. A
// successful publish can supersede a ready frame that no reader acquired.
// Returns false for invalid input, allocation failure, or unavailable storage.
// `stride` must be at least w * bpp(format). Row padding is not copied, so
// callers must not depend on padding in an acquired view.
bool farsee_frame_slot_publish(farsee_frame_slot *s, const uint8_t *pixels,
                               uint32_t w, uint32_t h, uint32_t stride,
                               farsee_pixel_format_kind format);

// Structured form for callers that must distinguish malformed input,
// temporary slot pressure, and allocation failure.
farsee_frame_publish_result farsee_frame_slot_publish_ex(
    farsee_frame_slot *s, const uint8_t *pixels, uint32_t w, uint32_t h,
    uint32_t stride, farsee_pixel_format_kind format);

// Copy a frame and composite an optional straight-alpha RGBA cursor into the
// slot copy before publication. The source frame and cursor remain unchanged.
// A NULL or hidden cursor is equivalent to farsee_frame_slot_publish_ex.
// A visible cursor requires an RGBA8888 destination and valid pixel storage.
farsee_frame_publish_result farsee_frame_slot_publish_composited_ex(
    farsee_frame_slot *s, const uint8_t *pixels, uint32_t w, uint32_t h,
    uint32_t stride, farsee_pixel_format_kind format,
    const farsee_cursor *cursor);

// Acquire the latest published frame for reading. Returns false if none.
// Caller must farsee_frame_slot_release() the unchanged view exactly once.
bool farsee_frame_slot_acquire(farsee_frame_slot *s, farsee_frame_view *out);

// Wait up to the absolute monotonic deadline for a frame with gen > after_gen,
// then acquire one reader reference. Returns false on timeout, when a non-NULL
// stop flag is set, or when a reader counter cannot accept another reference.
// Spurious wakes and kick without stop/new publication continue the same wait.
bool farsee_frame_slot_acquire_wait(farsee_frame_slot *s, uint64_t after_gen,
                                    uint64_t deadline_monotonic_ms,
                                    farsee_atomic_int *stop,
                                    farsee_frame_view *out);

void farsee_frame_slot_release(farsee_frame_slot *s, const farsee_frame_view *v);

// Wake waiters so they can re-check publication and stop state. This function
// neither sets a stop flag nor invalidates outstanding views.
void farsee_frame_slot_kick(farsee_frame_slot *s);

#ifdef __cplusplus
}
#endif

#endif /* FARSEE_INCLUDE_FARSEE_FARSEE_FRAME_SLOT_H */
