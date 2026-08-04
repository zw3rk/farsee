// SPDX-License-Identifier: Apache-2.0
//
// Farsee bounded queue.
// (FARSEE_ARCHITECTURE_IMPROVEMENT_PLAN.md §8.5 — F3 gate.)
//
// A bounded FIFO used to carry typed commands/events between ownership
// domains (e.g. main thread -> RDP worker, worker -> main reactor). It is
// bounded by BOTH item count AND aggregate payload bytes (§3.2). Entries
// are tagged-union values with explicit destructors (§8.5).
//
// Saturation policy (§8.5): the queue reserves a path for terminal errors
// and cancellation so they are NEVER dropped under saturation, even when
// ordinary entries are rejected. `farsee_queue_push_terminal` always
// succeeds once admitted.
//
// This is the container. Later gates (F4 display, F5 input/clipboard)
// define the concrete tagged-union entry types that ride in it. Here we
// provide a queue of opaque tagged blobs with a tag + destructor hook.

#ifndef FARSEE_INCLUDE_FARSEE_FARSEE_QUEUE_H
#define FARSEE_INCLUDE_FARSEE_FARSEE_QUEUE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Entry tags. The TERMINAL tag is reserved for terminal errors /
// cancellation and bypasses the byte/count budget when pushed (§8.5).
typedef enum {
    FARSEE_QUEUE_TAG_NORMAL    = 0,
    FARSEE_QUEUE_TAG_PRIORITY  = 1,  // admitted ahead of normal entries
    FARSEE_QUEUE_TAG_TERMINAL  = 2,  // cancellation / terminal error
} farsee_queue_tag;

typedef struct farsee_queue farsee_queue;

// Queue configuration. max_items and max_bytes are hard caps; a push that
// would exceed either is rejected (unless TERMINAL).
typedef struct farsee_queue_config {
    size_t max_items;
    size_t max_bytes;
} farsee_queue_config;

// Create a queue. Returns NULL on bad config or OOM.
farsee_queue *farsee_queue_create(farsee_queue_config cfg);

// Destroy the queue, invoking each remaining entry's destructor (if any),
// then free. Safe on NULL.
void farsee_queue_destroy(farsee_queue **q);

// Push an entry. `payload` is copied into the queue (the queue owns its own
// buffer); `user_destructor`, if non-NULL, is invoked on `user` when the
// entry is destroyed (popped or dropped on queue destroy). Returns false
// if the queue is full (count or byte cap) for non-TERMINAL tags, or if
// the queue is already terminal/closed.
//
// TERMINAL entries bypass the caps but are admitted at most once: after a
// terminal entry is pushed, the queue is marked terminal and all further
// pushes are rejected. This guarantees cancellation/terminal-error
// delivery under saturation (§8.5).
bool farsee_queue_push(farsee_queue *q, farsee_queue_tag tag,
                       const void *payload, size_t payload_bytes,
                       void (*user_destructor)(void *user), void *user);

// Pop the next entry (FIFO; PRIORITY entries jump the queue; TERMINAL
// entries are delivered after all queued entries or immediately if the
// queue is otherwise empty). Returns false if the queue is empty.
// On success: *out_payload points to the entry's internal buffer (valid
// until the next pop/destroy), *out_bytes receives the size, *out_tag
// receives the tag, *out_user receives the user pointer.
bool farsee_queue_pop(farsee_queue *q,
                      const void **out_payload, size_t *out_bytes,
                      farsee_queue_tag *out_tag, void **out_user);

// --- Diagnostics -----------------------------------------------------------
size_t farsee_queue_count(const farsee_queue *q);
size_t farsee_queue_bytes(const farsee_queue *q);
bool   farsee_queue_is_terminal(const farsee_queue *q);
// High-water mark of items observed since create (§3.2 metrics).
size_t farsee_queue_high_water_items(const farsee_queue *q);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_FARSEE_QUEUE_H
