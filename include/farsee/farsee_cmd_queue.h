// SPDX-License-Identifier: Apache-2.0
//
// Bounded, protocol-neutral input-command queue from an input thread to a
// protocol thread. A full-queue push first attempts to reclaim one pure mouse
// move.
//
// Concurrency and lifetime contract:
//   - The supported product topology is one producer (input) and one consumer
//     (protocol). push, pop, and kick serialize through the queue mutex.
//   - Commands are copied into/out of the queue; no caller pointer is retained.
//   - init and destroy require exclusive access. Destroy only after producer
//     and consumer exit; kick does not cancel them by itself.
//   - q/count/head/drop counters are internal synchronized state. Do not read
//     them concurrently except while holding mu; quiescent diagnostics may
//     inspect them after the worker threads have joined.

#ifndef FARSEE_INCLUDE_FARSEE_FARSEE_CMD_QUEUE_H
#define FARSEE_INCLUDE_FARSEE_FARSEE_CMD_QUEUE_H

#include "farsee/farsee_atomic.h"
#include "farsee/farsee_input.h"
#include "farsee/farsee_thread.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FARSEE_CMD_QUEUE_CAP 256u

typedef enum {
    FARSEE_CMD_KEY = 1,
    FARSEE_CMD_POINTER,
    FARSEE_CMD_RELEASE_ALL,
} farsee_cmd_kind;

typedef struct farsee_cmd {
    farsee_cmd_kind kind;
    farsee_key_event key;
    farsee_pointer_event pe;
    // Previous button mask for pointer edge detection (protocol inject).
    unsigned prev_buttons;
} farsee_cmd;

typedef struct farsee_cmd_queue {
    farsee_mutex *mu;
    farsee_cond *cv;
    farsee_cmd q[FARSEE_CMD_QUEUE_CAP];
    size_t head;
    size_t count;
    uint64_t dropped_moves; // pure pointer moves dropped for latest-wins
    uint64_t dropped_keys;  // reclaimed key-downs plus refused release/key commands
} farsee_cmd_queue;

// After a successful init, destroy exactly once after both workers quiesce.
bool farsee_cmd_queue_init(farsee_cmd_queue *q);
void farsee_cmd_queue_destroy(farsee_cmd_queue *q);
// Wake a blocked pop so it can re-check its stop flag and deadline. Does not
// set stop and does not remove or add a command.
void farsee_cmd_queue_kick(farsee_cmd_queue *q);

// Non-blocking push. When full, it first reclaims one pure move. A
// privileged release can then reclaim one held-button move or one key-down.
// Returns false for NULL input or if the queue remains full. Reclaimed
// key-downs and refused key or privileged-release commands increment dropped_keys.
bool farsee_cmd_queue_push(farsee_cmd_queue *q, const farsee_cmd *cmd);

// Pop one command; waits until the absolute monotonic deadline while empty.
// A queued command is returned even if stop is already set; stop cancels only
// an empty wait. NULL stop means no cancellation. Returns false when the empty
// wait times out or observes stop.
bool farsee_cmd_queue_pop(farsee_cmd_queue *q, farsee_cmd *out,
                          uint64_t deadline_monotonic_ms,
                          farsee_atomic_int *stop);

#ifdef __cplusplus
}
#endif

#endif /* FARSEE_INCLUDE_FARSEE_FARSEE_CMD_QUEUE_H */
