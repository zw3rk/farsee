// SPDX-License-Identifier: Apache-2.0
//
// Bounded input-command queue: input thread → protocol thread.
// Latest-wins for pure mouse moves when full; keys are never dropped if
// any slot can be reclaimed from a move. Protocol-neutral.

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
    uint64_t dropped_keys;  // KEY / RELEASE_ALL refused when full of non-moves
} farsee_cmd_queue;

bool farsee_cmd_queue_init(farsee_cmd_queue *q);
void farsee_cmd_queue_destroy(farsee_cmd_queue *q);
void farsee_cmd_queue_kick(farsee_cmd_queue *q);

// Non-blocking push. When full, drops one pure move (latest-wins) to make
// room. Privileged releases (key-up, RELEASE_ALL, pointer falling edge) may
// also reclaim an unpaired key-down. Returns false only if still full so
// press/release pairing cannot go silently missing.
bool farsee_cmd_queue_push(farsee_cmd_queue *q, const farsee_cmd *cmd);

// Pop one command; waits until deadline or stop. Returns false if empty
// on timeout/stop.
bool farsee_cmd_queue_pop(farsee_cmd_queue *q, farsee_cmd *out,
                          uint64_t deadline_monotonic_ms,
                          farsee_atomic_int *stop);

#ifdef __cplusplus
}
#endif

#endif /* FARSEE_INCLUDE_FARSEE_FARSEE_CMD_QUEUE_H */
