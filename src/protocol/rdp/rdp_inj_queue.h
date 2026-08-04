// SPDX-License-Identifier: Apache-2.0
//
// RDP inject queue: thin wrapper over farsee_cmd_queue.
// Keeps rdp_inj_cmd shape (keysym/unicode/down/repeat) for main/callbacks.

#ifndef FARSEE_SRC_PROTOCOL_RDP_RDP_INJ_QUEUE_H
#define FARSEE_SRC_PROTOCOL_RDP_RDP_INJ_QUEUE_H

#include "farsee/farsee_atomic.h"
#include "farsee/farsee_cmd_queue.h"
#include "farsee/farsee_input.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RDP_INJ_QUEUE_CAP FARSEE_CMD_QUEUE_CAP

typedef enum {
    RDP_INJ_KEY = 1,
    RDP_INJ_POINTER,
    RDP_INJ_RELEASE_ALL,
} rdp_inj_kind;

// RDP-facing command form (keysym path used by main.c live input).
typedef struct rdp_inj_cmd {
    rdp_inj_kind kind;
    uint32_t keysym;
    uint32_t unicode;
    bool down;
    bool repeat;
    farsee_pointer_event pe;
    unsigned prev_buttons;
} rdp_inj_cmd;

// Storage is farsee_cmd_queue; dropped_moves is the same field name.
typedef farsee_cmd_queue rdp_inj_queue;

bool rdp_inj_queue_init(rdp_inj_queue *q);
void rdp_inj_queue_destroy(rdp_inj_queue *q);
void rdp_inj_queue_kick(rdp_inj_queue *q);

// Non-blocking push. Converts rdp_inj_cmd → farsee_cmd.
bool rdp_inj_queue_push(rdp_inj_queue *q, const rdp_inj_cmd *cmd);

// Pop one command; converts farsee_cmd → rdp_inj_cmd.
bool rdp_inj_queue_pop(rdp_inj_queue *q, rdp_inj_cmd *out,
                       uint64_t deadline_monotonic_ms,
                       farsee_atomic_int *stop);

#ifdef __cplusplus
}
#endif

#endif /* FARSEE_SRC_PROTOCOL_RDP_RDP_INJ_QUEUE_H */
