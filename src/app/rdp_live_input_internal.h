// SPDX-License-Identifier: Apache-2.0
//
// Private RDP input-loop boundary for deterministic owner tests.

#ifndef FARSEE_SRC_APP_RDP_LIVE_INPUT_INTERNAL_H
#define FARSEE_SRC_APP_RDP_LIVE_INPUT_INTERNAL_H

#include "app/rdp_live_input.h"

#ifdef FARSEE_WITH_RDP

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

// A supplied table must contain every operation. Each operation keeps its
// normal production contract; the table substitutes time, host I/O, and the
// shell presentation effects that the input owner schedules.
typedef struct rdp_live_input_ops {
    void *user;
    uint64_t (*monotonic_ms)(void *user);
    bool (*probe_winsize)(void *user, int fd, uint16_t *cols,
                          uint16_t *rows, uint16_t *pixel_width,
                          uint16_t *pixel_height);
    bool (*refresh_layout)(void *user, farsee_live_shell *shell,
                           bool apply_kitty);
    void (*draw_status)(void *user, farsee_live_shell *shell);
    int (*poll_input)(void *user, int fd, int timeout_ms,
                      short *out_revents, int *out_error);
    ssize_t (*read_input)(void *user, int fd, uint8_t *buffer, size_t capacity,
                          int *out_error);
} rdp_live_input_ops;

farsee_mt_terminal_kind rdp_live_input_run(
    rdp_live_tick *tick, rdp_inj_queue *inj, farsee_atomic_int *stop,
    farsee_mt_terminal *terminal, const rdp_live_input_ops *ops);

#endif  // FARSEE_WITH_RDP

#endif  // FARSEE_SRC_APP_RDP_LIVE_INPUT_INTERNAL_H
