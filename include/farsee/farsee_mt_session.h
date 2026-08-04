// SPDX-License-Identifier: Apache-2.0
//
// Three-thread live session skeleton (protocol / present / input).
//
// Protocol-neutral: engines supply three callbacks; the shared runner
// creates threads, joins protocol first, then kicks and joins the others.
// Prefer latency: intermediate frames never shown are dropped in the slot.

#ifndef FARSEE_INCLUDE_FARSEE_FARSEE_MT_SESSION_H
#define FARSEE_INCLUDE_FARSEE_FARSEE_MT_SESSION_H

#include "farsee/farsee_atomic.h"
#include "farsee/farsee_cmd_queue.h"
#include "farsee/farsee_error.h"
#include "farsee/farsee_frame_slot.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Protocol loop body: engine I/O, decode, inject from queue, publish frames.
// Runs until stop is set (or the engine sets it). Must only touch FreeRDP /
// RFB socket / parsers on this thread.
typedef void (*farsee_mt_protocol_fn)(void *user, farsee_frame_slot *slot,
                                      farsee_cmd_queue *cmds,
                                      farsee_atomic_int *stop);

// Present loop body: fixed FPS, latest-wins from slot. Or call
// farsee_mt_present_loop from inside.
typedef void (*farsee_mt_present_fn)(void *user, farsee_frame_slot *slot,
                                     farsee_atomic_int *stop);

// Input loop body: TTY demux → command queue only.
typedef void (*farsee_mt_input_fn)(void *user, farsee_cmd_queue *cmds,
                                   farsee_atomic_int *stop);

// Optional: run after each present (e.g. drain Kitty APC to stdout).
// Called only on the present thread.
typedef void (*farsee_mt_after_present_fn)(void *user);

// Called with each acquired frame view. Return true if a present happened
// (triggers optional after_present).
typedef bool (*farsee_mt_on_frame_fn)(void *user, const farsee_frame_view *v);

typedef struct farsee_mt_config {
    farsee_frame_slot *slot;
    farsee_cmd_queue *cmds;
    farsee_atomic_int *stop_flag;
    farsee_mt_protocol_fn protocol_fn;
    void *protocol_user;
    farsee_mt_present_fn present_fn;
    void *present_user;
    farsee_mt_input_fn input_fn;
    void *input_user;
} farsee_mt_config;

// Create three threads, block until they exit. Joins protocol first, then
// sets *stop_flag, kicks slot/cmds, and joins present + input.
// Returns FARSEE_E_OK on clean stop, FARSEE_ERR_STATE on bad config /
// thread create failure.
farsee_error farsee_mt_run(const farsee_mt_config *cfg);

// Fixed-FPS present helper: acquire latest, call on_frame, optional
// after_present when on_frame returns true. interval_ms 0 → 16 (~60 fps).
// If force_repaint is non-NULL and load != 0, on_frame is called even for
// an already-attempted generation; the flag is cleared via exchange(0).
// Pair with farsee_frame_slot_kick so the present thread wakes immediately.
// last_gen / generation skip state is owned only by this present loop —
// input must not write generation counters; set force_repaint + kick only.
void farsee_mt_present_loop(farsee_frame_slot *slot,
                            farsee_atomic_int *stop, uint32_t interval_ms,
                            farsee_mt_on_frame_fn on_frame, void *on_frame_user,
                            farsee_mt_after_present_fn after_present,
                            void *after_present_user,
                            farsee_atomic_int *force_repaint);

#ifdef __cplusplus
}
#endif

#endif /* FARSEE_INCLUDE_FARSEE_FARSEE_MT_SESSION_H */
