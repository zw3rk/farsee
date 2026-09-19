// SPDX-License-Identifier: Apache-2.0
//
// Three-thread live session skeleton (protocol / present / input).
//
// Protocol-neutral: engines supply three callbacks; the shared runner
// creates threads, joins protocol first, then kicks and joins the others.
// The frame slot can overwrite intermediate frames that were not acquired.

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

typedef enum farsee_mt_terminal_kind {
    FARSEE_MT_TERMINAL_NONE = 0,
    FARSEE_MT_TERMINAL_REQUESTED_STOP = 1,
    FARSEE_MT_TERMINAL_PEER_CLOSED = 2,
    FARSEE_MT_TERMINAL_PROTOCOL_FAILURE = 3,
    FARSEE_MT_TERMINAL_PRESENTER_FAILURE = 4,
    FARSEE_MT_TERMINAL_INPUT_FAILURE = 5,
    FARSEE_MT_TERMINAL_THREAD_CREATION_FAILURE = 6,
    FARSEE_MT_TERMINAL_ALLOCATION_FAILURE = 7,
    FARSEE_MT_TERMINAL_INTERNAL_FAILURE = 8,
} farsee_mt_terminal_kind;

// A single atomic latch shared by all three worker threads. The first valid,
// non-NONE report wins, and later reports cannot replace it. Reporting is
// thread-safe. The runner owns the latch storage and keeps it alive until every
// callback has returned.
typedef struct farsee_mt_terminal {
    farsee_atomic_int kind;
} farsee_mt_terminal;

typedef struct farsee_mt_outcome {
    farsee_mt_terminal_kind kind;
    farsee_error error;
} farsee_mt_outcome;

void farsee_mt_terminal_init(farsee_mt_terminal *terminal);
bool farsee_mt_terminal_report(farsee_mt_terminal *terminal,
                               farsee_mt_terminal_kind kind);
farsee_mt_terminal_kind farsee_mt_terminal_load(
    const farsee_mt_terminal *terminal);
farsee_error farsee_mt_terminal_error(farsee_mt_terminal_kind kind);

// Protocol loop body: engine I/O, decode, inject from queue, publish frames.
// Exactly one protocol callback runs on its dedicated worker. It must keep all
// FreeRDP/RFB socket/parser access on that thread and return a terminal kind
// when it exits. It may report a more precise terminal kind before teardown;
// first report wins.
typedef farsee_mt_terminal_kind (*farsee_mt_protocol_fn)(
    void *user, farsee_frame_slot *slot, farsee_cmd_queue *cmds,
    farsee_atomic_int *stop, farsee_mt_terminal *terminal);

// Present loop body: exactly one dedicated present worker. It is the sole
// presenter caller and frame-view consumer in the product topology. It may
// use farsee_mt_present_loop as its loop body.
typedef farsee_mt_terminal_kind (*farsee_mt_present_fn)(
    void *user, farsee_frame_slot *slot, farsee_atomic_int *stop,
    farsee_mt_terminal *terminal);

// Input loop body: exactly one dedicated input worker. It may read/demux TTY,
// push commands, and request stop; it must not touch protocol-engine state.
typedef farsee_mt_terminal_kind (*farsee_mt_input_fn)(
    void *user, farsee_cmd_queue *cmds, farsee_atomic_int *stop,
    farsee_mt_terminal *terminal);

typedef farsee_thread *(*farsee_mt_thread_create_fn)(farsee_thread_fn fn,
                                                     void *arg);

// Optional: run after each present cadence step (e.g. drain Kitty APC to
// stdout). Called only on the present thread. The borrowed user pointer must
// remain valid until farsee_mt_present_loop returns.
typedef void (*farsee_mt_after_present_fn)(void *user);

// Called only on the present thread with a borrowed acquired view. The callback
// must not retain or release the view. Return true to report a successful
// present. The optional after_present callback runs after either result, and
// the loop releases the view after both callbacks.
typedef bool (*farsee_mt_on_frame_fn)(void *user, const farsee_frame_view *v);

typedef struct farsee_mt_config {
    // Every pointer in this config is borrowed. The config, users, slot, queue,
    // stop flag, and optional thread-create seam must remain valid until
    // farsee_mt_run returns. The runner does not destroy caller-owned objects.
    farsee_frame_slot *slot;
    farsee_cmd_queue *cmds;
    farsee_atomic_int *stop_flag;
    farsee_mt_protocol_fn protocol_fn;
    void *protocol_user;
    farsee_mt_present_fn present_fn;
    void *present_user;
    farsee_mt_input_fn input_fn;
    void *input_user;
    // Optional deterministic failure seam. NULL uses farsee_thread_create.
    // A replacement must create a joinable worker with the same semantics and
    // must not call fn inline before returning.
    farsee_mt_thread_create_fn thread_create;
} farsee_mt_config;

// Create exactly three workers and block until they exit. No callback starts
// until all three workers exist. Failure to create any worker invokes no
// callback, requests stop, joins created workers, and reports THREAD_CREATION.
//
// Return of any callback is terminal: its kind is reported, stop is set, and
// slot/queue waiters are kicked. The runner joins protocol first, then requests
// stop again and joins present and input. There is no forced thread cancel;
// callbacks must observe stop/wake-ups and return. The first valid terminal
// report wins. If none is reported, INTERNAL_FAILURE is returned. Requested
// stop and clean peer close map to FARSEE_E_OK; `outcome`, when non-NULL,
// receives the winning kind and its structured error.
farsee_error farsee_mt_run(const farsee_mt_config *cfg,
                           farsee_mt_outcome *outcome);

// Fixed-FPS present helper: acquire latest and call on_frame for each new or
// forced generation. The optional after_present callback runs after each frame
// attempt (success or failure) and on empty cadence ticks so output draining and
// cooperative stop can progress while no frame is available. interval_ms 0 →
// 16 (~60 fps).
// If force_repaint is non-NULL and load != 0, on_frame is called even for
// an already-attempted generation; the flag is cleared via exchange(0).
// Pair with farsee_frame_slot_kick so the present thread wakes immediately.
// last_gen / generation skip state is owned only by this present loop —
// input must not write generation counters; set force_repaint + kick only.
farsee_mt_terminal_kind farsee_mt_present_loop(
    farsee_frame_slot *slot, farsee_atomic_int *stop, uint32_t interval_ms,
    farsee_mt_on_frame_fn on_frame, void *on_frame_user,
    farsee_mt_after_present_fn after_present, void *after_present_user,
    farsee_atomic_int *force_repaint, farsee_mt_terminal *terminal);

#ifdef __cplusplus
}
#endif

#endif /* FARSEE_INCLUDE_FARSEE_FARSEE_MT_SESSION_H */
