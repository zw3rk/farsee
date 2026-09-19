// SPDX-License-Identifier: Apache-2.0
//
// Three-thread live RDP session (thin wrapper over farsee_mt_session):
//   1) protocol — FreeRDP pump + inject queue drain
//   2) present  — fixed FPS, latest-wins from frame slot → Kitty
//   3) input    — TTY demux → inject queue
//
// Prefer latency: intermediate frames never shown are dropped in the slot.
//
// Threading contract:
//   - The protocol worker exclusively owns FreeRDP calls, inject application,
//     key/button ledger mutation, and link-metric publication.
//   - The present worker exclusively calls the presenter and after-present
//     callback. The input worker may only enqueue commands and request stop.
//   - FreeRDP callbacks that publish GDI frames run as part of the protocol
//     pump; the present worker consumes the copied frame-slot view.
//   - Return of any worker is terminal. The shared first-report-wins and
//     cooperative stop/kick/join rules are those in farsee_mt_session.h.

#ifndef FARSEE_SRC_PROTOCOL_RDP_RDP_MT_SESSION_H
#define FARSEE_SRC_PROTOCOL_RDP_RDP_MT_SESSION_H

#include "farsee/farsee_atomic.h"
#include "farsee/farsee_error.h"
#include "farsee/farsee_input.h"
#include "farsee/farsee_mt_session.h"
#include "farsee/farsee_presenter_v2.h"
#include "farsee/farsee_thread.h"
#include "rdp_callbacks.h"
#include "rdp_frame_slot.h"
#include "rdp_freerdp_facade.h"
#include "rdp_inj_queue.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Input loop body: called exactly once on the input thread until stop is set.
// Must only push inject commands or set stop; FreeRDP calls go via the queue.
// `user`, `inj`, `stop`, and `terminal` are borrowed for the callback duration.
typedef farsee_mt_terminal_kind (*rdp_mt_input_fn)(
    void *user, rdp_inj_queue *inj, farsee_atomic_int *stop,
    farsee_mt_terminal *terminal);

// Optional: run after each present (e.g. drain Kitty APC to stdout).
// Called only on the present thread.
typedef void (*rdp_mt_after_present_fn)(void *user);

typedef struct rdp_mt_config {
    // All pointers are borrowed through rdp_mt_run. The caller must keep them
    // valid and must not destroy ctx/sink/presenter/slot/inj until it returns.
    rdp_freerdp_ctx *ctx;
    rdp_display_sink *sink;
    // Already installed on sink. Called only by the present worker.
    farsee_presenter *presenter;
    rdp_frame_slot *slot;
    rdp_inj_queue *inj;
    // Optional protocol-worker-owned key ledger for RDP_INJ_RELEASE_ALL. When
    // NULL, RELEASE_ALL is refused at inject (not a silent success).
    farsee_key_ledger *ledger;
    // Optional protocol-worker-owned button mask updated only after successful
    // FreeRDP pointer injection. Read it only before run or after join;
    // teardown must release this mask.
    unsigned *wire_buttons;
    farsee_atomic_int *stop_flag;
    // Present cadence (ms). 16 ≈ 60 fps, 33 ≈ 30 fps.
    uint32_t present_interval_ms;
    rdp_mt_input_fn input_fn;
    void *input_user;
    rdp_mt_after_present_fn after_present_fn;
    void *after_present_user;
    // Optional: zoom/layout re-show same frame gen (same as RFB present).
    // When non-NULL, farsee_mt_present_loop honors force_repaint + slot kick.
    farsee_atomic_int *force_repaint;
    // Optional link metrics (protocol writes; other threads use atomic loads).
    // meta uses farsee_link_meta_pack; rate_pub uses farsee_link_rate_pack.
    farsee_atomic_u64 *link_meta;
    farsee_atomic_u64 *link_rx_bytes;
    farsee_atomic_u64 *link_rate_pub; // may be NULL
    // Optional borrowed mutex that serializes present-worker Kitty output
    // append against status inspection. It must outlive rdp_mt_run.
    farsee_mutex *io_mu; // may be NULL
} rdp_mt_config;

// Block until stop, callback failure, or peer disconnect. The function sets
// sink->frame_slot for the run, clears it after all three workers join, and
// returns only after no callback can access borrowed config state. It reports
// the shared first terminal outcome; clean stop/peer close return FARSEE_E_OK.
farsee_error rdp_mt_run(const rdp_mt_config *cfg, bool *out_got_frame,
                        farsee_mt_outcome *outcome);

#ifdef __cplusplus
}
#endif

#endif /* FARSEE_SRC_PROTOCOL_RDP_RDP_MT_SESSION_H */
