// SPDX-License-Identifier: Apache-2.0
//
// Three-thread live RDP session (thin wrapper over farsee_mt_session):
//   1) protocol — FreeRDP pump + inject queue drain
//   2) present  — fixed FPS, latest-wins from frame slot → Kitty
//   3) input    — TTY demux → inject queue
//
// Prefer latency: intermediate frames never shown are dropped in the slot.

#ifndef FARSEE_SRC_PROTOCOL_RDP_RDP_MT_SESSION_H
#define FARSEE_SRC_PROTOCOL_RDP_RDP_MT_SESSION_H

#include "farsee/farsee_atomic.h"
#include "farsee/farsee_error.h"
#include "farsee/farsee_input.h"
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

// Input loop body: called on the input thread until stop is set.
// Must only push inject commands / set stop; FreeRDP calls go via queue.
typedef void (*rdp_mt_input_fn)(void *user, rdp_inj_queue *inj,
                                farsee_atomic_int *stop);

// Optional: run after each present (e.g. drain Kitty APC to stdout).
// Called only on the present thread.
typedef void (*rdp_mt_after_present_fn)(void *user);

typedef struct rdp_mt_config {
    rdp_freerdp_ctx *ctx;
    rdp_display_sink *sink;
    farsee_presenter *presenter;  // already installed on sink
    rdp_frame_slot *slot;
    rdp_inj_queue *inj;
    // Optional key ledger for RDP_INJ_RELEASE_ALL (2026-07-31 T9). When
    // NULL, RELEASE_ALL is refused at inject (not a silent success).
    farsee_key_ledger *ledger;
    // Optional protocol-owned button mask updated only after successful
    // FreeRDP pointer inject (loop r3). Teardown should release this mask.
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
    // Optional link metrics (protocol thread writes; status reads).
    // meta: farsee_link_meta_pack; rate_pub: farsee_link_rate_pack (r3 T1).
    farsee_atomic_u64 *link_meta;
    farsee_atomic_u64 *link_rx_bytes;
    farsee_atomic_u64 *link_rate_pub; // may be NULL
    // Optional: serialize Kitty out buffer append vs status length (residual D2).
    farsee_mutex *io_mu; // may be NULL
} rdp_mt_config;

// Block until stop or peer disconnect. Joins all three threads before
// return. Requires sink->frame_slot == slot already set (or sets it).
farsee_error rdp_mt_run(const rdp_mt_config *cfg, bool *out_got_frame);

#ifdef __cplusplus
}
#endif

#endif /* FARSEE_SRC_PROTOCOL_RDP_RDP_MT_SESSION_H */
