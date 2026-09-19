// SPDX-License-Identifier: Apache-2.0
//
// Private RDP live input and shell-operations owner.

#ifndef FARSEE_SRC_APP_RDP_LIVE_INPUT_H
#define FARSEE_SRC_APP_RDP_LIVE_INPUT_H

#ifdef FARSEE_WITH_RDP

#include "app/live_shell.h"
#include "farsee/buffer.h"
#include "farsee/farsee_atomic.h"
#include "farsee/farsee_input.h"
#include "farsee/modifier_synth.h"
#include "protocol/rdp/rdp_callbacks.h"
#include "protocol/rdp/rdp_frame_slot.h"
#include "protocol/rdp/rdp_freerdp_facade.h"
#include "protocol/rdp/rdp_inj_queue.h"
#include "protocol/rdp/rdp_mt_session.h"

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Live-session state shared by the connection owner and input owner. The
// caller owns every pointer and keeps it valid until the MT session joins.
// process_stop is required before shell binding or input execution. It must
// refer to session-lived storage so quit and signal paths share one latch.
typedef struct rdp_live_tick {
    farsee_live_shell shell;
    farsee_live_shell_ops shell_ops;
    rfb_buffer *kitty_out;
    rdp_freerdp_ctx *ctx;
    farsee_key_ledger ledger;
    unsigned prev_buttons;
    rdp_display_sink *sink;
    bool verbose;
    bool log_flowing;
    rdp_inj_queue *inj;
    unsigned wire_buttons;
    bool need_home;
    farsee_atomic_u64 link_meta;
    farsee_atomic_u64 link_rx_bytes;
    farsee_atomic_u64 link_rate_pub;
    farsee_modifier_synth synth_mods;
    farsee_atomic_int force_repaint;
    rdp_frame_slot *slot;
    farsee_atomic_int *process_stop;
} rdp_live_tick;

void rdp_live_log(rdp_live_tick *tick, const char *fmt, ...)
#if defined(__GNUC__) || defined(__clang__)
    __attribute__((format(printf, 2, 3)))
#endif
    ;

void rdp_live_bind_shell_ops(rdp_live_tick *tick);
farsee_mt_terminal_kind rdp_live_input_fn(
    void *user, rdp_inj_queue *inj, farsee_atomic_int *stop,
    farsee_mt_terminal *terminal);

#ifdef __cplusplus
}
#endif

#else

// Keep the unconditionally listed product translation unit non-empty when
// the optional RDP feature is disabled.
typedef struct rdp_live_input_disabled rdp_live_input_disabled;

#endif  // FARSEE_WITH_RDP

#endif  // FARSEE_SRC_APP_RDP_LIVE_INPUT_H
