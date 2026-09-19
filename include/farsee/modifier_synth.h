// SPDX-License-Identifier: Apache-2.0
//
// Protocol-neutral modifier synthesis for normalized keyboard input.

#ifndef FARSEE_INCLUDE_FARSEE_MODIFIER_SYNTH_H
#define FARSEE_INCLUDE_FARSEE_MODIFIER_SYNTH_H

#include "farsee/normalized_input.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum farsee_modifier_synth_action_kind {
    FARSEE_MODIFIER_SYNTH_ACTION_PRIMARY = 0,
    FARSEE_MODIFIER_SYNTH_ACTION_MODIFIER,
} farsee_modifier_synth_action_kind;

// One protocol delivery request. A modifier action uses a left-side keysym,
// zero text, no repeat, and one RFB_MOD_* bit. A primary action preserves the
// normalized key event and has RFB_MOD_NONE in `modifier`.
typedef struct farsee_modifier_synth_action {
    farsee_modifier_synth_action_kind kind;
    uint32_t keysym;
    uint32_t text;
    uint16_t modifier;
    bool down;
    bool repeat;
} farsee_modifier_synth_action;

typedef struct farsee_modifier_synth {
    uint16_t held;
    uint16_t reconcile;
    farsee_modifier_synth_action pending_primary;
    bool pending_primary_valid;
    bool stop_required;
} farsee_modifier_synth;

// A protocol adapter sends one normalized key action. Return true only after
// the protocol accepted the action and any protocol-specific bookkeeping
// succeeded.
typedef bool (*farsee_modifier_synth_send_fn)(
    void *user, const farsee_modifier_synth_action *action);

// The production queue adapters retain each protocol's established command
// mapping. The RFB adapter emits logical press/release commands. The RDP
// adapter also preserves text and repeat. `user` must point to an initialized
// farsee_cmd_queue (rdp_inj_queue is the same storage type).
bool farsee_modifier_synth_rfb_queue_send(
    void *user, const farsee_modifier_synth_action *action);
bool farsee_modifier_synth_rdp_queue_send(
    void *user, const farsee_modifier_synth_action *action);

// Direct RDP delivery updates its key ledger only after the protocol accepts
// the action. The live RDP single-thread path and unit tests share this exact
// adapter seam.
typedef bool (*farsee_modifier_synth_rdp_deliver_fn)(
    void *user, const farsee_modifier_synth_action *action);
typedef void (*farsee_modifier_synth_rdp_ledger_fn)(
    void *user, const farsee_modifier_synth_action *action);

typedef struct farsee_modifier_synth_rdp_direct_adapter {
    void *user;
    farsee_modifier_synth_rdp_deliver_fn deliver;
    farsee_modifier_synth_rdp_ledger_fn ledger;
} farsee_modifier_synth_rdp_direct_adapter;

bool farsee_modifier_synth_rdp_direct_send(
    void *user, const farsee_modifier_synth_action *action);

void farsee_modifier_synth_init(farsee_modifier_synth *state);

// Deliver one normalized key transaction. The state machine:
//   - reconciles a prior failed synthetic release before any primary edge;
//   - rejects unknown normalized modifier bits before sending anything;
//   - presses missing modifiers in Shift, Control, Alt, Meta order;
//   - suppresses the primary edge and cleans up if any press fails;
//   - performs legacy auto-up and releases modifiers in reverse order; and
//   - retains failed primary and modifier releases for reconciliation before
//     the next primary.
// A failed physical modifier or Caps Lock transaction requires the live
// session to stop because the demux has already accepted the local edge.
// Return true only if every required edge was supported and delivered.
bool farsee_modifier_synth_inject(farsee_modifier_synth *state,
                                  const rfb_norm_key *key,
                                  uint16_t physical_modifiers,
                                  farsee_modifier_synth_send_fn send,
                                  void *user);

uint16_t farsee_modifier_synth_held(const farsee_modifier_synth *state);
bool farsee_modifier_synth_needs_reconciliation(
    const farsee_modifier_synth *state);
bool farsee_modifier_synth_requires_stop(
    const farsee_modifier_synth *state);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_MODIFIER_SYNTH_H
