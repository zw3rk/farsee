// SPDX-License-Identifier: Apache-2.0
//
// Farsee common session lifecycle states and transition rules.
//
// These are the externally visible session states common to every engine.
// An engine MAY expose a sanitized protocol-specific subphase, but the
// coarse lifecycle is universal and validated here.

#ifndef FARSEE_INCLUDE_FARSEE_FARSEE_LIFECYCLE_H
#define FARSEE_INCLUDE_FARSEE_FARSEE_LIFECYCLE_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    FARSEE_LIFECYCLE_NEW                   = 0,
    FARSEE_LIFECYCLE_CONFIGURED            = 1,
    FARSEE_LIFECYCLE_CONNECTING            = 2,
    FARSEE_LIFECYCLE_NEGOTIATING_SECURITY  = 3,
    FARSEE_LIFECYCLE_AUTHENTICATING        = 4,
    FARSEE_LIFECYCLE_ESTABLISHING_SESSION  = 5,
    FARSEE_LIFECYCLE_ACTIVE                = 6,
    FARSEE_LIFECYCLE_RECONNECTING          = 7,  // optional, explicit
    FARSEE_LIFECYCLE_DRAINING              = 8,
    FARSEE_LIFECYCLE_CLOSED                = 9,
    FARSEE_LIFECYCLE_FAILED                = 10,
} farsee_lifecycle_state;

// True iff `s` is a terminal state (no further transitions out).
bool farsee_lifecycle_is_terminal(farsee_lifecycle_state s);

// True iff `from -> to` is a legal transition per §6.1.
//   - forward edges along the happy path;
//   - any nonterminal -> DRAINING (cancellation);
//   - any nonterminal -> FAILED (error/cancel);
//   - ACTIVE -> RECONNECTING and RECONNECTING -> CONNECTING (explicit);
//   - nothing leaves a terminal state.
bool farsee_lifecycle_can_transition(farsee_lifecycle_state from,
                                     farsee_lifecycle_state to);

// Stable literal name (for diagnostics). Never secrets.
const char *farsee_lifecycle_state_name(farsee_lifecycle_state s);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_FARSEE_LIFECYCLE_H
