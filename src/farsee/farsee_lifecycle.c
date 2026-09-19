// SPDX-License-Identifier: Apache-2.0
//
// Farsee common session lifecycle transition validator.
//
// The validator permits this forward path:
//   NEW -> CONFIGURED -> CONNECTING -> NEGOTIATING_SECURITY
//       -> AUTHENTICATING -> ESTABLISHING_SESSION -> ACTIVE
//       -> RECONNECTING -> CONNECTING
// Every nonterminal state also permits a self-transition, FAILED, or DRAINING;
// DRAINING permits CLOSED.

#include "farsee/farsee_lifecycle.h"

bool farsee_lifecycle_is_terminal(farsee_lifecycle_state s)
{
    return s == FARSEE_LIFECYCLE_CLOSED || s == FARSEE_LIFECYCLE_FAILED;
}

bool farsee_lifecycle_can_transition(farsee_lifecycle_state from,
                                     farsee_lifecycle_state to)
{
    // No transitions out of a terminal state.
    if (farsee_lifecycle_is_terminal(from)) {
        return false;
    }
    // Self-transition is a no-op; allow it (idempotent re-report).
    if (from == to) {
        return true;
    }
    // Any nonterminal state may go to FAILED or DRAINING.
    if (to == FARSEE_LIFECYCLE_FAILED || to == FARSEE_LIFECYCLE_DRAINING) {
        return true;
    }
    // After the generic cases above, DRAINING can only proceed to CLOSED.
    if (from == FARSEE_LIFECYCLE_DRAINING) {
        return to == FARSEE_LIFECYCLE_CLOSED;
    }
    // Forward transition edges.
    switch (from) {
    case FARSEE_LIFECYCLE_NEW:
        return to == FARSEE_LIFECYCLE_CONFIGURED;
    case FARSEE_LIFECYCLE_CONFIGURED:
        return to == FARSEE_LIFECYCLE_CONNECTING;
    case FARSEE_LIFECYCLE_CONNECTING:
        return to == FARSEE_LIFECYCLE_NEGOTIATING_SECURITY;
    case FARSEE_LIFECYCLE_NEGOTIATING_SECURITY:
        return to == FARSEE_LIFECYCLE_AUTHENTICATING;
    case FARSEE_LIFECYCLE_AUTHENTICATING:
        return to == FARSEE_LIFECYCLE_ESTABLISHING_SESSION;
    case FARSEE_LIFECYCLE_ESTABLISHING_SESSION:
        return to == FARSEE_LIFECYCLE_ACTIVE;
    case FARSEE_LIFECYCLE_ACTIVE:
        // May reconnect or begin draining (draining handled above).
        return to == FARSEE_LIFECYCLE_RECONNECTING;
    case FARSEE_LIFECYCLE_RECONNECTING:
        // Explicit reconnect goes back through connecting, or fails.
        return to == FARSEE_LIFECYCLE_CONNECTING;
    case FARSEE_LIFECYCLE_DRAINING:
    case FARSEE_LIFECYCLE_CLOSED:
    case FARSEE_LIFECYCLE_FAILED:
        // Handled above (terminal / draining); unreachable here but listed
        // to satisfy -Wswitch-enum exhaustiveness.
        return false;
    }
    return false;  // unreachable; satisfies -Wreturn-type across compilers
}

const char *farsee_lifecycle_state_name(farsee_lifecycle_state s)
{
    switch (s) {
    case FARSEE_LIFECYCLE_NEW:                   return "NEW";
    case FARSEE_LIFECYCLE_CONFIGURED:            return "CONFIGURED";
    case FARSEE_LIFECYCLE_CONNECTING:            return "CONNECTING";
    case FARSEE_LIFECYCLE_NEGOTIATING_SECURITY:  return "NEGOTIATING_SECURITY";
    case FARSEE_LIFECYCLE_AUTHENTICATING:        return "AUTHENTICATING";
    case FARSEE_LIFECYCLE_ESTABLISHING_SESSION:  return "ESTABLISHING_SESSION";
    case FARSEE_LIFECYCLE_ACTIVE:                return "ACTIVE";
    case FARSEE_LIFECYCLE_RECONNECTING:          return "RECONNECTING";
    case FARSEE_LIFECYCLE_DRAINING:              return "DRAINING";
    case FARSEE_LIFECYCLE_CLOSED:                return "CLOSED";
    case FARSEE_LIFECYCLE_FAILED:                return "FAILED";
    }
    return "UNKNOWN";
}
