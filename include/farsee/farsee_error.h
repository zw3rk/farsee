// SPDX-License-Identifier: Apache-2.0
//
// Farsee common structured error contract.
//
// This is the common, protocol-neutral structured error. It is DISTINCT
// from the existing flat `rfb_error` enum in include/farsee/error.h:
//   - `rfb_error` is the RFB protocol engine's internal code, preserved
//     per §5.2 (protocol-internal names remain).
//   - `farsee_error` is the common architecture's structured error that
//     all engines (RFB, RDP, ...) map their failures into above the
//     engine boundary.
//
// A farsee_error carries:
//   - a stable code;
//   - a subsystem (where it originated);
//   - a lifecycle phase;
//   - retryability + user-action classification (derived from the code);
//   - a sanitized human message (never secrets);
//   - a bounded causal chain.
//
// Secret safety (§7.3): the message field is caller-controlled prose.
// Callers MUST NOT pass passwords, tokens, certificate blobs, clipboard
// contents, or attacker-controlled remote text into the builder. The
// builder never appends platform errno strings or paths.

#ifndef FARSEE_INCLUDE_FARSEE_FARSEE_ERROR_H
#define FARSEE_INCLUDE_FARSEE_FARSEE_ERROR_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Maximum depth of the causal chain. Deep nesting is clamped to this, not
// allowed to overflow (see farsee_error__bounded_chain test).
#define FARSEE_ERROR_MAX_CAUSE_DEPTH 8

// Stable error categories (§7.2). Append-only; never renumber.
typedef enum {
    FARSEE_E_OK                          = 0,
    FARSEE_ERR_CONFIGURATION             = 1,
    FARSEE_ERR_UNSUPPORTED_FEATURE       = 2,
    FARSEE_ERR_RESOURCE_LIMIT            = 3,
    FARSEE_ERR_OUT_OF_MEMORY             = 4,
    FARSEE_ERR_CANCELLED                 = 5,
    FARSEE_ERR_TIMEOUT                   = 6,
    FARSEE_ERR_DNS_FAILURE               = 7,
    FARSEE_ERR_CONNECT_FAILURE           = 8,
    FARSEE_ERR_TRANSPORT_CLOSED          = 9,
    FARSEE_ERR_TLS_FAILURE               = 10,
    FARSEE_ERR_PEER_IDENTITY_UNTRUSTED   = 11,
    FARSEE_ERR_PEER_IDENTITY_CHANGED     = 12,
    FARSEE_ERR_AUTHENTICATION_REJECTED   = 13,
    FARSEE_ERR_AUTHENTICATION_UNAVAILABLE = 14,
    FARSEE_ERR_PROTOCOL_VIOLATION        = 15,
    FARSEE_ERR_CODEC_FAILURE             = 16,
    FARSEE_ERR_CHANNEL_FAILURE           = 17,
    FARSEE_ERR_PRESENTER_FAILURE         = 18,
    FARSEE_ERR_LOCAL_IO_FAILURE          = 19,
    FARSEE_ERR_THIRD_PARTY_BACKEND_FAILURE = 20,
    FARSEE_ERR_STATE                     = 21,  // operation invalid in current state
    FARSEE_ERR_INTERNAL                  = 22,  // invariant violated (bug)
} farsee_error_code;

// Subsystem origin (§7.1).
typedef enum {
    FARSEE_SUB_NONE    = 0,
    FARSEE_SUB_CORE    = 1,
    FARSEE_SUB_TRANSPORT = 2,
    FARSEE_SUB_TLS     = 3,
    FARSEE_SUB_TRUST   = 4,
    FARSEE_SUB_RFB     = 5,
    FARSEE_SUB_RDP     = 6,
    FARSEE_SUB_SPICE   = 7,
    FARSEE_SUB_AHPSS   = 8,
    FARSEE_SUB_PRESENTER = 9,
    FARSEE_SUB_INPUT   = 10,
    FARSEE_SUB_CLIPBOARD = 11,
} farsee_subsystem;

// Lifecycle phase at which the error occurred (mirrors farsee_lifecycle_state).
typedef enum {
    FARSEE_PHASE_NONE                   = 0,
    FARSEE_PHASE_NEW                    = 1,
    FARSEE_PHASE_CONFIGURED             = 2,
    FARSEE_PHASE_CONNECTING             = 3,
    FARSEE_PHASE_NEGOTIATING_SECURITY   = 4,
    FARSEE_PHASE_AUTHENTICATING         = 5,
    FARSEE_PHASE_ESTABLISHING_SESSION   = 6,
    FARSEE_PHASE_ACTIVE                 = 7,
    FARSEE_PHASE_RECONNECTING           = 8,
    FARSEE_PHASE_DRAINING               = 9,
    FARSEE_PHASE_CLOSED                 = 10,
    FARSEE_PHASE_FAILED                 = 11,
} farsee_phase;

// The structured error. message is a borrowed pointer (static literal or
// a buffer owned elsewhere); farsee_error does not copy it. cause, if
// non-NULL, points to another farsee_error (typically stack-allocated by
// the caller as the root cause).
typedef struct farsee_error {
    farsee_error_code code;
    farsee_subsystem  subsystem;
    farsee_phase      phase;
    const char       *message;          // sanitized prose; may be NULL
    const struct farsee_error *cause;   // bounded chain; NULL at end
} farsee_error;

// --- Constructors ----------------------------------------------------------

// Minimal structured error (no message, no cause).
farsee_error farsee_error_make(farsee_error_code code,
                               farsee_subsystem subsystem,
                               farsee_phase phase);

// With a sanitized message. `msg` MUST be caller-owned, static, or
// outlive the error's use. Must never contain secrets.
farsee_error farsee_error_make_with_msg(farsee_error_code code,
                                        farsee_subsystem subsystem,
                                        farsee_phase phase,
                                        const char *msg);

// With a causal parent. Chain depth is clamped to
// FARSEE_ERROR_MAX_CAUSE_DEPTH: if `parent` is already at the depth
// limit, the new error's cause is set to NULL rather than overflowing.
farsee_error farsee_error_make_with_cause(farsee_error_code code,
                                          farsee_subsystem subsystem,
                                          farsee_phase phase,
                                          const farsee_error *parent);

// --- Accessors -------------------------------------------------------------

// True iff the code is a failure (anything except FARSEE_E_OK).
bool farsee_error_failed(farsee_error e);

// Retryability classification (§7). Transient/network errors are
// retryable; trust/auth/cancel/internal errors are NOT. "Retryable" means
// the *same* operation may be tried again (e.g. reconnect). It NEVER
// authorizes retrying a weaker security method or a different protocol
// after a trust/auth failure (§6.2, §10.5).
bool farsee_error_is_retryable(farsee_error e);

// Whether user action is required (e.g. re-enter credentials, approve a
// changed certificate, fix configuration).
bool farsee_error_requires_user_action(farsee_error e);

// Returns e.message if set, otherwise a stable static literal describing
// the code. Never returns NULL; never contains paths or secrets.
const char *farsee_error_message_or_default(farsee_error e);

// Stable literal name for a code (e.g. "FARSEE_ERR_TIMEOUT").
const char *farsee_error_code_name(farsee_error_code code);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_FARSEE_ERROR_H
