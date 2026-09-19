// SPDX-License-Identifier: Apache-2.0
//
// Shared live-client password acquisition.

#ifndef FARSEE_INCLUDE_FARSEE_CREDENTIAL_ACQUIRE_H
#define FARSEE_INCLUDE_FARSEE_CREDENTIAL_ACQUIRE_H

#include "farsee/farsee_security.h"

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum farsee_credential_acquire_status {
    FARSEE_CREDENTIAL_ACQUIRE_OK = 0,
    FARSEE_CREDENTIAL_ACQUIRE_INVALID,
    FARSEE_CREDENTIAL_ACQUIRE_INPUT_FAILED,
    FARSEE_CREDENTIAL_ACQUIRE_EMPTY,
    FARSEE_CREDENTIAL_ACQUIRE_TOO_LONG,
    FARSEE_CREDENTIAL_ACQUIRE_NO_MEMORY,
    FARSEE_CREDENTIAL_ACQUIRE_TERMINAL_SIGNAL,
} farsee_credential_acquire_status;

typedef struct farsee_credential_acquire_config {
    // An fd >= 0 takes precedence and transfers to this function. The
    // function closes it exactly once on every acquisition result.
    int password_fd;

    // Private test/injection seam. Production frontends leave this NULL so
    // passwords never arrive in argv or URL storage.
    const char *password_inline;

    // When true, every selected source must produce at least one byte. When
    // false and no source is selected, success returns an empty secret.
    bool required;
} farsee_credential_acquire_config;

// Acquire one complete password into the caller's empty owned secret.
// Passwords are bounded by FARSEE_CREDENTIAL_PASSWORD_MAX and are never
// shortened for a protocol. Classic VNC applies its eight-byte boundary only
// when rfb_handshake_set_password copies the acquired secret.
//
// out_password must be zero-initialized. On failure it remains empty.
// out_terminal_signal receives SIGINT, SIGTERM, or SIGHUP only when the
// result is FARSEE_CREDENTIAL_ACQUIRE_TERMINAL_SIGNAL; otherwise it is zero.
farsee_credential_acquire_status farsee_credential_acquire_password(
    const farsee_credential_acquire_config *config,
    farsee_secret *out_password, int *out_terminal_signal);

// Close a password descriptor after ownership transfers to a live frontend.
// A negative descriptor is a successful no-op. A nonnegative descriptor is
// closed once without retry, so an EINTR cannot close a reused descriptor.
bool farsee_credential_close_password_fd(int password_fd);

// Restore the default disposition and re-raise a terminal signal after the
// prompt restored its terminal and the caller finished local cleanup. A zero
// signal is a no-op. A nonzero signal does not return under its normal default
// disposition; _exit(1) is the fail-closed fallback if raise returns.
void farsee_credential_reraise_terminal_signal(int signal_number);

#ifdef __cplusplus
}
#endif

#endif /* FARSEE_INCLUDE_FARSEE_CREDENTIAL_ACQUIRE_H */
