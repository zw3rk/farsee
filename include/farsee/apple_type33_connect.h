// SPDX-License-Identifier: Apache-2.0
//
// farsee — Apple RFB 003.889 SRP connect path.
//
// After TCP connect, this path handles the client banner, security selection,
// Apple SRP authentication, ClientInit, ServerInit, ViewerInfo handling, and
// the caller-provided setup hook through rfb_io_pump.
//
// The caller receives the wrap key; this module does not frame post-auth
// records.

#ifndef FARSEE_INCLUDE_FARSEE_APPLE_TYPE33_CONNECT_H
#define FARSEE_INCLUDE_FARSEE_APPLE_TYPE33_CONNECT_H

#include "farsee/error.h"
#include "farsee/handshake.h"
#include "farsee/rfb_io_pump.h"
#include "farsee/rfb_session.h"
#include "farsee/server_init.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Caller-provided setup after ServerInit (framebuffer size, encodings, first FBUR).
// ctx is opaque caller storage; si is a valid parsed ServerInit.
typedef struct apple_type33_connect_hooks {
    void *ctx;
    rfb_error (*setup_after_server_init)(void *ctx, const rfb_server_init *si);
} apple_type33_connect_hooks;

// Pure: how many leading bytes of `data` form a complete ViewerInfo-live
// server ack (u16be body_len + body) that may be consumed.
//
// Returns:
//   - 2 + body_len when a full, plausible ack is present
//   - 0 when the prefix looks like classic FBU (00 00…), body_len is out
//     of the supported ack range, or the buffer is incomplete
//
// Peek-only contract: callers must never consume then re-append a header
// to the buffer tail (that corrupts a shared in-buffer that already holds
// the rest of an FBU). Leave non-ack / incomplete bytes in place for demux.
size_t apple_viewer_info_live_ack_consume_len(const uint8_t *data, size_t len);

// Run the Apple SRP connect path after TCP is up.
//
// Precondition: TCP connected; server banner already consumed (caller
// selected this path from RFB 003.889 / auth_mode APPLE). pump must have
// valid io/in/out (and optionally last_error/stop_flag).
//
// On success:
//   - wrap_key_out holds 16 bytes (caller zeroizes when done with secret)
//   - *has_wrap_key_out = true
//   - *dialect_out = RFB_SESSION_DIALECT_APPLE_CLEARTEXT_MVP
//   - cfg->apple_attach may be resolved from ASK → SHARE/LOGIN
//   - hooks->setup_after_server_init has been invoked successfully
//
// On failure returns a typed rfb_error and may set pump->last_error.
// Secrets used during auth are zeroized before return.
// sk32_out: optional; when non-NULL, receives SHA-256(SRP K) (32 bytes).
// Caller must zeroize. Pass NULL if unused.
// Security policy for the Apple connect path, including the preference
// between types 33 and 36.
farsee_rfb_security_policy apple_connect_security_policy(
    const rfb_session_config *cfg);

// Build the default per-user trust-store path. Returns false and leaves an
// empty string when HOME is missing or the full path does not fit.
bool apple_type33_known_hosts_path(char *out, size_t cap, const char *home);

rfb_error apple_type33_connect(rfb_io_pump *pump,
                               rfb_session_config *cfg,
                               const apple_type33_connect_hooks *hooks,
                               uint8_t wrap_key_out[16],
                               bool *has_wrap_key_out,
                               rfb_session_dialect *dialect_out,
                               uint8_t *sk32_out);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_APPLE_TYPE33_CONNECT_H
