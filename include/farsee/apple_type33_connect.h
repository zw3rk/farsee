// SPDX-License-Identifier: Apache-2.0
//
// farsee — Apple RFB 003.889 type-33 connect path (extracted from rfb_session).
//
// Full type-33 branch after TCP connect: client banner → security list →
// type-33 auth → live ClientInit → ServerInit → ViewerInfo prelude →
// classic cleartext setup (via hook). I/O goes through rfb_io_pump;
// session-owned FB setup is injected so this module stays free of the
// full session layout.
//
// Post-auth AEAD (ChaCha records) is NOT faked. wrap_key is returned for
// a future record layer. G17 AES-CBC must not be used against real peers.

#ifndef FARSEE_INCLUDE_FARSEE_APPLE_TYPE33_CONNECT_H
#define FARSEE_INCLUDE_FARSEE_APPLE_TYPE33_CONNECT_H

#include "farsee/error.h"
#include "farsee/rfb_io_pump.h"
#include "farsee/rfb_session.h"
#include "farsee/server_init.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Session-owned setup after ServerInit (FB resize, encodings, first FBUR).
// ctx is opaque session storage; si is a valid parsed ServerInit.
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
//     of the observed ack range, or the buffer is incomplete
//
// Peek-only contract: callers must never consume then re-append a header
// to the buffer tail (that corrupts a shared in-buffer that already holds
// the rest of an FBU). Leave non-ack / incomplete bytes in place for demux.
size_t apple_viewer_info_live_ack_consume_len(const uint8_t *data, size_t len);

// Run the full Apple type-33 connect path after TCP is up.
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
rfb_error apple_type33_connect(rfb_io_pump *pump,
                               rfb_session_config *cfg,
                               const apple_type33_connect_hooks *hooks,
                               uint8_t wrap_key_out[16],
                               bool *has_wrap_key_out,
                               rfb_session_dialect *dialect_out);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_APPLE_TYPE33_CONNECT_H
