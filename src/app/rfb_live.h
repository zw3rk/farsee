// SPDX-License-Identifier: Apache-2.0
//
// Classic RFB live CLI path (vnc:// / rfb:// / bare host).
// Three-thread session after connect: protocol / present / input.

#ifndef FARSEE_SRC_APP_RFB_LIVE_H
#define FARSEE_SRC_APP_RFB_LIVE_H

#include "farsee/cli_target.h"
#include "farsee/farsee_atomic.h"
#include "farsee/handshake.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Async-signal-safe cooperative stop: atomic store 1 into *flag if non-NULL.
// Safe from a signal handler when atomic_int is lock-free (asserted in tests).
// Does not restore TTY or perform any I/O.
void farsee_rfb_stop_flag_set(farsee_atomic_int *flag);

// Process-wide RFB stop request (sets the session stop flag only).
// Used by the SIGINT/SIGTERM handler; TTY restore is not done here.
void farsee_rfb_request_stop(void);

// Run an RFB live (or dump) session. Returns process exit code.
//
// Auth: maps farsee_rfb_auth_mode. On RFB 003.889 peers, type-33
// (RSA1+SRP) is selected when offered; username is required for that
// path (URL user or --user). Classic VNC Auth still uses the first 8
// bytes of the password only.
//
// Live Kitty sessions use farsee_mt_run (protocol / present / input).
// Dump/null stay single-threaded on the protocol path.
// view_scale_pct: percent of max aspect-fit Kitty place (20..100).
// 0 → FARSEE_VIEW_SCALE_DEFAULT_PCT (50). Leader C-] + / - adjusts live.
// apple_attach: 0=ask (TTY prompt), 1=share console, 2=login-as-user.
// Non-interactive / dump paths resolve ask → share.
int farsee_run_rfb(const char *host, uint16_t port,
                   const char *username,
                   int password_fd,
                   const char *password_inline, bool allow_none_auth,
                   bool shared, uint8_t apple_attach,
                   farsee_rfb_auth_mode auth_mode,
                   const char *presenter_name, const char *dump_frame,
                   uint32_t max_fps, bool view_only,
                   const farsee_cli_leader *leader,
                   uint32_t view_scale_pct,
                   uint32_t connect_timeout_ms);

#ifdef __cplusplus
}
#endif

#endif /* FARSEE_SRC_APP_RFB_LIVE_H */
