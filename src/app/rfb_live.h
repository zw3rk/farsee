// SPDX-License-Identifier: Apache-2.0
//
// Classic RFB live CLI path (vnc:// / rfb:// / bare host).
// Three-thread session after connect: protocol / present / input.

#ifndef FARSEE_SRC_APP_RFB_LIVE_H
#define FARSEE_SRC_APP_RFB_LIVE_H

#include "farsee/cli_target.h"
#include "farsee/farsee_frame_slot.h"
#include "farsee/handshake.h"
#include "farsee/rfb_session.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Run an RFB live session. Returns process exit code.
//
// Auth: maps farsee_rfb_auth_mode. On RFB 003.889 peers, policy recognizes
// types 33 and 36 and prefers 33. apple_require_type_36 withdraws type 33.
// Both Apple paths need a username (URL user or --user). Classic VNC Auth
// uses only the first eight password bytes.
//
// Live Kitty sessions use farsee_mt_run (protocol / present / input).
// Null presentation stays single-threaded on the protocol path.
// view_scale_pct: percent of max aspect-fit Kitty place (20..100).
// 0 → FARSEE_VIEW_SCALE_DEFAULT_PCT (50). Leader C-] + / - adjusts live.
// apple_attach: 0=ask (TTY prompt), 1=share console, 2=login-as-user.
// Non-interactive paths resolve ask → login.
// password_fd >= 0 transfers descriptor ownership at function entry. The
// function closes it on every return path.
int farsee_run_rfb(const char *host, uint16_t port,
                   const char *username,
                   int password_fd, bool allow_none_auth,
                   bool shared, uint8_t apple_attach,
                   farsee_rfb_auth_mode auth_mode,
                   rfb_apple_postauth_mode apple_postauth_mode,
                   bool apple_send_viewer_info,
                   bool apple_disable_wake_keys,
                   const char *presenter_name,
                   uint32_t max_fps, bool view_only,
                   const farsee_cli_leader *leader,
                   uint32_t view_scale_pct,
                   uint32_t connect_timeout_ms,
                   bool accept_new_host,
                   bool apple_require_type_36);

#ifdef __cplusplus
}
#endif

#endif /* FARSEE_SRC_APP_RFB_LIVE_H */
