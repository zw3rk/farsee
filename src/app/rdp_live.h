// SPDX-License-Identifier: Apache-2.0
//
// RDP live CLI path (rdp:// / --protocol rdp / port 3389 auto).
// Three-thread session after connect: protocol / present / input.
// Compiled only when FARSEE_WITH_RDP=1.

#ifndef FARSEE_SRC_APP_RDP_LIVE_H
#define FARSEE_SRC_APP_RDP_LIVE_H

#include "farsee/cli_target.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef FARSEE_WITH_RDP
#include "protocol/rdp/rdp_freerdp_facade.h"

#ifdef __cplusplus
extern "C" {
#endif

// Run an RDP live (or dump) session. Returns process exit code.
//
// Requires --user. Password via --password-fd or password_inline
// (URL userinfo passwords are rejected at CLI parse; password_inline
// is reserved for test/injection paths and is normally NULL).
//
// Live Kitty sessions use rdp_mt_run (protocol / present / input).
// Dump/null stay single-threaded with a settle window after first frame.
// cert_policy: NULL or "prompt" (default trust) vs "ignore" (allow insecure).
// liblog: FreeRDP WLog level (--verbose / --log-level).
// leader_spec: live prefix (default C-]); NULL → farsee_cli_leader_default.
int farsee_run_rdp(const char *host, uint16_t port,
                   const char *user, const char *domain,
                   const char *cert_policy, int password_fd,
                   const char *password_inline,
                   uint32_t desk_w, uint32_t desk_h,
                   const char *presenter_name, const char *dump_frame,
                   uint64_t connect_timeout_ms,
                   bool view_only, bool clipboard_on,
                   rdp_liblog_level liblog,
                   const farsee_cli_leader *leader_spec);

#ifdef __cplusplus
}
#endif

#endif /* FARSEE_WITH_RDP */

#endif /* FARSEE_SRC_APP_RDP_LIVE_H */
