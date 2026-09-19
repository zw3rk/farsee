// SPDX-License-Identifier: Apache-2.0
//
// Farsee RDP cliprdr client wiring (R6 plain-text clipboard, §15.13).
//
// Registers the FreeRDP cliprdr channel addin + PubSub handlers and applies
// the F5/R5 policy (rdp_clipboard_bridge + farsee_clip_sanitize_text) to
// text-only transfers. Host pasteboard I/O is via rdp_host_clipboard.
//
// FreeRDP types stay confined to the .c file. PRIVATE to src/protocol/rdp/.
// Only compiled when FARSEE_WITH_RDP=1.

#ifndef FARSEE_SRC_PROTOCOL_RDP_RDP_CLIPRDR_H
#define FARSEE_SRC_PROTOCOL_RDP_RDP_CLIPRDR_H

#include "rdp_freerdp_facade.h"
#include "farsee/farsee_clipboard.h"

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Call once when installing callbacks (from rdp_callbacks_install).
// Registers the static addin provider + sets LoadChannels if not already,
// and subscribes PubSub ChannelConnected for "cliprdr".
// Returns false on NULL ctx or FreeRDP setup failure.
bool rdp_cliprdr_prepare_instance(rdp_freerdp_ctx *ctx);

// Bind policy + optional enable. Call before connect when clipboard is
// desired. Copies the policy (NULL policy disables). When enabled is
// false, ChannelConnected will not install cliprdr callbacks (and
// FreeRDP_RedirectClipboard is already gated by the channel allowlist).
void rdp_cliprdr_configure(rdp_freerdp_ctx *ctx,
                           const farsee_clip_policy *policy,
                           bool enabled);

// True when configure() last set enabled=true on this instance (NULL-safe).
// Intended for tests and diagnostics.
bool rdp_cliprdr_is_enabled(const rdp_freerdp_ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_SRC_PROTOCOL_RDP_RDP_CLIPRDR_H
