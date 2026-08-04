// SPDX-License-Identifier: Apache-2.0
//
// Farsee RDP clipboard bridge (R5 gate, §15.13, §13.3).
//
// Applies the F5 clipboard policy to RDP clipboard transfers: plain text
// only, direction enforced, size capped, terminal escapes sanitized. The
// policy logic is deterministic and testable without a live server. Live
// cliprdr channel negotiation runs against an independent RDP endpoint.
//
// PRIVATE to src/protocol/rdp/.

#ifndef FARSEE_SRC_PROTOCOL_RDP_RDP_CLIPBOARD_BRIDGE_H
#define FARSEE_SRC_PROTOCOL_RDP_RDP_CLIPBOARD_BRIDGE_H

#include "farsee/farsee_clipboard.h"

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Decide whether an inbound (remote-to-local) text transfer of `bytes` is
// permitted. Returns the action to take.
typedef enum {
    RDP_CLIP_ALLOW       = 0,   // proceed (caller will sanitize)
    RDP_CLIP_REJECT_SIZE = 1,   // exceeds max_bytes
    RDP_CLIP_REJECT_DIR  = 2,   // direction policy forbids remote-to-local
    RDP_CLIP_REJECT_FMT  = 3,   // not plain text
} rdp_clip_inbound_result;

rdp_clip_inbound_result rdp_clip_check_inbound(const farsee_clip_policy *p,
                                               size_t bytes,
                                               farsee_clip_format fmt);

// Decide whether an outbound (local-to-remote) text transfer is permitted.
bool rdp_clip_allows_outbound(const farsee_clip_policy *p, size_t bytes);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_SRC_PROTOCOL_RDP_RDP_CLIPBOARD_BRIDGE_H
