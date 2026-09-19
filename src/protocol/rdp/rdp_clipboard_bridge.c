// SPDX-License-Identifier: Apache-2.0
//
// Farsee RDP clipboard bridge implementation (R5 gate, §15.13).

#include "rdp_clipboard_bridge.h"

rdp_clip_inbound_result rdp_clip_check_inbound(const farsee_clip_policy *p,
                                               size_t bytes,
                                               farsee_clip_format fmt)
{
    if (p == NULL) {
        return RDP_CLIP_REJECT_DIR;  // fail closed
    }
    // §13.3: plain text only.
    if (fmt != FARSEE_CLIP_FORMAT_UTF8_TEXT) {
        return RDP_CLIP_REJECT_FMT;
    }
    // Direction policy: remote-to-local must be allowed.
    if (!farsee_clip_policy_allows(p, FARSEE_CLIP_DIRECTION_REMOTE_TO_LOCAL)) {
        return RDP_CLIP_REJECT_DIR;
    }
    // Size cap.
    if (!farsee_clip_policy_size_ok(p, bytes)) {
        return RDP_CLIP_REJECT_SIZE;
    }
    return RDP_CLIP_ALLOW;
}

bool rdp_clip_allows_outbound(const farsee_clip_policy *p, size_t bytes)
{
    if (p == NULL) {
        return false;
    }
    if (!farsee_clip_policy_allows(p, FARSEE_CLIP_DIRECTION_LOCAL_TO_REMOTE)) {
        return false;
    }
    return farsee_clip_policy_size_ok(p, bytes);
}
