// SPDX-License-Identifier: Apache-2.0
//
// Pure arithmetic used by the RFB session.

#ifndef FARSEE_SRC_RFB_RFB_SESSION_MATH_H
#define FARSEE_SRC_RFB_RFB_SESSION_MATH_H

#include "farsee/limits.h"

#include <stdint.h>

// Convert high-resolution wheel units (120 per notch), truncating toward zero.
static inline int32_t rfb_session_wheel_notches(int32_t high_res)
{
    if (high_res >= 0) {
        return high_res / 120;
    }
    // Promote before negation so INT32_MIN remains defined.
    return (int32_t)(-((-((int64_t)high_res)) / 120));
}

// Return an absolute connect deadline. Zero selects the policy default.
static inline uint64_t
rfb_session_connect_deadline(uint64_t now_ms,
                             uint32_t configured_timeout_ms)
{
    const uint32_t timeout_ms = configured_timeout_ms == 0u
                                    ? RFB_LIMIT_CONNECT_TIMEOUT_MS
                                    : configured_timeout_ms;
    if (now_ms > UINT64_MAX - (uint64_t)timeout_ms) {
        return UINT64_MAX;
    }
    return now_ms + (uint64_t)timeout_ms;
}

#endif  // FARSEE_SRC_RFB_RFB_SESSION_MATH_H
