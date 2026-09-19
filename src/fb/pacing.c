// SPDX-License-Identifier: Apache-2.0
//
// farsee — request pacing state machine.

#include "farsee/pacing.h"

#include <string.h>

void rfb_pacing_init(rfb_pacing *p, uint32_t max_fps)
{
    if (p == NULL) return;
    memset(p, 0, sizeof *p);
    p->max_fps = max_fps;
}

bool rfb_pacing_should_send_request(rfb_pacing *p, bool *incremental,
                                    uint64_t now_ms)
{
    if (p == NULL || incremental == NULL) return false;
    if (p->request_outstanding) return false;
    if (p->backpressure) return false;
    // Cap FBUR rate to max_fps so a chatty peer + full-frame 4K decode
    // cannot run unbounded (one outstanding alone still allows hundreds
    // of tiny update/request round-trips per second).
    if (p->max_fps > 0u && p->has_sent_request) {
        const uint64_t interval = 1000u / (uint64_t)p->max_fps;
        if (now_ms - p->last_request_ms < interval) {
            return false;
        }
    }
    *incremental = p->initial_sent;  // false on first, true after
    return true;
}

void rfb_pacing_request_sent(rfb_pacing *p, bool incremental, uint64_t now_ms)
{
    if (p == NULL) return;
    p->request_outstanding = true;
    p->last_request_ms = now_ms;
    p->has_sent_request = true;
    if (!incremental) {
        p->initial_sent = true;
    }
}

void rfb_pacing_update_received(rfb_pacing *p)
{
    if (p == NULL) return;
    p->request_outstanding = false;
    p->metrics_updates_received++;
}

void rfb_pacing_force_full_refresh(rfb_pacing *p)
{
    if (p == NULL) return;
    p->request_outstanding = false;
    p->initial_sent = false;
    // Allow the next FBUR immediately (do not wait out max_fps since the
    // previous request). Critical for type-33 wake: first paint is often
    // black and we need a second full paint without a 33ms+ stall.
    p->has_sent_request = false;
    p->last_request_ms = 0;
}

void rfb_pacing_set_backpressure(rfb_pacing *p, bool active)
{
    if (p == NULL) return;
    p->backpressure = active;
}

void rfb_pacing_presented(rfb_pacing *p, uint64_t now_ms, uint32_t rect_count,
                          size_t bytes_decoded)
{
    if (p == NULL) return;
    p->last_present_ms = now_ms;
    p->metrics_presentations++;
    p->metrics_rects_decoded += rect_count;
    p->metrics_bytes_received += bytes_decoded;
}

bool rfb_pacing_can_present(const rfb_pacing *p, uint64_t now_ms)
{
    if (p == NULL) return true;
    if (p->max_fps == 0) return true;
    // Interval in ms = 1000 / max_fps.
    uint64_t interval = 1000u / p->max_fps;
    return (now_ms - p->last_present_ms) >= interval;
}
