// SPDX-License-Identifier: Apache-2.0
//
// farsee — request pacing state machine (plan.md §G9, §18).
//
// Maintains the "at most one outstanding FramebufferUpdateRequest"
// invariant (plan.md §18). The session loop calls these functions to
// decide when to send incremental vs non-incremental requests, and when
// to pause/resume requests under presentation backpressure.

#ifndef FARSEE_INCLUDE_FARSEE_PACING_H
#define FARSEE_INCLUDE_FARSEE_PACING_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rfb_pacing {
    bool request_outstanding;     // true iff we've sent a request and are
                                  // waiting for the FramebufferUpdate
    bool initial_sent;            // true after the first non-incremental req
    bool backpressure;            // true when presenter is at high-water mark
    uint32_t max_fps;             // 0 = unlimited
    uint64_t last_present_ms;     // monotonic timestamp of the last present
    uint64_t last_request_ms;     // monotonic timestamp of last FBUR sent
    bool has_sent_request;        // true after first request_sent
    // Metrics (plan.md §G9).
    uint64_t metrics_updates_received;
    uint64_t metrics_presentations;
    uint64_t metrics_rects_decoded;
    uint64_t metrics_bytes_received;
} rfb_pacing;

void rfb_pacing_init(rfb_pacing *p, uint32_t max_fps);

// Called when the session loop wants to send a request. Returns true if
// a request should be sent now (no outstanding request, no backpressure,
// and max_fps interval since last request). Sets `*incremental` to false
// for the first request, true thereafter. `now_ms` is monotonic ms.
bool rfb_pacing_should_send_request(rfb_pacing *p, bool *incremental,
                                    uint64_t now_ms);

// Called after a request is sent.
void rfb_pacing_request_sent(rfb_pacing *p, bool incremental, uint64_t now_ms);

// Called when a FramebufferUpdate arrives (clears the outstanding flag).
void rfb_pacing_update_received(rfb_pacing *p);

// Force the next request to be a non-incremental full-screen FBUR
// (clears outstanding + initial_sent). Used after DesktopSize and after
// Apple type-33 first-frame bootstrap (first paint is often a black
// placeholder until a second full refresh / wake).
void rfb_pacing_force_full_refresh(rfb_pacing *p);

// Called when the presenter reaches the high-water mark (pause requests)
// or drops below the low-water mark (resume requests).
void rfb_pacing_set_backpressure(rfb_pacing *p, bool active);

// Called after a presentation. Updates the cadence and metrics.
void rfb_pacing_presented(rfb_pacing *p, uint64_t now_ms, uint32_t rect_count,
                          size_t bytes_decoded);

// True if enough time has elapsed since the last present for the next one
// (based on max_fps). If max_fps is 0, always true.
bool rfb_pacing_can_present(const rfb_pacing *p, uint64_t now_ms);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_PACING_H
