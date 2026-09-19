// SPDX-License-Identifier: Apache-2.0
//
// Request-pacing tests.

#include "rfb_test.h"
#include "farsee/pacing.h"

// --- one outstanding request invariant ---------------------------------

RFB_TEST(pacing, pacing__initial__should_send_non_incremental) {
    rfb_pacing p;
    rfb_pacing_init(&p, 0);
    bool incremental = true;
    RFB_CHECK(rfb_pacing_should_send_request(&p, &incremental, 0));
    RFB_CHECK(!incremental);  // first request is non-incremental
}

RFB_TEST(pacing, pacing__after_request_sent__should_not_send_again) {
    rfb_pacing p;
    rfb_pacing_init(&p, 0);
    bool inc = false;
    RFB_CHECK(rfb_pacing_should_send_request(&p, &inc, 0));
    rfb_pacing_request_sent(&p, inc, 0);
    RFB_CHECK(!rfb_pacing_should_send_request(&p, &inc, 0));  // outstanding
}

RFB_TEST(pacing, pacing__after_update_received__should_send_incremental) {
    rfb_pacing p;
    rfb_pacing_init(&p, 0);
    bool inc = false;
    rfb_pacing_should_send_request(&p, &inc, 0);
    rfb_pacing_request_sent(&p, inc, 0);
    rfb_pacing_update_received(&p);
    RFB_CHECK(rfb_pacing_should_send_request(&p, &inc, 0));
    RFB_CHECK(inc);  // subsequent requests are incremental
}

RFB_TEST(pacing, pacing__force_full_refresh__next_request_non_incremental) {
    rfb_pacing p;
    rfb_pacing_init(&p, 0);
    bool inc = false;
    rfb_pacing_should_send_request(&p, &inc, 0);
    rfb_pacing_request_sent(&p, false, 0);
    rfb_pacing_update_received(&p);
    // Would be incremental now…
    RFB_CHECK(rfb_pacing_should_send_request(&p, &inc, 0));
    RFB_CHECK(inc);
    // …unless we force a full refresh (type-33 second paint / DesktopSize).
    rfb_pacing_force_full_refresh(&p);
    RFB_CHECK(rfb_pacing_should_send_request(&p, &inc, 0));
    RFB_CHECK(!inc);
}

RFB_TEST(pacing, pacing__force_full_refresh__bypasses_max_fps_wait) {
    rfb_pacing p;
    rfb_pacing_init(&p, 30);
    bool inc = false;
    RFB_CHECK(rfb_pacing_should_send_request(&p, &inc, 0));
    rfb_pacing_request_sent(&p, false, 0);
    rfb_pacing_update_received(&p);
    // Within max_fps window — blocked.
    RFB_CHECK(!rfb_pacing_should_send_request(&p, &inc, 10));
    // Wake / DesktopSize must not wait for that window.
    rfb_pacing_force_full_refresh(&p);
    RFB_CHECK(rfb_pacing_should_send_request(&p, &inc, 10));
    RFB_CHECK(!inc);
}

RFB_TEST(pacing, pacing__max_fps__caps_request_rate) {
    rfb_pacing p;
    rfb_pacing_init(&p, 30);  // ~33ms interval
    bool inc = false;
    RFB_CHECK(rfb_pacing_should_send_request(&p, &inc, 0));
    rfb_pacing_request_sent(&p, false, 0);
    rfb_pacing_update_received(&p);
    // Too soon for another request at 30fps.
    RFB_CHECK(!rfb_pacing_should_send_request(&p, &inc, 20));
    // After interval, allowed.
    RFB_CHECK(rfb_pacing_should_send_request(&p, &inc, 34));
}

// --- backpressure pauses requests ---------------------------------------

RFB_TEST(pacing, pacing__backpressure__should_not_send) {
    rfb_pacing p;
    rfb_pacing_init(&p, 0);
    rfb_pacing_set_backpressure(&p, true);
    bool inc = false;
    RFB_CHECK(!rfb_pacing_should_send_request(&p, &inc, 0));
}

RFB_TEST(pacing, pacing__backpressure_cleared__should_send) {
    rfb_pacing p;
    rfb_pacing_init(&p, 0);
    rfb_pacing_set_backpressure(&p, true);
    rfb_pacing_set_backpressure(&p, false);
    bool inc = false;
    RFB_CHECK(rfb_pacing_should_send_request(&p, &inc, 0));
}

// --- present cadence ----------------------------------------------------

RFB_TEST(pacing, pacing__can_present_no_fps_limit__always_true) {
    rfb_pacing p;
    rfb_pacing_init(&p, 0);
    RFB_CHECK(rfb_pacing_can_present(&p, 0));
    RFB_CHECK(rfb_pacing_can_present(&p, 1000));
}

RFB_TEST(pacing, pacing__can_present_30fps__respects_interval) {
    rfb_pacing p;
    rfb_pacing_init(&p, 30);
    rfb_pacing_presented(&p, 0, 1, 100);
    // At 30 FPS, interval is ~33ms. At 20ms, can't present yet.
    RFB_CHECK(!rfb_pacing_can_present(&p, 20));
    // At 34ms, can present.
    RFB_CHECK(rfb_pacing_can_present(&p, 34));
}

// --- metrics ------------------------------------------------------------

RFB_TEST(pacing, pacing__metrics__update_and_present_counted) {
    rfb_pacing p;
    rfb_pacing_init(&p, 0);
    rfb_pacing_update_received(&p);
    rfb_pacing_presented(&p, 0, 5, 1000);
    RFB_CHECK_EQ_UINT(p.metrics_updates_received, 1u);
    RFB_CHECK_EQ_UINT(p.metrics_presentations, 1u);
    RFB_CHECK_EQ_UINT(p.metrics_rects_decoded, 5u);
    RFB_CHECK_EQ_UINT(p.metrics_bytes_received, 1000u);
}
