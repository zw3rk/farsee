// SPDX-License-Identifier: Apache-2.0
//
// F8 — RFB engine adapter tests (§14, §22/F8).
//
// Drives the existing RFB session through the common farsee_engine
// interface and verifies the adapter:
//   - implements farsee_engine_ops correctly;
//   - transitions common lifecycle states legally;
//   - rejects repeated start, allows idempotent stop;
//   - reports RFB's capability set (no RDP/SPICE redirection caps);
//   - destroys cleanly (password zeroized by rfb_handshake_destroy).
//
// The common interface (farsee_engine.h) contains no RFB types; the adapter
// header uses rfb_* only as a documented bridge.

#include "farsee/rfb_engine_adapter.h"
#include "farsee/allocator.h"
#include "farsee/handshake.h"
#include "tests/test_framework/rfb_test.h"

RFB_TEST(farsee_engine, rfb_adapter__create_start_stop_destroy)
{
    rfb_engine_adapter a;
    rfb_handshake_policy pol = rfb_handshake_policy_default();
    rfb_engine_adapter_init(&a, &pol, rfb_default_allocator());
    RFB_CHECK(rfb_engine_adapter_lifecycle(&a) == FARSEE_LIFECYCLE_CONFIGURED);

    farsee_engine *eng = (farsee_engine *)&a;
    RFB_CHECK(farsee_engine_start(eng).code == FARSEE_E_OK);
    RFB_CHECK(rfb_engine_adapter_lifecycle(&a) == FARSEE_LIFECYCLE_CONNECTING);

    // Repeated start rejected (§8.6).
    RFB_CHECK(farsee_engine_start(eng).code == FARSEE_ERR_STATE);

    // Idempotent stop (§6.2).
    RFB_CHECK(farsee_engine_request_stop(eng).code == FARSEE_E_OK);
    RFB_CHECK(rfb_engine_adapter_lifecycle(&a) == FARSEE_LIFECYCLE_DRAINING);
    RFB_CHECK(farsee_engine_request_stop(eng).code == FARSEE_E_OK);

    farsee_engine_destroy(&eng);
    RFB_CHECK(eng == NULL);
    RFB_CHECK(rfb_engine_adapter_lifecycle(&a) == FARSEE_LIFECYCLE_CLOSED);
}

RFB_TEST(farsee_engine, rfb_adapter__capabilities_report_rfb_set)
{
    rfb_engine_adapter a;
    rfb_engine_adapter_init(&a, NULL, rfb_default_allocator());
    farsee_engine *eng = (farsee_engine *)&a;
    farsee_capability_set caps;
    farsee_capability_set_init(&caps);
    RFB_CHECK(farsee_engine_query_capabilities(eng, &caps).code == FARSEE_E_OK);

    // RFB supports these (§6.5).
    RFB_CHECK(farsee_capability_get(&caps, FARSEE_CAP_ABSOLUTE_POINTER));
    RFB_CHECK(farsee_capability_get(&caps, FARSEE_CAP_REMOTE_RESIZE));
    RFB_CHECK(farsee_capability_get(&caps, FARSEE_CAP_CLIPBOARD_TEXT));
    RFB_CHECK(farsee_capability_get(&caps, FARSEE_CAP_UNICODE_INPUT));
    // RFB does NOT do redirection / audio capture (high-risk, off).
    RFB_CHECK(farsee_capability_get(&caps, FARSEE_CAP_DRIVE_REDIRECTION) == false);
    RFB_CHECK(farsee_capability_get(&caps, FARSEE_CAP_AUDIO_CAPTURE) == false);
    RFB_CHECK(farsee_capability_get(&caps, FARSEE_CAP_PRINTER_REDIRECTION) == false);
    farsee_engine_destroy(&eng);
}

RFB_TEST(farsee_engine, rfb_adapter__common_interface_dispatches_ops)
{
    // Verify the adapter ops are reachable through the common accessors and
    // that the ops table is the adapter's first member (header layout).
    rfb_engine_adapter a;
    rfb_engine_adapter_init(&a, NULL, rfb_default_allocator());
    farsee_engine *eng = (farsee_engine *)&a;
    // The common accessors read a->ops via the farsee_engine_header overlay.
    // A successful query proves the dispatch path works end-to-end.
    farsee_capability_set caps;
    RFB_CHECK(farsee_engine_query_capabilities(eng, &caps).code == FARSEE_E_OK);
    farsee_engine_destroy(&eng);
    RFB_CHECK(eng == NULL);
}
