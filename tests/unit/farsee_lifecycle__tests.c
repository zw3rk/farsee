// SPDX-License-Identifier: Apache-2.0
//
// Unit tests for lifecycle transitions, capability bits, and fake engine ops.
//
// These cases cover allowed and rejected transitions, terminal-state
// classification, capability toggles, repeated start, idempotent stop,
// NULL-safe destroy, allocation failure, and the fake's fixed capabilities.
// They do not exercise session orchestration or application callback work.

#include "farsee/farsee_lifecycle.h"
#include "farsee/farsee_capability.h"
#include "farsee/farsee_engine.h"
#include "fakes/fake_engine.h"
#include "tests/test_framework/rfb_test.h"

// ---- lifecycle transitions -------------------------------------------------

RFB_TEST(farsee_lifecycle, legal_forward_transition__accepted)
{
    RFB_CHECK(farsee_lifecycle_can_transition(FARSEE_LIFECYCLE_NEW,
                                              FARSEE_LIFECYCLE_CONFIGURED));
    RFB_CHECK(farsee_lifecycle_can_transition(FARSEE_LIFECYCLE_CONFIGURED,
                                              FARSEE_LIFECYCLE_CONNECTING));
    RFB_CHECK(farsee_lifecycle_can_transition(FARSEE_LIFECYCLE_CONNECTING,
                                              FARSEE_LIFECYCLE_NEGOTIATING_SECURITY));
    RFB_CHECK(farsee_lifecycle_can_transition(FARSEE_LIFECYCLE_NEGOTIATING_SECURITY,
                                              FARSEE_LIFECYCLE_AUTHENTICATING));
    RFB_CHECK(farsee_lifecycle_can_transition(FARSEE_LIFECYCLE_AUTHENTICATING,
                                              FARSEE_LIFECYCLE_ESTABLISHING_SESSION));
    RFB_CHECK(farsee_lifecycle_can_transition(FARSEE_LIFECYCLE_ESTABLISHING_SESSION,
                                              FARSEE_LIFECYCLE_ACTIVE));
    RFB_CHECK(farsee_lifecycle_can_transition(FARSEE_LIFECYCLE_ACTIVE,
                                              FARSEE_LIFECYCLE_DRAINING));
    RFB_CHECK(farsee_lifecycle_can_transition(FARSEE_LIFECYCLE_DRAINING,
                                              FARSEE_LIFECYCLE_CLOSED));
}

RFB_TEST(farsee_lifecycle, any_nonterminal_to_failed__accepted)
{
    // Every nonterminal state permits a transition to FAILED.
    farsee_lifecycle_state nonterminal[] = {
        FARSEE_LIFECYCLE_NEW, FARSEE_LIFECYCLE_CONFIGURED,
        FARSEE_LIFECYCLE_CONNECTING, FARSEE_LIFECYCLE_NEGOTIATING_SECURITY,
        FARSEE_LIFECYCLE_AUTHENTICATING, FARSEE_LIFECYCLE_ESTABLISHING_SESSION,
        FARSEE_LIFECYCLE_ACTIVE, FARSEE_LIFECYCLE_RECONNECTING,
        FARSEE_LIFECYCLE_DRAINING,
    };
    for (size_t i = 0; i < sizeof(nonterminal) / sizeof(nonterminal[0]); ++i) {
        RFB_CHECK_MSG(farsee_lifecycle_can_transition(nonterminal[i],
                                                      FARSEE_LIFECYCLE_FAILED),
                      "nonterminal state must be able to fail");
    }
}

RFB_TEST(farsee_lifecycle, illegal_skip_transition__rejected)
{
    // Cannot jump from NEW straight to ACTIVE.
    RFB_CHECK(farsee_lifecycle_can_transition(FARSEE_LIFECYCLE_NEW,
                                              FARSEE_LIFECYCLE_ACTIVE) == false);
    // Cannot leave a terminal state (CLOSED/FAILED).
    RFB_CHECK(farsee_lifecycle_can_transition(FARSEE_LIFECYCLE_CLOSED,
                                              FARSEE_LIFECYCLE_ACTIVE) == false);
    RFB_CHECK(farsee_lifecycle_can_transition(FARSEE_LIFECYCLE_FAILED,
                                              FARSEE_LIFECYCLE_ACTIVE) == false);
    RFB_CHECK(farsee_lifecycle_can_transition(FARSEE_LIFECYCLE_CLOSED,
                                              FARSEE_LIFECYCLE_NEW) == false);
}

RFB_TEST(farsee_lifecycle, terminal_states__identified)
{
    RFB_CHECK(farsee_lifecycle_is_terminal(FARSEE_LIFECYCLE_CLOSED));
    RFB_CHECK(farsee_lifecycle_is_terminal(FARSEE_LIFECYCLE_FAILED));
    RFB_CHECK(farsee_lifecycle_is_terminal(FARSEE_LIFECYCLE_NEW) == false);
    RFB_CHECK(farsee_lifecycle_is_terminal(FARSEE_LIFECYCLE_ACTIVE) == false);
}

// ---- capability set --------------------------------------------------------

RFB_TEST(farsee_capability, initialized_set__sampled_capabilities_absent)
{
    farsee_capability_set caps;
    farsee_capability_set_init(&caps);
    // Sample four capability bits after initialization.
    RFB_CHECK(farsee_capability_get(&caps, FARSEE_CAP_REMOTE_RESIZE) == false);
    RFB_CHECK(farsee_capability_get(&caps, FARSEE_CAP_ABSOLUTE_POINTER) == false);
    RFB_CHECK(farsee_capability_get(&caps, FARSEE_CAP_CLIPBOARD_TEXT) == false);
    RFB_CHECK(farsee_capability_get(&caps, FARSEE_CAP_DRIVE_REDIRECTION) == false);
}

RFB_TEST(farsee_capability, set_and_get__round_trips)
{
    farsee_capability_set caps;
    farsee_capability_set_init(&caps);
    farsee_capability_set_set(&caps, FARSEE_CAP_ABSOLUTE_POINTER, true);
    farsee_capability_set_set(&caps, FARSEE_CAP_REMOTE_RESIZE, true);
    RFB_CHECK(farsee_capability_get(&caps, FARSEE_CAP_ABSOLUTE_POINTER));
    RFB_CHECK(farsee_capability_get(&caps, FARSEE_CAP_REMOTE_RESIZE));
    // Toggling off.
    farsee_capability_set_set(&caps, FARSEE_CAP_ABSOLUTE_POINTER, false);
    RFB_CHECK(farsee_capability_get(&caps, FARSEE_CAP_ABSOLUTE_POINTER) == false);
}

RFB_TEST(farsee_capability, high_risk_redirection__disabled_by_default)
{
    // Check five redirection-related bits after initialization.
    farsee_capability_set caps;
    farsee_capability_set_init(&caps);
    farsee_capability_id high_risk[] = {
        FARSEE_CAP_DRIVE_REDIRECTION, FARSEE_CAP_PRINTER_REDIRECTION,
        FARSEE_CAP_SMARTCARD_REDIRECTION, FARSEE_CAP_CLIPBOARD_FILES,
        FARSEE_CAP_AUDIO_CAPTURE,
    };
    for (size_t i = 0; i < sizeof(high_risk) / sizeof(high_risk[0]); ++i) {
        RFB_CHECK_MSG(farsee_capability_get(&caps, high_risk[i]) == false,
                      "high-risk redirection must be off by default");
    }
}

// ---- fake engine operations ------------------------------------------------

RFB_TEST(farsee_engine, fake_engine__create_start_stop_destroy)
{
    farsee_engine *eng = NULL;
    farsee_error err = fake_engine_create(&eng);
    RFB_CHECK(err.code == FARSEE_E_OK);
    RFB_CHECK(eng != NULL);

    err = farsee_engine_start(eng);
    RFB_CHECK(err.code == FARSEE_E_OK);

    // A second start returns FARSEE_ERR_STATE.
    err = farsee_engine_start(eng);
    RFB_CHECK(err.code == FARSEE_ERR_STATE);

    err = farsee_engine_request_stop(eng);
    RFB_CHECK(err.code == FARSEE_E_OK);
    // A second stop also succeeds.
    err = farsee_engine_request_stop(eng);
    RFB_CHECK(err.code == FARSEE_E_OK);

    farsee_engine_destroy(&eng);
    RFB_CHECK(eng == NULL);
}

RFB_TEST(farsee_engine, fake_engine__destroy_null_is_safe)
{
    farsee_engine *eng = NULL;
    // Destroy accepts a pointer to a NULL handle.
    farsee_engine_destroy(&eng);
    RFB_CHECK(eng == NULL);
}

RFB_TEST(farsee_engine, fake_engine__create_failure_returns_oom)
{
    // The configured allocation failure returns typed OOM and leaves no handle.
    fake_engine_inject_alloc_failures(1);
    farsee_engine *eng = NULL;
    farsee_error err = fake_engine_create(&eng);
    RFB_CHECK(err.code == FARSEE_ERR_OUT_OF_MEMORY);
    RFB_CHECK(eng == NULL);
    fake_engine_reset_injection();
}

RFB_TEST(farsee_engine, fake_engine__destroy_leaves_test_sentinel_zero)
{
    // This fake has no callback source; observe its sentinel after destroy.
    farsee_engine *eng = NULL;
    (void)fake_engine_create(&eng);
    (void)farsee_engine_start(eng);
    farsee_engine_destroy(&eng);
    RFB_CHECK(fake_engine_post_destroy_callbacks() == 0);
}

RFB_TEST(farsee_engine, fake_engine__query_capabilities)
{
    farsee_engine *eng = NULL;
    (void)fake_engine_create(&eng);
    farsee_capability_set caps;
    farsee_capability_set_init(&caps);
    farsee_error err = farsee_engine_query_capabilities(eng, &caps);
    RFB_CHECK(err.code == FARSEE_E_OK);
    // Check two advertised capability bits and one absent bit.
    RFB_CHECK(farsee_capability_get(&caps, FARSEE_CAP_ABSOLUTE_POINTER));
    RFB_CHECK(farsee_capability_get(&caps, FARSEE_CAP_REMOTE_RESIZE));
    RFB_CHECK(farsee_capability_get(&caps, FARSEE_CAP_DRIVE_REDIRECTION) == false);
    farsee_engine_destroy(&eng);
}
