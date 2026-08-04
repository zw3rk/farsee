// SPDX-License-Identifier: Apache-2.0
//
// R1 — RDP settings + worker tests (§22/R1).
//
// Deterministic: the settings mapper, channel allowlist, worker state
// machine, OOM cleanup, unsafe-config rejection, and abortable cancellation
// are all exercised without a live RDP server. (Live connect + render needs
// independent Windows/xrdp hardware — R3/R6.)

#ifdef FARSEE_WITH_RDP

#include "protocol/rdp/rdp_settings.h"
#include "protocol/rdp/rdp_worker.h"
#include "tests/test_framework/rfb_test.h"

// --- settings defaults (§15.4, §10.6) ---------------------------------------

RFB_TEST(farsee_rdp_settings, defaults__tls_nla_on_redirection_off)
{
    farsee_rdp_settings s = farsee_rdp_settings_defaults();
    RFB_CHECK(s.security == FARSEE_RDP_SECURITY_TLS_NLA);
    RFB_CHECK(s.require_tls);
    RFB_CHECK(s.require_nla);
    RFB_CHECK(s.allow_legacy_rdp_security == false);
    RFB_CHECK_EQ_UINT(s.port, 3390u - 1u);  // 3389
    // Every optional redirection channel OFF (§10.6).
    RFB_CHECK(farsee_rdp_settings_channels_within_baseline(&s));
    RFB_CHECK(s.channels.drive_redirection == false);
    RFB_CHECK(s.channels.clipboard_text == false);  // R5 enables it
}

RFB_TEST(farsee_rdp_settings, init_for_host__applies_defaults_and_endpoint)
{
    farsee_rdp_settings s;
    RFB_CHECK(farsee_rdp_settings_init_for_host(&s, "windows.example", 0, "alice", "EXAMPLE"));
    RFB_CHECK(s.port == 3389);
    RFB_CHECK(farsee_rdp_settings_valid(&s));
    // username/domain bound.
    RFB_CHECK(s.username[0] == 'a');
    RFB_CHECK(s.domain[0] == 'E');
}

RFB_TEST(farsee_rdp_settings, init_for_host__bad_args_rejected)
{
    farsee_rdp_settings s;
    RFB_CHECK(farsee_rdp_settings_init_for_host(&s, "", 0, NULL, NULL) == false);
    RFB_CHECK(farsee_rdp_settings_init_for_host(NULL, "h", 0, NULL, NULL) == false);
}

// --- channel allowlist (§10.6) ---------------------------------------------

RFB_TEST(farsee_rdp_settings, baseline_rejects_high_risk_channels)
{
    farsee_rdp_settings s = farsee_rdp_settings_defaults();
    RFB_CHECK(farsee_rdp_settings_init_for_host(&s, "h", 0, NULL, NULL));
    // Enabling drive redirection takes it out of baseline.
    s.channels.drive_redirection = true;
    RFB_CHECK(farsee_rdp_settings_channels_within_baseline(&s) == false);
    // clipboard_text alone is within baseline.
    s.channels.drive_redirection = false;
    s.channels.clipboard_text = true;
    RFB_CHECK(farsee_rdp_settings_channels_within_baseline(&s));
    // File clipboard is NOT within baseline.
    s.channels.file_clipboard = true;
    RFB_CHECK(farsee_rdp_settings_channels_within_baseline(&s) == false);
}

// --- settings validation (§15.4 fail-closed) --------------------------------

RFB_TEST(farsee_rdp_settings, valid__rejects_legacy_without_explicit_allow)
{
    farsee_rdp_settings s = farsee_rdp_settings_defaults();
    RFB_CHECK(farsee_rdp_settings_init_for_host(&s, "h", 0, NULL, NULL));
    s.security = FARSEE_RDP_SECURITY_RDP;  // legacy
    // legacy selected but not explicitly allowed -> invalid
    RFB_CHECK(farsee_rdp_settings_valid(&s) == false);
    // Even allowing it while requiring TLS is contradictory.
    s.allow_legacy_rdp_security = true;
    RFB_CHECK(farsee_rdp_settings_valid(&s) == false);
    // Legacy allowed AND TLS not required: technically valid shape (still
    // unsafe; surfaced only via a separately-named option, §15.4).
    s.require_tls = false;
    s.require_nla = false;
    RFB_CHECK(farsee_rdp_settings_valid(&s));
}

// --- worker lifecycle + cleanup at every init step (§22/R1) ----------------

RFB_TEST(rdp_worker, lifecycle__create_init_connect_stop_destroy)
{
    farsee_rdp_settings s;
    RFB_CHECK(farsee_rdp_settings_init_for_host(&s, "windows.example", 0, "alice", NULL));
    rdp_worker w;
    RFB_CHECK(rdp_worker_create(&w, &s));
    RFB_CHECK(rdp_worker_state_of(&w) == RDP_WORKER_NEW);

    RFB_CHECK(rdp_worker_initialize(&w).code == FARSEE_E_OK);
    RFB_CHECK(rdp_worker_state_of(&w) == RDP_WORKER_INITIALIZED);
    RFB_CHECK(w.rdp != NULL);

    RFB_CHECK(rdp_worker_start_connect(&w).code == FARSEE_E_OK);
    RFB_CHECK(rdp_worker_state_of(&w) == RDP_WORKER_CONNECTING);

    // Abortable cancellation (R1 exit criterion): request_stop during connect.
    RFB_CHECK(rdp_worker_request_stop(&w).code == FARSEE_E_OK);
    RFB_CHECK(w.cancel_requested);
    RFB_CHECK(rdp_worker_state_of(&w) == RDP_WORKER_STOPPING);

    rdp_worker_destroy(&w);
    RFB_CHECK(rdp_worker_state_of(&w) == RDP_WORKER_TERMINATED);
    RFB_CHECK(w.rdp == NULL);
}

RFB_TEST(rdp_worker, cancel__idempotent_and_interruptible)
{
    farsee_rdp_settings s;
    RFB_CHECK(farsee_rdp_settings_init_for_host(&s, "h", 0, NULL, NULL));
    rdp_worker w;
    RFB_CHECK(rdp_worker_create(&w, &s));
    RFB_CHECK(rdp_worker_initialize(&w).code == FARSEE_E_OK);
    RFB_CHECK(rdp_worker_start_connect(&w).code == FARSEE_E_OK);
    // Repeated stop requests are all OK (idempotent, §6.2).
    RFB_CHECK(rdp_worker_request_stop(&w).code == FARSEE_E_OK);
    RFB_CHECK(rdp_worker_request_stop(&w).code == FARSEE_E_OK);
    RFB_CHECK(w.cancel_requested);
    rdp_worker_destroy(&w);
}

// --- OOM / failure cleanup at every step (§3.2) ----------------------------

RFB_TEST(rdp_worker, init__oom_on_facade_create_is_destructible)
{
    farsee_rdp_settings s;
    RFB_CHECK(farsee_rdp_settings_init_for_host(&s, "h", 0, NULL, NULL));
    rdp_worker w;
    RFB_CHECK(rdp_worker_create(&w, &s));
    w.alloc_fail_inject = true;
    RFB_CHECK(rdp_worker_initialize(&w).code == FARSEE_ERR_OUT_OF_MEMORY);
    // Worker is left destructible; destroy must be safe from this partial state.
    rdp_worker_destroy(&w);
    RFB_CHECK(rdp_worker_state_of(&w) == RDP_WORKER_TERMINATED);
    RFB_CHECK(w.rdp == NULL);
}

RFB_TEST(rdp_worker, init__rejects_unsafe_channel_allowlist)
{
    farsee_rdp_settings s = farsee_rdp_settings_defaults();
    RFB_CHECK(farsee_rdp_settings_init_for_host(&s, "h", 0, NULL, NULL));
    s.channels.drive_redirection = true;  // §10.6: not in baseline
    rdp_worker w;
    RFB_CHECK(rdp_worker_create(&w, &s));
    farsee_error e = rdp_worker_initialize(&w);
    RFB_CHECK(e.code == FARSEE_ERR_UNSUPPORTED_FEATURE);
    RFB_CHECK(w.rdp == NULL);  // facade released on failure
    rdp_worker_destroy(&w);
}

RFB_TEST(rdp_worker, state_transitions__illegal_rejected)
{
    farsee_rdp_settings s;
    RFB_CHECK(farsee_rdp_settings_init_for_host(&s, "h", 0, NULL, NULL));
    rdp_worker w;
    RFB_CHECK(rdp_worker_create(&w, &s));
    // start_connect before initialize -> STATE.
    RFB_CHECK(rdp_worker_start_connect(&w).code == FARSEE_ERR_STATE);
    // double-initialize -> STATE.
    RFB_CHECK(rdp_worker_initialize(&w).code == FARSEE_E_OK);
    RFB_CHECK(rdp_worker_initialize(&w).code == FARSEE_ERR_STATE);
    rdp_worker_destroy(&w);
}

// --- create rejects invalid settings ---------------------------------------

RFB_TEST(rdp_worker, create__rejects_invalid_settings)
{
    farsee_rdp_settings s = farsee_rdp_settings_defaults();  // empty hostname -> invalid
    rdp_worker w;
    RFB_CHECK(rdp_worker_create(&w, &s) == false);
}

#endif  // FARSEE_WITH_RDP
