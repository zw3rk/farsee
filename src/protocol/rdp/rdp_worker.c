// SPDX-License-Identifier: Apache-2.0
//
// RDP worker state scaffold.
//
// Stores a settings snapshot and owns a FreeRDP facade context through its
// lifecycle states. It does not create a thread, queue commands, or call
// freerdp_connect.

#include "rdp_worker.h"

#include <stddef.h>
#include <string.h>

bool rdp_worker_create(rdp_worker *w, const farsee_rdp_settings *settings)
{
    if (w == NULL || settings == NULL || !farsee_rdp_settings_valid(settings)) {
        return false;
    }
    w->state = RDP_WORKER_NEW;
    w->settings = *settings;
    w->rdp = NULL;
    w->cancel_requested = false;
    w->alloc_fail_inject = false;
    return true;
}

farsee_error rdp_worker_initialize(rdp_worker *w)
{
    if (w == NULL || w->state != RDP_WORKER_NEW) {
        return farsee_error_make(FARSEE_ERR_STATE, FARSEE_SUB_RDP,
                                 FARSEE_PHASE_NEW);
    }
    // Step 1: create the FreeRDP facade context. (§15.5 allocate wrapper.)
    if (w->alloc_fail_inject) {
        return farsee_error_make(FARSEE_ERR_OUT_OF_MEMORY, FARSEE_SUB_RDP,
                                 FARSEE_PHASE_NEW);
    }
    w->rdp = rdp_freerdp_create();
    if (w->rdp == NULL) {
        return farsee_error_make(FARSEE_ERR_OUT_OF_MEMORY, FARSEE_SUB_RDP,
                                 FARSEE_PHASE_NEW);
    }
    // Step 2: validate the channel and TLS/NLA policy before marking the
    // scaffold initialized. Settings are not applied to the facade here.
    if (!farsee_rdp_settings_channels_within_baseline(&w->settings)) {
        // Fail closed: a high-risk channel is enabled without a gate.
        rdp_freerdp_destroy(&w->rdp);
        return farsee_error_make_with_msg(FARSEE_ERR_UNSUPPORTED_FEATURE,
                                          FARSEE_SUB_RDP, FARSEE_PHASE_NEW,
                                          "redirection channel not allowlisted");
    }
    if (!w->settings.require_tls || (!w->settings.require_nla &&
        w->settings.security == FARSEE_RDP_SECURITY_TLS_NLA)) {
        // §15.4: TLS+NLA defaults must hold for the default security level.
        rdp_freerdp_destroy(&w->rdp);
        return farsee_error_make_with_msg(FARSEE_ERR_CONFIGURATION,
                                          FARSEE_SUB_RDP, FARSEE_PHASE_NEW,
                                          "TLS/NLA defaults not met");
    }
    w->state = RDP_WORKER_INITIALIZED;
    return farsee_error_make(FARSEE_E_OK, FARSEE_SUB_NONE, FARSEE_PHASE_NONE);
}

farsee_error rdp_worker_start_connect(rdp_worker *w)
{
    if (w == NULL || w->state != RDP_WORKER_INITIALIZED) {
        return farsee_error_make(FARSEE_ERR_STATE, FARSEE_SUB_RDP,
                                 FARSEE_PHASE_CONNECTING);
    }
    w->state = RDP_WORKER_CONNECTING;
    // This scaffold records CONNECTING; it does not start a network connect.
    return farsee_error_make(FARSEE_E_OK, FARSEE_SUB_NONE,
                             FARSEE_PHASE_CONNECTING);
}

farsee_error rdp_worker_request_stop(rdp_worker *w)
{
    if (w == NULL) {
        return farsee_error_make(FARSEE_ERR_STATE, FARSEE_SUB_RDP,
                                 FARSEE_PHASE_DRAINING);
    }
    // Record an idempotent stop request.
    w->cancel_requested = true;
    if (w->state != RDP_WORKER_TERMINATED) {
        w->state = RDP_WORKER_STOPPING;
    }
    return farsee_error_make(FARSEE_E_OK, FARSEE_SUB_NONE,
                             FARSEE_PHASE_DRAINING);
}

void rdp_worker_destroy(rdp_worker *w)
{
    if (w == NULL) {
        return;
    }
    // Release the facade context (reverse order of creation). Safe from any
    // partial state — rdp may be NULL if init failed early.
    if (w->rdp != NULL) {
        rdp_freerdp_destroy(&w->rdp);
    }
    // Zero the settings (no secrets are stored there, but be tidy).
    memset(&w->settings, 0, sizeof(w->settings));
    w->cancel_requested = false;
    w->state = RDP_WORKER_TERMINATED;
}

rdp_worker_state rdp_worker_state_of(const rdp_worker *w)
{
    return (w != NULL) ? w->state : RDP_WORKER_TERMINATED;
}
