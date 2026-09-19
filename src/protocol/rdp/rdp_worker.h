// SPDX-License-Identifier: Apache-2.0
//
// RDP worker state scaffold.
//
// PRIVATE to src/protocol/rdp/. It stores settings, owns a facade context,
// and records lifecycle states and stop requests. It does not create a
// thread, use a command queue, or perform a network connect. No FreeRDP type
// crosses this boundary.

#ifndef FARSEE_SRC_PROTOCOL_RDP_RDP_WORKER_H
#define FARSEE_SRC_PROTOCOL_RDP_RDP_WORKER_H

#include "farsee/farsee_error.h"
#include "farsee/farsee_lifecycle.h"
#include "rdp_freerdp_facade.h"
#include "rdp_settings.h"

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Worker states (a subset of §15.5 lifecycle, worker-scoped).
typedef enum {
    RDP_WORKER_NEW = 0,
    RDP_WORKER_INITIALIZED,   // facade created, policy validated
    RDP_WORKER_CONNECTING,    // start_connect recorded
    RDP_WORKER_ACTIVE,        // reserved; not entered by this module
    RDP_WORKER_STOPPING,      // stop request recorded
    RDP_WORKER_TERMINATED,    // facade released
} rdp_worker_state;

typedef struct rdp_worker {
    rdp_worker_state state;
    farsee_rdp_settings settings;
    rdp_freerdp_ctx *rdp;        // NULL until initialize; freed by destroy
    bool cancel_requested;       // set by request_stop
    bool alloc_fail_inject;      // test-only: inject OOM on init
} rdp_worker;

// Initialize the scaffold in NEW with a settings snapshot. The facade is
// created later by rdp_worker_initialize. Returns false on bad arguments.
bool rdp_worker_create(rdp_worker *w, const farsee_rdp_settings *settings);

// Create the FreeRDP facade context and validate the channel and TLS/NLA
// policy. Transitions NEW -> INITIALIZED. On failure, releases any facade
// context created by this function and leaves the scaffold destructible.
farsee_error rdp_worker_initialize(rdp_worker *w);

// Record the transition INITIALIZED -> CONNECTING. This function does not
// start a thread or network connect. Returns STATE if not INITIALIZED.
farsee_error rdp_worker_start_connect(rdp_worker *w);

// Record an idempotent stop request and transition to STOPPING unless the
// scaffold is already TERMINATED.
farsee_error rdp_worker_request_stop(rdp_worker *w);

// Tear down: release the facade context, transition to TERMINATED. Safe
// from any state (§3.2 deterministic release). Sets rdp to NULL.
void rdp_worker_destroy(rdp_worker *w);

// Current worker state (for tests/diagnostics).
rdp_worker_state rdp_worker_state_of(const rdp_worker *w);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_SRC_PROTOCOL_RDP_RDP_WORKER_H
