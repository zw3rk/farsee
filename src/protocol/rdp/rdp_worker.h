// SPDX-License-Identifier: Apache-2.0
//
// Farsee RDP worker — in-process confined worker (R1 gate, §15.2.1, §15.5).
//
// One RDP worker owns the FreeRDP instance/context and every call into it
// (§8.3). The main thread never calls FreeRDP directly after the worker
// starts. Commands travel in through a bounded queue (F3); lifecycle
// events travel out. Cancellation is interruptible (§15.5 stop arrow).
//
// PRIVATE to src/protocol/rdp/. Built on the F3 farsee_queue/thread
// primitives and the R0 facade. No FreeRDP type crosses this boundary.

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
    RDP_WORKER_INITIALIZED,   // facade context created, settings applied
    RDP_WORKER_CONNECTING,    // connect attempt in flight (abortable)
    RDP_WORKER_ACTIVE,        // connected (not used until R3 rendering)
    RDP_WORKER_STOPPING,      // cancellation requested
    RDP_WORKER_TERMINATED,    // joined, resources released
} rdp_worker_state;

typedef struct rdp_worker {
    rdp_worker_state state;
    farsee_rdp_settings settings;
    rdp_freerdp_ctx *rdp;        // NULL until create; freed on stop
    bool cancel_requested;       // set by request_stop (interruptible)
    bool alloc_fail_inject;      // test-only: inject OOM on init
} rdp_worker;

// Initialize a worker in NEW with the given settings. Does not create the
// FreeRDP context yet (that happens in rdp_worker_start_connect). Returns
// false on bad args.
bool rdp_worker_create(rdp_worker *w, const farsee_rdp_settings *settings);

// Create the FreeRDP facade context and apply settings (allowlist + TLS/NLA).
// Transitions NEW -> INITIALIZED. Returns a typed farsee_error on failure;
// on any failure the worker is left destructible (§3.2) and the facade
// context is released.
farsee_error rdp_worker_initialize(rdp_worker *w);

// Begin a connect attempt. Transitions INITIALIZED -> CONNECTING. The
// actual network connect would run on a worker thread (R1 wires the
// cancellation path; the real FreeRDP connect lands with live-server
// evidence in R3). Returns STATE if not INITIALIZED.
farsee_error rdp_worker_start_connect(rdp_worker *w);

// Request cancellation (§15.5 stop). Idempotent. Sets the cancel flag and
// transitions to STOPPING. A connect in flight must be abortable.
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
