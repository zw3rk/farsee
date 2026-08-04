// SPDX-License-Identifier: Apache-2.0
//
// Farsee common protocol-engine interface.
// (FARSEE_ARCHITECTURE_IMPROVEMENT_PLAN.md §6.3 — F1 gate.)
//
// Opaque, protocol-neutral. Every engine (RFB, RDP, SPICE, AHPSS)
// implements this. The interface MUST NOT require every engine to expose
// raw sockets to the application: an inline engine (RFB) registers
// waitables with the reactor; a worker-owned engine (RDP/FreeRDP)
// communicates through bounded queues.
//
// No RFB, FreeRDP/WinPR, SPICE, Apple wire, OpenSSL/CommonCrypto, Kitty,
// pthread, or raw-platform types appear here (§4.2). Engine-specific
// types stay behind the engine boundary.

#ifndef FARSEE_INCLUDE_FARSEE_FARSEE_ENGINE_H
#define FARSEE_INCLUDE_FARSEE_FARSEE_ENGINE_H

#include "farsee/farsee_error.h"
#include "farsee/farsee_capability.h"

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Opaque engine handle. The concrete type lives behind the engine's
// implementation boundary.
typedef struct farsee_engine farsee_engine;

// Execution model (§6.3, §8.3). An inline engine runs on the reactor
// thread; a worker-owned engine runs on a confined worker thread.
typedef enum {
    FARSEE_ENGINE_INLINE_REACTOR = 1,
    FARSEE_ENGINE_WORKER_OWNED   = 2,
} farsee_engine_execution_model;

// The v-table every engine publishes. Concrete engines provide a
// `create` factory that returns an opaque farsee_engine*; the ops table
// is accessed through the accessors below so the struct layout stays
// private.
//
// Semantic contract (§6.3):
//   create            - construct the engine; never starts I/O.
//   start             - begin connecting; idempotent rejection on re-start.
//   request_stop      - request cancellation; idempotent (§6.2).
//   query_capabilities- report what the engine supports.
//   destroy           - join/release all resources; sets *engine to NULL.
//                       Must be safe to call from any partial state (§3.2)
//                       and must never invoke callbacks after return (§6.2).
typedef struct farsee_engine_ops {
    farsee_error_code (*start)(farsee_engine *engine);
    farsee_error_code (*request_stop)(farsee_engine *engine);
    farsee_error_code (*query_capabilities)(const farsee_engine *engine,
                                            farsee_capability_set *out_caps);
    void (*destroy)(farsee_engine **engine_ptr);
} farsee_engine_ops;

// --- Public accessors (dispatch through the engine's ops table) -------------
// These let call sites drive any engine without knowing its concrete type.

farsee_error farsee_engine_start(farsee_engine *engine);
farsee_error farsee_engine_request_stop(farsee_engine *engine);
farsee_error farsee_engine_query_capabilities(const farsee_engine *engine,
                                              farsee_capability_set *out_caps);

// Destroys the engine and sets *engine_ptr to NULL. Safe on a NULL input
// (no-op). Safe from any partial state.
void farsee_engine_destroy(farsee_engine **engine_ptr);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_FARSEE_ENGINE_H
