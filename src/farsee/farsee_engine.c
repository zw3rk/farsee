// SPDX-License-Identifier: Apache-2.0
//
// Farsee common protocol-engine dispatch (F1 gate, §6.3).
//
// The concrete engine type is defined by each engine implementation
// (e.g. tests/fakes/fake_engine.c). It begins with a pointer to its
// farsee_engine_ops v-table, so the accessors here can dispatch without
// knowing the concrete layout. This keeps the common layer free of any
// protocol-specific types (§4.2).

#include "farsee/farsee_engine.h"

#include <stddef.h>

// Every concrete engine's first member MUST be a const farsee_engine_ops*.
// We access it through this struct overlay.
typedef struct farsee_engine_header {
    const farsee_engine_ops *ops;
} farsee_engine_header;

static const farsee_engine_ops *engine_ops(const farsee_engine *engine)
{
    if (engine == NULL) {
        return NULL;
    }
    return ((const farsee_engine_header *)(const void *)engine)->ops;
}

farsee_error farsee_engine_start(farsee_engine *engine)
{
    const farsee_engine_ops *ops = engine_ops(engine);
    if (ops == NULL || ops->start == NULL) {
        return farsee_error_make(FARSEE_ERR_STATE, FARSEE_SUB_CORE,
                                 FARSEE_PHASE_NEW);
    }
    farsee_error_code code = ops->start(engine);
    return farsee_error_make(code,
                             code == FARSEE_E_OK ? FARSEE_SUB_NONE : FARSEE_SUB_CORE,
                             FARSEE_PHASE_CONNECTING);
}

farsee_error farsee_engine_request_stop(farsee_engine *engine)
{
    const farsee_engine_ops *ops = engine_ops(engine);
    if (ops == NULL || ops->request_stop == NULL) {
        return farsee_error_make(FARSEE_ERR_STATE, FARSEE_SUB_CORE,
                                 FARSEE_PHASE_DRAINING);
    }
    farsee_error_code code = ops->request_stop(engine);
    return farsee_error_make(code,
                             code == FARSEE_E_OK ? FARSEE_SUB_NONE : FARSEE_SUB_CORE,
                             FARSEE_PHASE_DRAINING);
}

farsee_error farsee_engine_query_capabilities(const farsee_engine *engine,
                                              farsee_capability_set *out_caps)
{
    const farsee_engine_ops *ops = engine_ops(engine);
    if (ops == NULL || ops->query_capabilities == NULL || out_caps == NULL) {
        return farsee_error_make(FARSEE_ERR_STATE, FARSEE_SUB_CORE,
                                 FARSEE_PHASE_NONE);
    }
    farsee_error_code code = ops->query_capabilities(engine, out_caps);
    return farsee_error_make(code,
                             code == FARSEE_E_OK ? FARSEE_SUB_NONE : FARSEE_SUB_CORE,
                             FARSEE_PHASE_NONE);
}

void farsee_engine_destroy(farsee_engine **engine_ptr)
{
    if (engine_ptr == NULL || *engine_ptr == NULL) {
        return;
    }
    const farsee_engine_ops *ops = engine_ops(*engine_ptr);
    if (ops != NULL && ops->destroy != NULL) {
        ops->destroy(engine_ptr);
    }
    // The engine's destroy is responsible for setting *engine_ptr = NULL.
}
