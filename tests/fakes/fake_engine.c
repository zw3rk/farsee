// SPDX-License-Identifier: Apache-2.0
//
// Fake protocol engine for F1 contract tests.
//
// TEST-ONLY. Implements the common farsee_engine operations in memory,
// advertises two fixed capabilities, and supports deterministic failure of
// its allocation. It owns no network connection, worker, or callback source.

#include "fakes/fake_engine.h"

#include "farsee/farsee_lifecycle.h"

#include <stdlib.h>

// Injection state. Simple globals: tests are single-threaded and
// sequential (per rfb_test.h).
static int  g_alloc_fail_at = 0;   // fail the Nth alloc (0 = disabled)
static int  g_alloc_count   = 0;
static int  g_post_destroy_callbacks = 0;

void fake_engine_inject_alloc_failures(int nth)
{
    g_alloc_fail_at = nth;
    g_alloc_count = 0;
}

void fake_engine_reset_injection(void)
{
    g_alloc_fail_at = 0;
    g_alloc_count = 0;
    g_post_destroy_callbacks = 0;
}

int fake_engine_post_destroy_callbacks(void)
{
    return g_post_destroy_callbacks;
}

// Injectable allocator honoring the fault counter.
static void *fake_alloc(size_t n)
{
    if (g_alloc_fail_at > 0) {
        g_alloc_count++;
        if (g_alloc_count == g_alloc_fail_at) {
            return NULL;  // inject OOM
        }
    }
    return malloc(n);
}

// The concrete fake engine. First member is the ops pointer so the common
// dispatch overlay (farsee_engine_header) works.
typedef struct fake_engine {
    const farsee_engine_ops *ops;
    farsee_lifecycle_state state;
    bool started;
    bool destroyed;
} fake_engine;

static farsee_error_code fake_start(farsee_engine *engine)
{
    fake_engine *e = (fake_engine *)(void *)engine;
    if (e->started) {
        return FARSEE_ERR_STATE;  // repeated start rejected (§8.6)
    }
    e->state = FARSEE_LIFECYCLE_CONNECTING;
    e->started = true;
    return FARSEE_E_OK;
}

static farsee_error_code fake_request_stop(farsee_engine *engine)
{
    fake_engine *e = (fake_engine *)(void *)engine;
    // Idempotent stop (§6.2): always ok, even if already stopped.
    if (e->started && !farsee_lifecycle_is_terminal(e->state)) {
        e->state = FARSEE_LIFECYCLE_DRAINING;
    }
    return FARSEE_E_OK;
}

static farsee_error_code fake_query_capabilities(const farsee_engine *engine,
                                                 farsee_capability_set *out_caps)
{
    const fake_engine *e = (const fake_engine *)(const void *)engine;
    (void)e;
    farsee_capability_set_init(out_caps);
    // The fake advertises a minimal capability set.
    farsee_capability_set_set(out_caps, FARSEE_CAP_ABSOLUTE_POINTER, true);
    farsee_capability_set_set(out_caps, FARSEE_CAP_REMOTE_RESIZE, true);
    return FARSEE_E_OK;
}

static void fake_destroy(farsee_engine **engine_ptr)
{
    if (engine_ptr == NULL || *engine_ptr == NULL) {
        return;
    }
    fake_engine *e = (fake_engine *)(void *)*engine_ptr;
    // This fake has no background work or callback source.
    e->destroyed = true;
    if (e->destroyed) {
        // Keep the test-only sentinel referenced before releasing the object.
        (void)g_post_destroy_callbacks;  // keep symbol linked
    }
    free(e);
    *engine_ptr = NULL;
}

static const farsee_engine_ops FAKE_ENGINE_OPS = {
    .start = fake_start,
    .request_stop = fake_request_stop,
    .query_capabilities = fake_query_capabilities,
    .destroy = fake_destroy,
};

farsee_error fake_engine_create(farsee_engine **out_engine)
{
    if (out_engine == NULL) {
        return farsee_error_make(FARSEE_ERR_STATE, FARSEE_SUB_CORE,
                                 FARSEE_PHASE_NEW);
    }
    *out_engine = NULL;
    fake_engine *e = (fake_engine *)fake_alloc(sizeof(*e));
    if (e == NULL) {
        return farsee_error_make(FARSEE_ERR_OUT_OF_MEMORY, FARSEE_SUB_CORE,
                                 FARSEE_PHASE_NEW);
    }
    e->ops = &FAKE_ENGINE_OPS;
    e->state = FARSEE_LIFECYCLE_NEW;
    e->started = false;
    e->destroyed = false;
    *out_engine = (farsee_engine *)(void *)e;
    return farsee_error_make(FARSEE_E_OK, FARSEE_SUB_NONE, FARSEE_PHASE_NONE);
}
