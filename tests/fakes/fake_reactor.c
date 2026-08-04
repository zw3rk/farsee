// SPDX-License-Identifier: Apache-2.0
//
// Deterministic fake reactor implementation (F2 gate, §8.2, §3.5).
//
// TEST-ONLY. Builds on the core farsee_reactor registration table via the
// private reactor_internal.h seam, overriding tick/time with an injectable
// monotonic clock and explicit event injection, so reactor-driven logic is
// testable without real I/O or wall-clock delays.

#include "fakes/fake_reactor.h"

// PRIVATE seam into the core reactor. Only this test fake uses it.
// Resolves via -I$(SRC_DIR) to src/farsee/reactor_internal.h.
#include "farsee/reactor_internal.h"

#include "farsee/farsee_reactor.h"

#include <stdbool.h>
#include <stddef.h>

// The fake's injected-time store. Tests are single-threaded and
// sequential, so a small per-reactor registry keyed by pointer suffices.
#define FAKE_MAX 8
static struct {
    const farsee_reactor *r;
    uint64_t now_ms;
} g_clock[FAKE_MAX];

static int find_slot(const farsee_reactor *r)
{
    for (int i = 0; i < FAKE_MAX; ++i) {
        if (g_clock[i].r == r) {
            return i;
        }
    }
    return -1;
}

static int claim_slot(const farsee_reactor *r)
{
    int i = find_slot(r);
    if (i >= 0) {
        return i;
    }
    for (int j = 0; j < FAKE_MAX; ++j) {
        if (g_clock[j].r == NULL) {
            g_clock[j].r = r;
            g_clock[j].now_ms = 0;
            return j;
        }
    }
    return -1;
}

static uint64_t fake_now_ms(const farsee_reactor *r)
{
    int i = find_slot(r);
    return (i >= 0) ? g_clock[i].now_ms : 0;
}

// Token packing mirrors the core (reactor_internal.h consumers may rely on
// the same layout as farsee_reactor.c's MAKE_TOKEN).
static farsee_reactor_token make_tok(size_t idx, uint32_t gen)
{
    return (((farsee_reactor_token)gen) << 32) |
           (farsee_reactor_token)(idx + 1u);
}

// Fake tick: dispatch fd slots with injected readiness, then expired
// timers, respecting the per-tick callback budget (§8.2 starvation guard).
static int fake_tick(farsee_reactor *r, size_t budget_callbacks)
{
    size_t budget = (budget_callbacks == 0) ? FARSEE_REACTOR_MAX_WAITABLES
                                            : budget_callbacks;
    int dispatched = 0;
    uint64_t now = fake_now_ms(r);

    // Ready fd slots.
    for (size_t i = 0; i < FARSEE_REACTOR_MAX_WAITABLES &&
                       (size_t)dispatched < budget; ++i) {
        farsee__slot *s = farsee_reactor__slot_at(r, i);
        if (s == NULL || s->kind != FARSEE__SLOT_FD) {
            continue;
        }
        if (s->injected == 0) {
            continue;
        }
        unsigned triggered = s->injected;
        farsee_reactor_cb cb = s->cb;
        void *user = s->user;
        s->injected = 0;
        // Snapshot gen so we can detect self-removal after the callback.
        uint32_t gen_before = s->generation;
        farsee_waitable h;
        h.token = make_tok(i, s->generation);
        cb(&h, triggered, user);
        ++dispatched;
        (void)gen_before;  // removal correctness is owned by farsee_reactor_remove
    }

    // Expired one-shot timers.
    for (size_t i = 0; i < FARSEE_REACTOR_MAX_WAITABLES &&
                       (size_t)dispatched < budget; ++i) {
        farsee__slot *s = farsee_reactor__slot_at(r, i);
        if (s == NULL || s->kind != FARSEE__SLOT_TIMER) {
            continue;
        }
        if (s->deadline_ms > now) {
            continue;
        }
        farsee_reactor_cb cb = s->cb;
        void *user = s->user;
        farsee_reactor_token tok = make_tok(i, s->generation);
        farsee_reactor_remove(r, tok);  // one-shot: remove before dispatch
        farsee_waitable h;
        h.token = tok;
        cb(&h, FARSEE_REACTOR_NONE, user);
        ++dispatched;
    }
    return dispatched;
}

farsee_reactor *fake_reactor_create(void)
{
    farsee_reactor *r = farsee_reactor_create();
    if (r == NULL) {
        return NULL;
    }
    (void)claim_slot(r);
    farsee_reactor__set_now_fn(r, fake_now_ms);
    farsee_reactor__set_tick_fn(r, fake_tick);
    return r;
}

void fake_reactor_advance(farsee_reactor *r, uint64_t ms)
{
    int i = find_slot(r);
    if (i >= 0) {
        g_clock[i].now_ms += ms;
    }
}

uint64_t fake_reactor_now_ms(const farsee_reactor *r)
{
    return fake_now_ms(r);
}

bool fake_reactor_inject_ready(farsee_reactor *r, farsee_reactor_token tok,
                               unsigned events)
{
    return farsee_reactor__inject(r, tok, events);
}

int fake_reactor_tick(farsee_reactor *r, size_t budget_callbacks)
{
    // The core farsee_reactor_tick dispatches to r->tick_fn (fake_tick).
    return farsee_reactor_tick(r, budget_callbacks);
}
