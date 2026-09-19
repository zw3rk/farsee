// SPDX-License-Identifier: Apache-2.0
//
// Unit tests for the deterministic fake reactor.
//
// They cover registration, injected readiness, subscription changes, token
// invalidation, one-shot timers, self-removal, the fixed registration cap, and
// the per-tick callback limit. They do not exercise the POSIX poll path,
// wall-clock time, wakeup implementation, or concurrent use.

#include "fakes/fake_reactor.h"
#include "farsee/farsee_reactor.h"
#include "farsee/farsee_wakeup.h"
#include "tests/test_framework/rfb_test.h"

// Shared callback context.
typedef struct {
    int fired_count;
    unsigned last_triggered;
    farsee_reactor_token self_tok;
    farsee_reactor *r;
    bool remove_self;
} cb_ctx;

static void on_event(farsee_waitable *w, unsigned triggered, void *user)
{
    (void)w;
    cb_ctx *c = (cb_ctx *)user;
    c->fired_count++;
    c->last_triggered = triggered;
    if (c->remove_self) {
        (void)farsee_reactor_remove(c->r, c->self_tok);
    }
}

// ---- add / dispatch / remove ----------------------------------------------

RFB_TEST(farsee_reactor, add_and_dispatch__fires_callback)
{
    farsee_reactor *r = fake_reactor_create();
    cb_ctx c = {0};
    farsee_reactor_token tok = farsee_reactor_add(r, /*fd*/3,
        FARSEE_REACTOR_READ, on_event, &c);
    RFB_CHECK(tok != FARSEE_REACTOR_INVALID_TOKEN);
    RFB_CHECK_EQ_UINT(farsee_reactor_count(r), 1u);

    RFB_CHECK(fake_reactor_inject_ready(r, tok, FARSEE_REACTOR_READ));
    int n = fake_reactor_tick(r, 16);
    RFB_CHECK_EQ_INT(n, 1);
    RFB_CHECK_EQ_INT(c.fired_count, 1);
    RFB_CHECK_EQ_UINT(c.last_triggered, FARSEE_REACTOR_READ);

    farsee_reactor_destroy(&r);
    RFB_CHECK(r == NULL);
}

RFB_TEST(farsee_reactor, modify__changes_subscribed_events)
{
    farsee_reactor *r = fake_reactor_create();
    cb_ctx c = {0};
    farsee_reactor_token tok = farsee_reactor_add(r, 4,
        FARSEE_REACTOR_READ, on_event, &c);
    RFB_CHECK(farsee_reactor_modify(r, tok, FARSEE_REACTOR_WRITE));
    // READ no longer subscribed: injecting READ must not fire.
    RFB_CHECK(fake_reactor_inject_ready(r, tok, FARSEE_REACTOR_READ) == false);
    int n = fake_reactor_tick(r, 16);
    RFB_CHECK_EQ_INT(n, 0);
    RFB_CHECK_EQ_INT(c.fired_count, 0);
    // WRITE is subscribed: injecting WRITE fires.
    RFB_CHECK(fake_reactor_inject_ready(r, tok, FARSEE_REACTOR_WRITE));
    n = fake_reactor_tick(r, 16);
    RFB_CHECK_EQ_INT(n, 1);
    RFB_CHECK_EQ_INT(c.fired_count, 1);
    farsee_reactor_destroy(&r);
}

RFB_TEST(farsee_reactor, remove_unknown_token__returns_false)
{
    farsee_reactor *r = fake_reactor_create();
    RFB_CHECK(farsee_reactor_remove(r, FARSEE_REACTOR_INVALID_TOKEN) == false);
    RFB_CHECK(farsee_reactor_remove(r, 999) == false);
    farsee_reactor_destroy(&r);
}

// ---- token generation after one remove/re-add -----------------------------

RFB_TEST(farsee_reactor, token_changes_after_one_remove_and_readd)
{
    farsee_reactor *r = fake_reactor_create();
    cb_ctx c1 = {0};
    farsee_reactor_token t1 = farsee_reactor_add(r, 5,
        FARSEE_REACTOR_READ, on_event, &c1);
    RFB_CHECK(farsee_reactor_remove(r, t1));
    cb_ctx c2 = {0};
    farsee_reactor_token t2 = farsee_reactor_add(r, 6,
        FARSEE_REACTOR_READ, on_event, &c2);
    // This immediate remove/re-add must produce a distinct token.
    RFB_CHECK_MSG(t2 != t1, "immediate remove/re-add returned the same token");
    RFB_CHECK(farsee_reactor_modify(r, t1, FARSEE_REACTOR_WRITE) == false);
    farsee_reactor_destroy(&r);
}

// ---- timers with injectable time ------------------------------------------

static void on_timer(farsee_waitable *w, unsigned triggered, void *user)
{
    (void)w; (void)triggered;
    cb_ctx *c = (cb_ctx *)user;
    c->fired_count++;
}

RFB_TEST(farsee_reactor, timer__fires_after_deadline)
{
    farsee_reactor *r = fake_reactor_create();
    cb_ctx c = {0};
    farsee_reactor_token t = farsee_reactor_add_timer(r,
        /*deadline_ms*/100, on_timer, &c);
    RFB_CHECK(t != FARSEE_REACTOR_INVALID_TOKEN);

    // Before the deadline: no fire.
    fake_reactor_advance(r, 50);
    RFB_CHECK_EQ_INT(fake_reactor_tick(r, 16), 0);
    RFB_CHECK_EQ_INT(c.fired_count, 0);

    // At/after the deadline: fires exactly once.
    fake_reactor_advance(r, 60);  // total 110 >= 100
    RFB_CHECK_EQ_INT(fake_reactor_tick(r, 16), 1);
    RFB_CHECK_EQ_INT(c.fired_count, 1);
    // A one-shot timer does not fire again on subsequent ticks.
    RFB_CHECK_EQ_INT(fake_reactor_tick(r, 16), 0);
    farsee_reactor_destroy(&r);
}

// ---- safe removal during callback dispatch --------------------------------

RFB_TEST(farsee_reactor, remove_during_callback__safe)
{
    farsee_reactor *r = fake_reactor_create();
    cb_ctx c = {0};
    c.r = r;
    c.self_tok = farsee_reactor_add(r, 7, FARSEE_REACTOR_READ, on_event, &c);
    c.remove_self = true;
    RFB_CHECK(fake_reactor_inject_ready(r, c.self_tok, FARSEE_REACTOR_READ));
    // The callback removes its slot; the tick reports one dispatch and the
    // registration table is empty afterward.
    int n = fake_reactor_tick(r, 16);
    RFB_CHECK_EQ_INT(n, 1);
    RFB_CHECK_EQ_INT(c.fired_count, 1);
    RFB_CHECK_EQ_UINT(farsee_reactor_count(r), 0u);
    farsee_reactor_destroy(&r);
}

// ---- registration cap ------------------------------------------------------

RFB_TEST(farsee_reactor, registration_cap__enforced)
{
    farsee_reactor *r = fake_reactor_create();
    cb_ctx c = {0};
    farsee_reactor_token last = FARSEE_REACTOR_INVALID_TOKEN;
    bool capped = false;
    // Register up to the cap; the (cap+1)th must be refused.
    for (int i = 0; i < FARSEE_REACTOR_MAX_WAITABLES + 4; ++i) {
        last = farsee_reactor_add(r, 100 + i, FARSEE_REACTOR_READ, on_event, &c);
        if (last == FARSEE_REACTOR_INVALID_TOKEN) {
            capped = true;
            break;
        }
    }
    RFB_CHECK_MSG(capped, "reactor did not enforce its registration cap");
    farsee_reactor_destroy(&r);
}

// ---- bounded callbacks per tick -------------------------------------------

RFB_TEST(farsee_reactor, bounded_callbacks_per_tick)
{
    farsee_reactor *r = fake_reactor_create();
    // Arm more ready waitables than the per-tick budget; this tick dispatches
    // exactly `budget` callbacks.
    enum { N = 8 };
    cb_ctx ctxs[N];
    for (int i = 0; i < N; ++i) {
        ctxs[i] = (cb_ctx){0};
        farsee_reactor_token t = farsee_reactor_add(r, 200 + i,
            FARSEE_REACTOR_READ, on_event, &ctxs[i]);
        RFB_CHECK(fake_reactor_inject_ready(r, t, FARSEE_REACTOR_READ));
    }
    int dispatched = fake_reactor_tick(r, /*budget*/3);
    RFB_CHECK_MSG(dispatched <= 3, "tick exceeded its callback budget");
    RFB_CHECK_EQ_INT(dispatched, 3);
    // Invoke later ticks for the remaining injected events.
    (void)fake_reactor_tick(r, 16);
    (void)fake_reactor_tick(r, 16);
    farsee_reactor_destroy(&r);
}
