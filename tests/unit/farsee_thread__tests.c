// SPDX-License-Identifier: Apache-2.0
//
// F3 — platform thread abstraction tests (§8.4).
//
// Verifies the pthread-backed opaque thread/mutex/condvar surface:
//   - create/join round-trips a return value;
//   - mutex provides mutual exclusion under two threads;
//   - condvar timedwait returns false on timeout, true on signal.
//
// NOTE: these use real threads and bounded waits. They are deterministic
// in *outcome* (not wall-clock) — a correct condvar signals before the
// timeout, an unsignaled one times out. No sleeps are used as assertions.

#include "farsee/farsee_thread.h"
#include "tests/test_framework/rfb_test.h"

// --- create / join ----------------------------------------------------------

static void *return_value_42(void *arg)
{
    (void)arg;
    return (void *)42;
}

RFB_TEST(farsee_thread, create_join__returns_value)
{
    farsee_thread *t = farsee_thread_create(return_value_42, NULL);
    RFB_CHECK(t != NULL);
    void *result = NULL;
    farsee_thread_join(&t, &result);
    RFB_CHECK(t == NULL);
    RFB_CHECK_EQ_INT((long long)(long)result, 42);
}

// --- mutex mutual exclusion -------------------------------------------------

static farsee_mutex *g_mtx;
static long g_counter;

static void *incrementer(void *arg)
{
    long iters = (long)(long)arg;
    for (long i = 0; i < iters; ++i) {
        farsee_mutex_lock(g_mtx);
        ++g_counter;
        farsee_mutex_unlock(g_mtx);
    }
    return NULL;
}

RFB_TEST(farsee_thread, mutex__mutual_exclusion)
{
    g_mtx = farsee_mutex_create();
    RFB_CHECK(g_mtx != NULL);
    g_counter = 0;
    enum { N = 2, ITERS = 20000 };
    farsee_thread *threads[N];
    for (int i = 0; i < N; ++i) {
        threads[i] = farsee_thread_create(incrementer, (void *)(long)ITERS);
        RFB_CHECK(threads[i] != NULL);
    }
    for (int i = 0; i < N; ++i) {
        farsee_thread_join(&threads[i], NULL);
        RFB_CHECK(threads[i] == NULL);
    }
    // Without correct exclusion the counter would lose updates.
    RFB_CHECK_EQ_INT(g_counter, (long)N * ITERS);
    farsee_mutex_destroy(&g_mtx);
    RFB_CHECK(g_mtx == NULL);
}

// --- condvar: signal wakes a waiter ----------------------------------------

static farsee_mutex *g_cmtx;
static farsee_cond *g_ccond;
static bool g_ready;

static void *signaler(void *arg)
{
    (void)arg;
    farsee_mutex_lock(g_cmtx);
    g_ready = true;
    farsee_cond_signal(g_ccond);
    farsee_mutex_unlock(g_cmtx);
    return NULL;
}

RFB_TEST(farsee_thread, condvar__signal_wakes_waiter)
{
    g_cmtx = farsee_mutex_create();
    g_ccond = farsee_cond_create();
    g_ready = false;
    farsee_thread *t = farsee_thread_create(signaler, NULL);
    RFB_CHECK(t != NULL);
    // Wait for the signaler to set ready. Bounded deadline so a bug fails
    // fast rather than hanging the suite.
    farsee_mutex_lock(g_cmtx);
    uint64_t deadline = farsee_thread_monotonic_ms() + 2000;
    while (!g_ready) {
        if (!farsee_cond_timedwait(g_ccond, g_cmtx, deadline)) {
            break;  // timeout — g_ready stays false, assertion below fails
        }
    }
    bool seen = g_ready;
    farsee_mutex_unlock(g_cmtx);
    farsee_thread_join(&t, NULL);
    RFB_CHECK(seen);
    farsee_cond_destroy(&g_ccond);
    farsee_mutex_destroy(&g_cmtx);
}

// --- condvar: unsignaled timedwait times out --------------------------------

RFB_TEST(farsee_thread, condvar__timedwait_timeout_returns_false)
{
    farsee_mutex *m = farsee_mutex_create();
    farsee_cond *c = farsee_cond_create();
    farsee_mutex_lock(m);
    // 1ms deadline in the past -> immediate timeout, no signaler.
    bool ok = farsee_cond_timedwait(c, m, farsee_thread_monotonic_ms());
    farsee_mutex_unlock(m);
    RFB_CHECK(ok == false);
    farsee_cond_destroy(&c);
    farsee_mutex_destroy(&m);
}

// --- destroy NULL is safe ---------------------------------------------------

RFB_TEST(farsee_thread, destroy_null_handles_are_safe)
{
    farsee_thread *t = NULL;
    farsee_mutex *m = NULL;
    farsee_cond *c = NULL;
    farsee_thread_join(&t, NULL);
    farsee_mutex_destroy(&m);
    farsee_cond_destroy(&c);
    RFB_CHECK(t == NULL && m == NULL && c == NULL);
}
