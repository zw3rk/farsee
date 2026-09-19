// SPDX-License-Identifier: Apache-2.0
//
// Farsee platform-thread abstraction with a POSIX pthread backend.
//
// pthread types remain in this implementation file. Public interfaces use
// opaque farsee_thread, farsee_mutex, and farsee_cond handles.

#include "farsee/farsee_thread.h"

#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>

struct farsee_thread {
    pthread_t tid;
    bool joined;
};

struct farsee_mutex {
    pthread_mutex_t m;
};

struct farsee_cond {
    pthread_cond_t c;
    bool monotonic_clock;  // true iff condattr bound us to CLOCK_MONOTONIC
};

uint64_t farsee_thread_monotonic_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

// --- Mutex -----------------------------------------------------------------

farsee_mutex *farsee_mutex_create(void)
{
    farsee_mutex *m = calloc(1, sizeof(*m));
    if (m == NULL) {
        return NULL;
    }
    if (pthread_mutex_init(&m->m, NULL) != 0) {
        free(m);
        return NULL;
    }
    return m;
}

void farsee_mutex_lock(farsee_mutex *m)
{
    if (m != NULL) {
        (void)pthread_mutex_lock(&m->m);
    }
}

void farsee_mutex_unlock(farsee_mutex *m)
{
    if (m != NULL) {
        (void)pthread_mutex_unlock(&m->m);
    }
}

void farsee_mutex_destroy(farsee_mutex **mp)
{
    if (mp == NULL || *mp == NULL) {
        return;
    }
    (void)pthread_mutex_destroy(&(*mp)->m);
    free(*mp);
    *mp = NULL;
}

// --- Condition variable ----------------------------------------------------

farsee_cond *farsee_cond_create(void)
{
    farsee_cond *c = calloc(1, sizeof(*c));
    if (c == NULL) {
        return NULL;
    }
    // Bind the condvar to CLOCK_MONOTONIC where supported so timedwait
    // deadlines (expressed as monotonic-ms) are interpreted correctly.
    // Fallback: default clock (CLOCK_REALTIME on macOS).
    pthread_condattr_t attr;
    bool have_attr = (pthread_condattr_init(&attr) == 0);
    bool use_monotonic = false;
    if (have_attr) {
// pthread_condattr_setclock is only declared where the platform advertises
// a monotonic clock for pthreads (Linux/glibc). Apple's pthread lacks the
// symbol entirely even though CLOCK_MONOTONIC exists, so guard on the
// POSIX feature macro, not the clock constant.
#if defined(_POSIX_MONOTONIC_CLOCK) && (_POSIX_MONOTONIC_CLOCK >= 0) && \
    defined(CLOCK_MONOTONIC)
        if (pthread_condattr_setclock(&attr, CLOCK_MONOTONIC) == 0) {
            use_monotonic = true;
        }
#endif
    }
    c->monotonic_clock = use_monotonic;
    int rc = pthread_cond_init(&c->c, have_attr ? &attr : NULL);
    if (have_attr) {
        pthread_condattr_destroy(&attr);
    }
    if (rc != 0) {
        free(c);
        return NULL;
    }
    return c;
}

void farsee_cond_wait(farsee_cond *c, farsee_mutex *m)
{
    if (c != NULL && m != NULL) {
        (void)pthread_cond_wait(&c->c, &m->m);
    }
}

bool farsee_cond_timedwait(farsee_cond *c, farsee_mutex *m,
                           uint64_t deadline_monotonic_ms)
{
    if (c == NULL || m == NULL) {
        return false;
    }
    struct timespec ts;
    if (c->monotonic_clock) {
        // Condvar is CLOCK_MONOTONIC-bound: deadline is an absolute
        // monotonic-ms timestamp.
        ts.tv_sec = (time_t)(deadline_monotonic_ms / 1000u);
        ts.tv_nsec = (long)((deadline_monotonic_ms % 1000u) * 1000000u);
    } else {
        // Fallback (e.g. macOS): condvar is CLOCK_REALTIME. Translate the
        // monotonic deadline into an absolute realtime deadline by adding
        // the remaining monotonic delta to the current realtime clock.
        uint64_t now_mono = farsee_thread_monotonic_ms();
        uint64_t delta = (deadline_monotonic_ms > now_mono)
                             ? (deadline_monotonic_ms - now_mono)
                             : 0;
        struct timespec rt;
        if (clock_gettime(CLOCK_REALTIME, &rt) != 0) {
            return false;
        }
        uint64_t rt_ms = (uint64_t)rt.tv_sec * 1000u +
                         (uint64_t)rt.tv_nsec / 1000000u;
        uint64_t abs_ms = rt_ms + delta;
        ts.tv_sec = (time_t)(abs_ms / 1000u);
        ts.tv_nsec = (long)((abs_ms % 1000u) * 1000000u);
    }
    int rc = pthread_cond_timedwait(&c->c, &m->m, &ts);
    return rc == 0;  // ETIMEDOUT -> false
}

void farsee_cond_signal(farsee_cond *c)
{
    if (c != NULL) {
        (void)pthread_cond_signal(&c->c);
    }
}

void farsee_cond_broadcast(farsee_cond *c)
{
    if (c != NULL) {
        (void)pthread_cond_broadcast(&c->c);
    }
}

void farsee_cond_destroy(farsee_cond **cp)
{
    if (cp == NULL || *cp == NULL) {
        return;
    }
    (void)pthread_cond_destroy(&(*cp)->c);
    free(*cp);
    *cp = NULL;
}

// --- Thread ----------------------------------------------------------------

farsee_thread *farsee_thread_create(farsee_thread_fn fn, void *arg)
{
    if (fn == NULL) {
        return NULL;
    }
    farsee_thread *t = calloc(1, sizeof(*t));
    if (t == NULL) {
        return NULL;
    }
    t->joined = false;
    if (pthread_create(&t->tid, NULL, fn, arg) != 0) {
        free(t);
        return NULL;
    }
    return t;
}

void farsee_thread_join(farsee_thread **tp, void **out_result)
{
    if (tp == NULL || *tp == NULL) {
        return;
    }
    farsee_thread *t = *tp;
    if (!t->joined) {
        void *res = NULL;
        (void)pthread_join(t->tid, &res);
        if (out_result != NULL) {
            *out_result = res;
        }
        t->joined = true;
    }
    free(t);
    *tp = NULL;
}
