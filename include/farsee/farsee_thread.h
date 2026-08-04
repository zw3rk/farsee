// SPDX-License-Identifier: Apache-2.0
//
// Farsee platform thread abstraction.
// (FARSEE_ARCHITECTURE_IMPROVEMENT_PLAN.md §8.4 — F3 gate.)
//
// The Curated C11 ban on <threads.h> stands. This is the very small
// platform thread surface the RDP worker (and only the RDP worker) uses.
// POSIX backends wrap pthread; no protocol header may include pthread.h
// (§4.2) — they use these opaque types instead.
//
// Opaque: pthread_t / pthread_mutex_t / pthread_cond_t never appear here.

#ifndef FARSEE_INCLUDE_FARSEE_FARSEE_THREAD_H
#define FARSEE_INCLUDE_FARSEE_FARSEE_THREAD_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Opaque handles. Concrete definitions live in the platform backend.
typedef struct farsee_thread farsee_thread;
typedef struct farsee_mutex farsee_mutex;
typedef struct farsee_cond  farsee_cond;

// Thread entry function.
typedef void *(*farsee_thread_fn)(void *arg);

// --- Mutex -----------------------------------------------------------------
// Creates a mutex or returns NULL on failure.
farsee_mutex *farsee_mutex_create(void);
void farsee_mutex_lock(farsee_mutex *m);
void farsee_mutex_unlock(farsee_mutex *m);
// Destroy and set to NULL. Safe on NULL.
void farsee_mutex_destroy(farsee_mutex **m);

// --- Condition variable ----------------------------------------------------
farsee_cond *farsee_cond_create(void);
// Atomically: unlock `m`, wait until signaled, re-lock `m`. Returns false
// on failure. Bounded waits use farsee_cond_timedwait.
void farsee_cond_wait(farsee_cond *c, farsee_mutex *m);
// Wait until signaled or `deadline_monotonic_ms` elapsed. Returns true if
// signaled, false on timeout (or failure).
bool farsee_cond_timedwait(farsee_cond *c, farsee_mutex *m,
                           uint64_t deadline_monotonic_ms);
void farsee_cond_signal(farsee_cond *c);     // wake one waiter
void farsee_cond_broadcast(farsee_cond *c);  // wake all waiters
void farsee_cond_destroy(farsee_cond **c);

// --- Thread ----------------------------------------------------------------
// Create and start a thread running `fn(arg)`. Returns NULL on failure.
farsee_thread *farsee_thread_create(farsee_thread_fn fn, void *arg);
// Block until the thread exits and release the handle. Sets *t to NULL.
// Safe to call after the thread has already exited. Returns the thread's
// exit value through `out_result` if non-NULL.
void farsee_thread_join(farsee_thread **t, void **out_result);

// Monotonic clock in milliseconds, suitable for condvar deadlines and
// bounded waits. Never goes backward.
uint64_t farsee_thread_monotonic_ms(void);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_FARSEE_THREAD_H
