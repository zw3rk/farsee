// SPDX-License-Identifier: Apache-2.0
//
// Farsee common reactor and waitable contract.
// (FARSEE_ARCHITECTURE_IMPROVEMENT_PLAN.md §8 — F2 gate.)
//
// A portable event-reactor facade. The proven POSIX poller
// (include/farsee/poller.h, rfb_poll_wait) is adapted BEHIND this facade;
// it is not replaced (§8.1). The reactor adds:
//   - add/modify/remove of waitables;
//   - read/write/error/hangup/timer/wakeup events;
//   - monotonic-deadline timers;
//   - a cancellation wakeup primitive;
//   - stable registration tokens immune to stale reuse;
//   - safe removal during callback dispatch;
//   - a deterministic fake (injectable time) for tests;
//   - overflow-safe timeout conversion and EINTR retry;
//   - a maximum registration count and bounded callbacks per tick.
//
// Opaque: no raw POSIX fd as the only waitable form (§4.2). A waitable is
// an abstract handle; the POSIX backend wraps an fd internally, a future
// Windows backend may wrap a HANDLE.

#ifndef FARSEE_INCLUDE_FARSEE_FARSEE_REACTOR_H
#define FARSEE_INCLUDE_FARSEE_FARSEE_REACTOR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Opaque reactor.
typedef struct farsee_reactor farsee_reactor;

// A stable registration token. A removed token is never reused for a
// different waitable (§8.2). FARSEE_REACTOR_INVALID_TOKEN marks none.
typedef uint64_t farsee_reactor_token;
#define FARSEE_REACTOR_INVALID_TOKEN ((farsee_reactor_token)0)

// Hard cap on simultaneous waitables+timers (§8.2 "a maximum registration
// count"). Sized to cover RFB (a few fds) plus headroom for the RDP worker
// wakeup and future multi-lane transports, while keeping allocations fixed.
#define FARSEE_REACTOR_MAX_WAITABLES 256

// A waitable handle passed to callbacks. It carries the stable registration
// token so a callback can identify itself (e.g. to remove its own waitable
// during dispatch, §8.2). Callers must not assume any other field meaning.
typedef struct farsee_waitable {
    farsee_reactor_token token;
} farsee_waitable;

// Event flags a waitable can subscribe to and receive.
typedef enum {
    FARSEE_REACTOR_NONE   = 0,
    FARSEE_REACTOR_READ   = 1u << 0,
    FARSEE_REACTOR_WRITE  = 1u << 1,
    FARSEE_REACTOR_ERROR  = 1u << 2,
    FARSEE_REACTOR_HANGUP = 1u << 3,
} farsee_reactor_event;

// Callback invoked when a waitable fires. `triggered` is the subset of
// subscribed events that occurred. `user` is the caller's opaque context.
// The callback MAY remove the waitable from the reactor during dispatch
// (safe-removal contract, §8.2).
typedef void (*farsee_reactor_cb)(farsee_waitable *w,
                                  unsigned triggered,
                                  void *user);

// --- Construction / destruction -------------------------------------------

// Create a reactor bound to the real POSIX backend (wraps poll()).
// Returns NULL on allocation failure.
farsee_reactor *farsee_reactor_create(void);

// Destroy the reactor and all waitables it owns. Safe on NULL. After
// return no callback may fire (§3.2 deterministic release).
void farsee_reactor_destroy(farsee_reactor **r);

// --- Waitable registration -------------------------------------------------

// Add a readable/writable fd-backed waitable. `events` selects READ/WRITE.
// Returns FARSEE_REACTOR_INVALID_TOKEN on failure (NULL reactor, too many
// registrations, OOM, or invalid fd). On success the token is stable for
// the waitable's lifetime.
farsee_reactor_token farsee_reactor_add(farsee_reactor *r, int fd,
                                        unsigned events,
                                        farsee_reactor_cb cb, void *user);

// Change the subscribed events of an existing waitable. Returns false if
// the token is unknown.
bool farsee_reactor_modify(farsee_reactor *r, farsee_reactor_token tok,
                           unsigned events);

// Remove a waitable. Safe to call from within a callback (the reactor
// defers the actual teardown until after callback dispatch returns, so
// the waitable pointer passed to the running callback stays valid for the
// callback's duration). Returns false if the token is unknown.
bool farsee_reactor_remove(farsee_reactor *r, farsee_reactor_token tok);

// --- Timers ----------------------------------------------------------------

// Arm a one-shot timer that fires after `deadline_monotonic_ms`. The
// callback reuses farsee_reactor_cb (triggered == FARSEE_REACTOR_NONE for
// timers). Returns a token (or INVALID on failure). Timers are coalesced
// into the poll timeout by the POSIX backend.
farsee_reactor_token farsee_reactor_add_timer(farsee_reactor *r,
                                              uint64_t deadline_monotonic_ms,
                                              farsee_reactor_cb cb,
                                              void *user);

// --- Run loop --------------------------------------------------------------

// Run one tick: wait for events or the nearest timer, dispatch ready
// callbacks (bounded per tick to prevent starvation, §8.2), then return.
// Returns the number of callbacks dispatched, or -1 on error. A zero
// `budget_callbacks` means a backend default cap. Respects EINTR retry
// for signals that do not otherwise terminate the loop.
int farsee_reactor_tick(farsee_reactor *r, size_t budget_callbacks);

// --- Diagnostics -----------------------------------------------------------

// Current registration count (fd waitables + timers).
size_t farsee_reactor_count(const farsee_reactor *r);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_FARSEE_REACTOR_H
