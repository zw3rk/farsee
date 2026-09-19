// SPDX-License-Identifier: Apache-2.0
//
// Farsee common reactor and waitable contract.
//
// A portable event-reactor facade over rfb_poll_wait. It provides:
//   - add/modify/remove of waitables;
//   - read/write/error/hangup and one-shot timer events;
//   - slot-and-generation registration tokens;
//   - removal during callback dispatch;
//   - a deterministic fake with injectable time;
//   - overflow-safe timeout conversion and EINTR retry;
//   - a fixed registration cap and bounded callbacks per tick.
//
// A waitable is an abstract callback handle. The POSIX backend stores its fd
// internally.

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

// A token combines a slot index with a 32-bit generation. Removed tokens are
// stale until that generation counter wraps. FARSEE_REACTOR_INVALID_TOKEN marks none.
typedef uint64_t farsee_reactor_token;
#define FARSEE_REACTOR_INVALID_TOKEN ((farsee_reactor_token)0)

// Hard cap on simultaneous waitables and timers. The fixed slot table avoids
// per-registration allocation.
#define FARSEE_REACTOR_MAX_WAITABLES 256

// A waitable handle passed to callbacks. It carries the registration token
// so a callback can identify and remove its own waitable. Callers must not
// assume any other field meaning.
typedef struct farsee_waitable {
    farsee_reactor_token token;
} farsee_waitable;

// READ and WRITE are selected at registration. The polling backend can also
// report ERROR and HANGUP without a subscription; a tick maps those results to
// the corresponding event bits.
typedef enum {
    FARSEE_REACTOR_NONE   = 0,
    FARSEE_REACTOR_READ   = 1u << 0,
    FARSEE_REACTOR_WRITE  = 1u << 1,
    FARSEE_REACTOR_ERROR  = 1u << 2,
    FARSEE_REACTOR_HANGUP = 1u << 3,
} farsee_reactor_event;

// Callback invoked when a waitable fires. `triggered` contains subscribed
// READ/WRITE events and can also contain backend ERROR/HANGUP regardless of
// subscription. `user` is the caller's opaque context. The callback may remove
// the waitable during dispatch.
typedef void (*farsee_reactor_cb)(farsee_waitable *w,
                                  unsigned triggered,
                                  void *user);

// --- Construction / destruction -------------------------------------------

// Create a reactor bound to the real POSIX backend (wraps poll()).
// Returns NULL on allocation failure.
farsee_reactor *farsee_reactor_create(void);

// Destroy the reactor and set the caller's pointer to NULL. Safe on NULL.
// Call only after no tick or callback can access the reactor.
void farsee_reactor_destroy(farsee_reactor **r);

// --- Waitable registration -------------------------------------------------

// Add a readable/writable fd-backed waitable. `events` selects READ/WRITE.
// Returns FARSEE_REACTOR_INVALID_TOKEN for a NULL reactor or callback, an
// invalid fd, or a full registration table. On success, the token remains
// valid until removal.
farsee_reactor_token farsee_reactor_add(farsee_reactor *r, int fd,
                                        unsigned events,
                                        farsee_reactor_cb cb, void *user);

// Change the subscribed events of an existing waitable. Returns false if
// the token is unknown.
bool farsee_reactor_modify(farsee_reactor *r, farsee_reactor_token tok,
                           unsigned events);

// Remove a waitable. Safe to call from within a callback: the callback's
// context (cb/user) is snapshotted before dispatch and the running
// callback keeps its handle for its full duration, and any dispatch
// entry for the removed waitable is re-validated (dropped) rather than
// fired from stale events. Returns false if the token is unknown.
bool farsee_reactor_remove(farsee_reactor *r, farsee_reactor_token tok);

// --- Timers ----------------------------------------------------------------

// Arm a one-shot timer for `deadline_monotonic_ms`. The callback reuses
// farsee_reactor_cb with triggered == FARSEE_REACTOR_NONE. With at least one
// registered fd, the POSIX backend uses the nearest timer for its first poll
// timeout. Returns a token, or INVALID on failure.
farsee_reactor_token farsee_reactor_add_timer(farsee_reactor *r,
                                              uint64_t deadline_monotonic_ms,
                                              farsee_reactor_cb cb,
                                              void *user);

// --- Run loop --------------------------------------------------------------

// Run one tick and dispatch at most `budget_callbacks` callbacks; zero selects
// the fixed registration cap. The POSIX backend polls fd sets in chunks of 16:
// only the first chunk waits, and later chunks use a zero timeout. With no fds,
// a tick does not sleep for a pending timer. A hard poll error stops later
// chunks and returns the callbacks dispatched; -1 is returned for a NULL reactor.
int farsee_reactor_tick(farsee_reactor *r, size_t budget_callbacks);

// --- Diagnostics -----------------------------------------------------------

// Current registration count (fd waitables + timers).
size_t farsee_reactor_count(const farsee_reactor *r);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_FARSEE_REACTOR_H
