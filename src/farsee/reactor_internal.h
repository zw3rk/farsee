// SPDX-License-Identifier: Apache-2.0
//
// Farsee reactor internal accessors (F2 gate).
//
// PRIVATE. Not installed, not included by callers. Exposes the reactor's
// slot table to the deterministic fake reactor (tests/fakes/) so the fake
// can override tick/time and inject readiness WITHOUT duplicating the
// registration, token, and dispatch logic that lives in farsee_reactor.c.
//
// This is an implementation seam, not a public API. Production code never
// includes this header.

#ifndef FARSEE_SRC_FARSEE_REACTOR_INTERNAL_H
#define FARSEE_SRC_FARSEE_REACTOR_INTERNAL_H

#include "farsee/farsee_reactor.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    FARSEE__SLOT_FREE  = 0,
    FARSEE__SLOT_FD    = 1,
    FARSEE__SLOT_TIMER = 2,
} farsee__slot_kind;

typedef struct {
    farsee__slot_kind kind;
    int   fd;
    unsigned events;
    uint64_t deadline_ms;
    farsee_reactor_cb cb;
    void *user;
    uint32_t generation;
    unsigned injected;       // fake-only readiness injection
    bool pending_remove;
} farsee__slot;

// Override hooks for the fake reactor. NULL => POSIX backend defaults.
void farsee_reactor__set_now_fn(farsee_reactor *r,
                                uint64_t (*fn)(const farsee_reactor *));
void farsee_reactor__set_tick_fn(farsee_reactor *r,
                                 int (*fn)(farsee_reactor *, size_t));

// Inject fake readiness into a slot. Returns true if the slot is now ready.
bool farsee_reactor__inject(farsee_reactor *r, farsee_reactor_token tok,
                            unsigned events);

// Direct slot access for the fake's dispatch loop. Returns NULL if idx is
// out of range.
farsee__slot *farsee_reactor__slot_at(farsee_reactor *r, size_t idx);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_SRC_FARSEE_REACTOR_INTERNAL_H
