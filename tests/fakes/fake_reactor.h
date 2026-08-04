// SPDX-License-Identifier: Apache-2.0
//
// Deterministic fake reactor for F2+ tests.
// (FARSEE_ARCHITECTURE_IMPROVEMENT_PLAN.md §8.2, §3.5 — F2 gate.)
//
// TEST-ONLY. Implements the farsee_reactor ops with injectable monotonic
// time and explicit event injection, so reactor-driven logic (timers,
// wakeup, safe-removal) can be tested without real I/O or wall-clock
// delays. NOT a production backend.

#ifndef FARSEE_TESTS_FAKES_FAKE_REACTOR_H
#define FARSEE_TESTS_FAKES_FAKE_REACTOR_H

#include "farsee/farsee_reactor.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Create a fake reactor. Starts at monotonic time 0.
farsee_reactor *fake_reactor_create(void);

// Advance the fake's monotonic clock by `ms`. Does not fire timers by
// itself; call fake_reactor_tick to dispatch.
void fake_reactor_advance(farsee_reactor *r, uint64_t ms);

// Read the fake's current monotonic time.
uint64_t fake_reactor_now_ms(const farsee_reactor *r);

// Inject a ready event on the waitable identified by `tok` (set of
// FARSEE_REACTOR_READ/WRITE/...). The next tick dispatches its callback.
// Returns false if the token is unknown.
bool fake_reactor_inject_ready(farsee_reactor *r, farsee_reactor_token tok,
                               unsigned events);

// Run one dispatch tick using the fake's injected events and elapsed time.
// (Mirrors farsee_reactor_tick but never blocks on real I/O.)
int fake_reactor_tick(farsee_reactor *r, size_t budget_callbacks);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_TESTS_FAKES_FAKE_REACTOR_H
