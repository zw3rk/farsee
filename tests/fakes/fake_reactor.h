// SPDX-License-Identifier: Apache-2.0
//
// Deterministic reactor test adapter.
//
// TEST-ONLY. It wraps the core registration table with injected time and
// readiness. Its tick dispatches ready slots and expired one-shot timers
// without poll or wall-clock waits. It is not a production backend.

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

// Record subscribed bits from `events` for a valid fd token. The next tick
// dispatches recorded bits. Returns false for an invalid token or when no
// supplied bit is currently subscribed.
bool fake_reactor_inject_ready(farsee_reactor *r, farsee_reactor_token tok,
                               unsigned events);

// Run one dispatch tick using the fake's injected events and elapsed time.
// (Mirrors farsee_reactor_tick but never blocks on real I/O.)
int fake_reactor_tick(farsee_reactor *r, size_t budget_callbacks);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_TESTS_FAKES_FAKE_REACTOR_H
