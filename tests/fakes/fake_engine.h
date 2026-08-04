// SPDX-License-Identifier: Apache-2.0
//
// Fake protocol engine for F1 contract tests.
// (FARSEE_ARCHITECTURE_IMPROVEMENT_PLAN.md §22/F1, §3.5 — deterministic
// fakes before production backends.)
//
// This is a TEST-ONLY engine. It implements the common farsee_engine ops
// in-memory with deterministic fault injection, so the lifecycle/
// capability/destruction invariants can be exercised without a network
// or a real protocol stack. It is NOT a protocol simulator and makes no
// interoperability claim.

#ifndef FARSEE_TESTS_FAKES_FAKE_ENGINE_H
#define FARSEE_TESTS_FAKES_FAKE_ENGINE_H

#include "farsee/farsee_engine.h"

#ifdef __cplusplus
extern "C" {
#endif

// Create a fake engine. Returns FARSEE_E_OK and *out_engine on success.
// Honors the allocation-failure injection counter below.
farsee_error fake_engine_create(farsee_engine **out_engine);

// Inject an allocation failure on the Nth allocation (1 = fail the first
// alloc inside create). Used to test OOM cleanup paths (§3.2, §8.6).
void fake_engine_inject_alloc_failures(int nth);
void fake_engine_reset_injection(void);

// Diagnostic: number of callbacks observed AFTER destroy was called.
// Must always be zero (§6.2: no callbacks after terminal state).
int fake_engine_post_destroy_callbacks(void);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_TESTS_FAKES_FAKE_ENGINE_H
