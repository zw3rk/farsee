// SPDX-License-Identifier: Apache-2.0
//
// Fake protocol engine for F1 contract tests.
//
// TEST-ONLY. The fake implements the common engine operations in memory,
// advertises two fixed capabilities, and supports deterministic allocation
// failure. It has no network, protocol stack, worker, or callback source.

#ifndef FARSEE_TESTS_FAKES_FAKE_ENGINE_H
#define FARSEE_TESTS_FAKES_FAKE_ENGINE_H

#include "farsee/farsee_engine.h"

#ifdef __cplusplus
extern "C" {
#endif

// Create a fake engine. Returns FARSEE_E_OK and *out_engine on success.
// Honors the allocation-failure injection counter below.
farsee_error fake_engine_create(farsee_engine **out_engine);

// Configure failure of the Nth fake allocation; 1 fails create's allocation.
void fake_engine_inject_alloc_failures(int nth);
void fake_engine_reset_injection(void);

// Return the test-only post-destroy sentinel. This fake has no callback
// source, so the sentinel remains at its reset value of zero.
int fake_engine_post_destroy_callbacks(void);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_TESTS_FAKES_FAKE_ENGINE_H
