// SPDX-License-Identifier: Apache-2.0
//
// Deterministic Apple authentication provider for tests.

#ifndef FARSEE_TESTS_FAKES_APPLE_AUTH_FAKE_H
#define FARSEE_TESTS_FAKES_APPLE_AUTH_FAKE_H

#include "farsee/apple_auth.h"

#include <stdint.h>

typedef struct apple_auth_fake {
    int messages_consumed;
    int messages_needed;
    uint8_t wrap_key[16];
} apple_auth_fake;

void apple_auth_fake_init(apple_auth_fake *fake, int messages_needed,
                          const uint8_t wrap_key[16]);
apple_auth_ctx apple_auth_fake_ctx(apple_auth_fake *fake);

#endif  // FARSEE_TESTS_FAKES_APPLE_AUTH_FAKE_H
