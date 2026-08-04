// SPDX-License-Identifier: Apache-2.0
//
// farsee — Apple dialect and authentication state-machine framework
// (goals.md G15). Supports the Apple 003.889 banner while keeping
// RFC 3.3/3.7/3.8 behavior unchanged. Provides an auth-provider
// contract with fake deterministic providers for testing.

#ifndef FARSEE_INCLUDE_FARSEE_APPLE_AUTH_H
#define FARSEE_INCLUDE_FARSEE_APPLE_AUTH_H

#include "farsee/error.h"
#include "farsee/handshake.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Apple security types (IANA + Apple registry).
#define APPLE_SEC_TYPE_30  30   // Legacy DH
#define APPLE_SEC_TYPE_33  33   // RSA/SRP local-user
#define APPLE_SEC_TYPE_35  35   // Kerberos/GSS-API
#define APPLE_SEC_TYPE_36  36   // Direct SRP

// Auth-provider result states (goals.md G15 contract).
typedef enum {
    APPLE_AUTH_NEED_MORE = 0,      // more branch messages needed
    APPLE_AUTH_SEND_BYTES,         // caller should send out_bytes
    APPLE_AUTH_AUTHENTICATED,      // success; wrap_key is valid
    APPLE_AUTH_REJECTED,           // server rejected credentials
    APPLE_AUTH_FATAL,              // unrecoverable error
} apple_auth_result_t;

// Auth-provider context. Implementations fill in the vtable.
// The wrap_key (if AUTHENTICATED) is owned by the caller after the call.
typedef struct apple_auth_ctx {
    const struct apple_auth_provider_ops *ops;
    void *impl;  // provider-specific state
} apple_auth_ctx;

// Auth-provider operations.
typedef struct apple_auth_provider_ops {
    // Process a branch message from the server. Returns the result state.
    // On SEND_BYTES, out_bytes/out_len hold what to send.
    // On AUTHENTICATED, wrap_key is filled (16 bytes).
    apple_auth_result_t (*process)(
        apple_auth_ctx *ctx,
        const uint8_t *in, size_t in_len,
        uint8_t *out_bytes, size_t out_cap, size_t *out_len,
        uint8_t wrap_key[16]);

    // Release provider-specific state.
    void (*destroy)(apple_auth_ctx *ctx);
} apple_auth_provider_ops;

// --- Fake deterministic provider (for testing) ---------------------------
// Always succeeds with a fixed wrap key after consuming N messages.
// Used to test every state-machine transition without real crypto.

typedef struct apple_auth_fake {
    int messages_consumed;
    int messages_needed;
    uint8_t wrap_key[16];
} apple_auth_fake;

void apple_auth_fake_init(apple_auth_fake *f, int messages_needed,
                          const uint8_t wrap_key[16]);

// Wrap the fake in a ctx.
apple_auth_ctx apple_auth_fake_ctx(apple_auth_fake *f);

// --- Dialect detection --------------------------------------------------
// True iff the banner matches the Apple 003.889 dialect.
bool apple_is_dialect_003_889(const uint8_t *banner, size_t len);

// --- Security type selection policy -------------------------------------
// Thin wrapper over farsee_rfb_select_security (APPLE mode; 33/36/35 on;
// type 30 only if allow_legacy). Prefer farsee_rfb_select_security with an
// explicit product policy for production. Returns 0 if none are acceptable.
int apple_select_security_type(const uint8_t *offered, size_t count,
                               bool allow_legacy);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_APPLE_AUTH_H
