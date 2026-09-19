// SPDX-License-Identifier: Apache-2.0
//
// farsee — Apple type-33 credential encryption + session key derivation.
// Uses the Apple crypto primitives and protocol contract
// to implement the RSA-based credential envelope and PBKDF2-SHA512 key
// derivation.

#ifndef FARSEE_INCLUDE_FARSEE_APPLE_TYPE33_H
#define FARSEE_INCLUDE_FARSEE_APPLE_TYPE33_H

#include "farsee/error.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Maximum username/password length (Apple uses 64-byte fixed fields).
#define APPLE33_CRED_MAX 64

// ChaCha20 key size (32 bytes).
#define APPLE33_KEY_SIZE 32

// Poly1305 tag size (16 bytes).
#define APPLE33_TAG_SIZE 16

// Nonce size for ChaCha20-Poly1305 (12 bytes).
#define APPLE33_NONCE_SIZE 12

// PBKDF2 iteration cap (defense against malicious servers).
#define APPLE33_PBKDF2_MAX_ITERATIONS 10000000u

// Encrypt credentials (username + password) using the server's RSA public key.
// The server's SPKI is in DER format. The output is a 256-byte RSA ciphertext.
// Username and password are padded to 64 bytes with random bytes (per Apple format).
// Returns true on success.
bool apple33_encrypt_credentials(
    const uint8_t *spki_der, size_t spki_len,
    const char *username, size_t username_len,
    const uint8_t *password, size_t password_len,
    uint8_t out[256]);

// Derive a ChaCha20-Poly1305 session key from PBKDF2-HMAC-SHA512.
// Uses the shared secret as password, a server-provided salt, and the
// server-provided iteration count. The output is a 32-byte key.
// Returns true on success, false if iterations exceed the cap.
bool apple33_derive_session_key(
    const uint8_t *shared_secret, size_t secret_len,
    const uint8_t *salt, size_t salt_len,
    uint32_t iterations,
    uint8_t out_key[APPLE33_KEY_SIZE]);

// Generate a random 12-byte nonce for ChaCha20-Poly1305.
bool apple33_generate_nonce(uint8_t nonce[APPLE33_NONCE_SIZE]);

// Encrypt a session record using ChaCha20-Poly1305 with the derived key.
// Output = ciphertext + 16-byte tag. Returns true on success.
bool apple33_encrypt_record(
    const uint8_t key[APPLE33_KEY_SIZE],
    const uint8_t nonce[APPLE33_NONCE_SIZE],
    const uint8_t *plaintext, size_t pt_len,
    uint8_t *out, size_t out_cap, size_t *out_len);

// Decrypt + authenticate a session record.
// ct_len includes the 16-byte tag. Returns true if authentication passes.
bool apple33_decrypt_record(
    const uint8_t key[APPLE33_KEY_SIZE],
    const uint8_t nonce[APPLE33_NONCE_SIZE],
    const uint8_t *ct, size_t ct_len,
    uint8_t *out, size_t out_cap, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_APPLE_TYPE33_H
