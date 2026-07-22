// SPDX-License-Identifier: Apache-2.0
//
// farsee — Apple type-33 credential encryption + session key derivation
// (goals.md G18). Uses G16 crypto primitives and captured wire-spec.

#include "farsee/apple_type33.h"
#include "farsee/apple_crypto.h"
#include "farsee/secret.h"

#include <string.h>

bool apple33_encrypt_credentials(
    const uint8_t *spki_der, size_t spki_len,
    const char *username, size_t username_len,
    const uint8_t *password, size_t password_len,
    uint8_t out[256])
{
    if (spki_der == NULL || username == NULL || password == NULL || out == NULL)
        return false;
    if (username_len > APPLE33_CRED_MAX || password_len > APPLE33_CRED_MAX)
        return false;

    // Build the credential plaintext: username[64] + password[64] = 128 bytes.
    // Pad with random bytes (Apple format: fixed 64-byte fields, random fill).
    uint8_t plaintext[128];
    memset(plaintext, 0, sizeof plaintext);
    memcpy(plaintext, username, username_len);
    memcpy(plaintext + 64, password, password_len);

    // Fill unused bytes with random data.
    if (username_len < 64) {
        if (!rfb_crypto_random_bytes(plaintext + username_len, 64 - username_len))
            return false;
    }
    if (password_len < 64) {
        if (!rfb_crypto_random_bytes(plaintext + 64 + password_len, 64 - password_len))
            return false;
    }

    // RSA-encrypt with the server's public key.
    bool ok = rfb_crypto_rsa_encrypt_pkcs1(spki_der, spki_len,
                                           plaintext, sizeof plaintext, out);
    // Zeroize the plaintext immediately.
    rfb_secret_zero(plaintext, sizeof plaintext);
    return ok;
}

bool apple33_derive_session_key(
    const uint8_t *shared_secret, size_t secret_len,
    const uint8_t *salt, size_t salt_len,
    uint32_t iterations,
    uint8_t out_key[APPLE33_KEY_SIZE])
{
    if (shared_secret == NULL || salt == NULL || out_key == NULL)
        return false;
    if (iterations == 0 || iterations > APPLE33_PBKDF2_MAX_ITERATIONS)
        return false;

    bool ok = rfb_crypto_pbkdf2_sha512(shared_secret, secret_len,
                                       salt, salt_len, iterations,
                                       out_key, APPLE33_KEY_SIZE);
    return ok;
}

bool apple33_generate_nonce(uint8_t nonce[APPLE33_NONCE_SIZE])
{
    if (nonce == NULL) return false;
    return rfb_crypto_random_bytes(nonce, APPLE33_NONCE_SIZE);
}

bool apple33_encrypt_record(
    const uint8_t key[APPLE33_KEY_SIZE],
    const uint8_t nonce[APPLE33_NONCE_SIZE],
    const uint8_t *plaintext, size_t pt_len,
    uint8_t *out, size_t out_cap, size_t *out_len)
{
    return rfb_crypto_chacha20_poly1305_encrypt(
        key, nonce, NULL, 0, plaintext, pt_len, out, out_cap, out_len);
}

bool apple33_decrypt_record(
    const uint8_t key[APPLE33_KEY_SIZE],
    const uint8_t nonce[APPLE33_NONCE_SIZE],
    const uint8_t *ct, size_t ct_len,
    uint8_t *out, size_t out_cap, size_t *out_len)
{
    return rfb_crypto_chacha20_poly1305_decrypt(
        key, nonce, NULL, 0, ct, ct_len, out, out_cap, out_len);
}
