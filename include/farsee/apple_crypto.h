// SPDX-License-Identifier: Apache-2.0
//
// farsee — Apple-auth crypto provider (plan.md/goals.md G16, ADR-0007).
//
// Narrow internal wrappers over OpenSSL 3.x for the crypto primitives
// required by Apple authentication (SRP, RSA, AES, PBKDF2, SHA, etc.).
// No OpenSSL types appear in this public header; all are hidden behind
// opaque pointers or plain byte arrays.

#ifndef FARSEE_INCLUDE_FARSEE_APPLE_CRYPTO_H
#define FARSEE_INCLUDE_FARSEE_APPLE_CRYPTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// --- Secure random -------------------------------------------------------
// Fill `buf` with `n` cryptographically random bytes. Returns true on success.
bool rfb_crypto_random_bytes(uint8_t *buf, size_t n);

// --- Constant-time compare -----------------------------------------------
// Returns true iff `a` and `b` have the same `n` bytes (constant-time).
bool rfb_crypto_ct_eq(const uint8_t *a, const uint8_t *b, size_t n);

// --- Zeroization ---------------------------------------------------------
// Already provided by rfb_secret_zero (G1). This is an alias for clarity.
#define rfb_crypto_zero(buf, n) rfb_secret_zero((buf), (n))

// --- Hash digests --------------------------------------------------------
// SHA-256: 32-byte output.
bool rfb_crypto_sha256(const uint8_t *data, size_t len, uint8_t out[32]);

// SHA-512: 64-byte output.
bool rfb_crypto_sha512(const uint8_t *data, size_t len, uint8_t out[64]);

// SHA-1: 20-byte output (legacy; used by SRP-6a for some operations).
bool rfb_crypto_sha1(const uint8_t *data, size_t len, uint8_t out[20]);

// MD5: 16-byte output (legacy; only for type-30 fallback when available).
bool rfb_crypto_md5(const uint8_t *data, size_t len, uint8_t out[16]);

// --- HMAC ----------------------------------------------------------------
// HMAC-SHA512: 64-byte output.
bool rfb_crypto_hmac_sha512(const uint8_t *key, size_t key_len,
                            const uint8_t *data, size_t data_len,
                            uint8_t out[64]);

// --- PBKDF2 --------------------------------------------------------------
// PBKDF2-HMAC-SHA512. Returns true on success.
bool rfb_crypto_pbkdf2_sha512(const uint8_t *password, size_t password_len,
                              const uint8_t *salt, size_t salt_len,
                              uint32_t iterations,
                              uint8_t *out, size_t out_len);

// --- RSA-2048 PKCS#1 v1.5 encryption ------------------------------------
// Encrypt `data` (len ≤ 245 for RSA-2048 with PKCS#1 v1.5 padding) using
// the RSA public key from a DER SubjectPublicKeyInfo blob. Output is 256 bytes.
// Returns true on success.
bool rfb_crypto_rsa_encrypt_pkcs1(const uint8_t *spki_der, size_t spki_len,
                                  const uint8_t *data, size_t data_len,
                                  uint8_t out[256]);

// --- DER SPKI fingerprint ------------------------------------------------
// Compute SHA-256 fingerprint of a DER SubjectPublicKeyInfo blob.
bool rfb_crypto_spki_fingerprint(const uint8_t *spki_der, size_t spki_len,
                                 uint8_t out_sha256[32]);

// --- AES-128-ECB single-block decrypt (unwrap) ---------------------------
// Decrypt a single 16-byte block with AES-128-ECB. Used for key unwrapping.
bool rfb_crypto_aes128_ecb_decrypt(const uint8_t key[16],
                                   const uint8_t in[16], uint8_t out[16]);

// --- AES-128-CBC bidirectional context -----------------------------------
// Opaque context for a persistent AES-128-CBC encryption/decryption stream.
typedef struct rfb_crypto_cbc_ctx rfb_crypto_cbc_ctx;

rfb_crypto_cbc_ctx *rfb_crypto_cbc_new(void);
void rfb_crypto_cbc_free(rfb_crypto_cbc_ctx *ctx);

// Initialize for encryption or decryption with key + IV.
bool rfb_crypto_cbc_init(rfb_crypto_cbc_ctx *ctx, bool encrypt,
                         const uint8_t key[16], const uint8_t iv[16]);

// Process data. For decryption, output may be shorter than input (padding).
// Sets *out_len to the actual output length.
bool rfb_crypto_cbc_update(rfb_crypto_cbc_ctx *ctx,
                           const uint8_t *in, size_t in_len,
                           uint8_t *out, size_t out_cap, size_t *out_len);

// Finalize (flush remaining block/padding).
bool rfb_crypto_cbc_final(rfb_crypto_cbc_ctx *ctx,
                          uint8_t *out, size_t out_cap, size_t *out_len);

// --- ChaCha20-Poly1305 AEAD -----------------------------------------------
// Encrypt plaintext with key (32 bytes), nonce (12 bytes), optional AAD.
// Output = ciphertext (same length as plaintext) + 16-byte Poly1305 tag.
// Returns true on success. out_cap must be >= pt_len + 16.
bool rfb_crypto_chacha20_poly1305_encrypt(
    const uint8_t key[32], const uint8_t nonce[12],
    const uint8_t *aad, size_t aad_len,
    const uint8_t *pt, size_t pt_len,
    uint8_t *out, size_t out_cap, size_t *out_len);

// Decrypt ciphertext+tag with key, nonce, optional AAD.
// ct_len includes the 16-byte tag. Returns true if authentication passes.
bool rfb_crypto_chacha20_poly1305_decrypt(
    const uint8_t key[32], const uint8_t nonce[12],
    const uint8_t *aad, size_t aad_len,
    const uint8_t *ct, size_t ct_len,
    uint8_t *out, size_t out_cap, size_t *out_len);
// Returns true on success.
bool rfb_crypto_modexp(const uint8_t *base, size_t base_len,
                       const uint8_t *exp, size_t exp_len,
                       const uint8_t *mod, size_t mod_len,
                       uint8_t *out, size_t out_len);

// Modular multiply: result = (a * b) mod m. Output is zero-padded to out_len.
// Returns true on success.
bool rfb_crypto_modmul(const uint8_t *a, size_t a_len,
                       const uint8_t *b, size_t b_len,
                       const uint8_t *mod, size_t mod_len,
                       uint8_t *out, size_t out_len);

// Modular add: result = (a + b) mod m. Output is zero-padded to out_len.
bool rfb_crypto_modadd(const uint8_t *a, size_t a_len,
                       const uint8_t *b, size_t b_len,
                       const uint8_t *mod, size_t mod_len,
                       uint8_t *out, size_t out_len);

// Modular subtract: result = (a - b) mod m. Output is zero-padded to out_len.
bool rfb_crypto_modsub(const uint8_t *a, size_t a_len,
                       const uint8_t *b, size_t b_len,
                       const uint8_t *mod, size_t mod_len,
                       uint8_t *out, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_APPLE_CRYPTO_H
