// SPDX-License-Identifier: Apache-2.0
//
// G18 — Apple type-33 credential encryption + session key derivation tests.
// Uses a self-generated RSA key pair for credential encryption tests and
// deterministic PBKDF2 vectors.

#include "rfb_test.h"
#include "farsee/apple_type33.h"
#include "farsee/apple_crypto.h"
#include "farsee/secret.h"

#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <string.h>
#include <stdlib.h>

// Helper: generate an RSA-2048 key pair and return SPKI DER + private key.
typedef struct {
    uint8_t spki_der[1024];
    size_t spki_len;
    EVP_PKEY *pkey;
} test_rsa_key;

static bool gen_rsa_key(test_rsa_key *k)
{
    memset(k, 0, sizeof *k);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (ctx == NULL) return false;
    bool ok = false;
    if (EVP_PKEY_keygen_init(ctx) == 1 &&
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) == 1 &&
        EVP_PKEY_keygen(ctx, &k->pkey) == 1) {
        // Extract SPKI DER.
        unsigned char *p = k->spki_der;
        int len = i2d_PUBKEY(k->pkey, &p);
        if (len > 0 && (size_t)len <= sizeof k->spki_der) {
            k->spki_len = (size_t)len;
            ok = true;
        }
    }
    EVP_PKEY_CTX_free(ctx);
    return ok;
}

static void free_rsa_key(test_rsa_key *k)
{
    if (k->pkey) EVP_PKEY_free(k->pkey);
}

// --- Credential encryption roundtrip (encrypt with SPKI, decrypt with private key) ---
RFB_TEST(g18_t33, credentials__encrypt_decrypt_roundtrip) {
    test_rsa_key key;
    RFB_CHECK(gen_rsa_key(&key));

    static const char *username = "testuser";
    static const uint8_t password[] = "testpass123";

    uint8_t encrypted[256];
    RFB_CHECK(apple33_encrypt_credentials(
        key.spki_der, key.spki_len,
        username, strlen(username),
        password, strlen((const char *)password),
        encrypted));

    // Decrypt with the private key.
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key.pkey, NULL);
    RFB_CHECK(ctx != NULL);
    uint8_t decrypted[256];
    size_t dec_len = sizeof decrypted;
    bool ok = (EVP_PKEY_decrypt_init(ctx) == 1 &&
               EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) == 1 &&
               EVP_PKEY_decrypt(ctx, decrypted, &dec_len, encrypted, 256) == 1);
    EVP_PKEY_CTX_free(ctx);
    RFB_CHECK(ok);
    RFB_CHECK_EQ_UINT(dec_len, 128u);  // username[64] + password[64]

    // Verify username is at the start.
    RFB_CHECK(strncmp((const char *)decrypted, username, strlen(username)) == 0);
    // Verify password is at offset 64.
    RFB_CHECK(strncmp((const char *)(decrypted + 64),
                      (const char *)password, strlen((const char *)password)) == 0);

    rfb_secret_zero(decrypted, sizeof decrypted);
    free_rsa_key(&key);
}

// --- Credential encryption with oversized inputs ---
RFB_TEST(g18_t33, credentials__oversized_username__fails) {
    test_rsa_key key;
    RFB_CHECK(gen_rsa_key(&key));

    char long_name[128];
    memset(long_name, 'A', sizeof long_name - 1);
    long_name[sizeof long_name - 1] = '\0';

    uint8_t encrypted[256];
    RFB_CHECK(!apple33_encrypt_credentials(
        key.spki_der, key.spki_len,
        long_name, strlen(long_name),
        (const uint8_t *)"pw", 2,
        encrypted));

    free_rsa_key(&key);
}

// --- PBKDF2 session key derivation ---
RFB_TEST(g18_t33, derive_key__pbkdf2_sha512__deterministic) {
    static const uint8_t secret[] = "shared_secret";
    static const uint8_t salt[] = "saltsalt";

    uint8_t key1[APPLE33_KEY_SIZE];
    uint8_t key2[APPLE33_KEY_SIZE];
    RFB_CHECK(apple33_derive_session_key(secret, sizeof secret - 1,
                                          salt, sizeof salt - 1, 1000, key1));
    RFB_CHECK(apple33_derive_session_key(secret, sizeof secret - 1,
                                          salt, sizeof salt - 1, 1000, key2));
    RFB_CHECK_MEM_EQ(key1, key2, APPLE33_KEY_SIZE);
    rfb_secret_zero(key1, sizeof key1);
    rfb_secret_zero(key2, sizeof key2);
}

// --- PBKDF2 iteration cap ---
RFB_TEST(g18_t33, derive_key__iterations_exceed_cap__fails) {
    uint8_t key[APPLE33_KEY_SIZE];
    RFB_CHECK(!apple33_derive_session_key(
        (const uint8_t *)"s", 1, (const uint8_t *)"s", 1,
        APPLE33_PBKDF2_MAX_ITERATIONS + 1, key));
}

// --- PBKDF2 zero iterations ---
RFB_TEST(g18_t33, derive_key__zero_iterations__fails) {
    uint8_t key[APPLE33_KEY_SIZE];
    RFB_CHECK(!apple33_derive_session_key(
        (const uint8_t *)"s", 1, (const uint8_t *)"s", 1, 0, key));
}

// --- Nonce generation ---
RFB_TEST(g18_t33, nonce__random_and_unique) {
    uint8_t n1[APPLE33_NONCE_SIZE];
    uint8_t n2[APPLE33_NONCE_SIZE];
    RFB_CHECK(apple33_generate_nonce(n1));
    RFB_CHECK(apple33_generate_nonce(n2));
    RFB_CHECK(!rfb_crypto_ct_eq(n1, n2, APPLE33_NONCE_SIZE));
}

// --- Session record encrypt/decrypt roundtrip ---
RFB_TEST(g18_t33, session_record__encrypt_decrypt_roundtrip) {
    uint8_t key[APPLE33_KEY_SIZE];
    static const uint8_t test_secret[] = "test_secret_for_key_derivation!!";  // 32 bytes
    memcpy(key, test_secret, APPLE33_KEY_SIZE);

    uint8_t nonce[APPLE33_NONCE_SIZE];
    RFB_CHECK(apple33_generate_nonce(nonce));

    static const uint8_t pt[] = "Hello Apple Session!";
    uint8_t ct[128];
    size_t ct_len = 0;
    RFB_CHECK(apple33_encrypt_record(key, nonce, pt, sizeof pt - 1,
                                      ct, sizeof ct, &ct_len));
    RFB_CHECK_EQ_UINT(ct_len, (sizeof pt - 1) + APPLE33_TAG_SIZE);

    uint8_t dec[128];
    size_t dec_len = 0;
    RFB_CHECK(apple33_decrypt_record(key, nonce, ct, ct_len,
                                      dec, sizeof dec, &dec_len));
    RFB_CHECK_EQ_UINT(dec_len, sizeof pt - 1);
    RFB_CHECK_MEM_EQ(dec, pt, sizeof pt - 1);

    rfb_secret_zero(key, sizeof key);
}

// --- Tampered session record ---
RFB_TEST(g18_t33, session_record__tampered__fails_auth) {
    uint8_t key[APPLE33_KEY_SIZE] = { 0xAB };
    uint8_t nonce[APPLE33_NONCE_SIZE] = { 0xCD };
    static const uint8_t pt[] = "tamper test";

    uint8_t ct[64];
    size_t ct_len = 0;
    RFB_CHECK(apple33_encrypt_record(key, nonce, pt, sizeof pt - 1,
                                      ct, sizeof ct, &ct_len));
    ct[0] ^= 0xFF;  // tamper

    uint8_t dec[64];
    size_t dec_len = 0;
    RFB_CHECK(!apple33_decrypt_record(key, nonce, ct, ct_len,
                                       dec, sizeof dec, &dec_len));
    rfb_secret_zero(key, sizeof key);
}

// --- NULL safety ---
RFB_TEST(g18_t33, null_safety__all_fail) {
    uint8_t dummy[256];
    RFB_CHECK(!apple33_encrypt_credentials(NULL, 0, "u", 1,
                                            (const uint8_t *)"p", 1, dummy));
    RFB_CHECK(!apple33_derive_session_key(NULL, 0, NULL, 0, 1, dummy));
    RFB_CHECK(!apple33_generate_nonce(NULL));
}
