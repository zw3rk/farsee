// SPDX-License-Identifier: Apache-2.0
//
// Apple crypto-provider tests using RFC and NIST vectors.

#include "rfb_test.h"
#include "farsee/apple_crypto.h"
#include "farsee/secret.h"

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <limits.h>
#include <string.h>

typedef struct generated_spki {
    uint8_t der[1024];
    size_t len;
} generated_spki;

static bool generate_spki(generated_spki *spki)
{
    memset(spki, 0, sizeof *spki);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (ctx == NULL) {
        return false;
    }
    EVP_PKEY *key = NULL;
    bool ok = false;
    if (EVP_PKEY_keygen_init(ctx) == 1 &&
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) == 1 &&
        EVP_PKEY_keygen(ctx, &key) == 1) {
        unsigned char *next = spki->der;
        const int len = i2d_PUBKEY(key, &next);
        if (len > 0 && (size_t)len < sizeof spki->der) {
            spki->len = (size_t)len;
            ok = true;
        }
    }
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);
    return ok;
}

typedef bool (*modular_operation)(
    const uint8_t *, size_t, const uint8_t *, size_t,
    const uint8_t *, size_t, uint8_t *, size_t);

static void check_modular_validation(modular_operation operation)
{
    const uint8_t value = 2u;
    const uint8_t modulus = 17u;
    const uint8_t zero = 0u;
    uint8_t out = 0u;
    const size_t above_int = (size_t)INT_MAX + 1u;

    RFB_CHECK(!operation(NULL, 1u, &value, 1u, &modulus, 1u, &out, 1u));
    RFB_CHECK(!operation(&value, 1u, NULL, 1u, &modulus, 1u, &out, 1u));
    RFB_CHECK(!operation(&value, 1u, &value, 1u, NULL, 1u, &out, 1u));
    RFB_CHECK(!operation(
        &value, 1u, &value, 1u, &modulus, 1u, NULL, 1u));
    RFB_CHECK(!operation(
        &value, above_int, &value, 1u, &modulus, 1u, &out, 1u));
    RFB_CHECK(!operation(
        &value, 1u, &value, above_int, &modulus, 1u, &out, 1u));
    RFB_CHECK(!operation(
        &value, 1u, &value, 1u, &modulus, above_int, &out, 1u));
    RFB_CHECK(!operation(
        &value, 1u, &value, 1u, &modulus, 1u, &out, above_int));
    RFB_CHECK(!operation(
        &value, 1u, &value, 1u, &zero, 1u, &out, 1u));
    RFB_CHECK(!operation(
        &value, 1u, &value, 1u, &modulus, 1u, &out, 0u));
}

// --- SHA-256 KAT (NIST FIPS 180-4 empty string) -------------------------
RFB_TEST(acrypto, sha256__empty__known_hash) {
    uint8_t out[32];
    rfb_crypto_sha256((const uint8_t *)"", 0, out);
    static const uint8_t expect[32] = {
        0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14,
        0x9a,0xfb,0xf4,0xc8,0x99,0x6f,0xb9,0x24,
        0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c,
        0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55
    };
    RFB_CHECK_MEM_EQ(out, expect, 32);
}

// --- SHA-256 "abc" (NIST FIPS 180-4) ------------------------------------
RFB_TEST(acrypto, sha256__abc__known_hash) {
    uint8_t out[32];
    rfb_crypto_sha256((const uint8_t *)"abc", 3, out);
    static const uint8_t expect[32] = {
        0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,
        0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
        0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,
        0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad
    };
    RFB_CHECK_MEM_EQ(out, expect, 32);
}

// --- SHA-512 empty (NIST) -----------------------------------------------
RFB_TEST(acrypto, sha512__empty__known_prefix) {
    uint8_t out[64];
    rfb_crypto_sha512((const uint8_t *)"", 0, out);
    // First 4 bytes of SHA-512("")
    RFB_CHECK_EQ_UINT(out[0], 0xcf);
    RFB_CHECK_EQ_UINT(out[1], 0x83);
    RFB_CHECK_EQ_UINT(out[2], 0xe1);
    RFB_CHECK_EQ_UINT(out[3], 0x35);
}

// --- SHA-1 "abc" (NIST FIPS 180-4) --------------------------------------
RFB_TEST(acrypto, sha1__abc__known_hash) {
    uint8_t out[20];
    rfb_crypto_sha1((const uint8_t *)"abc", 3, out);
    static const uint8_t expect[20] = {
        0xa9,0x99,0x3e,0x36,0x47,0x06,0x81,0x6a,
        0xba,0x3e,0x25,0x71,0x78,0x50,0xc2,0x6c,
        0x9c,0xd0,0xd8,0x9d
    };
    RFB_CHECK_MEM_EQ(out, expect, 20);
}

// --- MD5 available (may fail under FIPS) --------------------------------
RFB_TEST(acrypto, md5__abc__known_hash_or_unsupported) {
    uint8_t out[16];
    if (rfb_crypto_md5((const uint8_t *)"abc", 3, out)) {
        static const uint8_t expect[16] = {
            0x90,0x01,0x50,0x98,0x3c,0xd2,0x4f,0xb0,
            0xd6,0x96,0x3f,0x7d,0x28,0xe1,0x7f,0x72
        };
        RFB_CHECK_MEM_EQ(out, expect, 16);
    }
    // Some FIPS configurations can report MD5 as unavailable.
}

// --- Constant-time compare ----------------------------------------------
RFB_TEST(acrypto, ct_eq__matching__true) {
    static const uint8_t a[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    RFB_CHECK(rfb_crypto_ct_eq(a, a, 8));
}

RFB_TEST(acrypto, ct_eq__mismatch__false) {
    static const uint8_t a[4] = { 1, 2, 3, 4 };
    static const uint8_t b[4] = { 1, 2, 3, 5 };
    RFB_CHECK(!rfb_crypto_ct_eq(a, b, 4));
}

// --- Secure random -------------------------------------------------------
RFB_TEST(acrypto, random_bytes__16__succeeds) {
    uint8_t buf[16] = { 0 };
    RFB_CHECK(rfb_crypto_random_bytes(buf, 16));
    // Extremely unlikely all zero.
    bool any_nonzero = false;
    for (int i = 0; i < 16; i++) if (buf[i] != 0) { any_nonzero = true; break; }
    RFB_CHECK(any_nonzero);
}

RFB_TEST(acrypto, random_bytes__two_calls_differ) {
    uint8_t a[16], b[16];
    rfb_crypto_random_bytes(a, 16);
    rfb_crypto_random_bytes(b, 16);
    RFB_CHECK(!rfb_crypto_ct_eq(a, b, 16));
}

// --- HMAC-SHA512 ---------------------------------------------------------
RFB_TEST(acrypto, hmac_sha512__rfc4231_test1_prefix) {
    // RFC 4231 Test Case 1: key = 0x0b*20, data = "Hi There"
    uint8_t key[20];
    memset(key, 0x0b, 20);
    uint8_t out[64];
    rfb_crypto_hmac_sha512(key, 20, (const uint8_t *)"Hi There", 8, out);
    // First 4 bytes of expected HMAC-SHA512.
    RFB_CHECK_EQ_UINT(out[0], 0x87);
    RFB_CHECK_EQ_UINT(out[1], 0xaa);
    RFB_CHECK_EQ_UINT(out[2], 0x7c);
    RFB_CHECK_EQ_UINT(out[3], 0xde);
}

// --- PBKDF2-HMAC-SHA512 -------------------------------------------------
RFB_TEST(acrypto, pbkdf2__sha512__basic_derivation) {
    // PBKDF2-HMAC-SHA512 with password="password", salt="salt",
    // iterations=1, and dkLen=64.
    uint8_t out[64];
    RFB_CHECK(rfb_crypto_pbkdf2_sha512(
        (const uint8_t *)"password", 8,
        (const uint8_t *)"salt", 4,
        1, out, 64));
    // First two bytes of the known output are 0x86, 0x7f.
    RFB_CHECK_EQ_UINT(out[0], 0x86);
    RFB_CHECK_EQ_UINT(out[1], 0x7f);
}

RFB_TEST(acrypto, pbkdf2__zero_iterations__rejected) {
    uint8_t out[32];
    RFB_CHECK(!rfb_crypto_pbkdf2_sha512(
        (const uint8_t *)"pw", 2,
        (const uint8_t *)"s", 1,
        0, out, 32));
}

// --- AES-128-ECB decrypt ------------------------------------------------
RFB_TEST(acrypto, aes128_ecb_decrypt__nist_vector) {
    // NIST SP 800-38A: key = 2b7e151628aed2a6abf7158809cf4f3c
    // ciphertext = 3ad77bb40d7a3660a89ecaf32466ef97
    // plaintext  = 6bc1bee22e409f96e93d7e117393172a
    static const uint8_t key[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };
    static const uint8_t ct[16] = {
        0x3a,0xd7,0x7b,0xb4,0x0d,0x7a,0x36,0x60,
        0xa8,0x9e,0xca,0xf3,0x24,0x66,0xef,0x97
    };
    static const uint8_t expect[16] = {
        0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
        0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a
    };
    uint8_t out[16];
    RFB_CHECK(rfb_crypto_aes128_ecb_decrypt(key, ct, out));
    RFB_CHECK_MEM_EQ(out, expect, 16);
}

RFB_TEST(acrypto, aes128_ecb_encrypt__roundtrip_nist) {
    // Same NIST vector: encrypt(pt) → ct; decrypt(ct) → pt.
    static const uint8_t key[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };
    static const uint8_t pt[16] = {
        0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
        0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a
    };
    static const uint8_t expect_ct[16] = {
        0x3a,0xd7,0x7b,0xb4,0x0d,0x7a,0x36,0x60,
        0xa8,0x9e,0xca,0xf3,0x24,0x66,0xef,0x97
    };
    uint8_t ct[16];
    uint8_t back[16];
    RFB_CHECK(rfb_crypto_aes128_ecb_encrypt(key, pt, ct));
    RFB_CHECK_MEM_EQ(ct, expect_ct, 16);
    RFB_CHECK(rfb_crypto_aes128_ecb_decrypt(key, ct, back));
    RFB_CHECK_MEM_EQ(back, pt, 16);
}

// --- AES-128-CBC context ------------------------------------------------
RFB_TEST(acrypto, aes128_cbc__encrypt_decrypt_roundtrip) {
    static const uint8_t key[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
        0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };
    static const uint8_t iv[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    static const uint8_t pt[32] = {
        'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P',
        'Q','R','S','T','U','V','W','X','Y','Z','1','2','3','4','5','6'
    };
    uint8_t ct[32] = { 0 };
    uint8_t decrypted[32] = { 0 };

    // Encrypt
    rfb_crypto_cbc_ctx *enc = rfb_crypto_cbc_new();
    RFB_CHECK(rfb_crypto_cbc_init(enc, true, key, iv));
    size_t outl = 0;
    RFB_CHECK(rfb_crypto_cbc_update(enc, pt, 32, ct, sizeof ct, &outl));
    RFB_CHECK_EQ_UINT(outl, 32u);
    rfb_crypto_cbc_free(enc);

    // Decrypt
    rfb_crypto_cbc_ctx *dec = rfb_crypto_cbc_new();
    RFB_CHECK(rfb_crypto_cbc_init(dec, false, key, iv));
    size_t decl = 0;
    RFB_CHECK(rfb_crypto_cbc_update(dec, ct, 32, decrypted, sizeof decrypted, &decl));
    RFB_CHECK_EQ_UINT(decl, 32u);
    rfb_crypto_cbc_free(dec);

    // Verify roundtrip
    RFB_CHECK_MEM_EQ(decrypted, pt, 32);
}

// --- Modular exponentiation ---------------------------------------------
RFB_TEST(acrypto, modexp__small_known_value) {
    // 2^10 mod 17 = 1024 mod 17 = 4
    uint8_t base[1] = { 2 };
    uint8_t exp[1] = { 10 };
    uint8_t mod[1] = { 17 };
    uint8_t out[1] = { 0 };
    RFB_CHECK(rfb_crypto_modexp(base, 1, exp, 1, mod, 1, out, 1));
    RFB_CHECK_EQ_UINT(out[0], 4u);
}

RFB_TEST(acrypto, modexp__zero_pad) {
    // 1^1 mod 255 = 1, with output buffer of 4 bytes → [0,0,0,1]
    uint8_t base[1] = { 1 };
    uint8_t exp[1] = { 1 };
    uint8_t mod[1] = { 255 };
    uint8_t out[4] = { 0 };
    RFB_CHECK(rfb_crypto_modexp(base, 1, exp, 1, mod, 1, out, 4));
    RFB_CHECK_EQ_UINT(out[0], 0u);
    RFB_CHECK_EQ_UINT(out[1], 0u);
    RFB_CHECK_EQ_UINT(out[2], 0u);
    RFB_CHECK_EQ_UINT(out[3], 1u);
}

RFB_TEST(acrypto, modular_arithmetic__small_known_values) {
    static const uint8_t seven[1] = { 7u };
    static const uint8_t nine[1] = { 9u };
    static const uint8_t thirteen[1] = { 13u };
    static const uint8_t fourteen[1] = { 14u };
    static const uint8_t eleven[1] = { 11u };
    static const uint8_t seventeen[1] = { 17u };
    static const uint8_t three[1] = { 3u };
    static const uint8_t five[1] = { 5u };
    uint8_t out[1] = { 0 };

    RFB_CHECK(rfb_crypto_modmul(seven, 1u, nine, 1u, thirteen, 1u,
                                out, sizeof out));
    RFB_CHECK_EQ_UINT(out[0], 11u);
    RFB_CHECK(rfb_crypto_modadd(fourteen, 1u, eleven, 1u, seventeen, 1u,
                                out, sizeof out));
    RFB_CHECK_EQ_UINT(out[0], 8u);
    RFB_CHECK(rfb_crypto_modsub(three, 1u, five, 1u, seventeen, 1u,
                                out, sizeof out));
    RFB_CHECK_EQ_UINT(out[0], 15u);
}

// --- SPKI fingerprint ---------------------------------------------------
RFB_TEST(acrypto, spki_fingerprint__sha256_of_der) {
    // Fingerprint = SHA-256 of the DER bytes (trivially verifiable).
    static const uint8_t der[4] = { 0xDE, 0xAD, 0xBE, 0xEF };
    uint8_t fp[32];
    uint8_t expect[32];
    rfb_crypto_spki_fingerprint(der, 4, fp);
    rfb_crypto_sha256(der, 4, expect);
    RFB_CHECK_MEM_EQ(fp, expect, 32);
}

RFB_TEST(acrypto, rsa_encrypt__trailing_der_bytes__rejected) {
    generated_spki spki;
    RFB_CHECK(generate_spki(&spki));
    spki.der[spki.len++] = 0u;
    static const uint8_t plaintext[] = "identity";
    uint8_t ciphertext[256];

    RFB_CHECK(!rfb_crypto_rsa_encrypt_pkcs1(
        spki.der, spki.len, plaintext, sizeof plaintext - 1u, ciphertext));
}

RFB_TEST(acrypto, provider_validation__rejects_invalid_inputs) {
    uint8_t byte = 1u;
    uint8_t digest[64];
    const size_t above_int = (size_t)INT_MAX + 1u;

    RFB_CHECK(!rfb_crypto_random_bytes(NULL, 1u));
    RFB_CHECK(!rfb_crypto_random_bytes(&byte, 0u));
    RFB_CHECK(!rfb_crypto_random_bytes(&byte, above_int));

    RFB_CHECK(rfb_crypto_ct_eq(NULL, NULL, 0u));
    RFB_CHECK(!rfb_crypto_ct_eq(NULL, &byte, 1u));
    RFB_CHECK(!rfb_crypto_ct_eq(&byte, NULL, 1u));

    RFB_CHECK(!rfb_crypto_sha256(NULL, 0u, digest));
    RFB_CHECK(!rfb_crypto_sha256(&byte, 1u, NULL));
    RFB_CHECK(!rfb_crypto_sha512(NULL, 0u, digest));
    RFB_CHECK(!rfb_crypto_sha512(&byte, 1u, NULL));
    RFB_CHECK(!rfb_crypto_sha1(NULL, 0u, digest));
    RFB_CHECK(!rfb_crypto_sha1(&byte, 1u, NULL));
    RFB_CHECK(!rfb_crypto_md5(NULL, 0u, digest));
    RFB_CHECK(!rfb_crypto_md5(&byte, 1u, NULL));
    RFB_CHECK(!rfb_crypto_spki_fingerprint(NULL, 0u, digest));
    RFB_CHECK(!rfb_crypto_spki_fingerprint(&byte, 1u, NULL));

    RFB_CHECK(!rfb_crypto_hmac_sha512(
        NULL, 1u, &byte, 1u, digest));
    RFB_CHECK(!rfb_crypto_hmac_sha512(
        &byte, 1u, NULL, 1u, digest));
    RFB_CHECK(!rfb_crypto_hmac_sha512(
        &byte, 1u, &byte, 1u, NULL));
    RFB_CHECK(!rfb_crypto_hmac_sha512(
        &byte, above_int, &byte, 1u, digest));

    RFB_CHECK(!rfb_crypto_pbkdf2_sha512(
        NULL, 1u, &byte, 1u, 1u, digest, 1u));
    RFB_CHECK(!rfb_crypto_pbkdf2_sha512(
        &byte, 1u, NULL, 1u, 1u, digest, 1u));
    RFB_CHECK(!rfb_crypto_pbkdf2_sha512(
        &byte, 1u, &byte, 1u, 1u, NULL, 1u));
    RFB_CHECK(!rfb_crypto_pbkdf2_sha512(
        &byte, 1u, &byte, 1u, 10000001u, digest, 1u));
    RFB_CHECK(!rfb_crypto_pbkdf2_sha512(
        &byte, above_int, &byte, 1u, 1u, digest, 1u));
    RFB_CHECK(!rfb_crypto_pbkdf2_sha512(
        &byte, 1u, &byte, above_int, 1u, digest, 1u));
    RFB_CHECK(!rfb_crypto_pbkdf2_sha512(
        &byte, 1u, &byte, 1u, 1u, digest, above_int));

    uint8_t ciphertext[256];
    RFB_CHECK(!rfb_crypto_rsa_encrypt_pkcs1(
        NULL, 1u, &byte, 1u, ciphertext));
    RFB_CHECK(!rfb_crypto_rsa_encrypt_pkcs1(
        &byte, 1u, NULL, 1u, ciphertext));
    RFB_CHECK(!rfb_crypto_rsa_encrypt_pkcs1(
        &byte, 1u, &byte, 1u, NULL));
#if SIZE_MAX > LONG_MAX
    RFB_CHECK(!rfb_crypto_rsa_encrypt_pkcs1(
        &byte, (size_t)LONG_MAX + 1u, &byte, 1u, ciphertext));
#endif
    RFB_CHECK(!rfb_crypto_rsa_encrypt_pkcs1(
        &byte, 1u, &byte, 246u, ciphertext));
    RFB_CHECK(!rfb_crypto_rsa_encrypt_pkcs1(
        &byte, 1u, &byte, 1u, ciphertext));

    uint8_t block[16] = {0u};
    RFB_CHECK(!rfb_crypto_aes128_ecb_decrypt(NULL, block, block));
    RFB_CHECK(!rfb_crypto_aes128_ecb_decrypt(block, NULL, block));
    RFB_CHECK(!rfb_crypto_aes128_ecb_decrypt(block, block, NULL));
    RFB_CHECK(!rfb_crypto_aes128_ecb_encrypt(NULL, block, block));
    RFB_CHECK(!rfb_crypto_aes128_ecb_encrypt(block, NULL, block));
    RFB_CHECK(!rfb_crypto_aes128_ecb_encrypt(block, block, NULL));
}

RFB_TEST(acrypto, cbc_validation_and_finalization__bounded) {
    static const uint8_t key[16] = {0u};
    static const uint8_t iv[16] = {0u};
    uint8_t block[16] = {0u};
    uint8_t out[16] = {0u};
    size_t out_len = 77u;

    rfb_crypto_cbc_free(NULL);
    RFB_CHECK(!rfb_crypto_cbc_init(NULL, true, key, iv));
    rfb_crypto_cbc_ctx *ctx = rfb_crypto_cbc_new();
    RFB_CHECK(ctx != NULL);
    RFB_CHECK(!rfb_crypto_cbc_init(ctx, true, NULL, iv));
    RFB_CHECK(!rfb_crypto_cbc_init(ctx, true, key, NULL));

    RFB_CHECK(!rfb_crypto_cbc_update(NULL, block, sizeof block,
                                     out, sizeof out, &out_len));
    RFB_CHECK_EQ_UINT(out_len, 0u);
    out_len = 77u;
    RFB_CHECK(!rfb_crypto_cbc_update(ctx, NULL, sizeof block,
                                     out, sizeof out, &out_len));
    RFB_CHECK_EQ_UINT(out_len, 0u);
    out_len = 77u;
    RFB_CHECK(!rfb_crypto_cbc_update(ctx, block, sizeof block,
                                     NULL, sizeof out, &out_len));
    RFB_CHECK_EQ_UINT(out_len, 0u);
    RFB_CHECK(!rfb_crypto_cbc_update(ctx, block, sizeof block,
                                     out, sizeof out, NULL));
    out_len = 77u;
    RFB_CHECK(!rfb_crypto_cbc_update(ctx, block, sizeof block,
                                     out, sizeof out - 1u, &out_len));
    RFB_CHECK_EQ_UINT(out_len, 0u);
    out_len = 77u;
    RFB_CHECK(!rfb_crypto_cbc_update(ctx, block, 1u,
                                     out, sizeof out, &out_len));
    RFB_CHECK_EQ_UINT(out_len, 0u);

    RFB_CHECK(!rfb_crypto_cbc_final(NULL, out, sizeof out, &out_len));
    RFB_CHECK_EQ_UINT(out_len, 0u);
    out_len = 77u;
    RFB_CHECK(!rfb_crypto_cbc_final(ctx, NULL, sizeof out, &out_len));
    RFB_CHECK_EQ_UINT(out_len, 0u);
    RFB_CHECK(!rfb_crypto_cbc_final(ctx, out, sizeof out, NULL));
    rfb_crypto_cbc_free(ctx);

    ctx = rfb_crypto_cbc_new();
    RFB_CHECK(ctx != NULL);
    RFB_CHECK(rfb_crypto_cbc_init(ctx, true, key, iv));
    RFB_CHECK(rfb_crypto_cbc_update(
        ctx, block, sizeof block, out, sizeof out, &out_len));
    RFB_CHECK_EQ_UINT(out_len, sizeof block);
    out_len = 77u;
    RFB_CHECK(rfb_crypto_cbc_final(ctx, out, 0u, &out_len));
    RFB_CHECK_EQ_UINT(out_len, 0u);
    rfb_crypto_cbc_free(ctx);

    ctx = rfb_crypto_cbc_new();
    RFB_CHECK(ctx != NULL);
    RFB_CHECK(rfb_crypto_cbc_init(ctx, false, key, iv));
    RFB_CHECK(rfb_crypto_cbc_update(
        ctx, block, sizeof block, out, sizeof out, &out_len));
    out_len = 77u;
    RFB_CHECK(rfb_crypto_cbc_final(ctx, out, sizeof out, &out_len));
    RFB_CHECK_EQ_UINT(out_len, 0u);
    rfb_crypto_cbc_free(ctx);
}

RFB_TEST(acrypto, modular_operations__reject_invalid_domains) {
    check_modular_validation(rfb_crypto_modexp);
    check_modular_validation(rfb_crypto_modmul);
    check_modular_validation(rfb_crypto_modadd);
    check_modular_validation(rfb_crypto_modsub);
}
