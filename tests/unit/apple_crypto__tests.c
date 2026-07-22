// SPDX-License-Identifier: Apache-2.0
//
// G16 — Apple crypto provider known-answer tests.
// Uses RFC/NIST test vectors and Python-stdlib-computed values.

#include "rfb_test.h"
#include "farsee/apple_crypto.h"
#include "farsee/secret.h"

#include <string.h>

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
RFB_TEST(acrypto, sha512__empty__known_hash) {
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
    // If MD5 returns false (FIPS mode), that's acceptable — type-30 reports
    // unsupported rather than weakening the provider.
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
RFB_TEST(acrypto, hmac_sha512__rfc4231_test1) {
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
    // RFC 7914 / standard PBKDF2 test: password="password", salt="salt",
    // iterations=1, dkLen=64.
    uint8_t out[64];
    RFB_CHECK(rfb_crypto_pbkdf2_sha512(
        (const uint8_t *)"password", 8,
        (const uint8_t *)"salt", 4,
        1, out, 64));
    // First 4 bytes of known output: 867f70cf
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
