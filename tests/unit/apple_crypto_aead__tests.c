// SPDX-License-Identifier: Apache-2.0
//
// G18 — ChaCha20-Poly1305 AEAD tests.
// RFC 8439 Test Vector 2 (AEAD).

#include "rfb_test.h"
#include "farsee/apple_crypto.h"

#include <limits.h>
#include <string.h>

// --- RFC 8439 §2.8.2 AEAD test vector ------------------------------------
RFB_TEST(g18_aead, chacha20_poly1305__rfc8439_roundtrip) {
    // Use a simple known key/nonce for roundtrip verification.
    static const uint8_t key[32] = {
        0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,
        0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f,
        0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,
        0x98,0x99,0x9a,0x9b,0x9c,0x9d,0x9e,0x9f
    };
    static const uint8_t nonce[12] = {
        0x07,0x00,0x00,0x00,0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47
    };
    static const uint8_t aad[] = { 0x50,0x51,0x52,0x53,0xc0,0xc1,0xc2,0xc3,
                                   0xc4,0xc5,0xc6,0xc7 };
    static const uint8_t pt[] = "Ladies and Gentlemen of the class of '99";

    uint8_t ct[128];
    size_t ct_len = 0;
    RFB_CHECK(rfb_crypto_chacha20_poly1305_encrypt(
        key, nonce, aad, sizeof aad, pt, sizeof pt - 1, ct, sizeof ct, &ct_len));
    RFB_CHECK_EQ_UINT(ct_len, (sizeof pt - 1) + 16u);

    // Decrypt and verify.
    uint8_t decrypted[128];
    size_t dec_len = 0;
    RFB_CHECK(rfb_crypto_chacha20_poly1305_decrypt(
        key, nonce, aad, sizeof aad, ct, ct_len, decrypted, sizeof decrypted, &dec_len));
    RFB_CHECK_EQ_UINT(dec_len, sizeof pt - 1);
    RFB_CHECK_MEM_EQ(decrypted, pt, sizeof pt - 1);
}

// --- Tampered ciphertext should fail --------------------------------------
RFB_TEST(g18_aead, chacha20_poly1305__tampered_ct__fails_auth) {
    static const uint8_t key[32] = { 0x01 };
    static const uint8_t nonce[12] = { 0x02 };
    static const uint8_t pt[] = "test payload here!";  // 18 bytes

    uint8_t ct[64];
    size_t ct_len = 0;
    RFB_CHECK(rfb_crypto_chacha20_poly1305_encrypt(
        key, nonce, NULL, 0, pt, sizeof pt - 1, ct, sizeof ct, &ct_len));

    // Tamper with a ciphertext byte.
    ct[0] ^= 0xFF;

    uint8_t dec[64];
    size_t dec_len = 0;
    RFB_CHECK(!rfb_crypto_chacha20_poly1305_decrypt(
        key, nonce, NULL, 0, ct, ct_len, dec, sizeof dec, &dec_len));
}

// --- Tampered tag should fail ---------------------------------------------
RFB_TEST(g18_aead, chacha20_poly1305__tampered_tag__fails_auth) {
    static const uint8_t key[32] = { 0x01 };
    static const uint8_t nonce[12] = { 0x02 };
    static const uint8_t pt[] = "auth check";

    uint8_t ct[64];
    size_t ct_len = 0;
    RFB_CHECK(rfb_crypto_chacha20_poly1305_encrypt(
        key, nonce, NULL, 0, pt, sizeof pt - 1, ct, sizeof ct, &ct_len));

    // Tamper with the tag (last 16 bytes).
    ct[ct_len - 1] ^= 0xFF;

    uint8_t dec[64];
    size_t dec_len = 0;
    RFB_CHECK(!rfb_crypto_chacha20_poly1305_decrypt(
        key, nonce, NULL, 0, ct, ct_len, dec, sizeof dec, &dec_len));
}

// --- Empty plaintext should work ------------------------------------------
RFB_TEST(g18_aead, chacha20_poly1305__empty_plaintext__tag_only) {
    static const uint8_t key[32] = { 0xAA };
    static const uint8_t nonce[12] = { 0xBB };

    uint8_t ct[32];
    size_t ct_len = 0;
    RFB_CHECK(rfb_crypto_chacha20_poly1305_encrypt(
        key, nonce, NULL, 0, (const uint8_t *)"", 0, ct, sizeof ct, &ct_len));
    RFB_CHECK_EQ_UINT(ct_len, 16u);  // just the tag

    uint8_t dec[32];
    size_t dec_len = 0;
    RFB_CHECK(rfb_crypto_chacha20_poly1305_decrypt(
        key, nonce, NULL, 0, ct, ct_len, dec, sizeof dec, &dec_len));
    RFB_CHECK_EQ_UINT(dec_len, 0u);
}

// --- NULL safety ----------------------------------------------------------
RFB_TEST(g18_aead, chacha20_poly1305__null_inputs__fail) {
    static const uint8_t key[32] = { 0 };
    static const uint8_t nonce[12] = { 0 };
    static const uint8_t pt[] = "x";
    uint8_t ct[32];
    size_t ct_len = 0;

    RFB_CHECK(!rfb_crypto_chacha20_poly1305_encrypt(
        NULL, nonce, NULL, 0, pt, 1, ct, sizeof ct, &ct_len));
    RFB_CHECK(!rfb_crypto_chacha20_poly1305_encrypt(
        key, NULL, NULL, 0, pt, 1, ct, sizeof ct, &ct_len));
    RFB_CHECK(!rfb_crypto_chacha20_poly1305_encrypt(
        key, nonce, NULL, 0, NULL, 1, ct, sizeof ct, &ct_len));
}

RFB_TEST(g18_aead, chacha20_poly1305__invalid_lengths__fail_closed) {
    static const uint8_t key[32] = {0u};
    static const uint8_t nonce[12] = {0u};
    uint8_t byte = 0u;
    uint8_t out[32];
    size_t out_len = 77u;
    const size_t above_int = (size_t)INT_MAX + 1u;

    RFB_CHECK(!rfb_crypto_chacha20_poly1305_encrypt(
        key, nonce, NULL, 0u, &byte, 1u, NULL, sizeof out, &out_len));
    RFB_CHECK_EQ_UINT(out_len, 0u);
    RFB_CHECK(!rfb_crypto_chacha20_poly1305_encrypt(
        key, nonce, NULL, 0u, &byte, 1u, out, sizeof out, NULL));
    out_len = 77u;
    RFB_CHECK(!rfb_crypto_chacha20_poly1305_encrypt(
        key, nonce, NULL, 1u, &byte, 1u, out, sizeof out, &out_len));
    RFB_CHECK_EQ_UINT(out_len, 0u);
    out_len = 77u;
    RFB_CHECK(!rfb_crypto_chacha20_poly1305_encrypt(
        key, nonce, &byte, above_int, &byte, 1u,
        out, sizeof out, &out_len));
    RFB_CHECK_EQ_UINT(out_len, 0u);
    out_len = 77u;
    RFB_CHECK(!rfb_crypto_chacha20_poly1305_encrypt(
        key, nonce, NULL, 0u, &byte, above_int,
        out, SIZE_MAX, &out_len));
    RFB_CHECK_EQ_UINT(out_len, 0u);
    out_len = 77u;
    RFB_CHECK(!rfb_crypto_chacha20_poly1305_encrypt(
        key, nonce, NULL, 0u, &byte, 1u, out, 16u, &out_len));
    RFB_CHECK_EQ_UINT(out_len, 0u);

    RFB_CHECK(!rfb_crypto_chacha20_poly1305_decrypt(
        NULL, nonce, NULL, 0u, out, 16u, &byte, 1u, &out_len));
    RFB_CHECK(!rfb_crypto_chacha20_poly1305_decrypt(
        key, NULL, NULL, 0u, out, 16u, &byte, 1u, &out_len));
    RFB_CHECK(!rfb_crypto_chacha20_poly1305_decrypt(
        key, nonce, NULL, 0u, NULL, 16u, &byte, 1u, &out_len));
    RFB_CHECK(!rfb_crypto_chacha20_poly1305_decrypt(
        key, nonce, NULL, 0u, out, 16u, NULL, 1u, &out_len));
    RFB_CHECK(!rfb_crypto_chacha20_poly1305_decrypt(
        key, nonce, NULL, 0u, out, 16u, &byte, 1u, NULL));
    out_len = 77u;
    RFB_CHECK(!rfb_crypto_chacha20_poly1305_decrypt(
        key, nonce, NULL, 0u, out, 15u, &byte, 1u, &out_len));
    RFB_CHECK_EQ_UINT(out_len, 0u);
    out_len = 77u;
    RFB_CHECK(!rfb_crypto_chacha20_poly1305_decrypt(
        key, nonce, NULL, 1u, out, 16u, &byte, 1u, &out_len));
    RFB_CHECK_EQ_UINT(out_len, 0u);
    out_len = 77u;
    RFB_CHECK(!rfb_crypto_chacha20_poly1305_decrypt(
        key, nonce, &byte, above_int, out, 16u,
        &byte, 1u, &out_len));
    RFB_CHECK_EQ_UINT(out_len, 0u);
    out_len = 77u;
    RFB_CHECK(!rfb_crypto_chacha20_poly1305_decrypt(
        key, nonce, NULL, 0u, &byte, above_int + 16u,
        out, SIZE_MAX, &out_len));
    RFB_CHECK_EQ_UINT(out_len, 0u);

    size_t ciphertext_len = 0u;
    RFB_CHECK(rfb_crypto_chacha20_poly1305_encrypt(
        key, nonce, NULL, 0u, &byte, 1u,
        out, sizeof out, &ciphertext_len));
    out_len = 77u;
    RFB_CHECK(!rfb_crypto_chacha20_poly1305_decrypt(
        key, nonce, NULL, 0u, out, ciphertext_len,
        &byte, 0u, &out_len));
    RFB_CHECK_EQ_UINT(out_len, 0u);
}
