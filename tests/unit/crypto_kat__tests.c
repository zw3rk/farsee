// SPDX-License-Identifier: Apache-2.0
//
// G2 — DES known-answer tests for the real crypto providers
// (plan.md §G2: "known-answer DES/VNC response vectors through each
// provider").
//
// The KAT was computed independently using the system openssl CLI
// (LibreSSL; not GPL) as a clean-room reference, not by copying any VNC
// implementation. Vector:
//   password  = "password" (8 bytes, no padding needed)
//   challenge = 16 x 0x00
//   expected response = ff97502e9422f089ff97502e9422f089
//
// The key schedule converts "password" to per-byte-bit-reversed key:
//   0e86ceceeef64e26
// Then DES-ECB encrypts each 8-byte challenge block independently.

#include "rfb_test.h"
#include "farsee/crypto_provider.h"

#include <string.h>

#if defined(__APPLE__)
#  define PROVIDER_NAME "CommonCrypto"
#  define PROVIDER_FN rfb_des_commoncrypto
#  define INACTIVE_PROVIDER_FN rfb_des_openssl
#else
#  define PROVIDER_NAME "OpenSSL"
#  define PROVIDER_FN rfb_des_openssl
#  define INACTIVE_PROVIDER_FN rfb_des_commoncrypto
#endif

// Schedule "password" and verify the per-byte bit-reversal.
RFB_TEST(crypto_kat, kat__password_schedule__matches_known_value) {
    uint8_t key[8] = { 'p','a','s','s','w','o','r','d' };
    rfb_vnc_key_schedule(key);
    static const uint8_t expect[8] = { 0x0e,0x86,0xce,0xce,0xee,0xf6,0x4e,0x26 };
    RFB_CHECK_MEM_EQ(key, expect, 8);
}

// End-to-end VNC auth response against the real DES provider.
RFB_TEST(crypto_kat, kat__vnc_auth_response__matches_known_answer) {
    static const uint8_t password[8] = { 'p','a','s','s','w','o','r','d' };
    static const uint8_t challenge[16] = { 0 };
    uint8_t response[16] = { 0 };
    RFB_CHECK(rfb_vnc_auth_respond(password, challenge, response, PROVIDER_FN));
    static const uint8_t expect[16] = {
        0xff,0x97,0x50,0x2e,0x94,0x22,0xf0,0x89,
        0xff,0x97,0x50,0x2e,0x94,0x22,0xf0,0x89,
    };
    RFB_CHECK_MEM_EQ(response, expect, 16);
}

// Single-block DES sanity: a nonzero plaintext with the scheduled key.
RFB_TEST(crypto_kat, kat__des_single_block__deterministic) {
    uint8_t key[8] = { 'p','a','s','s','w','o','r','d' };
    rfb_vnc_key_schedule(key);
    static const uint8_t in[8] = { 1,2,3,4,5,6,7,8 };
    uint8_t out1[8] = { 0 };
    uint8_t out2[8] = { 0 };
    RFB_CHECK(PROVIDER_FN(key, in, out1));
    RFB_CHECK(PROVIDER_FN(key, in, out2));
    RFB_CHECK_MEM_EQ(out1, out2, 8);  // deterministic
}

// A different plaintext must produce a different ciphertext (DES is not
// the identity).
RFB_TEST(crypto_kat, kat__des_different_plaintexts__different_ciphertexts) {
    uint8_t key[8] = { 'p','a','s','s','w','o','r','d' };
    rfb_vnc_key_schedule(key);
    static const uint8_t in_a[8] = { 0,0,0,0,0,0,0,0 };
    static const uint8_t in_b[8] = { 1,0,0,0,0,0,0,0 };
    uint8_t out_a[8] = { 0 };
    uint8_t out_b[8] = { 0 };
    RFB_CHECK(PROVIDER_FN(key, in_a, out_a));
    RFB_CHECK(PROVIDER_FN(key, in_b, out_b));
    // At least one byte differs.
    bool any_differ = false;
    for (int i = 0; i < 8; i++) {
        if (out_a[i] != out_b[i]) { any_differ = true; break; }
    }
    RFB_CHECK(any_differ);
}

RFB_TEST(crypto_kat, active_provider__null_arguments_fail_closed)
{
    static const uint8_t key[8] = { 0 };
    static const uint8_t in[8] = { 0 };
    uint8_t out[8] = { 0 };

    RFB_CHECK(!PROVIDER_FN(NULL, in, out));
    RFB_CHECK(!PROVIDER_FN(key, NULL, out));
    RFB_CHECK(!PROVIDER_FN(key, in, NULL));
}

RFB_TEST(crypto_kat, inactive_provider__fails_closed)
{
    static const uint8_t key[8] = { 0 };
    static const uint8_t in[8] = { 0 };
    uint8_t out[8] = { 0 };

    RFB_CHECK(!INACTIVE_PROVIDER_FN(key, in, out));
}
