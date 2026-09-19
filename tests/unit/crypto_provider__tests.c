// SPDX-License-Identifier: Apache-2.0
//
// VNC Authentication key-schedule and response tests (RFC 6143 §7.2.2).
//
// The response tests use an injectable transform to inspect key scheduling
// and both eight-byte provider calls without selecting a crypto backend.

#include "rfb_test.h"
#include "farsee/crypto_provider.h"
#include "farsee/secret.h"

#include <string.h>

// --- key schedule: per-byte bit reversal ---------------------------------

RFB_TEST(crypto, vnc_key_schedule__zero_password__stays_zero) {
    uint8_t key[8] = { 0,0,0,0,0,0,0,0 };
    rfb_vnc_key_schedule(key);
    for (int i = 0; i < 8; i++) {
        RFB_CHECK_EQ_UINT(key[i], 0u);
    }
}

RFB_TEST(crypto, vnc_key_schedule__0x01__becomes_0x80) {
    // Reversing 00000001 gives 10000000.
    uint8_t key[8] = { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 };
    rfb_vnc_key_schedule(key);
    for (int i = 0; i < 8; i++) {
        RFB_CHECK_EQ_UINT(key[i], 0x80u);
    }
}

RFB_TEST(crypto, vnc_key_schedule__0xff__stays_0xff) {
    // All-ones is invariant under bit reversal.
    uint8_t key[8] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
    rfb_vnc_key_schedule(key);
    for (int i = 0; i < 8; i++) {
        RFB_CHECK_EQ_UINT(key[i], 0xFFu);
    }
}

RFB_TEST(crypto, vnc_key_schedule__0xaa__becomes_0x55) {
    // 10101010 reversed is 01010101.
    uint8_t key[8] = { 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA };
    rfb_vnc_key_schedule(key);
    for (int i = 0; i < 8; i++) {
        RFB_CHECK_EQ_UINT(key[i], 0x55u);
    }
}

RFB_TEST(crypto, vnc_key_schedule__mixed_bytes__each_reversed) {
    static const uint8_t in[8]  = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80 };
    static const uint8_t exp[8] = { 0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01 };
    uint8_t key[8];
    memcpy(key, in, 8);
    rfb_vnc_key_schedule(key);
    RFB_CHECK_MEM_EQ(key, exp, 8);
}

RFB_TEST(crypto, vnc_key_schedule__null__is_noop_safe) {
    rfb_vnc_key_schedule(NULL);  // must not crash
    RFB_CHECK(true);
}

// --- response assembly with an injectable DES stub ----------------------
//
// The stub XORs the key into each input block. This is NOT real DES, but
// it gives us a deterministic transform we can verify: response[i] =
// block[i] ^ key[i % 8]. The assertions cover the scheduled key and both
// eight-byte provider calls.

static bool stub_des(const uint8_t key[8], const uint8_t in[8], uint8_t out[8])
{
    for (int i = 0; i < 8; i++) {
        out[i] = (uint8_t)(in[i] ^ key[i]);
    }
    return true;
}

static bool stub_des_writes_then_fails(const uint8_t key[8],
                                       const uint8_t in[8], uint8_t out[8])
{
    (void)key;
    (void)in;
    memset(out, 0xA5, 8);
    return false;  // simulate a provider that fails after a partial write
}

static bool stub_des_second_block_fails(const uint8_t key[8],
                                        const uint8_t in[8], uint8_t out[8])
{
    (void)key;
    memset(out, 0x5A, 8);
    return in[0] != 9u;
}

RFB_TEST(crypto, vnc_auth_respond__applies_key_schedule_and_processes_both_blocks) {
    static const uint8_t password[8]  = { 0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08 };
    static const uint8_t challenge[16] = {
        0x10,0x20,0x30,0x40,0x50,0x60,0x70,0x80,
        0x11,0x21,0x31,0x41,0x51,0x61,0x71,0x81,
    };
    uint8_t response[16] = { 0 };
    RFB_CHECK(rfb_vnc_auth_respond(password, challenge, response, stub_des));
    // Expected key after schedule = per-byte bit-reversal of password.
    // reverse(0x01)=0x80, reverse(0x02)=0x40, reverse(0x03)=0xC0,
    // reverse(0x04)=0x20, reverse(0x05)=0xA0, reverse(0x06)=0x60,
    // reverse(0x07)=0xE0, reverse(0x08)=0x10.
    static const uint8_t exp_key[8] = { 0x80,0x40,0xC0,0x20,0xA0,0x60,0xE0,0x10 };
    uint8_t exp[16];
    for (int i = 0; i < 8; i++) {
        exp[i]      = (uint8_t)(challenge[i]     ^ exp_key[i]);
        exp[i + 8]  = (uint8_t)(challenge[i + 8] ^ exp_key[i]);
    }
    RFB_CHECK_MEM_EQ(response, exp, 16);
}

RFB_TEST(crypto, vnc_auth_respond__des_failure__returns_false) {
    static const uint8_t password[8] = { 0 };
    static const uint8_t challenge[16] = { 0 };
    static const uint8_t zero_response[16] = { 0 };
    uint8_t response[16];
    memset(response, 0xCC, sizeof response);
    RFB_CHECK(!rfb_vnc_auth_respond(
        password, challenge, response, stub_des_writes_then_fails));
    RFB_CHECK_MEM_EQ(response, zero_response, sizeof response);
}

RFB_TEST(crypto, vnc_auth_respond__second_des_failure__clears_both_blocks) {
    static const uint8_t password[8] = { 0 };
    static const uint8_t challenge[16] = {
        1, 2, 3, 4, 5, 6, 7, 8,
        9, 10, 11, 12, 13, 14, 15, 16,
    };
    static const uint8_t zero_response[16] = { 0 };
    uint8_t response[16];
    memset(response, 0xCC, sizeof response);
    RFB_CHECK(!rfb_vnc_auth_respond(
        password, challenge, response, stub_des_second_block_fails));
    RFB_CHECK_MEM_EQ(response, zero_response, sizeof response);
}

RFB_TEST(crypto, vnc_auth_respond__null_args__returns_false) {
    static const uint8_t password[8] = { 0 };
    static const uint8_t challenge[16] = { 0 };
    uint8_t response[16] = { 0 };
    RFB_CHECK(!rfb_vnc_auth_respond(NULL, challenge, response, stub_des));
    RFB_CHECK(!rfb_vnc_auth_respond(password, NULL, response, stub_des));
    RFB_CHECK(!rfb_vnc_auth_respond(password, challenge, NULL, stub_des));
    RFB_CHECK(!rfb_vnc_auth_respond(password, challenge, response, NULL));
}

// --- caller-owned password buffer ---------------------------------------
// The caller can wipe its input after response assembly.

RFB_TEST(crypto, vnc_auth_respond__password_can_be_zeroized_after_use) {
    uint8_t password[8] = { 's','e','c','r','e','t','1','2' };
    static const uint8_t challenge[16] = { 0 };
    uint8_t response[16] = { 0 };
    RFB_CHECK(rfb_vnc_auth_respond(password, challenge, response, stub_des));
    rfb_secret_zero(password, sizeof password);
    for (int i = 0; i < 8; i++) {
        RFB_CHECK_EQ_UINT(password[i], 0u);
    }
}
