// SPDX-License-Identifier: Apache-2.0
//
// farsee — VNC Authentication key schedule and response assembly
// (plan.md §G2, ADR-0002, RFC 6143 §7.2.2).
//
// The key schedule is the well-known VNC bit-reversal transform described
// in RFC 6143 §7.2.2: the password's first 8 bytes (zero-padded) are each
// bit-reversed to form the DES key. This is a public standard table; we
// implement it directly, not by copying any implementation. The DES-ECB
// primitive itself is supplied by the provider (CommonCrypto/OpenSSL).

#include "farsee/crypto_provider.h"
#include "farsee/secret.h"

#include <stdbool.h>
#include <string.h>

// Reverse the 8 bits of a byte. Used per-password-byte by the VNC key
// schedule (RFC 6143 §7.2.2: "each byte ... has its bits reversed").
static uint8_t reverse_bits_8(uint8_t b)
{
    unsigned int r = 0;
    unsigned int v = (unsigned int)b;
    for (int i = 0; i < 8; i++) {
        r = (r << 1) | (v & 1u);
        v = v >> 1;
    }
    return (uint8_t)r;
}

void rfb_vnc_key_schedule(uint8_t key[8])
{
    if (key == NULL) {
        return;
    }
    for (int i = 0; i < 8; i++) {
        key[i] = reverse_bits_8(key[i]);
    }
}

bool rfb_vnc_auth_respond(
    const uint8_t password[8],
    const uint8_t challenge[16],
    uint8_t response[16],
    rfb_des_ecb_encrypt_fn des)
{
    if (des == NULL || password == NULL || challenge == NULL || response == NULL) {
        return false;
    }
    uint8_t key[8];
    memcpy(key, password, 8);
    rfb_vnc_key_schedule(key);
    // DES-ECB on two independent 8-byte blocks.
    bool ok = des(key, challenge, response) &&
              des(key, challenge + 8, response + 8);
    rfb_secret_zero(key, sizeof key);
    return ok;
}
