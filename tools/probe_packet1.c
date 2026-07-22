// SPDX-License-Identifier: Apache-2.0
//
// G18A §4 probe helper — produces the 655-byte selector+packet1 buffer
// using the project's tested apple_rsa1 module.
//
// Reads the DER SPKI blob from stdin, encrypts the identity plaintext for
// username "probe-test" (no password — §4 does not require a password-
// derived proof), and writes the coalesced selector+packet1 to stdout.
//
// Build (inside nix develop):
//   cc -std=c11 -Wall -Wextra -Werror \
//      -Iinclude -Isrc \
//      tools/probe_packet1.c \
//      src/rfb/apple_rsa1.c src/crypto/apple_crypto.c \
//      -lcrypto -o build/probe_packet1
//
// Usage:
//   build/probe_packet1 < der_spki.bin > selector_packet1.bin
//
// This is a one-shot probe tool, NOT production code — it has no tests
// because the serializers it calls are already fully tested in G18A.

#include "farsee/apple_rsa1.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    // Read DER SPKI from stdin.
    uint8_t spki[4096];
    size_t spki_len = fread(spki, 1, sizeof spki, stdin);
    if (spki_len == 0) {
        fprintf(stderr, "probe_packet1: no DER SPKI on stdin\n");
        return 1;
    }
    fprintf(stderr, "probe_packet1: read %zu bytes of DER SPKI\n", spki_len);

    // Build the identity plaintext for username "probe-test".
    // §4: u32_be payload_len, u32_be username_len, username, u16 0, u8 0
    static const uint8_t username[] = "probe-test";
    size_t ulen = sizeof username - 1;  // 10

    uint8_t plaintext[256];
    size_t pt_len = 0;
    rfb_error e = apple_rsa1_serialize_identity(
        username, ulen, plaintext, sizeof plaintext, &pt_len);
    if (e != RFB_OK) {
        fprintf(stderr, "probe_packet1: serialize_identity failed: %d\n", e);
        return 1;
    }
    fprintf(stderr, "probe_packet1: identity plaintext %zu bytes\n", pt_len);

    // RSA-2048 PKCS#1 v1.5 encrypt (never OAEP).
    uint8_t ciphertext[APPLE_RSA1_CIPHERTEXT_LEN];
    if (!apple_rsa1_encrypt_identity(spki, spki_len,
                                     plaintext, pt_len, ciphertext)) {
        fprintf(stderr, "probe_packet1: RSA encrypt failed\n");
        return 1;
    }
    // Zeroize the plaintext immediately.
    memset(plaintext, 0, sizeof plaintext);
    fprintf(stderr, "probe_packet1: RSA ciphertext %d bytes\n",
            APPLE_RSA1_CIPHERTEXT_LEN);

    // After a key-request exchange, packet 1 is sent WITHOUT the leading
    // selector byte (RSA1-UNBLOCK.md §4 line 135-136: the selector prefix
    // is only for the "no key-request exchange needed" path).
    // Serialize packet 1 only (654 bytes).
    uint8_t out[654];
    size_t out_len = 0;
    e = apple_rsa1_serialize_packet1(
        ciphertext, out, sizeof out, &out_len);
    if (e != RFB_OK) {
        fprintf(stderr, "probe_packet1: serialize failed: %d\n", e);
        return 1;
    }
    fprintf(stderr, "probe_packet1: packet1 %zu bytes\n", out_len);

    // Write to stdout.
    if (fwrite(out, 1, out_len, stdout) != out_len) {
        fprintf(stderr, "probe_packet1: write failed\n");
        return 1;
    }

    return 0;
}
