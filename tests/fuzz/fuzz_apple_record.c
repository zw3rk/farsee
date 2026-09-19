// SPDX-License-Identifier: Apache-2.0
//
// G25 fuzz target for the Apple encrypted record layer.
//
// Initializes a record layer with fixed synthetic keys and passes bounded
// arbitrary ciphertext to apple_record_decrypt. On success, it traps if the
// reported plaintext length exceeds the ciphertext length. Other result codes
// are not classified.
//
// For inputs of at least two blocks, it also calls apple_record_rekey with
// arbitrary wrapped blocks. It does not inspect the rekey result or state.

#include "farsee/apple_record.h"
#include "farsee/apple_crypto.h"
#include "farsee/allocator.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#define FUZZ_MAX_INPUT 8192u

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size > FUZZ_MAX_INPUT) {
        size = FUZZ_MAX_INPUT;
    }
    if (size == 0) {
        return 0;
    }

    // Initialize the record layer with a synthetic wrap key (all 0x42).
    static const uint8_t wrap_key[APPLE_BLOCK_SIZE] = {
        0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42,
        0x42,0x42,0x42,0x42,0x42,0x42,0x42,0x42,
    };
    static const uint8_t content_key[APPLE_BLOCK_SIZE] = {
        0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,
        0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,
    };
    static const uint8_t iv[APPLE_BLOCK_SIZE] = {
        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
        0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,
    };

    apple_record_layer rl;
    apple_record_init(&rl, wrap_key);
    (void)apple_record_set_direction(&rl, APPLE_DIR_DECRYPT, content_key, iv);

    // --- Decrypt arbitrary ciphertext -------------------------------------
    // Cap the plaintext buffer at the harness input limit and inspect the length
    // only when decryption succeeds.
    uint8_t plaintext[FUZZ_MAX_INPUT];
    size_t pt_len = 0;
    rfb_error e = apple_record_decrypt(&rl, data, size,
                                       plaintext, sizeof plaintext, &pt_len);
    if (e == RFB_OK) {
        // Plaintext must never exceed ciphertext length.
        if (pt_len > size) {
            __builtin_trap();
        }
    }
    // Non-OK results are not classified by this harness.

    // --- Rekey with arbitrary wrapped blocks ------------------------------
    // For inputs of at least two blocks, call rekey with two input blocks and a
    // fixed new wrapping key. The result and layer state are not inspected.
    if (size >= 2 * APPLE_BLOCK_SIZE) {
        static const uint8_t new_wrap[APPLE_BLOCK_SIZE] = {
            0xab,0xcd,0xef,0x01,0x23,0x45,0x67,0x89,
            0xab,0xcd,0xef,0x01,0x23,0x45,0x67,0x89,
        };
        (void)apple_record_rekey(&rl, APPLE_DIR_DECRYPT,
                                 data, data + APPLE_BLOCK_SIZE, new_wrap);
    }

    apple_record_destroy(&rl);
    return 0;
}
