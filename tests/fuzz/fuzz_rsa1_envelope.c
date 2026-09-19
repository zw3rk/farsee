// SPDX-License-Identifier: Apache-2.0
//
// G25 fuzz target for the RSA1 envelope parser and serializer.
//
// Calls both parsers with bounded arbitrary input. After a successful envelope
// parse, it traps if key lengths exceed local bounds. It serializes the key
// into a fixed buffer and, after successful serialization and reparsing,
// compares the two encoded lengths. Other results are not classified.
// It also invokes serialization with a one-byte output buffer and ignores the
// result.

#include "farsee/rsa1_envelope.h"

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

    // --- Parse envelope (client→server raw envelope) ----------------------
    rsa1_public_key key;
    rfb_error e = rsa1_parse_envelope(data, size, &key);
    if (e == RFB_OK) {
        if (key.modulus_len > RSA1_MAX_KEY_BYTES) {
            __builtin_trap();
        }
        if (key.exponent_len > 4) {
            __builtin_trap();
        }
    }

    // --- Parse descriptor (26-byte server key descriptor) -----------------
    rsa1_descriptor desc;
    (void)rsa1_parse_descriptor(data, size, &desc);

    // --- Serialize-then-parse round trip ----------------------------------
    // After a successful parse, serialize into a fixed buffer.
    if (e == RFB_OK) {
        uint8_t buf[1024];
        size_t out_len = 0;
        rfb_error se = rsa1_serialize_envelope(&key, buf, sizeof buf, &out_len);
        if (se == RFB_OK) {
            if (out_len > sizeof buf) {
                __builtin_trap();
            }
            // Reparse successful output; compare lengths only if reparsing succeeds.
            rsa1_public_key key2;
            rfb_error pe = rsa1_parse_envelope(buf, out_len, &key2);
            if (pe == RFB_OK) {
                if (key2.modulus_len != key.modulus_len) {
                    __builtin_trap();
                }
                if (key2.exponent_len != key.exponent_len) {
                    __builtin_trap();
                }
            }
        }
        // Also invoke serialization with a one-byte buffer; ignore the result.
        uint8_t tiny[1];
        size_t tiny_len = 0;
        (void)rsa1_serialize_envelope(&key, tiny, sizeof tiny, &tiny_len);
    }

    return 0;
}
