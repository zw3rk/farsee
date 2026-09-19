// SPDX-License-Identifier: Apache-2.0
//
// Apple RSA1 key-response parser fuzz target.
//
// Passes bounded arbitrary bytes to apple_rsa1_parse_key_response. On success,
// it checks that the borrowed SPKI range stays within the input, its length
// meets the parser limit and DER-length contract, and the version is 0x00000100.
// Output fields are not inspected after a non-OK result.
//
// The parser is invoked directly without an allocator or crypto provider.

#include "farsee/apple_rsa1.h"

#include <stdint.h>
#include <stddef.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#define FUZZ_MAX_INPUT 8192u

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size > FUZZ_MAX_INPUT) {
        size = FUZZ_MAX_INPUT;
    }

    apple_rsa1_key_response resp;
    rfb_error e = apple_rsa1_parse_key_response(data, size, &resp);
    if (e == RFB_OK) {
        // The borrowed DER pointer must lie within [data, data+size).
        if (resp.spki_der < data) {
            __builtin_trap();
        }
        // spki_der + spki_len must not exceed data + size.
        size_t offset = (size_t)(resp.spki_der - data);
        if (offset > size || resp.spki_len > size - offset) {
            __builtin_trap();
        }
        if (resp.spki_len > APPLE_RSA1_MAX_SPKI_DER) {
            __builtin_trap();
        }
        if (resp.spki_len != resp.der_len) {
            __builtin_trap();
        }
        if (resp.version != 0x00000100u) {
            __builtin_trap();
        }
    }
    return 0;
}
