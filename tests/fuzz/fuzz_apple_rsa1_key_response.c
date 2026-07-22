// SPDX-License-Identifier: Apache-2.0
//
// G18A fuzz target: apple_rsa1 key-response parser (RSA1-UNBLOCK.md §3).
//
// Feeds arbitrary bytes into apple_rsa1_parse_key_response and asserts:
//   - no crash, no sanitizer finding;
//   - on success, the borrowed DER pointer lies within the input buffer
//     and spki_len <= der_len <= APPLE_RSA1_MAX_SPKI_DER;
//   - on failure, no field of the output struct is used (the contract is
//     that callers ignore the output on a non-OK return).
//
// The parser is a pure byte codec (no allocation, no crypto provider), so
// this target exercises every code path cheaply.

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
