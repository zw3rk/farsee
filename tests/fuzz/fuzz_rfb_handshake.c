// SPDX-License-Identifier: Apache-2.0
//
// G2 fuzz target for the RFB handshake state machine (plan.md §G2, §14.9).
//
// Appends bounded arbitrary bytes to one input buffer and calls the handshake
// step at most 64 times. It traps if the output buffer exceeds 256 bytes and
// stops on an error, completion, or a successful step that changes neither
// input nor output. It does not compare handshake states between steps.
//
// The DES provider is a deterministic XOR stub.

#include "farsee/handshake.h"
#include "farsee/buffer.h"
#include "farsee/allocator.h"

#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#define FUZZ_MAX_INPUT 4096u
#define FUZZ_MAX_OUTPUT 256u   // banner(12) + selection(1) + response(16) + slack
#define FUZZ_MAX_STEPS 64

static bool fuzz_stub_des(const uint8_t key[8], const uint8_t in[8], uint8_t out[8])
{
    for (int i = 0; i < 8; i++) {
        out[i] = (uint8_t)(in[i] ^ key[i]);
    }
    return true;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size > FUZZ_MAX_INPUT) {
        size = FUZZ_MAX_INPUT;
    }

    rfb_handshake_policy pol = rfb_handshake_policy_default();
    pol.allow_none_auth = true;  // exercise both paths

    rfb_handshake h;
    rfb_handshake_init(&h, &pol, rfb_default_allocator());
    rfb_handshake_set_des_provider(&h, fuzz_stub_des);
    static const uint8_t pw[8] = { 'f','u','z','z','p','a','s','s' };
    rfb_handshake_set_password(&h, pw, 8);

    rfb_buffer in, out;
    rfb_buffer_init(&in, rfb_default_allocator(), FUZZ_MAX_INPUT);
    rfb_buffer_init(&out, rfb_default_allocator(), FUZZ_MAX_OUTPUT);
    (void)rfb_buffer_append(&in, data, size);

    for (int i = 0; i < FUZZ_MAX_STEPS && !rfb_handshake_finished(&h); i++) {
        size_t before_in = rfb_buffer_length(&in);
        size_t before_out = rfb_buffer_length(&out);
        rfb_error e = rfb_handshake_step(&h, &in, &out);
        // Stop on any non-OK result; error classification is outside this harness.
        if (e != RFB_OK) {
            break;
        }
        // Bounded output.
        if (rfb_buffer_length(&out) > FUZZ_MAX_OUTPUT) {
            __builtin_trap();
        }
        // Detect a successful step that changes neither buffer and has not finished.
        // Handshake state changes are not compared here.
        if (rfb_buffer_length(&in) == before_in &&
            rfb_buffer_length(&out) == before_out &&
            !rfb_handshake_finished(&h)) {
            // Stop because this harness supplies no later input.
            break;
        }
    }

    rfb_buffer_destroy(&in);
    rfb_buffer_destroy(&out);
    rfb_handshake_destroy(&h);
    return 0;
}
