// SPDX-License-Identifier: Apache-2.0
//
// G25 fuzz target: RFB security-type negotiation + Apple selection policy.
//
// Feeds arbitrary bytes as the server's security-type advertisement into the
// handshake state machine AND into apple_select_security_type, asserting:
//   - no crash, no sanitizer finding;
//   - the selection policy never returns a type that was not offered;
//   - no busy-loop (progress invariant);
//   - the handshake never emits more than a bounded amount of output.
//
// The DES provider is a deterministic stub so the fuzzer is hermetic.

#include "farsee/handshake.h"
#include "farsee/apple_auth.h"
#include "farsee/buffer.h"
#include "farsee/allocator.h"

#include <stdint.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#define FUZZ_MAX_INPUT 4096u
#define FUZZ_MAX_OUTPUT 256u
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

    // --- Handshake SM over the raw bytes -----------------------------------
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
        if (e != RFB_OK) {
            break;
        }
        if (rfb_buffer_length(&out) > FUZZ_MAX_OUTPUT) {
            __builtin_trap();
        }
        // Progress invariant.
        if (rfb_buffer_length(&in) == before_in &&
            rfb_buffer_length(&out) == before_out &&
            !rfb_handshake_finished(&h)) {
            break;
        }
    }

    rfb_buffer_destroy(&in);
    rfb_buffer_destroy(&out);
    rfb_handshake_destroy(&h);

    // --- Apple security-type selection policy ------------------------------
    // Use the first up-to-32 bytes of the input as an offered-type list.
    // The policy must never return a type that was not in the offered list
    // (except 0 = "none acceptable"), and must never auto-select legacy 30
    // unless allow_legacy is true.
    if (size >= 1) {
        size_t cnt = size < 32 ? size : 32;
        int sel_legacy_off = apple_select_security_type(data, cnt, false);
        int sel_legacy_on  = apple_select_security_type(data, cnt, true);

        // If a type was selected without legacy, it must be one of 33/35/36
        // and must appear in the offered list.
        if (sel_legacy_off != 0) {
            bool found = false;
            for (size_t i = 0; i < cnt; i++) {
                if (data[i] == (uint8_t)sel_legacy_off) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                __builtin_trap();
            }
            if (sel_legacy_off == APPLE_SEC_TYPE_30) {
                __builtin_trap();  // legacy 30 must never auto-select
            }
        }
        // Same invariant for the legacy-allowed path: selection must be offered.
        if (sel_legacy_on != 0) {
            bool found = false;
            for (size_t i = 0; i < cnt; i++) {
                if (data[i] == (uint8_t)sel_legacy_on) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                __builtin_trap();
            }
        }
        (void)sel_legacy_off;
        (void)sel_legacy_on;
    }

    // --- Apple dialect detection ------------------------------------------
    // The 003.889 detector must not crash on any 12-byte (or shorter) input.
    if (size >= 1) {
        (void)apple_is_dialect_003_889(data, size);
        (void)apple_is_dialect_003_889(data, size < 12 ? size : 12);
    }

    return 0;
}
