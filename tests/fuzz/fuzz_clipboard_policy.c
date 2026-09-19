// SPDX-License-Identifier: Apache-2.0
//
// G25 fuzz target for clipboard policy helpers.
//
// Calls UTF-8 validation and repair, escape sanitization, size-policy checks,
// and loop-suppression hashing with bounded arbitrary input. It traps if a
// reported repair length exceeds its buffer, or if sanitized output exceeds
// input length or contains ESC. Other helper results are not inspected.

#include "farsee/clipboard.h"

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

    // --- UTF-8 validation -------------------------------------------------
    (void)rfb_clip_utf8_valid(data, size);

    // --- UTF-8 repair -------------------------------------------------------
    {
        uint8_t out[FUZZ_MAX_INPUT * 3 + 16];  // U+FFFD is 3 bytes
        size_t out_len = 0;
        (void)rfb_clip_utf8_repair(data, size, out, sizeof out, &out_len);
        if (out_len > sizeof out) {
            __builtin_trap();
        }
        // Invoke validation on nonempty repaired output; ignore the result.
        if (out_len > 0) {
            (void)rfb_clip_utf8_valid(out, out_len);
        }
    }

    // --- Escape sanitization ---------------------------------------------
    {
        uint8_t out[FUZZ_MAX_INPUT + 16];
        size_t out_len = 0;
        (void)rfb_clip_sanitize(data, size, out, sizeof out, &out_len);
        if (out_len > size) {
            __builtin_trap();  // sanitization only drops bytes
        }
        // The sanitized output must never contain an ESC (0x1B) byte.
        for (size_t i = 0; i < out_len; i++) {
            if (out[i] == 0x1Bu) {
                __builtin_trap();
            }
        }
    }

    // --- Size-cap enforcement --------------------------------------------
    rfb_clip_policy p = rfb_clip_policy_default();
    (void)rfb_clip_size_ok(&p, size);
    (void)rfb_clip_allow_outbound(&p, size);

    // --- Loop suppression hashing ----------------------------------------
    rfb_clip_loop loop;
    rfb_clip_loop_init(&loop);
    rfb_clip_loop_record_inbound(&loop, data, size);
    // Invoke the echo check on the recorded bytes; ignore its result.
    (void)rfb_clip_loop_is_echo(&loop, data, size);
    rfb_clip_loop_clear(&loop);

    return 0;
}
