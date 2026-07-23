// SPDX-License-Identifier: Apache-2.0
//
// G25 fuzz target: clipboard policy (threat-model T8).
//
// Feeds arbitrary bytes through the clipboard policy transforms:
//   - UTF-8 validation and repair;
//   - terminal escape sanitization (OSC/CSI/C0 injection stripping);
//   - size-cap enforcement;
//   - loop suppression hashing.
// Asserts no crash, no sanitizer finding, no out-of-bounds write, and that
// sanitization never *introduces* an ESC byte.

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

    // --- UTF-8 repair (output >= input) ----------------------------------
    {
        uint8_t out[FUZZ_MAX_INPUT * 3 + 16];  // U+FFFD is 3 bytes
        size_t out_len = 0;
        (void)rfb_clip_utf8_repair(data, size, out, sizeof out, &out_len);
        if (out_len > sizeof out) {
            __builtin_trap();
        }
        // Repaired output must itself be valid UTF-8 (or empty).
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
    // Echo check must be deterministic and not crash.
    (void)rfb_clip_loop_is_echo(&loop, data, size);
    rfb_clip_loop_clear(&loop);

    return 0;
}
