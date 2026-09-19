// SPDX-License-Identifier: Apache-2.0
//
// G25 fuzz target for Apple session-control helpers.
//
// Passes one bounded arbitrary encrypted-step record to apple_session_step,
// then independently calls cursor store/select and framebuffer resize with
// fuzz-derived values. It traps only if the reported step output exceeds the
// 512-byte buffer. Other return values and resulting session state are not
// inspected.

#include "farsee/apple_session.h"
#include "farsee/apple_postauth.h"
#include "farsee/framebuffer.h"
#include "farsee/allocator.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#define FUZZ_MAX_INPUT 4096u

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size > FUZZ_MAX_INPUT) {
        size = FUZZ_MAX_INPUT;
    }

    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());

    apple_session s;
    apple_session_init(&s, NULL, &fb, rfb_default_allocator(), 4u * 1024u * 1024u);

    // Pass the bytes in one encrypted step and inspect only the reported output
    // length. The harness makes one step call.
    uint8_t out_bytes[512];
    size_t out_len = 0;

    apple_session_record step = {
        .kind = APPLE_STEP_ENCRYPTED,
        .data = data,
        .len  = size,
    };
    // The single call exercises whichever step path accepts the current state and
    // bytes; its result and state transition are not inspected.
    (void)apple_session_step(&s, &step, out_bytes, sizeof out_bytes, &out_len);
    if (out_len > sizeof out_bytes) {
        __builtin_trap();
    }

    // Independently call cursor store/select with a fuzz-derived index, dimensions,
    // and bounded payload slice; ignore both results.
    if (size >= 4) {
        uint8_t idx = data[0];
        uint16_t w = (uint16_t)(data[1] & 0x3F);   // <= 63
        uint16_t h = (uint16_t)(data[2] & 0x3F);   // <= 63
        (void)apple_session_cursor_store(&s, idx, w, h, 0, 0,
                                         data + 4, size < (size_t)4 + (size_t)w * h
                                            ? (size > 4 ? size - 4 : 0)
                                            : (size_t)w * h);
        (void)apple_session_cursor_select(&s, idx);
    }

    // Independently request a resize with nonzero fuzz-derived dimensions.
    if (size >= 4) {
        uint16_t rw = (uint16_t)(data[0] | 1);  // never zero
        uint16_t rh = (uint16_t)(data[1] | 1);
        (void)apple_session_resize(&s, rw, rh);
    }

    apple_session_destroy(&s);
    rfb_framebuffer_destroy(&fb);
    return 0;
}
