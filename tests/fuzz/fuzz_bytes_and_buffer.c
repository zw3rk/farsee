// SPDX-License-Identifier: Apache-2.0
//
// G1 fuzz target: byte reader/writer + buffer invariants
// (plan.md §G1: "Create fuzz_bytes_and_buffer or equivalent for
// reader/buffer invariants").
//
// The harness feeds arbitrary bytes into:
//   - rfb_reader sequence of u8/u16/u32/bytes/skip reads; verifies the
//     offset never exceeds the length;
//   - rfb_writer appends into a fixed buffer; verifies length never
//     exceeds capacity;
//   - rfb_buffer append/consume loop; verifies length stays within the
//     hard limit.
//
// No crash, no sanitizer finding, no progress-invariant violation is the
// passing contract. Memory and time are bounded by the harness itself.
//
// Build: this file is compiled with -fsanitize=fuzzer (the fuzz BUILD
// mode) and linked into a standalone binary by the Makefile's fuzz
// target. It can also be invoked manually with a corpus directory.

#include "farsee/bytes.h"
#include "farsee/buffer.h"
#include "farsee/allocator.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// libFuzzer's entrypoint. Declared here to satisfy -Wmissing-prototypes
// (we do not depend on <stddef.h>'s fuzzer header).
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

// Bound the fuzz input so a pathological case cannot OOM.
#define FUZZ_MAX_INPUT (64u * 1024u)

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size > FUZZ_MAX_INPUT) {
        size = FUZZ_MAX_INPUT;
    }
    if (size == 0) {
        return 0;
    }

    // --- reader invariants ---
    rfb_reader r = rfb_reader_make(data, size);
    // Drive a deterministic sequence of reads derived from the input
    // itself, so different bytes exercise different paths.
    size_t guard = 0;
    const size_t guard_max = 4096;
    while (rfb_reader_remaining(&r) > 0 && guard < guard_max) {
        guard++;
        // Use the next byte (if available) to pick an op; else default to u8.
        uint8_t op = 0;
        if (!rfb_peek_u8(&r, 0, &op)) {
            break;
        }
        switch (op & 3u) {
        case 0: {
            uint8_t v;
            (void)rfb_read_u8(&r, &v);
            break;
        }
        case 1: {
            uint16_t v;
            (void)rfb_read_u16(&r, &v);
            break;
        }
        case 2: {
            uint32_t v;
            (void)rfb_read_u32(&r, &v);
            break;
        }
        case 3: {
            uint8_t buf[8];
            (void)rfb_read_bytes(&r, buf, sizeof buf);
            break;
        }
        }
        // Invariant: offset never exceeds length.
        if (r.offset > r.length) {
            __builtin_trap();
        }
    }

    // --- writer invariants ---
    // Use a modest fixed buffer so we exercise overflow paths too.
    uint8_t wbuf[128];
    rfb_writer w = rfb_writer_make(wbuf, sizeof wbuf);
    for (size_t i = 0; i < size && w.length <= w.capacity; i++) {
        switch (data[i] & 3u) {
        case 0: (void)rfb_write_u8(&w, data[i]);      break;
        case 1: (void)rfb_write_u16(&w, (uint16_t)i); break;
        case 2: (void)rfb_write_u32(&w, (uint32_t)i); break;
        case 3: (void)rfb_write_bytes(&w, data + i, 1); break;
        }
        if (w.length > w.capacity) {
            __builtin_trap();
        }
    }

    // --- buffer invariants ---
    rfb_buffer b;
    rfb_buffer_init(&b, rfb_default_allocator(), 2048);
    // Append the whole input; the hard limit caps it.
    (void)rfb_buffer_append(&b, data, size);
    if (rfb_buffer_length(&b) > 2048u) {
        __builtin_trap();
    }
    // Consume some, then append again; length must stay bounded.
    rfb_buffer_consume(&b, rfb_buffer_length(&b) / 2);
    (void)rfb_buffer_append(&b, data, size);
    if (rfb_buffer_length(&b) > 2048u) {
        __builtin_trap();
    }
    rfb_buffer_destroy(&b);
    return 0;
}
