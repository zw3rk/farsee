// SPDX-License-Identifier: Apache-2.0
//
// farsee — fake I/O adapter for tests (plan.md §14.5 "Socket fault
// tests"). Test-only; not linked into release artifacts.
//
// The fake is a pair of byte queues (server-to-client, client-to-server)
// with a scriptable write behavior: the next N write calls can be made
// to short-write, return EAGAIN, or return EINTR, so tests can drive the
// drain loop through every fault path deterministically.

#ifndef FARSEE_TESTS_TEST_FRAMEWORK_FAKE_IO_H
#define FARSEE_TESTS_TEST_FRAMEWORK_FAKE_IO_H

#include "farsee/io_adapter.h"
#include "farsee/buffer.h"
#include "farsee/allocator.h"

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    FAKE_W_NORMAL = 0,    // write as many bytes as asked (up to capacity)
    FAKE_W_SHORT  = 1,    // next write returns only `short_n` bytes
    FAKE_W_EAGAIN = 2,    // next write returns RFB_IO_BLOCK, *out_n=0
    FAKE_W_ERROR  = 3,    // next write returns RFB_IO_ERROR
} fake_write_mode;

typedef struct fake_io {
    // Bytes the "server" has sent that the client can read.
    rfb_buffer inbox;
    // Bytes the client has written (server's view).
    rfb_buffer outbox;
    // Scriptable write behavior.
    fake_write_mode wmode;
    size_t short_n;        // when wmode == FAKE_W_SHORT
    bool eof_on_empty_read;  // true: reading an empty inbox returns EOF
    bool connected;
} fake_io;

void fake_io_init(fake_io *f, rfb_allocator *alloc);
void fake_io_destroy(fake_io *f);

// Seed the inbox with bytes the "server" sent.
void fake_io_seed_inbox(fake_io *f, const void *data, size_t n);

// Read what the client wrote.
const uint8_t *fake_io_outbox_data(const fake_io *f);
size_t fake_io_outbox_len(const fake_io *f);

// Build an adapter backed by this fake.
rfb_io_adapter fake_io_adapter_make(fake_io *f);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_TESTS_TEST_FRAMEWORK_FAKE_IO_H
