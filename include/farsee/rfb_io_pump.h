// SPDX-License-Identifier: Apache-2.0
//
// farsee — nonblocking socket I/O pump for RFB session (extracted Q3).
//
// Drain outbound buffer, append inbound into a buffer, with POLLIN-only
// waits and residual floor sleep to avoid CPU spin (see type-33 live
// CPU-peg notes). No product essays; last_error write-back only.
//
// All pointers on rfb_io_pump are borrowed for the duration of use.
// Not thread-safe.

#ifndef FARSEE_INCLUDE_FARSEE_RFB_IO_PUMP_H
#define FARSEE_INCLUDE_FARSEE_RFB_IO_PUMP_H

#include "farsee/buffer.h"
#include "farsee/error.h"
#include "farsee/farsee_atomic.h"
#include "farsee/io_adapter.h"
#include "farsee/server_init.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Default single-read chunk size (matches historical session constant).
#define RFB_IO_PUMP_READ_CHUNK 8192u

// Borrowed handles into a live session (or test double). Zero-init is
// not a valid pump — set io/in/out before use. fd is the poll target.
typedef struct rfb_io_pump {
    rfb_io_adapter *io;            // required
    int fd;                        // poll fd (typically sock.fd)
    rfb_buffer *in;                // required
    rfb_buffer *out;               // required
    rfb_error *last_error;         // optional write-back; may be NULL
    farsee_atomic_int *stop_flag;  // optional cooperative cancel
    // Absolute CLOCK_MONOTONIC deadline in ms for handshake/recv loops.
    // 0 = use iteration caps only (legacy). When set, recv_exact and
    // read_server_init fail with RFB_ERR_TIMEOUT past this deadline.
    uint64_t deadline_mono_ms;
} rfb_io_pump;

// Monotonic milliseconds (CLOCK_MONOTONIC). Returns 0 on clock failure.
uint64_t rfb_io_mono_ms(void);

// True if stop_flag is non-NULL and currently non-zero.
bool rfb_io_stop_requested(const rfb_io_pump *p);

// Drain *out via io->write with optional POLLOUT wait.
// timeout_ms <= 0: non-blocking try only.
// Returns RFB_OK even if not fully drained (caller retries).
// RFB_ERR_IO on hard write/poll error (sets *last_error when set).
rfb_error rfb_io_drain_out(rfb_io_pump *p, int timeout_ms);

// Append to *out and drain with a 1000 ms budget.
rfb_error rfb_io_queue_bytes(rfb_io_pump *p, const uint8_t *data, size_t n);

// One POLLIN wait + read into *in. Never combines POLLOUT with a sleep
// wait (connected TCP is almost always writable → busy-spin otherwise).
// When no input bytes are gained and timeout_ms > 0, burns residual time
// so the protocol loop cannot re-enter poll() in a tight spin.
rfb_error rfb_io_read_some(rfb_io_pump *p, int timeout_ms);

// Fill data[0..n) from *in then read_some loops. Honors stop_flag →
// RFB_ERR_CANCELLED. Bounded by ~10000 iterations × poll timeout.
rfb_error rfb_io_recv_exact(rfb_io_pump *p, uint8_t *data, size_t n);

// Read and parse ServerInit from the pump input buffer (RFC 6143 §7.3.2),
// draining/reading as needed. name length capped by RFB_LIMIT_DESKTOP_NAME.
rfb_error rfb_io_read_server_init(rfb_io_pump *p, rfb_server_init *si);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_RFB_IO_PUMP_H
