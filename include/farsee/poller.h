// SPDX-License-Identifier: Apache-2.0
//
// farsee — reusable poll() event loop (plan.md §G5, §9: src/io/poller_posix.c).
//
// A thin wrapper around poll() that the session loop uses to wait for
// readability/writability on file descriptors with a timeout. Factored
// from the lifecycle integration driver so the session loop, tests, and
// the CLI all share one poll abstraction (plan.md §G5, ADR-0004).

#ifndef FARSEE_INCLUDE_FARSEE_POLLER_H
#define FARSEE_INCLUDE_FARSEE_POLLER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Events to wait for on a single fd.
typedef enum {
    RFB_POLL_NONE  = 0,
    RFB_POLL_READ  = 1,
    RFB_POLL_WRITE = 2,
} rfb_poll_event;

// A single fd + the events to wait for.
typedef struct rfb_poll_fd {
    int fd;
    rfb_poll_event events;   // input: what to wait for
    rfb_poll_event revents;  // output: what actually happened
} rfb_poll_fd;

// Wait for events on up to `count` fds. Returns the number of fds with
// events, 0 on timeout, or -1 on error. `timeout_ms` is -1 for infinite.
int rfb_poll_wait(rfb_poll_fd *fds, size_t count, int timeout_ms);

// Convenience: wait for readability on a single fd.
bool rfb_poll_readable(int fd, int timeout_ms);

// Convenience: wait for writability on a single fd.
bool rfb_poll_writable(int fd, int timeout_ms);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_POLLER_H
