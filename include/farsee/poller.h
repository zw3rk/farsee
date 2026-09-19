// SPDX-License-Identifier: Apache-2.0
//
// farsee — reusable poll() event loop (plan.md §G5, §9: src/io/poller_posix.c).
//
// A thin wrapper around poll() used by the reactor and poller-focused tests.
// It translates readability, writability, hangup, and error events into
// rfb_poll_event values and provides single-fd convenience waits with
// caller-supplied timeouts.

#ifndef FARSEE_INCLUDE_FARSEE_POLLER_H
#define FARSEE_INCLUDE_FARSEE_POLLER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Events to wait for on a single fd. HUP and ERR are output-only: poll()
// reports them in revents regardless of the subscribed events, and
// rfb_poll_wait counts them as ready so a dead fd is never mistaken for
// a timeout (POLLNVAL maps to ERR).
typedef enum {
    RFB_POLL_NONE  = 0,
    RFB_POLL_READ  = 1,
    RFB_POLL_WRITE = 2,
    RFB_POLL_HUP   = 4,  // revents only: peer hangup (POLLHUP)
    RFB_POLL_ERR   = 8,  // revents only: error / invalid fd (POLLERR|POLLNVAL)
} rfb_poll_event;

// A single fd + the events to wait for.
typedef struct rfb_poll_fd {
    int fd;
    rfb_poll_event events;   // input: what to wait for
    rfb_poll_event revents;  // output: what actually happened
} rfb_poll_fd;

// Wait for events on up to 16 fds. Returns ready count, 0 on timeout, or -1
// on error (including count > 16). `timeout_ms` is -1 for infinite.
int rfb_poll_wait(rfb_poll_fd *fds, size_t count, int timeout_ms);

// Wait for read readiness or terminal HUP/ERR on one fd.
bool rfb_poll_readable(int fd, int timeout_ms);

// Wait for write readiness or terminal HUP/ERR on one fd.
bool rfb_poll_writable(int fd, int timeout_ms);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_POLLER_H
