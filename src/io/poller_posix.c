// SPDX-License-Identifier: Apache-2.0
//
// farsee — POSIX poll() adapter (plan.md §G5, §9).
//
// Thin wrapper used by the reactor and poller-focused tests.

#include "farsee/poller.h"

#include <errno.h>
#include <poll.h>
#include <unistd.h>

int rfb_poll_wait(rfb_poll_fd *fds, size_t count, int timeout_ms)
{
    if (fds == NULL || count == 0) {
        return 0;
    }
    if (count > 16) {
        errno = EINVAL;
        return -1;  // too many fds; caller must batch
    }
    // Translate to a fixed POSIX pollfd array; the API limit is 16 fds.
    struct pollfd pfd[16];
    for (size_t i = 0; i < count; i++) {
        pfd[i].fd = fds[i].fd;
        pfd[i].events = 0;
        if (fds[i].events & RFB_POLL_READ)  pfd[i].events |= POLLIN;
        if (fds[i].events & RFB_POLL_WRITE) pfd[i].events |= POLLOUT;
        pfd[i].revents = 0;
    }
    // Retry on EINTR (signal delivered during wait).
    int rc;
    do {
        rc = poll(pfd, (nfds_t)count, timeout_ms);
    } while (rc < 0 && errno == EINTR);
    if (rc <= 0) {
        return rc;  // 0 = timeout, -1 = error
    }
    int ready = 0;
    for (size_t i = 0; i < count; i++) {
        fds[i].revents = RFB_POLL_NONE;
        if (pfd[i].revents & POLLIN)   fds[i].revents |= RFB_POLL_READ;
        if (pfd[i].revents & POLLOUT)  fds[i].revents |= RFB_POLL_WRITE;
        if (pfd[i].revents & POLLHUP)  fds[i].revents |= RFB_POLL_HUP;
        // POLLERR and POLLNVAL are both dead-fd errors; poll reports them
        // in revents regardless of the requested events, so a dead fd is
        // counted as ready instead of looking like a timeout.
        if (pfd[i].revents & (POLLERR | POLLNVAL)) fds[i].revents |= RFB_POLL_ERR;
        if (fds[i].revents != RFB_POLL_NONE) ready++;
    }
    return ready;
}

bool rfb_poll_readable(int fd, int timeout_ms)
{
    rfb_poll_fd pfd;
    pfd.fd = fd;
    pfd.events = RFB_POLL_READ;
    pfd.revents = RFB_POLL_NONE;
    return rfb_poll_wait(&pfd, 1, timeout_ms) > 0;
}

bool rfb_poll_writable(int fd, int timeout_ms)
{
    rfb_poll_fd pfd;
    pfd.fd = fd;
    pfd.events = RFB_POLL_WRITE;
    pfd.revents = RFB_POLL_NONE;
    return rfb_poll_wait(&pfd, 1, timeout_ms) > 0;
}
