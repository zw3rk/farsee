// SPDX-License-Identifier: Apache-2.0
//
// Farsee POSIX self-pipe wakeup implementation.
//
// A nonblocking self-pipe lets a caller interrupt poll(): writing a byte makes
// the read end readable. Repeated signals can coalesce because one consume
// drains all pending bytes. The implementation uses no mutex.

#include "farsee/farsee_wakeup.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>

struct farsee_wakeup {
    int read_fd;
    int write_fd;
};

static bool set_nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return false;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

farsee_wakeup *farsee_wakeup_create(void)
{
    farsee_wakeup *w = calloc(1, sizeof(*w));
    if (w == NULL) {
        return NULL;
    }
    w->read_fd = -1;
    w->write_fd = -1;

    int pipefd[2];
    if (pipe(pipefd) != 0) {
        free(w);
        return NULL;
    }
    if (!set_nonblock(pipefd[0]) || !set_nonblock(pipefd[1])) {
        (void)close(pipefd[0]);
        (void)close(pipefd[1]);
        free(w);
        return NULL;
    }
    w->read_fd = pipefd[0];
    w->write_fd = pipefd[1];
    return w;
}

void farsee_wakeup_destroy(farsee_wakeup **wptr)
{
    if (wptr == NULL || *wptr == NULL) {
        return;
    }
    farsee_wakeup *w = *wptr;
    if (w->read_fd >= 0) {
        (void)close(w->read_fd);
    }
    if (w->write_fd >= 0) {
        (void)close(w->write_fd);
    }
    free(w);
    *wptr = NULL;
}

farsee_reactor_token farsee_wakeup_register(farsee_wakeup *w,
                                            farsee_reactor *r,
                                            farsee_reactor_cb cb,
                                            void *user)
{
    if (w == NULL || r == NULL || cb == NULL) {
        return FARSEE_REACTOR_INVALID_TOKEN;
    }
    return farsee_reactor_add(r, w->read_fd, FARSEE_REACTOR_READ, cb, user);
}

bool farsee_wakeup_signal(farsee_wakeup *w)
{
    if (w == NULL || w->write_fd < 0) {
        return false;
    }
    // Retry EINTR. EAGAIN means the nonblocking pipe already contains a
    // pending byte and counts as success. Other write errors return false.
    unsigned char byte = 1;
    ssize_t n;
    do {
        n = write(w->write_fd, &byte, 1);
    } while (n < 0 && errno == EINTR);
    if (n == 1) {
        return true;
    }
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        return true;  // a wakeup is already pending
    }
    return false;
}

bool farsee_wakeup_consume(farsee_wakeup *w)
{
    if (w == NULL || w->read_fd < 0) {
        return false;
    }
    // Drain all pending bytes in one read loop. Nonblocking read returns
    // -1/EAGAIN when the pipe is empty.
    unsigned char buf[64];
    ssize_t n;
    size_t total = 0;
    while ((n = read(w->read_fd, buf, sizeof(buf))) > 0) {
        total += (size_t)n;  // consume n so the analyzer sees it read
    }
    // n < 0 with EAGAIN means drained (expected). n == 0 means write end
    // closed — not expected here, treated as nothing pending.
    return total > 0;
}
