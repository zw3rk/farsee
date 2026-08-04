// SPDX-License-Identifier: Apache-2.0
//
// Shared password-fd reader tests (P0-N2).
//
// Positive: strip trailing CR/LF, NUL-terminate, return length excl. NUL.
// Negative: nonblocking empty pipe (EAGAIN), invalid fd, null out.

#include "rfb_test.h"
#include "farsee/secret_fd.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int write_all_close(int wfd, const void *buf, size_t n)
{
    const uint8_t *p = (const uint8_t *)buf;
    size_t left = n;
    while (left > 0u) {
        ssize_t w = write(wfd, p, left);
        if (w > 0) {
            p += (size_t)w;
            left -= (size_t)w;
            continue;
        }
        if (w < 0 && errno == EINTR) {
            continue;
        }
        (void)close(wfd);
        return -1;
    }
    if (close(wfd) != 0) {
        return -1;
    }
    return 0;
}

RFB_TEST(secret_fd, read__pw_newline__strips_and_returns_length_2)
{
    int fds[2];
    RFB_CHECK(pipe(fds) == 0);
    RFB_CHECK(write_all_close(fds[1], "pw\n", 3) == 0);

    char *out = (char *)(uintptr_t)0x1; /* non-NULL so we detect overwrite */
    long n = farsee_read_fd_secret(fds[0], &out, FARSEE_SECRET_FD_DEFAULT_CAP);
    (void)close(fds[0]);

    RFB_CHECK_EQ_INT(n, 2);
    RFB_CHECK(out != NULL);
    RFB_CHECK(strcmp(out, "pw") == 0);
    free(out);
}

RFB_TEST(secret_fd, read__pw_crlf__strips_and_returns_length_2)
{
    int fds[2];
    RFB_CHECK(pipe(fds) == 0);
    RFB_CHECK(write_all_close(fds[1], "pw\r\n", 4) == 0);

    char *out = NULL;
    long n = farsee_read_fd_secret(fds[0], &out, FARSEE_SECRET_FD_DEFAULT_CAP);
    (void)close(fds[0]);

    RFB_CHECK_EQ_INT(n, 2);
    RFB_CHECK(out != NULL);
    RFB_CHECK(strcmp(out, "pw") == 0);
    free(out);
}

RFB_TEST(secret_fd, read__nonblocking_empty_pipe__returns_error_no_spin)
{
    int fds[2];
    RFB_CHECK(pipe(fds) == 0);
    int flags = fcntl(fds[0], F_GETFL);
    RFB_CHECK(flags >= 0);
    RFB_CHECK(fcntl(fds[0], F_SETFL, flags | O_NONBLOCK) == 0);
    /* No writer data: read must hit EAGAIN and fail closed (not spin). */

    char *out = (char *)(uintptr_t)0xDEAD;
    long n = farsee_read_fd_secret(fds[0], &out, FARSEE_SECRET_FD_DEFAULT_CAP);
    (void)close(fds[0]);
    (void)close(fds[1]);

    RFB_CHECK_EQ_INT(n, -1);
    RFB_CHECK(out == NULL);
}

RFB_TEST(secret_fd, read__invalid_fd__returns_error)
{
    char *out = (char *)(uintptr_t)0x1;
    long n = farsee_read_fd_secret(-1, &out, FARSEE_SECRET_FD_DEFAULT_CAP);
    RFB_CHECK_EQ_INT(n, -1);
    RFB_CHECK(out == NULL);
}

RFB_TEST(secret_fd, read__null_out__returns_error)
{
    int fds[2];
    RFB_CHECK(pipe(fds) == 0);
    RFB_CHECK(write_all_close(fds[1], "x\n", 2) == 0);

    long n = farsee_read_fd_secret(fds[0], NULL, FARSEE_SECRET_FD_DEFAULT_CAP);
    (void)close(fds[0]);
    RFB_CHECK_EQ_INT(n, -1);
}

RFB_TEST(secret_fd, read__empty_eof__returns_empty_string)
{
    int fds[2];
    RFB_CHECK(pipe(fds) == 0);
    RFB_CHECK(close(fds[1]) == 0); /* immediate EOF */

    char *out = NULL;
    long n = farsee_read_fd_secret(fds[0], &out, FARSEE_SECRET_FD_DEFAULT_CAP);
    (void)close(fds[0]);

    RFB_CHECK_EQ_INT(n, 0);
    RFB_CHECK(out != NULL);
    RFB_CHECK(out[0] == '\0');
    free(out);
}

RFB_TEST(secret_fd, read__zero_cap__returns_error)
{
    char *out = (char *)(uintptr_t)0x1;
    long n = farsee_read_fd_secret(0, &out, 0);
    RFB_CHECK_EQ_INT(n, -1);
    RFB_CHECK(out == NULL);
}

// Cap reached with more data remaining: fail closed (no silent truncate).
// cap=4 => room for 3 secret bytes + NUL; payload longer than that fails.
RFB_TEST(secret_fd, read__oversize_secret__fails_closed_no_truncate)
{
    int fds[2];
    RFB_CHECK(pipe(fds) == 0);
    RFB_CHECK(write_all_close(fds[1], "toolong\n", 8) == 0);

    char *out = (char *)(uintptr_t)0xBEEF;
    long n = farsee_read_fd_secret(fds[0], &out, 4u);
    (void)close(fds[0]);

    RFB_CHECK_EQ_INT(n, -1);
    RFB_CHECK(out == NULL);
}

// Exact fit at cap-1 (no trailing newline) succeeds; EOF after fill is OK.
RFB_TEST(secret_fd, read__exact_cap_minus_one__succeeds)
{
    int fds[2];
    RFB_CHECK(pipe(fds) == 0);
    RFB_CHECK(write_all_close(fds[1], "abc", 3) == 0);

    char *out = NULL;
    long n = farsee_read_fd_secret(fds[0], &out, 4u);
    (void)close(fds[0]);

    RFB_CHECK_EQ_INT(n, 3);
    RFB_CHECK(out != NULL);
    RFB_CHECK(strcmp(out, "abc") == 0);
    free(out);
}

// Partial read then hard error (EIO on closed-after-write side is hard to
// force portably). Simulate via a small-cap path that fails mid-read is
// covered by nonblocking empty; error free path is exercised when EAGAIN
// hits after a partial write+read: write 2 bytes, set nonblock, call with
// large cap — first read succeeds, second hits EAGAIN → fail, *out NULL.
RFB_TEST(secret_fd, read__partial_then_eagain__fails_and_no_leak)
{
    int fds[2];
    RFB_CHECK(pipe(fds) == 0);
    RFB_CHECK(write(fds[1], "ab", 2) == 2);
    int flags = fcntl(fds[0], F_GETFL);
    RFB_CHECK(flags >= 0);
    RFB_CHECK(fcntl(fds[0], F_SETFL, flags | O_NONBLOCK) == 0);
    /* Writer still open so no EOF; after draining "ab", next read is EAGAIN. */

    char *out = (char *)(uintptr_t)0xCAFE;
    long n = farsee_read_fd_secret(fds[0], &out, FARSEE_SECRET_FD_DEFAULT_CAP);
    (void)close(fds[0]);
    (void)close(fds[1]);

    RFB_CHECK_EQ_INT(n, -1);
    RFB_CHECK(out == NULL);
}
