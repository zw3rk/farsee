// SPDX-License-Identifier: Apache-2.0
//
// Shared credential-fd reader tests for generic secrets and exact Apple
// username framing.

#include "rfb_test.h"
#include "farsee/secret.h"
#include "farsee/secret_fd.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int write_all(int wfd, const void *buf, size_t n)
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
        return -1;
    }
    return 0;
}

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

// Probe would-block must not be accepted as EOF: a cap-1
// secret on a nonblocking pipe whose writer is still composing would be
// silently truncated to its prefix; the probe may only accept a clean
// EOF, everything else fails closed.
RFB_TEST(secret_fd, read__probe_eagain_writer_live__fails_no_silent_truncate)
{
    int live[2];
    RFB_CHECK(pipe(live) == 0);
    RFB_CHECK(write_all(live[1], "abc", 3) == 0);
    int flags = fcntl(live[0], F_GETFL, 0);
    RFB_CHECK(flags >= 0);
    RFB_CHECK(fcntl(live[0], F_SETFL, flags | O_NONBLOCK) == 0);

    char *out = (char *)(uintptr_t)0xBEEF;
    long n = farsee_read_fd_secret(live[0], &out, 4u);
    (void)close(live[0]);
    (void)close(live[1]);

    RFB_CHECK_EQ_INT(n, -1);
    RFB_CHECK(out == NULL);
}

// A partial read followed by EAGAIN fails with *out left NULL: write two
// bytes, leave the nonblocking writer open, then request a larger capacity.
RFB_TEST(secret_fd, read__partial_then_eagain__fails_with_null_out)
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

static long read_username_bytes(const uint8_t *data, size_t length,
                                char **out)
{
    int fds[2];
    if (pipe(fds) != 0) {
        return -2;
    }
    if (write_all_close(fds[1], data, length) != 0) {
        (void)close(fds[0]);
        return -2;
    }
    const long result = farsee_read_fd_username(fds[0], out);
    (void)close(fds[0]);
    return result;
}

RFB_TEST(secret_fd, username__lengths_one_and_234_accept_raw_lf_and_crlf)
{
    uint8_t logical[234];
    memset(logical, 'u', sizeof logical);
    for (size_t logical_length = 1u; logical_length <= sizeof logical;
         logical_length += sizeof logical - 1u) {
        for (unsigned terminator = 0u; terminator < 3u; terminator++) {
            uint8_t wire[236];
            memcpy(wire, logical, logical_length);
            size_t wire_length = logical_length;
            if (terminator == 1u) {
                wire[wire_length++] = '\n';
            } else if (terminator == 2u) {
                wire[wire_length++] = '\r';
                wire[wire_length++] = '\n';
            }
            char *out = (char *)(uintptr_t)1u;
            RFB_CHECK_EQ_INT(read_username_bytes(wire, wire_length, &out),
                             (long)logical_length);
            RFB_CHECK(out != NULL);
            RFB_CHECK_EQ_INT(memcmp(out, logical, logical_length), 0);
            RFB_CHECK(out[logical_length] == '\0');
            rfb_secret_wipe_free(out, FARSEE_USERNAME_FD_CAP);
        }
    }
}

RFB_TEST(secret_fd, username__preserves_exact_non_nul_bytes_and_length)
{
    static const uint8_t wire[] = {0x80u, 0xffu, 'x', '\n'};
    char *out = NULL;
    RFB_CHECK_EQ_INT(read_username_bytes(wire, sizeof wire, &out), 3);
    static const uint8_t expected[] = {0x80u, 0xffu, 'x'};
    RFB_CHECK_EQ_INT(memcmp(out, expected, sizeof expected), 0);
    RFB_CHECK(out[sizeof expected] == '\0');
    rfb_secret_wipe_free(out, FARSEE_USERNAME_FD_CAP);
}

RFB_TEST(secret_fd, username__rejects_empty_overlong_and_noncanonical_framing)
{
    static const uint8_t empty[] = {0u};
    uint8_t overlong[235];
    memset(overlong, 'u', sizeof overlong);
    uint8_t after_max_terminator[236];
    memset(after_max_terminator, 'u', 234u);
    after_max_terminator[234] = '\n';
    after_max_terminator[235] = 'x';
    static const uint8_t only_lf[] = {'\n'};
    static const uint8_t only_crlf[] = {'\r', '\n'};
    static const uint8_t nul_first[] = {0u, 'a'};
    static const uint8_t nul_middle[] = {'a', 0u, 'b'};
    static const uint8_t nul_last[] = {'a', 0u};
    static const uint8_t internal_lf[] = {'a', '\n', 'b'};
    static const uint8_t internal_cr[] = {'a', '\r', 'b'};
    static const uint8_t bare_cr[] = {'a', '\r'};
    static const uint8_t repeated_lf[] = {'a', '\n', '\n'};
    static const uint8_t repeated_crlf[] = {'a', '\r', '\n', '\r', '\n'};
    static const uint8_t bytes_after_lf[] = {'a', '\n', 'b'};
    const struct {
        const uint8_t *data;
        size_t length;
    } cases[] = {
        {empty, 0u}, {only_lf, sizeof only_lf},
        {only_crlf, sizeof only_crlf}, {overlong, sizeof overlong},
        {after_max_terminator, sizeof after_max_terminator},
        {nul_first, sizeof nul_first}, {nul_middle, sizeof nul_middle},
        {nul_last, sizeof nul_last}, {internal_lf, sizeof internal_lf},
        {internal_cr, sizeof internal_cr}, {bare_cr, sizeof bare_cr},
        {repeated_lf, sizeof repeated_lf},
        {repeated_crlf, sizeof repeated_crlf},
        {bytes_after_lf, sizeof bytes_after_lf},
    };
    for (size_t i = 0u; i < sizeof cases / sizeof cases[0]; i++) {
        char *out = (char *)(uintptr_t)1u;
        RFB_CHECK_EQ_INT(read_username_bytes(
                             cases[i].data, cases[i].length, &out),
                         -1);
        RFB_CHECK(out == NULL);
    }
}

RFB_TEST(secret_fd, username__rejects_closed_eagain_and_partial_eagain)
{
    char *out = (char *)(uintptr_t)1u;
    RFB_CHECK_EQ_INT(farsee_read_fd_username(-1, &out), -1);
    RFB_CHECK(out == NULL);

    int fds[2];
    RFB_CHECK(pipe(fds) == 0);
    const int closed_fd = fds[0];
    RFB_CHECK(close(fds[0]) == 0);
    RFB_CHECK(close(fds[1]) == 0);
    out = (char *)(uintptr_t)1u;
    RFB_CHECK_EQ_INT(farsee_read_fd_username(closed_fd, &out), -1);
    RFB_CHECK(out == NULL);

    RFB_CHECK(pipe(fds) == 0);
    int flags = fcntl(fds[0], F_GETFL);
    RFB_CHECK(flags >= 0);
    RFB_CHECK(fcntl(fds[0], F_SETFL, flags | O_NONBLOCK) == 0);
    out = (char *)(uintptr_t)1u;
    RFB_CHECK_EQ_INT(farsee_read_fd_username(fds[0], &out), -1);
    RFB_CHECK(out == NULL);
    RFB_CHECK(write(fds[1], "partial", 7u) == 7);
    out = (char *)(uintptr_t)1u;
    RFB_CHECK_EQ_INT(farsee_read_fd_username(fds[0], &out), -1);
    RFB_CHECK(out == NULL);
    (void)close(fds[1]);
    (void)close(fds[0]);
}
