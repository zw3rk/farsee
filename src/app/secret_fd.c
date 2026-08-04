// SPDX-License-Identifier: Apache-2.0
//
// Shared password-fd reader (P0-N2). See farsee/secret_fd.h.

#include "farsee/secret_fd.h"
#include "farsee/secret.h"

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

long farsee_read_fd_secret(int fd, char **out, size_t cap)
{
    if (out == NULL) {
        return -1;
    }
    *out = NULL;
    if (fd < 0 || cap < 1u) {
        return -1;
    }

    char *buf = (char *)malloc(cap);
    if (buf == NULL) {
        return -1;
    }

    size_t total = 0;
    while (total + 1u < cap) {
        ssize_t n = read(fd, buf + total, cap - 1u - total);
        if (n > 0) {
            total += (size_t)n;
            continue;
        }
        if (n == 0) {
            break; /* EOF */
        }
        /* n == -1 */
        if (errno == EINTR) {
            continue;
        }
        /* EAGAIN / EWOULDBLOCK or hard error — fail closed, never spin. */
        rfb_secret_zero(buf, cap);
        free(buf);
        return -1;
    }

    /* Capacity exhausted before EOF: probe one more byte. Any extra data
     * means the secret does not fit — fail closed rather than truncate. */
    if (total + 1u >= cap) {
        char probe = 0;
        for (;;) {
            ssize_t n = read(fd, &probe, 1);
            if (n < 0 && errno == EINTR) {
                continue;
            }
            if (n > 0) {
                rfb_secret_zero(buf, cap);
                rfb_secret_zero(&probe, sizeof probe);
                free(buf);
                return -1;
            }
            break; /* EOF or hard empty (EAGAIN): treat as full, no more data */
        }
        rfb_secret_zero(&probe, sizeof probe);
    }

    while (total > 0u &&
           (buf[total - 1u] == '\n' || buf[total - 1u] == '\r')) {
        total--;
    }
    buf[total] = '\0';
    *out = buf;
    return (long)total;
}
