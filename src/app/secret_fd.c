// SPDX-License-Identifier: Apache-2.0
//
// Shared credential-fd readers. See farsee/secret_fd.h.

#include "farsee/secret_fd.h"
#include "farsee/secret.h"

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
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

    /* Capacity exhausted before EOF: probe one more byte. Extra data
     * means the secret does not fit — fail closed rather than truncate.
     * Only a CLEAN EOF may satisfy an exactly-full secret; a would-block
     * or hard error means the tail is unknown, and accepting the prefix
     * would silently truncate the secret. */
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
            if (n == 0) {
                break; /* clean EOF: exactly-full secret is valid */
            }
            /* EAGAIN / hard error: fail closed, never truncate. */
            rfb_secret_zero(buf, cap);
            rfb_secret_zero(&probe, sizeof probe);
            free(buf);
            return -1;
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

long farsee_read_fd_username(int fd, char **out)
{
    if (out == NULL) {
        return -1;
    }
    *out = NULL;
    if (fd < 0) {
        return -1;
    }

    char *buffer = (char *)calloc(FARSEE_USERNAME_FD_CAP, 1u);
    if (buffer == NULL) {
        return -1;
    }
    size_t length = 0u;
    bool saw_cr = false;
    bool terminated = false;
    uint8_t byte = 0u;
    for (;;) {
        const ssize_t count = read(fd, &byte, 1u);
        if (count == 0) {
            if (length == 0u || saw_cr) {
                goto fail;
            }
            buffer[length] = '\0';
            rfb_secret_zero(&byte, sizeof byte);
            *out = buffer;
            return (long)length;
        }
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            goto fail;
        }
        if (terminated) {
            goto fail;
        }
        if (saw_cr) {
            if (byte != (uint8_t)'\n') {
                goto fail;
            }
            saw_cr = false;
            terminated = true;
            continue;
        }
        if (byte == 0u) {
            goto fail;
        }
        if (byte == (uint8_t)'\n') {
            terminated = true;
            continue;
        }
        if (byte == (uint8_t)'\r') {
            saw_cr = true;
            continue;
        }
        if (length >= FARSEE_USERNAME_FD_CAP - 1u) {
            goto fail;
        }
        buffer[length++] = (char)byte;
    }

fail:
    rfb_secret_zero(&byte, sizeof byte);
    rfb_secret_zero(buffer, FARSEE_USERNAME_FD_CAP);
    free(buffer);
    return -1;
}
