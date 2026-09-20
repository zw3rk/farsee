// SPDX-License-Identifier: Apache-2.0
//
// Shared password-acquisition ownership and policy tests.

#include "farsee/credential_acquire.h"
#include "app/rfb_live.h"
#include "tests/test_framework/rfb_test.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static bool write_all(int fd, const uint8_t *data, size_t length)
{
    size_t offset = 0u;
    while (offset < length) {
        const ssize_t count = write(fd, data + offset, length - offset);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            return false;
        }
        offset += (size_t)count;
    }
    return true;
}

static int password_pipe(const uint8_t *data, size_t length)
{
    int descriptors[2] = {-1, -1};
    if (pipe(descriptors) != 0) {
        return -1;
    }
    if (!write_all(descriptors[1], data, length) ||
        close(descriptors[1]) != 0) {
        (void)close(descriptors[0]);
        (void)close(descriptors[1]);
        return -1;
    }
    return descriptors[0];
}

RFB_TEST(credential_acquire, fd__long_password_is_exact_and_fd_is_closed)
{
    static const uint8_t password[] = "eight-8:rdp-tail";
    const int fd = password_pipe(password, sizeof password - 1u);
    RFB_CHECK(fd >= 0);
    farsee_secret acquired = {0};
    int terminal_signal = -1;
    const farsee_credential_acquire_config config = {
        .password_fd = fd,
        .password_inline = NULL,
        .required = true,
    };

    RFB_CHECK_EQ_INT(farsee_credential_acquire_password(
                         &config, &acquired, &terminal_signal),
                     FARSEE_CREDENTIAL_ACQUIRE_OK);
    RFB_CHECK_EQ_INT(terminal_signal, 0);
    RFB_CHECK_EQ_UINT(acquired.len, sizeof password - 1u);
    RFB_CHECK_EQ_UINT(acquired.cap, FARSEE_CREDENTIAL_PASSWORD_MAX + 1u);
    RFB_CHECK_MEM_EQ(acquired.data, password, sizeof password - 1u);
    errno = 0;
    RFB_CHECK_EQ_INT(fcntl(fd, F_GETFD), -1);
    RFB_CHECK_EQ_INT(errno, EBADF);
    farsee_secret_destroy(&acquired);
}

RFB_TEST(credential_acquire, required__empty_fd_is_rejected_and_released)
{
    const int fd = password_pipe(NULL, 0u);
    RFB_CHECK(fd >= 0);
    farsee_secret acquired = {0};
    int terminal_signal = -1;
    const farsee_credential_acquire_config config = {
        .password_fd = fd,
        .password_inline = NULL,
        .required = true,
    };

    RFB_CHECK_EQ_INT(farsee_credential_acquire_password(
                         &config, &acquired, &terminal_signal),
                     FARSEE_CREDENTIAL_ACQUIRE_EMPTY);
    RFB_CHECK(acquired.data == NULL);
    RFB_CHECK_EQ_UINT(acquired.len, 0u);
    RFB_CHECK_EQ_UINT(acquired.cap, 0u);
    RFB_CHECK_EQ_INT(terminal_signal, 0);
    errno = 0;
    RFB_CHECK_EQ_INT(fcntl(fd, F_GETFD), -1);
    RFB_CHECK_EQ_INT(errno, EBADF);
}

RFB_TEST(credential_acquire, optional__no_source_returns_empty_secret)
{
    farsee_secret acquired = {0};
    int terminal_signal = -1;
    const farsee_credential_acquire_config config = {
        .password_fd = -1,
        .password_inline = NULL,
        .required = false,
    };

    RFB_CHECK_EQ_INT(farsee_credential_acquire_password(
                         &config, &acquired, &terminal_signal),
                     FARSEE_CREDENTIAL_ACQUIRE_OK);
    RFB_CHECK(acquired.data == NULL);
    RFB_CHECK_EQ_UINT(acquired.len, 0u);
    RFB_CHECK_EQ_UINT(acquired.cap, 0u);
    RFB_CHECK_EQ_INT(terminal_signal, 0);
}

RFB_TEST(credential_acquire, optional__empty_selected_source_is_owned)
{
    const int fd = password_pipe(NULL, 0u);
    RFB_CHECK(fd >= 0);
    farsee_secret acquired = {0};
    int terminal_signal = -1;
    const farsee_credential_acquire_config config = {
        .password_fd = fd,
        .password_inline = NULL,
        .required = false,
    };

    RFB_CHECK_EQ_INT(farsee_credential_acquire_password(
                         &config, &acquired, &terminal_signal),
                     FARSEE_CREDENTIAL_ACQUIRE_OK);
    RFB_CHECK(acquired.data != NULL);
    RFB_CHECK_EQ_UINT(acquired.len, 0u);
    RFB_CHECK_EQ_UINT(acquired.cap, FARSEE_CREDENTIAL_PASSWORD_MAX + 1u);
    RFB_CHECK_EQ_UINT(acquired.data[0], 0u);
    farsee_secret_destroy(&acquired);
}

RFB_TEST(credential_acquire, fd__password_over_capacity_fails_closed)
{
    uint8_t password[FARSEE_CREDENTIAL_PASSWORD_MAX + 1u];
    memset(password, 'x', sizeof password);
    const int fd = password_pipe(password, sizeof password);
    RFB_CHECK(fd >= 0);
    farsee_secret acquired = {0};
    int terminal_signal = -1;
    const farsee_credential_acquire_config config = {
        .password_fd = fd,
        .password_inline = NULL,
        .required = true,
    };

    RFB_CHECK_EQ_INT(farsee_credential_acquire_password(
                         &config, &acquired, &terminal_signal),
                     FARSEE_CREDENTIAL_ACQUIRE_INPUT_FAILED);
    RFB_CHECK(acquired.data == NULL);
    RFB_CHECK_EQ_UINT(acquired.len, 0u);
    RFB_CHECK_EQ_UINT(acquired.cap, 0u);
    RFB_CHECK_EQ_INT(terminal_signal, 0);
}

RFB_TEST(credential_acquire, inline__long_password_is_not_vnc_truncated)
{
    static const char password[] = "01234567-full-protocol-secret";
    farsee_secret acquired = {0};
    int terminal_signal = -1;
    const farsee_credential_acquire_config config = {
        .password_fd = -1,
        .password_inline = password,
        .required = true,
    };

    RFB_CHECK_EQ_INT(farsee_credential_acquire_password(
                         &config, &acquired, &terminal_signal),
                     FARSEE_CREDENTIAL_ACQUIRE_OK);
    RFB_CHECK_EQ_UINT(acquired.len, sizeof password - 1u);
    RFB_CHECK_EQ_UINT(acquired.cap, sizeof password);
    RFB_CHECK_MEM_EQ(acquired.data, password, sizeof password);
    farsee_secret_destroy(&acquired);
}

RFB_TEST(credential_acquire, invalid_or_live_output__fails_without_mutation)
{
    farsee_secret acquired = {0};
    int terminal_signal = -1;
    RFB_CHECK_EQ_INT(farsee_credential_acquire_password(
                         NULL, &acquired, &terminal_signal),
                     FARSEE_CREDENTIAL_ACQUIRE_INVALID);
    RFB_CHECK(acquired.data == NULL);
    RFB_CHECK_EQ_INT(terminal_signal, 0);

    uint8_t sentinel = 0x5au;
    acquired.data = &sentinel;
    acquired.len = 1u;
    acquired.cap = 1u;
    const int fd = password_pipe(NULL, 0u);
    RFB_CHECK(fd >= 0);
    const farsee_credential_acquire_config config = {
        .password_fd = fd,
        .password_inline = "unused",
        .required = true,
    };
    RFB_CHECK_EQ_INT(farsee_credential_acquire_password(
                         &config, &acquired, &terminal_signal),
                     FARSEE_CREDENTIAL_ACQUIRE_INVALID);
    RFB_CHECK_EQ_INT(terminal_signal, 0);
    RFB_CHECK(acquired.data == &sentinel);
    RFB_CHECK_EQ_UINT(acquired.len, 1u);
    RFB_CHECK_EQ_UINT(sentinel, 0x5au);
    errno = 0;
    RFB_CHECK_EQ_INT(fcntl(fd, F_GETFD), -1);
    RFB_CHECK_EQ_INT(errno, EBADF);
}

RFB_TEST(credential_acquire, inline__over_capacity_fails_closed)
{
    char password[FARSEE_CREDENTIAL_PASSWORD_MAX + 2u];
    memset(password, 'x', sizeof password);
    password[sizeof password - 1u] = '\0';
    farsee_secret acquired = {0};
    int terminal_signal = -1;
    const farsee_credential_acquire_config config = {
        .password_fd = -1,
        .password_inline = password,
        .required = true,
    };

    RFB_CHECK_EQ_INT(farsee_credential_acquire_password(
                         &config, &acquired, &terminal_signal),
                     FARSEE_CREDENTIAL_ACQUIRE_TOO_LONG);
    RFB_CHECK(acquired.data == NULL);
    RFB_CHECK_EQ_INT(terminal_signal, 0);
}

RFB_TEST(credential_acquire, rfb_frontend__invalid_host_closes_password_fd)
{
    const int fd = password_pipe(NULL, 0u);
    const bool require_apple_type36 = false;
    RFB_CHECK(fd >= 0);

    RFB_CHECK_EQ_INT(
        farsee_run_rfb("", 5900u, NULL, fd, false, true, 0u,
                       FARSEE_AUTH_MODE_AUTO,
                       RFB_APPLE_POSTAUTH_CLEARTEXT, false, false, "null",
                       0u, true, false, NULL, 0u, 0u, false,
                       require_apple_type36),
        2);
    errno = 0;
    RFB_CHECK_EQ_INT(fcntl(fd, F_GETFD), -1);
    RFB_CHECK_EQ_INT(errno, EBADF);
}
