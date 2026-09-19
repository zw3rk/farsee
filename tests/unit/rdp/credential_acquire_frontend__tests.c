// SPDX-License-Identifier: Apache-2.0
//
// RDP frontend credential-descriptor ownership tests.

#include "app/rdp_live.h"
#include "tests/test_framework/rfb_test.h"

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

static int empty_password_pipe(void)
{
    int descriptors[2] = {-1, -1};
    if (pipe(descriptors) != 0) {
        return -1;
    }
    if (close(descriptors[1]) != 0) {
        (void)close(descriptors[0]);
        return -1;
    }
    return descriptors[0];
}

static bool queued_password_pipe(int *owned_fd, int *observer_fd)
{
    int descriptors[2] = {-1, -1};
    if (owned_fd == NULL || observer_fd == NULL || pipe(descriptors) != 0) {
        return false;
    }
    const char byte = 'p';
    if (write(descriptors[1], &byte, 1u) != 1) {
        (void)close(descriptors[0]);
        (void)close(descriptors[1]);
        return false;
    }
    const int duplicate = dup(descriptors[0]);
    if (duplicate < 0 || close(descriptors[1]) != 0) {
        if (duplicate >= 0) {
            (void)close(duplicate);
        }
        (void)close(descriptors[0]);
        return false;
    }
    *owned_fd = descriptors[0];
    *observer_fd = duplicate;
    return true;
}

static void check_owned_fd_closed_password_unread(int owned_fd,
                                                   int observer_fd)
{
    errno = 0;
    RFB_CHECK_EQ_INT(fcntl(owned_fd, F_GETFD), -1);
    RFB_CHECK_EQ_INT(errno, EBADF);
    char byte = '\0';
    RFB_CHECK_EQ_INT(read(observer_fd, &byte, 1u), 1);
    RFB_CHECK_EQ_INT(byte, 'p');
    RFB_CHECK_EQ_INT(close(observer_fd), 0);
}

RFB_TEST(credential_acquire, rdp_frontend__missing_user_closes_password_fd)
{
    const int fd = empty_password_pipe();
    RFB_CHECK(fd >= 0);

    RFB_CHECK_EQ_INT(
        farsee_run_rdp("host", 3389u, NULL, NULL, NULL, fd, 0u, 0u,
                       "null", 0u, true, false, RDP_LIBLOG_OFF, NULL),
        2);
    errno = 0;
    RFB_CHECK_EQ_INT(fcntl(fd, F_GETFD), -1);
    RFB_CHECK_EQ_INT(errno, EBADF);
}

RFB_TEST(credential_acquire, rdp_frontend__invalid_host_closes_password_fd)
{
    const int fd = empty_password_pipe();
    RFB_CHECK(fd >= 0);

    RFB_CHECK_EQ_INT(
        farsee_run_rdp("", 3389u, "user", NULL, NULL, fd, 0u, 0u,
                       "null", 0u, true, false, RDP_LIBLOG_OFF, NULL),
        2);
    errno = 0;
    RFB_CHECK_EQ_INT(fcntl(fd, F_GETFD), -1);
    RFB_CHECK_EQ_INT(errno, EBADF);
}

RFB_TEST(credential_acquire, rdp_frontend__wlog_policy_closes_password_fd)
{
    int fd = -1;
    int observer_fd = -1;
    RFB_CHECK(queued_password_pipe(&fd, &observer_fd));

#ifdef FARSEE_ENABLE_WLOG_DIAGNOSTICS
    RFB_CHECK(rdp_freerdp_set_library_log_level(RDP_LIBLOG_INFO));
    RFB_CHECK_EQ_INT(close(fd), 0);
    RFB_CHECK_EQ_INT(close(observer_fd), 0);
#else
    RFB_CHECK_EQ_INT(
        farsee_run_rdp("host", 3389u, "user", NULL, NULL, fd, 0u, 0u,
                       "null", 0u, true, false, RDP_LIBLOG_INFO, NULL),
        2);
    check_owned_fd_closed_password_unread(fd, observer_fd);
#endif
}

RFB_TEST(credential_acquire, rdp_frontend__invalid_wlog_rejects_before_password)
{
    int fd = -1;
    int observer_fd = -1;
    RFB_CHECK(queued_password_pipe(&fd, &observer_fd));

    RFB_CHECK_EQ_INT(
        farsee_run_rdp("host", 3389u, "user", NULL, NULL, fd, 0u, 0u,
                       "null", 0u, true, false, (rdp_liblog_level)999, NULL),
        2);
    check_owned_fd_closed_password_unread(fd, observer_fd);
}
