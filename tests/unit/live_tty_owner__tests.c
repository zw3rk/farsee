// SPDX-License-Identifier: Apache-2.0
//
// Private live-session input descriptor ownership.

#include "rfb_test.h"
#include "app/live_shell_tty_guard.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <string.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#if defined(__APPLE__)
#  include <util.h>
#elif defined(__linux__)
#  include <pty.h>
#endif

static int stdin_fallback_child(void)
{
    int master = -1;
    int slave = -1;
    int output[2] = {-1, -1};
    if (openpty(&master, &slave, NULL, NULL, NULL) != 0 ||
        pipe(output) != 0 || dup2(slave, STDIN_FILENO) < 0 ||
        dup2(output[1], STDOUT_FILENO) < 0) {
        return 2;
    }
    close(slave);
    close(output[0]);
    close(output[1]);

    for (unsigned cycle = 0u; cycle < 2u; cycle++) {
        int initial = fcntl(STDIN_FILENO, F_GETFL, 0);
        if (initial < 0) {
            return 3;
        }
        if (cycle == 0u) {
            initial &= ~O_NONBLOCK;
        } else {
            initial |= O_NONBLOCK;
        }
        if (fcntl(STDIN_FILENO, F_SETFL, initial) != 0) {
            return 4;
        }
        initial = fcntl(STDIN_FILENO, F_GETFL, 0);

        int input_fd = -1;
        bool owned = true;
        if (!farsee_live_shell_tty_open_input(&input_fd, &owned) ||
            input_fd != STDIN_FILENO || owned) {
            return 5;
        }
        const int armed = fcntl(STDIN_FILENO, F_GETFL, 0);
        if (armed < 0 || (armed & O_NONBLOCK) == 0) {
            return 6;
        }
        farsee_live_shell_tty_guard_restore();
        if (fcntl(STDIN_FILENO, F_GETFL, 0) != initial) {
            return 7;
        }
        farsee_live_shell_tty_close_input(input_fd, owned);
        if (fcntl(STDIN_FILENO, F_GETFL, 0) != initial) {
            return 8;
        }
    }
    close(master);
    return 0;
}

RFB_TEST(live_tty_owner, stdin_fallback__guard_restores_exact_flags_twice)
{
    const pid_t child = fork();
    RFB_CHECK(child >= 0);
    if (child == 0) {
        _exit(stdin_fallback_child());
    }
    int status = 0;
    RFB_CHECK(waitpid(child, &status, 0) == child);
    RFB_CHECK(WIFEXITED(status));
    RFB_CHECK_EQ_INT(WIFEXITED(status) ? WEXITSTATUS(status) : -1, 0);
}

RFB_TEST(live_tty_owner, input_helpers__reject_null_and_label_ownership)
{
    int fd = 99;
    bool owned = true;
    RFB_CHECK(!farsee_live_shell_tty_open_input(NULL, &owned));
    RFB_CHECK(!farsee_live_shell_tty_open_input(&fd, NULL));
    RFB_CHECK(strcmp(farsee_live_shell_tty_input_label(
                         STDIN_FILENO, false), "stdin") == 0);
    RFB_CHECK(strcmp(farsee_live_shell_tty_input_label(
                         -1, false), "fd") == 0);
    RFB_CHECK(strcmp(farsee_live_shell_tty_input_label(
                         -1, true), "/dev/tty") == 0);
}

RFB_TEST(live_tty_owner, owned_close__does_not_change_standard_stream_flags)
{
    int descriptors[2] = {-1, -1};
    RFB_CHECK(pipe(descriptors) == 0);
    if (descriptors[0] < 0 || descriptors[1] < 0) {
        return;
    }
    const int stdin_flags = fcntl(STDIN_FILENO, F_GETFL, 0);
    const int stdout_flags = fcntl(STDOUT_FILENO, F_GETFL, 0);
    farsee_live_shell_tty_close_input(descriptors[0], true);
    errno = 0;
    RFB_CHECK(fcntl(descriptors[0], F_GETFL, 0) < 0 && errno == EBADF);
    RFB_CHECK_EQ_INT(fcntl(STDIN_FILENO, F_GETFL, 0), stdin_flags);
    RFB_CHECK_EQ_INT(fcntl(STDOUT_FILENO, F_GETFL, 0), stdout_flags);
    farsee_live_shell_tty_close_input(-1, true);
    farsee_live_shell_tty_close_input(-1, false);
    close(descriptors[1]);
}
