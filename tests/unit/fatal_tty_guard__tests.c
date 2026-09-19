// SPDX-License-Identifier: Apache-2.0
//
// atexit cannot run on fatal-signal death. tty_guard_arm installs SA_RESETHAND
// restorers whose pre-composed byte sequence is written before re-raising.
//
// Harness: the child arms the guard against a pipe (attrs_saved=false),
// then dereferences NULL. The fatal handler's write lands in the pipe; the
// parent asserts the sequence and the honest SIGSEGV wait status. No pty
// is involved; normal teardown owns the non-async-safe termios restoration.

#include "rfb_test.h"
#include "app/live_shell.h"
#include "app/live_shell_tty_guard.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#if defined(__APPLE__)
#  include <util.h>
#elif defined(__linux__)
#  include <pty.h>
#endif

RFB_TEST(fatal_tty_guard, sigsegv_mid_session__restore_seq_written_and_dies)
{
    int pfd[2];
    RFB_CHECK(pipe(pfd) == 0);

    pid_t kid = fork();
    RFB_CHECK(kid >= 0);
    if (kid == 0) {
        close(pfd[0]);
        farsee_live_shell_tty_guard_arm(pfd[1], false, NULL, true, true);
        *(volatile int *)0 = 0;  // SIGSEGV
        _exit(1);                // unreachable
    }
    close(pfd[1]);

    int status = 0;
    RFB_CHECK(waitpid(kid, &status, 0) == kid);
    {
        char msg[80];
        (void)snprintf(msg, sizeof msg,
                       "raw=0x%x exited=%d code=%d stopped=%d",
                       status, WIFEXITED(status), WEXITSTATUS(status),
                       WIFSTOPPED(status));
        RFB_CHECK_MSG(WIFSIGNALED(status), msg);
    }
    RFB_CHECK_EQ_INT(WTERMSIG(status), SIGSEGV);

    // Bounded read of whatever the fatal handler wrote before dying.
    char buf[96];
    size_t have = 0;
    int left = 5000;
    while (left > 0 && have < sizeof buf) {
        struct pollfd p;
        p.fd = pfd[0];
        p.events = POLLIN;
        p.revents = 0;
        int pr = poll(&p, 1, 50);
        if (pr < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (pr == 0) {
            left -= 50;
            continue;
        }
        ssize_t n = read(pfd[0], buf + have, sizeof buf - have);
        if (n <= 0) {
            break;
        }
        have += (size_t)n;
    }
    close(pfd[0]);

    // The pre-composed sequence ends with cursor-show + reset (10 bytes);
    // the mouse-disable prefix comes from the SGR helper.
    RFB_CHECK(have >= 10u);
    if (memcmp(buf + have - 10u, "\033[?25h\033[0m", 10) != 0) {
        static char msg[3 * 96 + 24];
        int off = snprintf(msg, 16, "n=%zu ", have);
        for (size_t i = 0; i < have && off < (int)sizeof msg - 4; i++) {
            off += snprintf(msg + off, 4, "%02x ",
                            (unsigned)(uint8_t)buf[i]);
        }
        msg[off > 0 ? off - 1 : 0] = '\0';
        RFB_CHECK_MSG(false, msg);
    }
}

RFB_TEST(fatal_tty_guard, disarm_then_fd_reuse__fatal_signal_writes_nothing)
{
    int old_pipe[2];
    int reused_pipe[2];
    RFB_CHECK(pipe(old_pipe) == 0);
    RFB_CHECK(pipe(reused_pipe) == 0);
    pid_t kid = fork();
    RFB_CHECK(kid >= 0);
    if (kid == 0) {
        close(old_pipe[0]);
        close(reused_pipe[0]);
        int old_fd = old_pipe[1];
        farsee_live_shell_tty_guard_arm(old_fd, false, NULL, true, true);
        farsee_live_shell_tty_guard_restore();
        close(old_fd);
        if (dup2(reused_pipe[1], old_fd) < 0) {
            _exit(2);
        }
        if (reused_pipe[1] != old_fd) {
            close(reused_pipe[1]);
        }
        (void)raise(SIGQUIT);
        _exit(3);
    }
    close(old_pipe[0]);
    close(old_pipe[1]);
    close(reused_pipe[1]);
    int status = 0;
    RFB_CHECK(waitpid(kid, &status, 0) == kid);
    RFB_CHECK(WIFSIGNALED(status));
    RFB_CHECK_EQ_INT(WTERMSIG(status), SIGQUIT);
    char byte = 0;
    RFB_CHECK_EQ_INT((int)read(reused_pipe[0], &byte, 1u), 0);
    close(reused_pipe[0]);
}

static volatile sig_atomic_t prior_fatal_seen;

static void prior_fatal_handler(int sig)
{
    prior_fatal_seen = sig;
}

RFB_TEST(fatal_tty_guard, disarm__restores_prior_signal_disposition)
{
    int pfd[2];
    RFB_CHECK(pipe(pfd) == 0);
    pid_t kid = fork();
    RFB_CHECK(kid >= 0);
    if (kid == 0) {
        static const int signals[] = {SIGSEGV, SIGBUS, SIGFPE, SIGQUIT};
        close(pfd[0]);
        struct sigaction sa;
        memset(&sa, 0, sizeof sa);
        sa.sa_handler = prior_fatal_handler;
        sigemptyset(&sa.sa_mask);
        for (size_t i = 0u; i < sizeof signals / sizeof signals[0]; i++) {
            if (sigaction(signals[i], &sa, NULL) != 0) {
                _exit(2);
            }
        }
        prior_fatal_seen = 0;
        farsee_live_shell_tty_guard_arm(pfd[1], false, NULL, false, false);
        farsee_live_shell_tty_guard_restore();
        for (size_t i = 0u; i < sizeof signals / sizeof signals[0]; i++) {
            struct sigaction current;
            memset(&current, 0, sizeof current);
            if (sigaction(signals[i], NULL, &current) != 0 ||
                current.sa_handler != prior_fatal_handler) {
                _exit(3);
            }
        }
        (void)raise(SIGQUIT);
        _exit(prior_fatal_seen == SIGQUIT ? 0 : 4);
    }
    close(pfd[0]);
    close(pfd[1]);
    int status = 0;
    RFB_CHECK(waitpid(kid, &status, 0) == kid);
    RFB_CHECK(WIFEXITED(status));
    RFB_CHECK_EQ_INT(WEXITSTATUS(status), 0);
}

static bool open_raw_pty(int *master, int *slave,
                         struct termios *saved, struct termios *raw)
{
    if (openpty(master, slave, NULL, NULL, NULL) != 0) {
        return false;
    }
    if (tcgetattr(*slave, saved) != 0) {
        close(*master);
        close(*slave);
        return false;
    }
    saved->c_lflag |= ECHO;
    if (tcsetattr(*slave, TCSANOW, saved) != 0) {
        close(*master);
        close(*slave);
        return false;
    }
    *raw = *saved;
    raw->c_iflag &= (tcflag_t)~(IGNBRK | BRKINT | PARMRK | ISTRIP |
                                INLCR | IGNCR | ICRNL | IXON);
    raw->c_oflag &= (tcflag_t)~OPOST;
    raw->c_lflag &= (tcflag_t)~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
    raw->c_cflag &= (tcflag_t)~(CSIZE | PARENB);
    raw->c_cflag |= CS8;
    if (tcsetattr(*slave, TCSANOW, raw) != 0) {
        close(*master);
        close(*slave);
        return false;
    }
    const int flags = fcntl(*slave, F_GETFL, 0);
    if (flags < 0 || fcntl(*slave, F_SETFL, flags | O_NONBLOCK) != 0) {
        close(*master);
        close(*slave);
        return false;
    }
    return true;
}

static pid_t spawn_master_drainer(int master, int slave, bool require_data)
{
    const pid_t drainer = fork();
    if (drainer != 0) {
        return drainer;
    }

    close(slave);
    bool received = false;
    for (;;) {
        struct pollfd pfd;
        memset(&pfd, 0, sizeof pfd);
        pfd.fd = master;
        pfd.events = POLLIN | POLLHUP;
        int ready;
        do {
            ready = poll(&pfd, 1, 1000);
        } while (ready < 0 && errno == EINTR);
        if (ready <= 0) {
            _exit(2);
        }

        uint8_t output[64];
        const ssize_t count = read(master, output, sizeof output);
        if (count > 0) {
            received = true;
            continue;
        }
        if (count == 0 || (count < 0 && errno == EIO)) {
            break;
        }
        if (count < 0 && errno == EINTR) {
            continue;
        }
        _exit(3);
    }
    close(master);
    _exit(received || !require_data ? 0 : 1);
}

static int attr_note_child(bool matching_fd)
{
    int master = -1;
    int slave = -1;
    struct termios saved;
    struct termios raw;
    if (!open_raw_pty(&master, &slave, &saved, &raw)) {
        return 2;
    }
    struct termios observed;
    farsee_live_shell_tty_guard_arm(slave, true, &saved, false, false);
    farsee_live_shell_tty_guard_update_attrs_for_fd(
        matching_fd ? slave : master, NULL);
    pid_t drainer = spawn_master_drainer(master, slave, !matching_fd);
    if (drainer < 0) {
        farsee_live_shell_tty_guard_restore();
        close(master);
        close(slave);
        return 3;
    }
    farsee_live_shell_tty_guard_restore();
    const bool attrs_ok = tcgetattr(slave, &observed) == 0 &&
                          (((observed.c_lflag & ECHO) != 0) != matching_fd);
    close(slave);
    int status = 0;
    const bool drainer_ok = waitpid(drainer, &status, 0) == drainer &&
                            WIFEXITED(status) && WEXITSTATUS(status) == 0;
    close(master);
    return attrs_ok && drainer_ok ? 0 : 4;
}

RFB_TEST(fatal_tty_guard, attr_note__only_matching_fd_changes_ownership)
{
    for (int matching_fd = 0; matching_fd <= 1; matching_fd++) {
        const pid_t kid = fork();
        RFB_CHECK(kid >= 0);
        if (kid < 0) {
            return;
        }
        if (kid == 0) {
            _exit(attr_note_child(matching_fd != 0));
        }
        int status = 0;
        RFB_CHECK(waitpid(kid, &status, 0) == kid);
        RFB_CHECK(WIFEXITED(status));
        RFB_CHECK_EQ_INT(WIFEXITED(status) ? WEXITSTATUS(status) : -1, 0);
    }
}

static bool same_termios(const struct termios *a, const struct termios *b)
{
    return a->c_iflag == b->c_iflag && a->c_oflag == b->c_oflag &&
           a->c_cflag == b->c_cflag && a->c_lflag == b->c_lflag &&
           memcmp(a->c_cc, b->c_cc, sizeof a->c_cc) == 0;
}

static int refreshed_attrs_child(void)
{
    int master = -1;
    int slave = -1;
    struct termios first_cooked;
    struct termios first_raw;
    if (!open_raw_pty(&master, &slave, &first_cooked, &first_raw)) {
        return 2;
    }
    farsee_live_shell_tty_guard_arm(
        slave, true, &first_cooked, false, false);
    farsee_live_shell_tty_guard_update_attrs_for_fd(slave, NULL);

    struct termios latest_cooked = first_cooked;
    latest_cooked.c_lflag ^= (tcflag_t)ECHONL;
    latest_cooked.c_iflag ^= (tcflag_t)ICRNL;
    if (tcsetattr(slave, TCSANOW, &latest_cooked) != 0) {
        return 3;
    }
    struct termios latest_raw = latest_cooked;
    latest_raw.c_lflag &= (tcflag_t)~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
    latest_raw.c_iflag &= (tcflag_t)~(IXON | ICRNL);
    if (tcsetattr(slave, TCSANOW, &latest_raw) != 0) {
        return 4;
    }
    farsee_live_shell_tty_guard_update_attrs_for_fd(
        slave, &latest_cooked);
    pid_t drainer = spawn_master_drainer(master, slave, true);
    if (drainer < 0) {
        return 5;
    }
    farsee_live_shell_tty_guard_restore();
    struct termios observed;
    const bool restored = tcgetattr(slave, &observed) == 0 &&
                          same_termios(&observed, &latest_cooked);
    close(slave);
    int status = 0;
    const bool drained = waitpid(drainer, &status, 0) == drainer &&
                         WIFEXITED(status) && WEXITSTATUS(status) == 0;
    close(master);
    return restored && drained ? 0 : 6;
}

RFB_TEST(fatal_tty_guard, resumed_attrs__restore_latest_cooked_snapshot)
{
    const pid_t child = fork();
    RFB_CHECK(child >= 0);
    if (child == 0) {
        _exit(refreshed_attrs_child());
    }
    int status = 0;
    RFB_CHECK(waitpid(child, &status, 0) == child);
    RFB_CHECK(WIFEXITED(status));
    RFB_CHECK_EQ_INT(WIFEXITED(status) ? WEXITSTATUS(status) : -1, 0);
}
