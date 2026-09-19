// SPDX-License-Identifier: Apache-2.0
//
// A terminal signal at the interactive password
// prompt must restore the tty from no-echo/non-canonical mode. The prompt runs
// before the session installs its own handlers, so it handles SIGINT locally.
//
// Harness per the project PTY rule: supervised pty whose slave is put in
// an explicitly configured state (ISIG on; the parent never writes ESC
// bytes), every master read poll-bounded so a dead child can never hang
// the runner, and master EOF/EIO breaks the loops. The prompt process is
// a fresh session leader with the pty as controlling tty. It verifies the
// RESTORED termios itself (before dying) and reports a result byte over a
// pipe — after a session leader's death macOS revokes the pty and the
// parent could no longer inspect termios post-mortem.

#include "rfb_test.h"
#include "app/credential_prompt_internal.h"
#include "farsee/credential_acquire.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#if defined(__APPLE__)
#  include <util.h>
#elif defined(__linux__)
#  include <pty.h>
#endif

// Deterministic slave state: echo+canonical+ISIG on, VMIN=0/VTIME=5. The
// prompt must clear ECHO|ECHONL|ICANON for its window and restore exactly
// this state afterwards (normal completion AND signal death).
static bool configure_probe_tty(int fd)
{
    struct termios st;
    if (tcgetattr(fd, &st) != 0) {
        return false;
    }
    st.c_lflag |= (tcflag_t)(ECHO | ECHONL | ICANON | ISIG);
    st.c_cc[VMIN] = 0;
    st.c_cc[VTIME] = 5;
    return tcsetattr(fd, TCSANOW, &st) == 0;
}

// Bounded read from the master until `needle` is seen, EOF/EIO, timeout.
static bool read_until(int master, const char *needle, int timeout_ms)
{
    const size_t need = strlen(needle);
    char buf[128];
    size_t have = 0;
    int left = timeout_ms;
    while (left > 0 && have < sizeof buf) {
        struct pollfd pfd;
        pfd.fd = master;
        pfd.events = POLLIN;
        pfd.revents = 0;
        int pr = poll(&pfd, 1, 50);
        if (pr < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        if (pr == 0) {
            left -= 50;
            continue;
        }
        ssize_t n = read(master, buf + have, sizeof buf - have);
        if (n <= 0) {
            return false;  // EOF / EIO: prompt process died before banner
        }
        have += (size_t)n;
        if (have >= need && memcmp(buf + have - need, needle, need) == 0) {
            return true;
        }
        if (have >= sizeof buf) {
            return false;
        }
    }
    return false;
}

// Bounded read of the kid's one-byte verification result.
static int read_result_byte(int fd)
{
    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    if (poll(&pfd, 1, 5000) != 1) {
        return -1;
    }
    uint8_t b = 0xFFu;
    ssize_t n = read(fd, &b, 1u);
    if (n != 1) {
        return -1;
    }
    return (int)b;
}

// Report-pipe fd, valid inside the kid after the parent closes its end.
static int g_kid_report_fd = -1;

// Fresh CLI-like process: default dispositions, empty mask, own session
// with the pty as controlling tty, own pgrp foreground (ISIG delivers to
// us), master closed.
static void kid_setup(int slave, int master)
{
    signal(SIGINT, SIG_DFL);
    signal(SIGTERM, SIG_DFL);
    signal(SIGHUP, SIG_DFL);
    sigset_t empty;
    sigemptyset(&empty);
    (void)sigprocmask(SIG_SETMASK, &empty, NULL);
    (void)setsid();
    (void)ioctl(slave, TIOCSCTTY, 0);
    (void)tcsetpgrp(slave, getpgrp());
    close(master);
}

// Kid-side verification of the RESTORED terminal state (the parent cannot
// do this after the kid dies: session-leader death revokes the pty).
// Returns 0 when every property holds, distinct codes otherwise.
static int kid_check_restored_termios(void)
{
    int tty = open("/dev/tty", O_RDONLY | O_NOCTTY);
    if (tty < 0) {
        return 1;
    }
    struct termios st;
    if (tcgetattr(tty, &st) != 0) {
        close(tty);
        return 2;
    }
    close(tty);
    if ((st.c_lflag & ECHO) == 0) {
        return 3;
    }
    if ((st.c_lflag & ICANON) == 0) {
        return 4;
    }
    if (st.c_cc[VMIN] != 0u) {
        return 5;
    }
    if (st.c_cc[VTIME] != 5u) {
        return 6;
    }
    return 0;
}

static void kid_report(int code)
{
    uint8_t b = (uint8_t)code;
    ssize_t w;
    do {
        w = write(g_kid_report_fd, &b, 1u);
    } while (w < 0 && errno == EINTR);
    (void)w;
}

static const char *kid_code_msg(int code)
{
    switch (code) {
    case 0:  return "kid verified restored termios";
    case 1:  return "kid: /dev/tty reopen failed";
    case 2:  return "kid: tcgetattr failed";
    case 3:  return "kid: ECHO not restored";
    case 4:  return "kid: ICANON not restored";
    case 5:  return "kid: VMIN not restored";
    case 6:  return "kid: VTIME not restored";
    case 10: return "kid: signal not reported by prompt";
    case 11: return "kid: reported signal is not SIGINT";
    case 20: return "kid: prompt failed on normal line input";
    case 21: return "kid: wrong secret captured";
    case 30: return "kid: cancelled prompt was accepted";
    case 31: return "kid: cancelled prompt reported a signal";
    case 32: return "kid: terminal close did not report SIGHUP";
    case 40: return "kid: partial signal installation was accepted";
    case 41: return "kid: signal installation rollback was incomplete";
    case 42: return "kid: partial signal failure reported a terminal signal";
    case 43: return "kid: overlong prompt did not return TOO_LONG";
    default: return "kid: unknown code";
    }
}

// Kid body for the signal case: prompt returns false after restoring;
// verify, report, then die honestly by SIGINT.
static void kid_prompt_sigint(void)
{
    farsee_secret password = {0};
    int sig = 0;
    const farsee_credential_acquire_config config = {
        .password_fd = -1,
        .password_inline = NULL,
        .required = true,
    };
    const farsee_credential_acquire_status status =
        farsee_credential_acquire_password(&config, &password, &sig);
    int code = 0;
    if (status == FARSEE_CREDENTIAL_ACQUIRE_OK) {
        code = 20;  // prompt must fail on the signal path
    } else if (status != FARSEE_CREDENTIAL_ACQUIRE_TERMINAL_SIGNAL ||
               sig == 0) {
        code = 10;
    } else if (sig != SIGINT) {
        code = 11;
    } else {
        code = kid_check_restored_termios();
    }
    farsee_secret_destroy(&password);
    kid_report(code);
    farsee_credential_reraise_terminal_signal(sig);
    _exit(1);
}

// Kid body for the normal-completion case: line entered, secret returned,
// termios restored.
static void kid_prompt_line(void)
{
    farsee_secret password = {0};
    int sig = 0;
    const farsee_credential_acquire_config config = {
        .password_fd = -1,
        .password_inline = NULL,
        .required = true,
    };
    const farsee_credential_acquire_status status =
        farsee_credential_acquire_password(&config, &password, &sig);
    int code = 0;
    if (status != FARSEE_CREDENTIAL_ACQUIRE_OK) {
        code = 20;
    } else if (password.data == NULL || password.len != 2u ||
               password.data[0] != (uint8_t)'p' ||
               password.data[1] != (uint8_t)'w') {
        code = 21;
    } else {
        code = kid_check_restored_termios();
    }
    farsee_secret_destroy(&password);
    kid_report(code);
    _exit(code == 0 ? 0 : 7);
}

static void kid_prompt_cancel(void)
{
    farsee_secret password = {0};
    int sig = 0;
    const farsee_credential_acquire_config config = {
        .password_fd = -1,
        .password_inline = NULL,
        .required = true,
    };
    const farsee_credential_acquire_status status =
        farsee_credential_acquire_password(&config, &password, &sig);
    int code = 0;
    if (status == FARSEE_CREDENTIAL_ACQUIRE_OK) {
        code = 30;
    } else if (sig != 0) {
        code = 31;
    } else {
        code = kid_check_restored_termios();
    }
    farsee_secret_destroy(&password);
    kid_report(code);
    _exit(code == 0 ? 0 : 7);
}

static void kid_prompt_overlong(void)
{
    farsee_secret password = {0};
    int sig = 0;
    const farsee_credential_acquire_config config = {
        .password_fd = -1,
        .password_inline = NULL,
        .required = true,
    };
    const farsee_credential_acquire_status status =
        farsee_credential_acquire_password(&config, &password, &sig);
    int code = 0;
    if (status != FARSEE_CREDENTIAL_ACQUIRE_TOO_LONG || sig != 0 ||
        password.data != NULL || password.len != 0u || password.cap != 0u) {
        code = 43;
    } else {
        code = kid_check_restored_termios();
    }
    farsee_secret_destroy(&password);
    kid_report(code);
    _exit(code == 0 ? 0 : 7);
}

static void kid_prompt_eof(void)
{
    farsee_secret password = {0};
    int sig = 0;
    const farsee_credential_acquire_config config = {
        .password_fd = -1,
        .password_inline = NULL,
        .required = true,
    };
    const farsee_credential_acquire_status status =
        farsee_credential_acquire_password(&config, &password, &sig);
    int code = 0;
    if (status == FARSEE_CREDENTIAL_ACQUIRE_OK) {
        code = 30;
    } else if (status != FARSEE_CREDENTIAL_ACQUIRE_TERMINAL_SIGNAL ||
               sig != SIGHUP) {
        code = 32;
    }
    farsee_secret_destroy(&password);
    kid_report(code);
    farsee_credential_reraise_terminal_signal(sig);
    _exit(1);
}

typedef struct prompt_arm_fault {
    int calls;
} prompt_arm_fault;

static bool reject_sigterm_arm(void *context, int signal_number)
{
    prompt_arm_fault *fault = (prompt_arm_fault *)context;
    fault->calls++;
    return signal_number != SIGTERM;
}

static void kid_prompt_partial_signal_install(void)
{
    struct sigaction ignored;
    memset(&ignored, 0, sizeof ignored);
    ignored.sa_handler = SIG_IGN;
    sigemptyset(&ignored.sa_mask);
    (void)sigaction(SIGINT, &ignored, NULL);

    prompt_arm_fault fault = {.calls = 0};
    char *password = NULL;
    size_t password_length = 0u;
    const farsee_credential_prompt_status prompt_status =
        farsee_prompt_password_tty_with_arm_check(
            &password, &password_length, reject_sigterm_arm, &fault);
    struct sigaction current;
    memset(&current, 0, sizeof current);
    (void)sigaction(SIGINT, NULL, &current);

    int code = 0;
    if (prompt_status != FARSEE_CREDENTIAL_PROMPT_INPUT_FAILED) {
        code = 40;
    } else if (fault.calls != 2 || current.sa_handler != SIG_IGN) {
        code = 41;
    } else if (farsee_prompt_take_terminal_signal() != 0) {
        code = 42;
    } else {
        code = kid_check_restored_termios();
    }
    kid_report(code);
    _exit(code == 0 ? 0 : 7);
}

typedef void (*kid_fn)(void);

static void fork_and_run_kid(int slave, int master, int report_wr,
                             kid_fn fn)
{
    g_kid_report_fd = report_wr;
    kid_setup(slave, master);
    fn();
    _exit(99);  // fn must not return
}

// SIGINT delivered mid-prompt (VINTR byte through the pty
// line discipline, ISIG on) must leave the tty restored; the prompt
// process still dies with SIGINT so the exit path is honest.
RFB_TEST(rfb_prompt_signal, prompt__sigint_mid_prompt__termios_restored_and_child_dies)
{
    int master = -1;
    int slave = -1;
    if (openpty(&master, &slave, NULL, NULL, NULL) != 0) {
        RFB_CHECK(false);
        return;
    }
    RFB_CHECK(configure_probe_tty(slave));
    (void)fcntl(master, F_SETFL, O_NONBLOCK);

    int report[2];
    RFB_CHECK(pipe(report) == 0);
    pid_t kid = fork();
    RFB_CHECK(kid >= 0);
    if (kid == 0) {
        close(report[0]);
        fork_and_run_kid(slave, master, report[1], kid_prompt_sigint);
    }
    close(report[1]);

    RFB_CHECK(read_until(master, "Password: ", 5000));
    ssize_t w;
    do {
        w = write(master, "\x03", 1);
    } while (w < 0 && errno == EINTR);
    RFB_CHECK(w == 1);

    int status = 0;
    RFB_CHECK(waitpid(kid, &status, 0) == kid);
    RFB_CHECK(WIFSIGNALED(status));
    RFB_CHECK_EQ_INT(WTERMSIG(status), SIGINT);

    const int code = read_result_byte(report[0]);
    close(report[0]);
    RFB_CHECK_MSG(code == 0, kid_code_msg(code));

    close(master);
    close(slave);
}

RFB_TEST(rfb_prompt_signal, prompt__partial_sigaction_install_rolls_back_before_termios)
{
    int master = -1;
    int slave = -1;
    if (openpty(&master, &slave, NULL, NULL, NULL) != 0) {
        RFB_CHECK(false);
        return;
    }
    RFB_CHECK(configure_probe_tty(slave));

    int report[2];
    RFB_CHECK(pipe(report) == 0);
    pid_t kid = fork();
    RFB_CHECK(kid >= 0);
    if (kid == 0) {
        close(report[0]);
        fork_and_run_kid(
            slave, master, report[1], kid_prompt_partial_signal_install);
    }
    close(report[1]);

    const int code = read_result_byte(report[0]);
    close(report[0]);
    int status = 0;
    RFB_CHECK(waitpid(kid, &status, 0) == kid);
    RFB_CHECK(WIFEXITED(status));
    RFB_CHECK_EQ_INT(WEXITSTATUS(status), 0);
    RFB_CHECK_MSG(code == 0, kid_code_msg(code));

    close(master);
    close(slave);
}

// The normal-completion path still
// restores termios and returns the typed secret.
RFB_TEST(rfb_prompt_signal, prompt__enter_completes__termios_restored_and_ok)
{
    int master = -1;
    int slave = -1;
    if (openpty(&master, &slave, NULL, NULL, NULL) != 0) {
        RFB_CHECK(false);
        return;
    }
    RFB_CHECK(configure_probe_tty(slave));

    int report[2];
    RFB_CHECK(pipe(report) == 0);
    pid_t kid = fork();
    RFB_CHECK(kid >= 0);
    if (kid == 0) {
        close(report[0]);
        fork_and_run_kid(slave, master, report[1], kid_prompt_line);
    }
    close(report[1]);

    RFB_CHECK(read_until(master, "Password: ", 5000));
    ssize_t w;
    do {
        w = write(master, "pw\n", 3);
    } while (w < 0 && errno == EINTR);
    RFB_CHECK(w == 3);
    // Drain the prompt's completion newline: the prompt's restore uses
    // TCSAFLUSH, which waits for pending output to drain through the
    // master — a real terminal emulator reads continuously, so this only
    // matters for a supervised pty whose master we hold.
    RFB_CHECK(read_until(master, "\n", 5000));

    int status = 0;
    RFB_CHECK(waitpid(kid, &status, 0) == kid);
    RFB_CHECK(WIFEXITED(status));
    RFB_CHECK_EQ_INT(WEXITSTATUS(status), 0);

    const int code = read_result_byte(report[0]);
    close(report[0]);
    RFB_CHECK_MSG(code == 0, kid_code_msg(code));

    close(master);
    close(slave);
}

RFB_TEST(rfb_prompt_signal, prompt__ctrl_d__cancels_and_restores_termios)
{
    int master = -1;
    int slave = -1;
    if (openpty(&master, &slave, NULL, NULL, NULL) != 0) {
        RFB_CHECK(false);
        return;
    }
    RFB_CHECK(configure_probe_tty(slave));

    int report[2];
    RFB_CHECK(pipe(report) == 0);
    pid_t kid = fork();
    RFB_CHECK(kid >= 0);
    if (kid == 0) {
        close(report[0]);
        fork_and_run_kid(slave, master, report[1], kid_prompt_cancel);
    }
    close(report[1]);

    RFB_CHECK(read_until(master, "Password: ", 5000));
    ssize_t written;
    do {
        written = write(master, "\x04", 1u);
    } while (written < 0 && errno == EINTR);
    RFB_CHECK(written == 1);
    RFB_CHECK(read_until(master, "\n", 5000));

    int status = 0;
    RFB_CHECK(waitpid(kid, &status, 0) == kid);
    RFB_CHECK(WIFEXITED(status));
    RFB_CHECK_EQ_INT(WEXITSTATUS(status), 0);
    const int code = read_result_byte(report[0]);
    close(report[0]);
    RFB_CHECK_MSG(code == 0, kid_code_msg(code));

    close(master);
    close(slave);
}

// Closing the controlling pty master is a terminal hangup, not a clean EOF.
// The prompt reports SIGHUP after cleanup, and the CLI path re-raises it.
// Ctrl-D above remains the clean cancellation path.
RFB_TEST(rfb_prompt_signal, prompt__terminal_eof__fails_closed)
{
    int master = -1;
    int slave = -1;
    if (openpty(&master, &slave, NULL, NULL, NULL) != 0) {
        RFB_CHECK(false);
        return;
    }
    RFB_CHECK(configure_probe_tty(slave));

    int report[2];
    RFB_CHECK(pipe(report) == 0);
    pid_t kid = fork();
    RFB_CHECK(kid >= 0);
    if (kid == 0) {
        close(report[0]);
        fork_and_run_kid(slave, master, report[1], kid_prompt_eof);
    }
    close(report[1]);

    RFB_CHECK(read_until(master, "Password: ", 5000));
    close(master);

    const int code = read_result_byte(report[0]);
    close(report[0]);
    int status = 0;
    RFB_CHECK(waitpid(kid, &status, 0) == kid);
    RFB_CHECK(WIFSIGNALED(status));
    RFB_CHECK_EQ_INT(WTERMSIG(status), SIGHUP);
    RFB_CHECK_MSG(code == 0, kid_code_msg(code));

    close(slave);
}

RFB_TEST(rfb_prompt_signal, prompt__overlong_password__fails_closed)
{
    int master = -1;
    int slave = -1;
    if (openpty(&master, &slave, NULL, NULL, NULL) != 0) {
        RFB_CHECK(false);
        return;
    }
    RFB_CHECK(configure_probe_tty(slave));

    int report[2];
    RFB_CHECK(pipe(report) == 0);
    pid_t kid = fork();
    RFB_CHECK(kid >= 0);
    if (kid == 0) {
        close(report[0]);
        fork_and_run_kid(slave, master, report[1], kid_prompt_overlong);
    }
    close(report[1]);

    RFB_CHECK(read_until(master, "Password: ", 5000));
    char input[257];
    memset(input, 'x', sizeof input - 1u);
    input[sizeof input - 1u] = '\n';
    size_t offset = 0u;
    while (offset < sizeof input) {
        const ssize_t written = write(master, input + offset,
                                      sizeof input - offset);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        RFB_CHECK(written > 0);
        if (written <= 0) {
            break;
        }
        offset += (size_t)written;
    }
    RFB_CHECK_EQ_UINT(offset, sizeof input);
    RFB_CHECK(read_until(master, "\n", 5000));

    int status = 0;
    RFB_CHECK(waitpid(kid, &status, 0) == kid);
    RFB_CHECK(WIFEXITED(status));
    RFB_CHECK_EQ_INT(WEXITSTATUS(status), 0);
    const int code = read_result_byte(report[0]);
    close(report[0]);
    RFB_CHECK_MSG(code == 0, kid_code_msg(code));

    close(master);
    close(slave);
}
