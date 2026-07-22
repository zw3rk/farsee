// SPDX-License-Identifier: Apache-2.0
//
// farsee — POSIX terminal raw-mode lifecycle (plan.md §G7, §G10, §6.3).
//
// Manages raw-mode entry/restore with signal-safe cleanup. The global
// saved-attributes pointer allows restoration from a signal handler
// without heap allocation (plan.md §6.3: "signal-safe terminal
// restoration strategy").

#include "farsee/tty_posix.h"

#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

// Global state for signal-safe restoration. Set by enter_raw_mode;
// read by signal_restore. Only one tty is active per process (the
// session loop is single-threaded, plan.md §8).
static struct termios *g_saved_attrs = NULL;
static volatile sig_atomic_t g_saved_fd = -1;

// When open_input falls back to shared STDIN_FILENO it may set O_NONBLOCK.
// Restore original flags on close so the parent shell is not left nonblocking
// (T3; dual with live_shell tty_guard when both paths arm).
static bool g_stdin_fl_valid = false;
static int g_stdin_fl = 0;

void rfb_tty_init(rfb_tty *t, int fd)
{
    if (t == NULL) return;
    t->fd = fd;
    t->in_raw_mode = false;
    t->saved_attrs = NULL;
}

bool rfb_tty_enter_raw_mode(rfb_tty *t)
{
    if (t == NULL || t->fd < 0) return false;
    if (t->in_raw_mode) return true;

    struct termios *saved = (struct termios *)calloc(1, sizeof *saved);
    if (saved == NULL) return false;

    if (tcgetattr(t->fd, saved) != 0) {
        free(saved);
        return false;
    }

    struct termios raw = *saved;
    // Disable: echo, canonical mode, extended input processing, signals
    // from INTR/QUIT/SUSP, output post-processing.
    raw.c_lflag &= (tcflag_t)~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
    raw.c_oflag &= (tcflag_t)~(OPOST);
    raw.c_iflag &= (tcflag_t)~(BRKINT | ICRNL | INPCK | ISTRIP | IXON);
    raw.c_cflag |= (tcflag_t)(CS8);
    // Set a reasonable read timeout (VMIN=1, VTIME=0 = block until 1 byte).
    raw.c_cc[VMIN] = 1;
    raw.c_cc[VTIME] = 0;

    if (tcsetattr(t->fd, TCSAFLUSH, &raw) != 0) {
        free(saved);
        return false;
    }

    t->saved_attrs = saved;
    t->in_raw_mode = true;
    // Set the globals for signal-safe restoration.
    g_saved_fd = t->fd;
    g_saved_attrs = saved;
    return true;
}

void rfb_tty_restore(rfb_tty *t)
{
    if (t == NULL || !t->in_raw_mode || t->saved_attrs == NULL) return;
    tcsetattr(t->fd, TCSAFLUSH, (struct termios *)t->saved_attrs);
    t->in_raw_mode = false;
}

void rfb_tty_signal_restore(int sig)
{
    // Best-effort terminal restoration from signal context.
    // tcsetattr is not officially async-signal-safe but is the only
    // option for restoring terminal state; this is a common pattern.
    if (g_saved_attrs != NULL) {
        int fd = g_saved_fd >= 0 ? g_saved_fd : STDIN_FILENO;
        tcsetattr(fd, TCSADRAIN, g_saved_attrs);
    }
    // Re-raise the default handler so the process terminates normally.
    signal(sig, SIG_DFL);
    raise(sig);
}

bool rfb_tty_install_signal_handlers(rfb_tty *t)
{
    if (t == NULL) return false;
    // Install our signal_restore for the three terminal-disconnect signals.
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = rfb_tty_signal_restore;
    sigemptyset(&sa.sa_mask);
    // SA_RESTART: retry interrupted system calls (but our loop uses poll).
    sa.sa_flags = SA_RESTART;

    if (sigaction(SIGINT, &sa, NULL) != 0) return false;
    if (sigaction(SIGTERM, &sa, NULL) != 0) return false;
    if (sigaction(SIGHUP, &sa, NULL) != 0) return false;
    return true;
}

void rfb_tty_destroy(rfb_tty *t)
{
    if (t == NULL) return;
    rfb_tty_restore(t);
    // Null the signal-handler globals BEFORE freeing to prevent
    // use-after-free if a signal arrives between free and the null.
    g_saved_attrs = NULL;
    g_saved_fd = -1;
    if (t->saved_attrs != NULL) {
        free(t->saved_attrs);
        t->saved_attrs = NULL;
    }
}

static bool same_tty_device(int a, int b)
{
    struct stat sa;
    struct stat sb;
    if (a < 0 || b < 0) {
        return false;
    }
    if (fstat(a, &sa) != 0 || fstat(b, &sb) != 0) {
        return false;
    }
    return sa.st_dev == sb.st_dev && sa.st_ino == sb.st_ino;
}

static bool open_named_tty(const char *name, int *out_fd)
{
    if (name == NULL || name[0] == '\0' || out_fd == NULL) {
        return false;
    }
    // Dedicated open: flags independent of stdout O_NONBLOCK (Kitty drain).
    int fd = open(name, O_RDWR | O_NONBLOCK | O_NOCTTY);
    if (fd < 0) {
        return false;
    }
    if (!isatty(fd)) {
        (void)close(fd);
        return false;
    }
    *out_fd = fd;
    return true;
}

bool farsee_tty_open_input(int *out_fd, bool *out_owned)
{
    if (out_fd == NULL || out_owned == NULL) {
        return false;
    }
    *out_fd = -1;
    *out_owned = false;

    // 1) Same device as STDOUT (where Kitty graphics + mouse tracking live).
    //    Live "in=0" with SGR flood after exit often means we armed mouse on
    //    stdout but polled a different/stale input fd.
    if (isatty(STDOUT_FILENO)) {
        const char *name = ttyname(STDOUT_FILENO);
        int fd = -1;
        if (open_named_tty(name, &fd)) {
            *out_fd = fd;
            *out_owned = true;
            return true;
        }
    }

    // 2) STDIN when it is a TTY (same device preferred but not required).
    if (isatty(STDIN_FILENO)) {
        if (isatty(STDOUT_FILENO) &&
            !same_tty_device(STDIN_FILENO, STDOUT_FILENO)) {
            // Unusual: stdin TTY ≠ graphics TTY — still fall through and use
            // stdin; graphics-side open already tried above.
        }
        // Last resort: shared STDIN. Save original flags once, set O_NONBLOCK.
        // Prefer dedicated open above so we never touch stdin flags.
        int fl = fcntl(STDIN_FILENO, F_GETFL, 0);
        if (fl >= 0) {
            if (!g_stdin_fl_valid) {
                g_stdin_fl = fl;
                g_stdin_fl_valid = true;
            }
            if ((fl & O_NONBLOCK) == 0) {
                (void)fcntl(STDIN_FILENO, F_SETFL, fl | O_NONBLOCK);
            }
        }
        *out_fd = STDIN_FILENO;
        *out_owned = false;
        return true;
    }

    // 3) Controlling terminal.
    {
        int fd = -1;
        if (open_named_tty("/dev/tty", &fd)) {
            *out_fd = fd;
            *out_owned = true;
            return true;
        }
    }
    return false;
}

void farsee_tty_close_input(int fd, bool owned)
{
    if (owned && fd >= 0) {
        (void)close(fd);
        return;
    }
    // Shared STDIN path: restore O_NONBLOCK flags if we changed them.
    if (fd == STDIN_FILENO && g_stdin_fl_valid) {
        (void)fcntl(STDIN_FILENO, F_SETFL, g_stdin_fl);
        g_stdin_fl_valid = false;
    }
}

const char *farsee_tty_input_label(int fd, bool owned)
{
    if (owned) {
        if (fd >= 0) {
            const char *n = ttyname(fd);
            if (n != NULL && n[0] != '\0') {
                return n;
            }
        }
        return "/dev/tty";
    }
    if (fd == STDIN_FILENO) {
        return "stdin";
    }
    return "fd";
}
