// SPDX-License-Identifier: Apache-2.0
//
// Process-wide terminal and fatal-signal restoration for live sessions.

#include "app/live_shell_tty_guard.h"

#include "farsee/sgr_mouse.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

// The fatal handler can use only async-signal-safe operations. Terminal
// attributes remain normal-teardown work because tcsetattr is not safe here.
static char g_fatal_seq[96];
static volatile sig_atomic_t g_fatal_seq_len;
static volatile sig_atomic_t g_fatal_tty_fd = -1;
static volatile sig_atomic_t g_fatal_armed;
static bool g_fatal_handlers_installed;
static bool g_guard_atexit_registered;
static struct sigaction g_fatal_previous[4];
static const int g_fatal_signals[4] = {SIGSEGV, SIGBUS, SIGFPE, SIGQUIT};

typedef struct live_tty_guard {
    int tty_fd;
    bool tty_attrs_saved;
    struct termios saved;
    bool mouse_on;
    bool kitty_kb_on;
    bool active;
    bool stdout_fl_valid;
    int stdout_fl;
    bool stdout_fl_armed;
    bool stdin_fl_valid;
    int stdin_fl;
    bool stdin_fl_armed;
} live_tty_guard;

static live_tty_guard g_tty_guard = {.tty_fd = -1};

static void live_shell_register_atexit_once(void)
{
    if (!g_guard_atexit_registered &&
        atexit(farsee_live_shell_tty_guard_restore) == 0) {
        g_guard_atexit_registered = true;
    }
}

static void live_shell_on_fatal_signal(int sig)
{
    struct sigaction default_action = {0};
    default_action.sa_handler = SIG_DFL;
    sigemptyset(&default_action.sa_mask);
    default_action.sa_flags = 0;
    const bool reset_to_default =
        sigaction(sig, &default_action, NULL) == 0;

    const sig_atomic_t fd = g_fatal_tty_fd;
    const sig_atomic_t length = g_fatal_seq_len;
    if (g_fatal_armed && length > 0 && fd >= 0) {
        const ssize_t written =
            write((int)fd, g_fatal_seq, (size_t)length);
        (void)written;
    }
    if (reset_to_default) {
        sigset_t fatal_signal;
        sigemptyset(&fatal_signal);
        (void)(sigaddset)(&fatal_signal, sig);
        if (sigprocmask(SIG_UNBLOCK, &fatal_signal, NULL) == 0) {
            (void)raise(sig);
        }
    }
    _exit(128 + sig);
}

static void fatal_signal_set(sigset_t *set)
{
    sigemptyset(set);
    for (size_t i = 0u; i < 4u; i++) {
        (void)(sigaddset)(set, g_fatal_signals[i]);
    }
}

static bool live_shell_arm_fatal_restorers(void)
{
    if (g_fatal_handlers_installed) {
        g_fatal_armed = 1;
        return true;
    }
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = live_shell_on_fatal_signal;
    sigemptyset(&sa.sa_mask);
    // Linux defines SA_RESETHAND with the unsigned high bit even though
    // sigaction.sa_flags is an int. The explicit conversion preserves the
    // POSIX flag bits without triggering -Wsign-conversion.
    // Keep the current fatal signal blocked while its one-shot handler runs.
    // The handler restores the default disposition before unblocking and
    // re-raising it. SA_NODEFER would permit recursive handler entry and can
    // fill the restoration pipe indefinitely on Linux.
    sa.sa_flags = (int)SA_RESETHAND;
    for (size_t i = 0u; i < 4u; i++) {
        if (sigaction(g_fatal_signals[i], NULL, &g_fatal_previous[i]) != 0) {
            return false;
        }
    }
    size_t installed = 0u;
    for (; installed < 4u; installed++) {
        if (sigaction(g_fatal_signals[installed], &sa, NULL) != 0) {
            break;
        }
    }
    if (installed != 4u) {
        for (size_t i = 0u; i < installed; i++) {
            (void)sigaction(g_fatal_signals[i], &g_fatal_previous[i], NULL);
        }
        return false;
    }
    g_fatal_handlers_installed = true;
    g_fatal_armed = 1;
    return true;
}

static void live_shell_disarm_fatal_restorers(void)
{
    sigset_t fatal_set;
    sigset_t old_set;
    fatal_signal_set(&fatal_set);
    const bool blocked =
        sigprocmask(SIG_BLOCK, &fatal_set, &old_set) == 0;
    g_fatal_armed = 0;
    if (g_fatal_handlers_installed) {
        for (size_t i = 0u; i < 4u; i++) {
            (void)sigaction(g_fatal_signals[i], &g_fatal_previous[i], NULL);
        }
        g_fatal_handlers_installed = false;
    }
    g_fatal_tty_fd = -1;
    g_fatal_seq_len = 0;
    memset(g_fatal_seq, 0, sizeof g_fatal_seq);
    if (blocked) {
        (void)sigprocmask(SIG_SETMASK, &old_set, NULL);
    }
}

static void live_shell_snapshot_standard_flags(void)
{
    // stdin and stdout can be dup'ed references to one PTY open-file
    // description. Snapshot both before changing either so the second arm
    // cannot record Farsee's O_NONBLOCK change as the caller's original
    // state.
    if (!g_tty_guard.stdout_fl_valid) {
        const int flags = fcntl(STDOUT_FILENO, F_GETFL, 0);
        if (flags >= 0) {
            g_tty_guard.stdout_fl = flags;
            g_tty_guard.stdout_fl_valid = true;
        }
    }
    if (!g_tty_guard.stdin_fl_valid) {
        const int flags = fcntl(STDIN_FILENO, F_GETFL, 0);
        if (flags >= 0) {
            g_tty_guard.stdin_fl = flags;
            g_tty_guard.stdin_fl_valid = true;
        }
    }
}

void farsee_live_shell_stdio_nonblock_arm(int fd)
{
    if (fd < 0) {
        return;
    }
    live_shell_register_atexit_once();
    if (fd == STDOUT_FILENO) {
        live_shell_snapshot_standard_flags();
        const int flags = fcntl(STDOUT_FILENO, F_GETFL, 0);
        if (flags >= 0 &&
            ((flags & O_NONBLOCK) != 0 ||
             fcntl(STDOUT_FILENO, F_SETFL, flags | O_NONBLOCK) == 0)) {
            g_tty_guard.stdout_fl_armed = true;
        }
        return;
    }
    if (fd == STDIN_FILENO) {
        live_shell_snapshot_standard_flags();
        const int flags = fcntl(STDIN_FILENO, F_GETFL, 0);
        if (flags >= 0 &&
            ((flags & O_NONBLOCK) != 0 ||
             fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK) == 0)) {
            g_tty_guard.stdin_fl_armed = true;
        }
        return;
    }
    const int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0 && (flags & O_NONBLOCK) == 0) {
        (void)fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }
}

size_t farsee_live_shell_write_all(int fd, const char *s, size_t n)
{
    if (fd < 0 || s == NULL || n == 0u) {
        return 0u;
    }
    size_t offset = 0u;
    unsigned eagain_rounds = 0u;
    while (offset < n) {
        const ssize_t written = write(fd, s + offset, n - offset);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                if (++eagain_rounds > 4u) {
                    break;
                }
                struct pollfd pfd;
                memset(&pfd, 0, sizeof pfd);
                pfd.fd = fd;
                pfd.events = POLLOUT;
                (void)poll(&pfd, 1, 5);
                continue;
            }
            break;
        }
        if (written == 0) {
            break;
        }
        eagain_rounds = 0u;
        offset += (size_t)written;
    }
    return offset;
}

static void guard_write_all(int fd, const char *s, size_t n)
{
    (void)farsee_live_shell_write_all(fd, s, n);
}

void farsee_live_shell_tty_guard_write_seq(const char *sequence)
{
    if (sequence == NULL || sequence[0] == '\0') {
        return;
    }
    const size_t length = strlen(sequence);
    if (isatty(STDOUT_FILENO)) {
        guard_write_all(STDOUT_FILENO, sequence, length);
    }
    if (g_tty_guard.tty_fd >= 0 &&
        g_tty_guard.tty_fd != STDOUT_FILENO &&
        isatty(g_tty_guard.tty_fd)) {
        guard_write_all(g_tty_guard.tty_fd, sequence, length);
    }
    if (isatty(STDERR_FILENO) && STDERR_FILENO != STDOUT_FILENO &&
        STDERR_FILENO != g_tty_guard.tty_fd) {
        guard_write_all(STDERR_FILENO, sequence, length);
    }
}

void farsee_live_shell_tty_guard_restore(void)
{
    if (g_tty_guard.stdout_fl_valid && g_tty_guard.stdout_fl_armed) {
        (void)fcntl(STDOUT_FILENO, F_SETFL, g_tty_guard.stdout_fl);
    }
    if (g_tty_guard.stdin_fl_valid && g_tty_guard.stdin_fl_armed) {
        (void)fcntl(STDIN_FILENO, F_SETFL, g_tty_guard.stdin_fl);
    }
    g_tty_guard.stdout_fl_valid = false;
    g_tty_guard.stdout_fl = 0;
    g_tty_guard.stdout_fl_armed = false;
    g_tty_guard.stdin_fl_valid = false;
    g_tty_guard.stdin_fl = 0;
    g_tty_guard.stdin_fl_armed = false;

    if (!g_tty_guard.active) {
        g_tty_guard.tty_fd = -1;
        g_tty_guard.tty_attrs_saved = false;
        memset(&g_tty_guard.saved, 0, sizeof g_tty_guard.saved);
        g_tty_guard.mouse_on = false;
        g_tty_guard.kitty_kb_on = false;
        live_shell_disarm_fatal_restorers();
        return;
    }
    g_tty_guard.active = false;

    if (g_tty_guard.mouse_on) {
        const char *disable = rfb_sgr_mouse_disable_seq();
        if (disable != NULL) {
            farsee_live_shell_tty_guard_write_seq(disable);
        }
        g_tty_guard.mouse_on = false;
    }
    if (g_tty_guard.kitty_kb_on) {
        farsee_live_shell_tty_guard_write_seq("\033[<u");
        g_tty_guard.kitty_kb_on = false;
    }
    farsee_live_shell_tty_guard_write_seq("\033[?25h\033[0m");

    if (g_tty_guard.tty_attrs_saved && g_tty_guard.tty_fd >= 0) {
        (void)tcsetattr(g_tty_guard.tty_fd, TCSAFLUSH, &g_tty_guard.saved);
    }
    g_tty_guard.tty_attrs_saved = false;
    if (g_tty_guard.tty_fd >= 0) {
        uint8_t junk[256];
        for (int i = 0; i < 8; i++) {
            const ssize_t read_size =
                read(g_tty_guard.tty_fd, junk, sizeof junk);
            if (read_size <= 0) {
                break;
            }
        }
    }
    g_tty_guard.tty_fd = -1;
    memset(&g_tty_guard.saved, 0, sizeof g_tty_guard.saved);
    live_shell_disarm_fatal_restorers();
}

void farsee_live_shell_tty_guard_arm(int tty_fd, bool attrs_saved,
                                     const struct termios *saved,
                                     bool mouse_on, bool kitty_kb_on)
{
    g_tty_guard.tty_fd = tty_fd;
    g_tty_guard.tty_attrs_saved = attrs_saved && saved != NULL && tty_fd >= 0;
    if (g_tty_guard.tty_attrs_saved) {
        g_tty_guard.saved = *saved;
    } else {
        memset(&g_tty_guard.saved, 0, sizeof g_tty_guard.saved);
    }
    g_tty_guard.mouse_on = mouse_on;
    g_tty_guard.kitty_kb_on = kitty_kb_on;
    g_tty_guard.active = true;
    live_shell_register_atexit_once();

    sigset_t fatal_set;
    sigset_t old_set;
    fatal_signal_set(&fatal_set);
    const bool blocked =
        sigprocmask(SIG_BLOCK, &fatal_set, &old_set) == 0;
    g_fatal_armed = 0;
    g_fatal_tty_fd = tty_fd;
    g_fatal_seq_len = 0u;
    if (mouse_on) {
        const char *disable = rfb_sgr_mouse_disable_seq();
        if (disable != NULL) {
            size_t length = strlen(disable);
            const size_t have = (size_t)g_fatal_seq_len;
            if (length > sizeof g_fatal_seq - have - 1u) {
                length = sizeof g_fatal_seq - have - 1u;
            }
            memcpy(g_fatal_seq + have, disable, length);
            g_fatal_seq_len = (sig_atomic_t)(have + length);
        }
    }
    if (kitty_kb_on) {
        static const char kitty_kb_off[] = "\033[<u";
        const size_t length = sizeof kitty_kb_off - 1u;
        const size_t have = (size_t)g_fatal_seq_len;
        if (length <= sizeof g_fatal_seq - have - 1u) {
            memcpy(g_fatal_seq + have, kitty_kb_off, length);
            g_fatal_seq_len = (sig_atomic_t)(have + length);
        }
    }
    {
        static const char show_cursor[] = "\033[?25h\033[0m";
        const size_t length = sizeof show_cursor - 1u;
        const size_t have = (size_t)g_fatal_seq_len;
        if (length <= sizeof g_fatal_seq - have - 1u) {
            memcpy(g_fatal_seq + have, show_cursor, length);
            g_fatal_seq_len = (sig_atomic_t)(have + length);
        }
    }
    (void)live_shell_arm_fatal_restorers();
    if (blocked) {
        (void)sigprocmask(SIG_SETMASK, &old_set, NULL);
    }
}

void farsee_live_shell_tty_guard_update_attrs_for_fd(
    int tty_fd, const struct termios *saved)
{
    if (!g_tty_guard.active || g_tty_guard.tty_fd != tty_fd) {
        return;
    }
    g_tty_guard.tty_attrs_saved = saved != NULL;
    if (saved != NULL) {
        g_tty_guard.saved = *saved;
    } else {
        memset(&g_tty_guard.saved, 0, sizeof g_tty_guard.saved);
    }
}

static bool same_tty_device(int a, int b)
{
    struct stat first;
    struct stat second;
    if (a < 0 || b < 0 || fstat(a, &first) != 0 ||
        fstat(b, &second) != 0) {
        return false;
    }
    return first.st_dev == second.st_dev && first.st_ino == second.st_ino;
}

static bool open_named_tty(const char *name, int *out_fd)
{
    if (name == NULL || name[0] == '\0' || out_fd == NULL) {
        return false;
    }
    const int fd = open(name, O_RDWR | O_NONBLOCK | O_NOCTTY);
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

bool farsee_live_shell_tty_open_input(int *out_fd, bool *out_owned)
{
    if (out_fd == NULL || out_owned == NULL) {
        return false;
    }
    *out_fd = -1;
    *out_owned = false;
    if (isatty(STDOUT_FILENO)) {
        int fd = -1;
        if (open_named_tty(ttyname(STDOUT_FILENO), &fd)) {
            *out_fd = fd;
            *out_owned = true;
            return true;
        }
    }
    if (isatty(STDIN_FILENO)) {
        if (isatty(STDOUT_FILENO) &&
            !same_tty_device(STDIN_FILENO, STDOUT_FILENO)) {
            // The preferred graphics-side open already failed. Shared stdin
            // remains the only usable descriptor.
        }
        farsee_live_shell_stdio_nonblock_arm(STDIN_FILENO);
        *out_fd = STDIN_FILENO;
        return true;
    }
    int fd = -1;
    if (open_named_tty("/dev/tty", &fd)) {
        *out_fd = fd;
        *out_owned = true;
        return true;
    }
    return false;
}

void farsee_live_shell_tty_close_input(int fd, bool owned)
{
    if (owned && fd >= 0) {
        (void)close(fd);
    }
}

const char *farsee_live_shell_tty_input_label(int fd, bool owned)
{
    if (owned) {
        if (fd >= 0) {
            const char *name = ttyname(fd);
            if (name != NULL && name[0] != '\0') {
                return name;
            }
        }
        return "/dev/tty";
    }
    return fd == STDIN_FILENO ? "stdin" : "fd";
}
