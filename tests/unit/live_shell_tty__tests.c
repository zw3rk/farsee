// SPDX-License-Identifier: Apache-2.0
//
// PTY and boundary contracts for the shared live-session shell.

#include "rfb_test.h"

#include "app/live_shell.h"
#include "farsee/allocator.h"
#include "farsee/buffer.h"
#include "farsee/kitty_tile.h"
#include "farsee/sgr_mouse.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

#if defined(__APPLE__)
#  include <util.h>
#elif defined(__linux__)
#  include <pty.h>
#endif

typedef struct live_shell_stdout_pty {
    int master;
    int saved_stdout;
} live_shell_stdout_pty;

typedef struct live_shell_stdio_redirect {
    int saved_stdout;
    int saved_stderr;
    int read_fd;
} live_shell_stdio_redirect;

static bool set_nonblocking(int fd)
{
    const int flags = fcntl(fd, F_GETFL, 0);
    return flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

static size_t read_available(int fd, char *buf, size_t cap)
{
    size_t used = 0u;
    while (used < cap) {
        const ssize_t n = read(fd, buf + used, cap - used);
        if (n > 0) {
            used += (size_t)n;
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            break;
        }
        break;
    }
    return used;
}

static bool stdout_pty_begin(live_shell_stdout_pty *capture)
{
    int slave = -1;
    capture->master = -1;
    capture->saved_stdout = -1;
    if (openpty(&capture->master, &slave, NULL, NULL, NULL) != 0) {
        return false;
    }
    capture->saved_stdout = dup(STDOUT_FILENO);
    if (capture->saved_stdout < 0 || fflush(stdout) != 0) {
        if (capture->saved_stdout >= 0) {
            (void)close(capture->saved_stdout);
        }
        (void)close(capture->master);
        (void)close(slave);
        capture->master = -1;
        capture->saved_stdout = -1;
        return false;
    }
    if (dup2(slave, STDOUT_FILENO) < 0 ||
        !set_nonblocking(capture->master)) {
        (void)dup2(capture->saved_stdout, STDOUT_FILENO);
        (void)close(capture->saved_stdout);
        (void)close(capture->master);
        (void)close(slave);
        capture->master = -1;
        capture->saved_stdout = -1;
        return false;
    }
    (void)close(slave);
    return true;
}

static bool stdout_pty_end(live_shell_stdout_pty *capture)
{
    bool ok = true;
    // Restore flags while fd 1 still names the PTY that was armed.
    farsee_live_shell_tty_guard_restore();
    if (fflush(stdout) != 0 || capture->saved_stdout < 0 ||
        dup2(capture->saved_stdout, STDOUT_FILENO) < 0) {
        ok = false;
    }
    if (capture->saved_stdout >= 0) {
        (void)close(capture->saved_stdout);
    }
    if (capture->master >= 0) {
        (void)close(capture->master);
    }
    capture->master = -1;
    capture->saved_stdout = -1;
    return ok;
}

static bool stdio_redirect_begin(live_shell_stdio_redirect *redirect)
{
    int pfd[2] = {-1, -1};
    redirect->saved_stdout = -1;
    redirect->saved_stderr = -1;
    redirect->read_fd = -1;
    if (fflush(stdout) != 0 || fflush(stderr) != 0 || pipe(pfd) != 0) {
        return false;
    }
    redirect->saved_stdout = dup(STDOUT_FILENO);
    redirect->saved_stderr = dup(STDERR_FILENO);
    if (redirect->saved_stdout < 0 || redirect->saved_stderr < 0 ||
        dup2(pfd[1], STDOUT_FILENO) < 0 ||
        dup2(pfd[1], STDERR_FILENO) < 0) {
        if (redirect->saved_stdout >= 0) {
            (void)dup2(redirect->saved_stdout, STDOUT_FILENO);
            (void)close(redirect->saved_stdout);
        }
        if (redirect->saved_stderr >= 0) {
            (void)dup2(redirect->saved_stderr, STDERR_FILENO);
            (void)close(redirect->saved_stderr);
        }
        (void)close(pfd[0]);
        (void)close(pfd[1]);
        redirect->saved_stdout = -1;
        redirect->saved_stderr = -1;
        return false;
    }
    (void)close(pfd[1]);
    redirect->read_fd = pfd[0];
    return true;
}

static bool stdio_redirect_end(live_shell_stdio_redirect *redirect)
{
    bool ok = fflush(stdout) == 0 && fflush(stderr) == 0;
    if (redirect->saved_stdout < 0 ||
        dup2(redirect->saved_stdout, STDOUT_FILENO) < 0) {
        ok = false;
    }
    if (redirect->saved_stderr < 0 ||
        dup2(redirect->saved_stderr, STDERR_FILENO) < 0) {
        ok = false;
    }
    if (redirect->saved_stdout >= 0) {
        (void)close(redirect->saved_stdout);
    }
    if (redirect->saved_stderr >= 0) {
        (void)close(redirect->saved_stderr);
    }
    if (redirect->read_fd >= 0) {
        (void)close(redirect->read_fd);
    }
    redirect->saved_stdout = -1;
    redirect->saved_stderr = -1;
    redirect->read_fd = -1;
    return ok;
}

RFB_TEST(live_shell_tty, quiet_mode__pty_roundtrip_and_resume_refresh)
{
    int master = -1;
    int slave = -1;
    RFB_CHECK(openpty(&master, &slave, NULL, NULL, NULL) == 0);
    if (master < 0 || slave < 0) {
        return;
    }

    struct termios cooked;
    RFB_CHECK(tcgetattr(slave, &cooked) == 0);
    cooked.c_lflag |= (tcflag_t)(ECHO | ECHONL | ICANON | IEXTEN | ISIG);
    cooked.c_iflag |= (tcflag_t)(IXON | ICRNL);
    RFB_CHECK(tcsetattr(slave, TCSANOW, &cooked) == 0);

    farsee_live_shell shell;
    farsee_live_shell_init(&shell, NULL, 1u);
    shell.tty_fd = slave;
    RFB_CHECK(farsee_live_shell_quiet_enter(&shell));
    RFB_CHECK(shell.tty_attrs_saved);

    struct termios raw;
    RFB_CHECK(tcgetattr(slave, &raw) == 0);
    RFB_CHECK((raw.c_lflag & (ECHO | ECHONL | ICANON | IEXTEN | ISIG)) == 0);
    RFB_CHECK((raw.c_iflag & (IXON | ICRNL)) == 0);
    RFB_CHECK_EQ_INT(raw.c_cc[VMIN], 0);
    RFB_CHECK_EQ_INT(raw.c_cc[VTIME], 0);

    // A resumed shell can restore cooked mode before the owner re-enters.
    RFB_CHECK(tcsetattr(slave, TCSANOW, &cooked) == 0);
    RFB_CHECK(farsee_live_shell_quiet_enter(&shell));
    farsee_live_shell_quiet_restore(&shell);
    RFB_CHECK(!shell.tty_attrs_saved);

    struct termios restored;
    RFB_CHECK(tcgetattr(slave, &restored) == 0);
    RFB_CHECK((restored.c_lflag & (ECHO | ICANON | ISIG)) ==
              (cooked.c_lflag & (ECHO | ICANON | ISIG)));

    (void)close(master);
    (void)close(slave);
}

RFB_TEST(live_shell_tty, quiet_mode__invalid_inputs_fail_closed)
{
    farsee_live_shell shell;
    farsee_live_shell_init(&shell, NULL, 1u);
    RFB_CHECK(!farsee_live_shell_quiet_enter(NULL));
    RFB_CHECK(!farsee_live_shell_quiet_enter(&shell));
    farsee_live_shell_quiet_restore(NULL);
    farsee_live_shell_quiet_restore(&shell);

    int pfd[2] = {-1, -1};
    RFB_CHECK(pipe(pfd) == 0);
    if (pfd[0] >= 0) {
        shell.tty_fd = pfd[0];
        RFB_CHECK(!farsee_live_shell_quiet_enter(&shell));
        (void)close(pfd[0]);
        (void)close(pfd[1]);
    }
}

RFB_TEST(live_shell_tty, probe_winsize__pty_returns_cells_and_pixels)
{
    int master = -1;
    int slave = -1;
    RFB_CHECK(openpty(&master, &slave, NULL, NULL, NULL) == 0);
    if (master < 0 || slave < 0) {
        return;
    }
    struct winsize want;
    memset(&want, 0, sizeof want);
    want.ws_col = 132u;
    want.ws_row = 43u;
    want.ws_xpixel = 1056u;
    want.ws_ypixel = 688u;
    RFB_CHECK(ioctl(slave, TIOCSWINSZ, &want) == 0);

    uint16_t cols = 0u;
    uint16_t rows = 0u;
    uint16_t pw = 0u;
    uint16_t ph = 0u;
    RFB_CHECK(farsee_live_shell_probe_winsize(slave, &cols, &rows, &pw, &ph));
    RFB_CHECK_EQ_UINT(cols, want.ws_col);
    RFB_CHECK_EQ_UINT(rows, want.ws_row);
    RFB_CHECK_EQ_UINT(pw, want.ws_xpixel);
    RFB_CHECK_EQ_UINT(ph, want.ws_ypixel);
    RFB_CHECK(!farsee_live_shell_probe_winsize(-1, &cols, &rows, &pw, &ph));

    (void)close(master);
    (void)close(slave);
}

RFB_TEST(live_shell_tty, input_enable__dedicated_tty_receives_both_modes)
{
    int master = -1;
    int slave = -1;
    RFB_CHECK(openpty(&master, &slave, NULL, NULL, NULL) == 0);
    if (master < 0 || slave < 0) {
        return;
    }
    RFB_CHECK(set_nonblocking(master));

    farsee_live_shell shell;
    farsee_live_shell_init(&shell, NULL, 1u);
    shell.tty_fd = slave;
    shell.want_mouse = true;
    shell.want_kitty_kb = true;
    live_shell_stdio_redirect redirect;
    RFB_CHECK(stdio_redirect_begin(&redirect));
    if (redirect.read_fd < 0) {
        (void)close(master);
        (void)close(slave);
        return;
    }
    farsee_live_shell_input_enable(&shell);
    RFB_CHECK(shell.mouse_enabled);

    char bytes[256];
    const size_t n = read_available(master, bytes, sizeof bytes - 1u);
    bytes[n] = '\0';
    RFB_CHECK(strstr(bytes, rfb_sgr_mouse_enable_seq()) != NULL);
    RFB_CHECK(strstr(bytes, "\033[>3u") != NULL);

    farsee_live_shell_input_disable(&shell);
    RFB_CHECK(!shell.mouse_enabled);
    farsee_live_shell_input_enable(NULL);
    farsee_live_shell_input_disable(NULL);

    RFB_CHECK(stdio_redirect_end(&redirect));

    (void)close(master);
    (void)close(slave);
}

RFB_TEST(live_shell_tty, cursor_helpers__tty_emit_clamped_rows)
{
    live_shell_stdout_pty capture;
    RFB_CHECK(stdout_pty_begin(&capture));
    if (capture.master < 0) {
        return;
    }

    farsee_live_shell shell;
    farsee_live_shell_init(&shell, NULL, 2u);
    farsee_live_shell_set_term_geom(&shell, 80u, 10u, 800u, 400u);
    farsee_atomic_u64_store(&shell.place_cells, 50u);
    farsee_live_shell_fix_status_rows(&shell);
    RFB_CHECK_EQ_INT(farsee_atomic_int_load(&shell.log_row), 10);

    farsee_live_shell_home_cursor();
    farsee_live_shell_park_status_cursor(&shell);
    farsee_live_shell_park_log_cursor(&shell);

    char bytes[256];
    const size_t n = read_available(capture.master, bytes, sizeof bytes - 1u);
    bytes[n] = '\0';
    RFB_CHECK(strstr(bytes, "\033[H") != NULL);
    RFB_CHECK(strstr(bytes, "\033[10;1H") != NULL);

    farsee_live_shell_fix_status_rows(NULL);
    farsee_live_shell_park_status_cursor(NULL);
    farsee_live_shell_park_log_cursor(NULL);
    RFB_CHECK(stdout_pty_end(&capture));
}

typedef struct status_record {
    unsigned calls;
} status_record;

static void record_status_extra(void *user, char *buf, size_t cap)
{
    status_record *record = (status_record *)user;
    record->calls++;
    (void)snprintf(buf, cap, "  EXTRA");
}

RFB_TEST(live_shell_tty, draw_status__tty_covers_help_modes_and_resync)
{
    live_shell_stdout_pty capture;
    RFB_CHECK(stdout_pty_begin(&capture));
    if (capture.master < 0) {
        return;
    }

    farsee_live_shell shell;
    farsee_live_shell_init(&shell, NULL, 2u);
    farsee_live_shell_set_term_geom(&shell, 80u, 24u, 800u, 480u);
    shell.layout_active = true;
    shell.place_rows = 20u;
    farsee_atomic_u64_store(&shell.place_cells, 20u);
    (void)snprintf(shell.status_proto, sizeof shell.status_proto, "rdp");
    (void)snprintf(shell.status_host, sizeof shell.status_host, "host");
    shell.status_port = 3389u;
    shell.status_resync = true;

    status_record record;
    memset(&record, 0, sizeof record);
    farsee_live_shell_ops ops;
    memset(&ops, 0, sizeof ops);
    ops.status_extra = record_status_extra;
    shell.ops = &ops;
    shell.ops_user = &record;

    for (unsigned armed = 0u; armed < 2u; armed++) {
        farsee_atomic_int_store(&shell.demux.leader_armed, (int)armed);
        for (unsigned mode = 0u; mode < 4u; mode++) {
            shell.show_zoom = (mode & 1u) != 0u;
            shell.show_suspend = (mode & 2u) != 0u;
            farsee_live_shell_draw_status(&shell);

            char bytes[1024];
            const size_t n = read_available(capture.master, bytes,
                                            sizeof bytes - 1u);
            bytes[n] = '\0';
            RFB_CHECK(n > 0u);
            RFB_CHECK(strstr(bytes, "rdp://host:3389") != NULL);
            RFB_CHECK(strstr(bytes, "EXTRA") != NULL);
            RFB_CHECK((strstr(bytes, "zoom") != NULL) == shell.show_zoom);
            RFB_CHECK((strstr(bytes, "suspend") != NULL) ==
                      shell.show_suspend);
            RFB_CHECK((strstr(bytes, "leader") != NULL) == (armed != 0u));
            if (armed == 0u && mode == 0u) {
                RFB_CHECK(memchr(bytes, '\x18', n) != NULL);
            }
        }
    }
    RFB_CHECK_EQ_UINT(record.calls, 8u);
    RFB_CHECK(!shell.status_resync);
    RFB_CHECK(stdout_pty_end(&capture));
}

RFB_TEST(live_shell_tty, boundary_helpers__null_and_invalid_state_fail_closed)
{
    farsee_live_shell shell;
    farsee_live_shell_init(&shell, NULL, 0u);
    RFB_CHECK_EQ_UINT(shell.status_rows, 1u);
    RFB_CHECK_EQ_UINT(farsee_live_shell_view_scale(NULL),
                      FARSEE_VIEW_SCALE_DEFAULT_PCT);
    farsee_live_shell_set_view_scale(NULL, 75u);
    farsee_live_shell_set_term_geom(NULL, 1u, 2u, 3u, 4u);
    RFB_CHECK(!farsee_live_shell_get_term_geom(NULL, NULL, NULL, NULL, NULL));
    RFB_CHECK(!farsee_live_shell_refresh_layout(NULL, false));
    RFB_CHECK(!farsee_live_shell_refresh_layout(&shell, false));
    farsee_live_shell_note_desk_size(NULL, 1u, 1u);
    farsee_live_shell_note_desk_size(&shell, 0u, 1u);
    farsee_live_shell_note_desk_size(&shell, 1u, 0u);
    RFB_CHECK(!farsee_live_shell_apply_pending_desk(NULL, false));
    RFB_CHECK(!farsee_live_shell_mouse_to_desktop(NULL, 1, 1, NULL, NULL,
                                                  NULL));
    farsee_live_shell_do_leader_cmd(NULL, RFB_LEADER_CMD_QUIT);
    farsee_live_shell_zoom(NULL, 1);
    farsee_live_shell_feed_tty(NULL, NULL, 0u, 0u);
    farsee_live_shell_tick_timeout(NULL, 0u);
    farsee_live_shell_draw_status(NULL);
}

RFB_TEST(live_shell_tty, kitty_pending__buffer_and_lock_paths_are_consistent)
{
    farsee_live_shell shell;
    farsee_live_shell_init(&shell, NULL, 1u);
    RFB_CHECK(!farsee_live_shell_kitty_pending(NULL));
    RFB_CHECK(!farsee_live_shell_kitty_pending(&shell));

    rfb_kitty_tile tile;
    memset(&tile, 0, sizeof tile);
    shell.kitty = &tile;
    RFB_CHECK(!farsee_live_shell_kitty_pending(&shell));

    rfb_buffer out;
    rfb_buffer_init(&out, rfb_default_allocator(), 32u);
    tile.out = &out;
    RFB_CHECK(!farsee_live_shell_kitty_pending(&shell));
    static const uint8_t byte = 0x1bu;
    RFB_CHECK(rfb_buffer_append(&out, &byte, 1u) == RFB_OK);
    RFB_CHECK(farsee_live_shell_kitty_pending(&shell));

    shell.io_mu = farsee_mutex_create();
    RFB_CHECK(shell.io_mu != NULL);
    if (shell.io_mu != NULL) {
        RFB_CHECK(farsee_live_shell_kitty_pending(&shell));
        farsee_mutex_destroy(&shell.io_mu);
    }
    rfb_buffer_destroy(&out);
}
