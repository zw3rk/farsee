// SPDX-License-Identifier: Apache-2.0
//
// Shared live shell (Q2): TTY guard/quiet, layout, status, demux feed wiring.

#include "app/live_shell.h"

#include "farsee/farsee_input.h"
#include "farsee/kitty_tile.h"
#include "farsee/sgr_mouse.h"

#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

// ---------------------------------------------------------------------------
// Process-wide atexit TTY guard (crash / early-return safety net)
// ---------------------------------------------------------------------------

typedef struct live_tty_guard {
    int            tty_fd;
    bool           tty_attrs_saved;
    struct termios saved;
    bool           mouse_on;
    bool           kitty_kb_on;
    bool           active;
    // Shared stdin/stdout O_NONBLOCK restore (T3). Saved once on first arm.
    bool           stdout_fl_valid;
    int            stdout_fl;
    bool           stdin_fl_valid;
    int            stdin_fl;
} live_tty_guard;

static live_tty_guard g_tty_guard;

// Save original fcntl flags (once) and set O_NONBLOCK on shared stdio fds.
// Dedicated session fds (owned, already O_NONBLOCK) are left alone when
// fd is not STDIN/STDOUT. Safe to call repeatedly.
void farsee_live_shell_stdio_nonblock_arm(int fd)
{
    if (fd < 0) {
        return;
    }
    if (fd == STDOUT_FILENO) {
        if (!g_tty_guard.stdout_fl_valid) {
            int fl = fcntl(STDOUT_FILENO, F_GETFL, 0);
            if (fl >= 0) {
                g_tty_guard.stdout_fl = fl;
                g_tty_guard.stdout_fl_valid = true;
            }
        }
        {
            int fl = fcntl(STDOUT_FILENO, F_GETFL, 0);
            if (fl >= 0 && (fl & O_NONBLOCK) == 0) {
                (void)fcntl(STDOUT_FILENO, F_SETFL, fl | O_NONBLOCK);
            }
        }
        return;
    }
    if (fd == STDIN_FILENO) {
        if (!g_tty_guard.stdin_fl_valid) {
            int fl = fcntl(STDIN_FILENO, F_GETFL, 0);
            if (fl >= 0) {
                g_tty_guard.stdin_fl = fl;
                g_tty_guard.stdin_fl_valid = true;
            }
        }
        {
            int fl = fcntl(STDIN_FILENO, F_GETFL, 0);
            if (fl >= 0 && (fl & O_NONBLOCK) == 0) {
                (void)fcntl(STDIN_FILENO, F_SETFL, fl | O_NONBLOCK);
            }
        }
        return;
    }
    // Owned/dedicated fd: set nonblock without process-wide restore.
    {
        int fl = fcntl(fd, F_GETFL, 0);
        if (fl >= 0 && (fl & O_NONBLOCK) == 0) {
            (void)fcntl(fd, F_SETFL, fl | O_NONBLOCK);
        }
    }
}

size_t farsee_live_shell_write_all(int fd, const char *s, size_t n)
{
    if (fd < 0 || s == NULL || n == 0u) {
        return 0u;
    }
    size_t off = 0;
    // Bounded POLLOUT retries so a full TTY cannot hang status forever,
    // but we wait briefly for drain (better than 64 busy spins).
    unsigned eagain_rounds = 0;
    while (off < n) {
        ssize_t w = write(fd, s + off, n - off);
        if (w < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                if (++eagain_rounds > 4u) {
                    break;
                }
                {
                    struct pollfd pfd;
                    memset(&pfd, 0, sizeof pfd);
                    pfd.fd = fd;
                    pfd.events = POLLOUT;
                    (void)poll(&pfd, 1, 5); // ~5 ms per round, ≤20 ms total
                }
                continue;
            }
            break;
        }
        if (w == 0) {
            break;
        }
        eagain_rounds = 0;
        off += (size_t)w;
    }
    return off;
}

static void shell_write_all(int fd, const char *s, size_t n)
{
    (void)farsee_live_shell_write_all(fd, s, n);
}

bool farsee_live_shell_kitty_pending(const farsee_live_shell *s)
{
    if (s == NULL || s->kitty == NULL || s->kitty->out == NULL) {
        return false;
    }
    // Prefer locked read when io_mu is available (post-t11 T7). Nested lock
    // is undefined (non-recursive); callers that already hold io_mu must
    // read length directly under that lock instead of calling this helper.
    if (s->io_mu != NULL) {
        farsee_mutex_lock(s->io_mu);
        const bool pending = rfb_buffer_length(s->kitty->out) > 0u;
        farsee_mutex_unlock(s->io_mu);
        return pending;
    }
    return rfb_buffer_length(s->kitty->out) > 0u;
}



// Write a control sequence to every TTY we may have armed.
static void shell_write_seq(const char *s)
{
    if (s == NULL || s[0] == '\0') {
        return;
    }
    const size_t n = strlen(s);
    if (isatty(STDOUT_FILENO)) {
        shell_write_all(STDOUT_FILENO, s, n);
    }
    if (g_tty_guard.tty_fd >= 0 && g_tty_guard.tty_fd != STDOUT_FILENO &&
        isatty(g_tty_guard.tty_fd)) {
        shell_write_all(g_tty_guard.tty_fd, s, n);
    }
    if (isatty(STDERR_FILENO) && STDERR_FILENO != STDOUT_FILENO &&
        STDERR_FILENO != g_tty_guard.tty_fd) {
        shell_write_all(STDERR_FILENO, s, n);
    }
}

void farsee_live_shell_tty_guard_restore(void)
{
    // Always restore stdio fcntl flags even if full arm never completed
    // (e.g. partial setup that only armed nonblock).
    if (g_tty_guard.stdout_fl_valid) {
        (void)fcntl(STDOUT_FILENO, F_SETFL, g_tty_guard.stdout_fl);
        g_tty_guard.stdout_fl_valid = false;
    }
    if (g_tty_guard.stdin_fl_valid) {
        (void)fcntl(STDIN_FILENO, F_SETFL, g_tty_guard.stdin_fl);
        g_tty_guard.stdin_fl_valid = false;
    }

    if (!g_tty_guard.active) {
        return;
    }
    g_tty_guard.active = false;

    if (g_tty_guard.mouse_on) {
        const char *dis = rfb_sgr_mouse_disable_seq();
        if (dis != NULL) {
            shell_write_seq(dis);
        }
        g_tty_guard.mouse_on = false;
    }
    if (g_tty_guard.kitty_kb_on) {
        static const char kitty_kb_off[] = "\033[<u";
        shell_write_seq(kitty_kb_off);
        g_tty_guard.kitty_kb_on = false;
    }
    shell_write_seq("\033[?25h\033[0m");

    if (g_tty_guard.tty_attrs_saved && g_tty_guard.tty_fd >= 0) {
        (void)tcsetattr(g_tty_guard.tty_fd, TCSAFLUSH, &g_tty_guard.saved);
        g_tty_guard.tty_attrs_saved = false;
    }
    if (g_tty_guard.tty_fd >= 0) {
        uint8_t junk[256];
        for (int i = 0; i < 8; i++) {
            ssize_t n = read(g_tty_guard.tty_fd, junk, sizeof junk);
            if (n <= 0) {
                break;
            }
        }
    }
}

void farsee_live_shell_tty_guard_arm(int tty_fd, bool attrs_saved,
                                     const struct termios *saved,
                                     bool mouse_on, bool kitty_kb_on)
{
    g_tty_guard.tty_fd = tty_fd;
    g_tty_guard.tty_attrs_saved = attrs_saved;
    if (attrs_saved && saved != NULL) {
        g_tty_guard.saved = *saved;
    }
    g_tty_guard.mouse_on = mouse_on;
    g_tty_guard.kitty_kb_on = kitty_kb_on;
    g_tty_guard.active = true;
    (void)atexit(farsee_live_shell_tty_guard_restore);
}

void farsee_live_shell_tty_guard_note_attrs(bool attrs_saved)
{
    g_tty_guard.tty_attrs_saved = attrs_saved;
}

// ---------------------------------------------------------------------------
// Init / quiet / input enable
// ---------------------------------------------------------------------------

void farsee_live_shell_init(farsee_live_shell *s,
                            const farsee_cli_leader *leader,
                            uint16_t status_rows)
{
    if (s == NULL) {
        return;
    }
    memset(s, 0, sizeof(*s));
    s->tty_fd = -1;
    s->status_rows = (status_rows > 0u) ? status_rows : 1u;
    farsee_live_shell_set_view_scale(s, FARSEE_VIEW_SCALE_DEFAULT_PCT);
    farsee_live_shell_set_term_geom(s, 80u, 24u, 0u, 0u);
    if (leader != NULL) {
        s->leader = *leader;
    } else {
        farsee_cli_leader_default(&s->leader);
    }
    farsee_live_demux_init(&s->demux, &s->leader);
}

uint32_t farsee_live_shell_view_scale(const farsee_live_shell *s)
{
    if (s == NULL) {
        return FARSEE_VIEW_SCALE_DEFAULT_PCT;
    }
    int v = farsee_atomic_int_load(&s->view_scale_pct);
    if (v <= 0) {
        return FARSEE_VIEW_SCALE_DEFAULT_PCT;
    }
    return farsee_view_scale_clamp((uint32_t)v);
}

void farsee_live_shell_set_view_scale(farsee_live_shell *s, uint32_t pct)
{
    if (s == NULL) {
        return;
    }
    farsee_atomic_int_store(&s->view_scale_pct,
                            (int)farsee_view_scale_clamp(pct));
}

void farsee_live_shell_set_term_geom(farsee_live_shell *s, uint16_t cols,
                                     uint16_t rows, uint16_t pw, uint16_t ph)
{
    if (s == NULL) {
        return;
    }
    s->term_cols = cols;
    s->term_rows = rows;
    s->term_pw = pw;
    s->term_ph = ph;
    const uint64_t cells = ((uint64_t)cols << 32) | (uint64_t)rows;
    const uint64_t px = ((uint64_t)pw << 32) | (uint64_t)ph;
    farsee_atomic_u64_store(&s->term_cells, cells);
    farsee_atomic_u64_store(&s->term_px, px);
}

bool farsee_live_shell_get_term_geom(const farsee_live_shell *s, uint16_t *cols,
                                     uint16_t *rows, uint16_t *pw,
                                     uint16_t *ph)
{
    if (s == NULL) {
        return false;
    }
    const uint64_t cells = farsee_atomic_u64_load(&s->term_cells);
    const uint64_t px = farsee_atomic_u64_load(&s->term_px);
    if (cols != NULL) {
        *cols = (uint16_t)(cells >> 32);
    }
    if (rows != NULL) {
        *rows = (uint16_t)(cells & 0xffffffffu);
    }
    if (pw != NULL) {
        *pw = (uint16_t)(px >> 32);
    }
    if (ph != NULL) {
        *ph = (uint16_t)(px & 0xffffffffu);
    }
    return true;
}

// farsee_link_rate_sample is inline in farsee/socket_posix.h.

bool farsee_live_shell_probe_winsize(int src_fd, uint16_t *out_cols,
                                     uint16_t *out_rows, uint16_t *out_pw,
                                     uint16_t *out_ph)
{
    if (out_cols == NULL || out_rows == NULL || out_pw == NULL ||
        out_ph == NULL) {
        return false;
    }
    struct winsize ws;
    memset(&ws, 0, sizeof ws);
    bool got = false;
    if (src_fd >= 0 && ioctl(src_fd, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0 &&
        ws.ws_row > 0) {
        got = true;
    } else if (isatty(STDOUT_FILENO) &&
               ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0 &&
               ws.ws_row > 0) {
        got = true;
    }
    if (!got) {
        return false;
    }
    uint16_t pw = ws.ws_xpixel;
    uint16_t ph = ws.ws_ypixel;
    // Merge missing pixels from stdout when primary lacked them.
    if ((pw == 0u || ph == 0u) && isatty(STDOUT_FILENO) && src_fd != STDOUT_FILENO) {
        struct winsize ws2;
        if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws2) == 0) {
            if (pw == 0u) {
                pw = ws2.ws_xpixel;
            }
            if (ph == 0u) {
                ph = ws2.ws_ypixel;
            }
        }
    }
    *out_cols = ws.ws_col;
    *out_rows = ws.ws_row;
    *out_pw = pw;
    *out_ph = ph;
    return true;
}

void farsee_live_shell_format_link_extra(char *buf, size_t cap,
                                         uint32_t scale_pct, uint32_t rtt_ms,
                                         bool have_rtt, uint32_t rate_kib_s,
                                         bool have_rate)
{
    if (buf == NULL || cap == 0u) {
        return;
    }
    buf[0] = '\0';
    if (have_rtt && have_rate) {
        (void)snprintf(buf, cap,
                       "  \033[38;5;114m%u%%\033[0m"
                       "  \033[2m%ums %uKiB/s\033[0m",
                       (unsigned)scale_pct, (unsigned)rtt_ms,
                       (unsigned)rate_kib_s);
    } else if (have_rtt) {
        (void)snprintf(buf, cap,
                       "  \033[38;5;114m%u%%\033[0m"
                       "  \033[2m%ums\033[0m",
                       (unsigned)scale_pct, (unsigned)rtt_ms);
    } else if (have_rate) {
        (void)snprintf(buf, cap,
                       "  \033[38;5;114m%u%%\033[0m"
                       "  \033[2m%uKiB/s\033[0m",
                       (unsigned)scale_pct, (unsigned)rate_kib_s);
    } else {
        (void)snprintf(buf, cap, "  \033[38;5;114m%u%%\033[0m",
                       (unsigned)scale_pct);
    }
}

size_t farsee_live_shell_clamp_snprintf_len(int n, size_t cap)
{
    if (n <= 0 || cap == 0u) {
        return 0u;
    }
    const size_t want = (size_t)n;
    const size_t max_payload = cap - 1u; // leave room for NUL already written
    return (want < max_payload) ? want : max_payload;
}

// When snprintf truncated, force a trailing SGR reset so the next TTY write
// is not consumed as CSI parameters (loop r2 T7 / r3 T3).
void farsee_live_shell_ensure_ansi_reset(char *buf, size_t *inout_len,
                                         size_t cap)
{
    static const char reset[] = "\033[0m";
    const size_t rlen = sizeof(reset) - 1u;
    if (buf == NULL || inout_len == NULL || cap == 0u) {
        return;
    }
    size_t n = *inout_len;
    // Fail closed on out-of-contract length (not a real snprintf truncation).
    if (n >= cap) {
        *inout_len = 0u;
        return;
    }
    if (n == 0u || n + 1u < cap) {
        // Not truncated (or empty): leave buffer intact.
        return;
    }
    // Truncated path: n == cap-1. Overwrite the tail with a complete reset.
    if (n >= rlen) {
        memcpy(buf + n - rlen, reset, rlen);
    }
}

bool farsee_live_shell_quiet_enter(farsee_live_shell *s)
{
    if (s == NULL || s->tty_fd < 0) {
        return false;
    }
    if (!s->tty_attrs_saved) {
        if (tcgetattr(s->tty_fd, &s->tty_saved) != 0) {
            return false;
        }
        s->tty_attrs_saved = true;
    } else {
        // After suspend/resume the shell may leave cooked mode; re-read so
        // restore() later returns to a sensible shell state.
        struct termios now;
        if (tcgetattr(s->tty_fd, &now) == 0) {
            s->tty_saved = now;
        }
    }
    struct termios raw = s->tty_saved;
    raw.c_lflag &= (tcflag_t) ~(ECHO | ECHONL | ICANON | IEXTEN | ISIG);
    raw.c_iflag &= (tcflag_t) ~(IXON | ICRNL);
    raw.c_cc[VMIN] = 0;
    raw.c_cc[VTIME] = 0;
    if (tcsetattr(s->tty_fd, TCSANOW, &raw) != 0) {
        return false;
    }
    return true;
}

void farsee_live_shell_quiet_restore(farsee_live_shell *s)
{
    if (s == NULL || s->tty_fd < 0 || !s->tty_attrs_saved) {
        return;
    }
    (void)tcsetattr(s->tty_fd, TCSAFLUSH, &s->tty_saved);
    s->tty_attrs_saved = false;
    if (g_tty_guard.tty_fd == s->tty_fd) {
        farsee_live_shell_tty_guard_note_attrs(false);
    }
}

void farsee_live_shell_input_enable(farsee_live_shell *s)
{
    if (s == NULL) {
        return;
    }
    // Write enable sequences to every terminal we use for I/O:
    //   - stdout (Kitty graphics surface)
    //   - dedicated input tty_fd when it is a different fd number
    //     (same device is fine — second write is idempotent)
    // Never write enables only to one and read the other if they differ.
    if (s->want_mouse) {
        const char *en = rfb_sgr_mouse_enable_seq();
        if (en != NULL) {
            const size_t n = strlen(en);
            if (isatty(STDOUT_FILENO)) {
                shell_write_all(STDOUT_FILENO, en, n);
            }
            if (s->tty_fd >= 0 && s->tty_fd != STDOUT_FILENO) {
                shell_write_all(s->tty_fd, en, n);
            }
            s->mouse_enabled = true;
        }
    }
    if (s->want_kitty_kb) {
        // flags 1|2 = disambiguate + event types (press/release CSI-u).
        static const char kitty_kb[] = "\033[>3u";
        if (isatty(STDOUT_FILENO)) {
            shell_write_all(STDOUT_FILENO, kitty_kb, sizeof(kitty_kb) - 1u);
        }
        if (s->tty_fd >= 0 && s->tty_fd != STDOUT_FILENO) {
            shell_write_all(s->tty_fd, kitty_kb, sizeof(kitty_kb) - 1u);
        }
    }
}

void farsee_live_shell_input_disable(farsee_live_shell *s)
{
    if (s == NULL) {
        return;
    }
    if (s->mouse_enabled) {
        const char *dis = rfb_sgr_mouse_disable_seq();
        if (dis != NULL) {
            shell_write_seq(dis);
        }
        s->mouse_enabled = false;
    }
    if (s->want_kitty_kb) {
        static const char kitty_kb_off[] = "\033[<u";
        shell_write_seq(kitty_kb_off);
    }
}

// ---------------------------------------------------------------------------
// Cursor / status
// ---------------------------------------------------------------------------

static void shell_io_lock(farsee_live_shell *s)
{
    if (s != NULL && s->io_mu != NULL) {
        farsee_mutex_lock(s->io_mu);
    }
}

static void shell_io_unlock(farsee_live_shell *s)
{
    if (s != NULL && s->io_mu != NULL) {
        farsee_mutex_unlock(s->io_mu);
    }
}

void farsee_live_shell_home_cursor(void)
{
    static const char home[] = "\033[H";
    shell_write_all(STDOUT_FILENO, home, sizeof(home) - 1u);
}

void farsee_live_shell_fix_status_rows(farsee_live_shell *s)
{
    if (s == NULL) {
        return;
    }
    uint16_t tr = 0u;
    (void)farsee_live_shell_get_term_geom(s, NULL, &tr, NULL, NULL);
    uint16_t rows = tr > 0u ? tr : 24u;
    uint64_t pack = farsee_atomic_u64_load(&s->place_cells);
    uint32_t pr_u = (uint32_t)(pack & 0xffffffffu);
    if (pr_u == 0u) {
        pr_u = s->place_rows;
    }
    uint16_t pr = pr_u > 0u ? (uint16_t)pr_u : 1u;
    uint16_t status = (uint16_t)(pr + 1u);
    if (status > rows) {
        status = rows;
    }
    if (status < 1u) {
        status = 1u;
    }
    farsee_atomic_int_store(&s->log_row, (int)status);
}

void farsee_live_shell_park_status_cursor(farsee_live_shell *s)
{
    if (s == NULL) {
        return;
    }
    int lr = farsee_atomic_int_load(&s->log_row);
    uint16_t row = lr > 0 ? (uint16_t)lr : 1u;
    char seq[24];
    int n = snprintf(seq, sizeof seq, "\033[%u;1H", (unsigned)row);
    if (n > 0 && (size_t)n < sizeof seq) {
        const size_t want = (size_t)n;
        if (farsee_live_shell_write_all(STDOUT_FILENO, seq, want) < want) {
            s->status_resync = true;
        }
    }
}

void farsee_live_shell_park_log_cursor(farsee_live_shell *s)
{
    if (s == NULL) {
        return;
    }
    // RFB: log line under status (status_rows >= 2). RDP: park on status.
    uint16_t tr = 0u;
    (void)farsee_live_shell_get_term_geom(s, NULL, &tr, NULL, NULL);
    uint16_t rows = tr > 0u ? tr : 24u;
    int lr = farsee_atomic_int_load(&s->log_row);
    uint16_t log = lr > 0 ? (uint16_t)lr : 1u;
    if (s->status_rows >= 2u) {
        log = (uint16_t)(log + 1u);
    }
    if (log > rows) {
        log = rows;
    }
    if (log < 1u) {
        log = 1u;
    }
    char seq[24];
    int n = snprintf(seq, sizeof seq, "\033[%u;1H", (unsigned)log);
    if (n > 0 && (size_t)n < sizeof seq) {
        const size_t want = (size_t)n;
        if (farsee_live_shell_write_all(STDOUT_FILENO, seq, want) < want) {
            s->status_resync = true;
        }
    }
}

void farsee_live_shell_draw_status(farsee_live_shell *s)
{
    if (s == NULL || !s->layout_active) {
        return;
    }
    // Prefer non-blocking so a full stdout pipe (present backpressure) cannot
    // stall the input thread on every status redraw. Original flags are
    // restored by farsee_live_shell_tty_guard_restore (T3).
    farsee_live_shell_stdio_nonblock_arm(STDOUT_FILENO);
    shell_io_lock(s);
    // Under the same mutex drain uses (write_mu == io_mu): skip CSI while
    // Kitty APC bytes remain (full2 T6). Checked only under lock.
    if (s->kitty != NULL && s->kitty->out != NULL &&
        rfb_buffer_length(s->kitty->out) > 0u) {
        shell_io_unlock(s);
        return;
    }
    if (!isatty(STDOUT_FILENO)) {
        shell_io_unlock(s);
        return;
    }
    farsee_live_shell_fix_status_rows(s);

    const char *proto =
        s->status_proto[0] != '\0' ? s->status_proto : "vnc";
    const char *host =
        s->status_host[0] != '\0' ? s->status_host : "?";
    unsigned port = s->status_port != 0u ? (unsigned)s->status_port : 0u;
    const char *L =
        s->leader.display[0] != '\0' ? s->leader.display : "C-]";

    char extra[128] = "";
    if (s->ops != NULL && s->ops->status_extra != NULL) {
        s->ops->status_extra(s->ops_user, extra, sizeof extra);
    }

    char line[384];
    int n;
    if (farsee_live_demux_leader_is_armed(&s->demux)) {
        if (s->show_suspend && s->show_zoom) {
            n = snprintf(
                line, sizeof line,
                "\033[38;5;214mfarsee:\033[0m \033[1m%s://%s:%u\033[0m"
                "  \033[38;5;214mleader…\033[0m"
                "  \033[2mq\033[0m quit"
                "  \033[2m+/-\033[0m zoom"
                "  \033[2mz\033[0m suspend"
                "  \033[2m%s\033[0m send"
                "  \033[2mesc\033[0m cancel%s",
                proto, host, port, L, extra);
        } else if (s->show_suspend) {
            n = snprintf(
                line, sizeof line,
                "\033[38;5;214mfarsee:\033[0m \033[1m%s://%s:%u\033[0m"
                "  \033[38;5;214mleader…\033[0m"
                "  \033[2mq\033[0m quit"
                "  \033[2mz\033[0m suspend"
                "  \033[2m%s\033[0m send"
                "  \033[2mesc\033[0m cancel%s",
                proto, host, port, L, extra);
        } else if (s->show_zoom) {
            n = snprintf(
                line, sizeof line,
                "\033[38;5;214mfarsee:\033[0m \033[1m%s://%s:%u\033[0m"
                "  \033[38;5;214mleader…\033[0m"
                "  \033[2mq\033[0m quit"
                "  \033[2m+/-\033[0m zoom"
                "  \033[2m%s\033[0m send"
                "  \033[2mesc\033[0m cancel%s",
                proto, host, port, L, extra);
        } else {
            n = snprintf(
                line, sizeof line,
                "\033[38;5;214mfarsee:\033[0m \033[1m%s://%s:%u\033[0m"
                "  \033[38;5;214mleader…\033[0m"
                "  \033[2mq\033[0m quit"
                "  \033[2m%s\033[0m send"
                "  \033[2mesc\033[0m cancel%s",
                proto, host, port, L, extra);
        }
    } else if (s->show_suspend && s->show_zoom) {
        n = snprintf(
            line, sizeof line,
            "\033[38;5;81mfarsee:\033[0m \033[1m%s://%s:%u\033[0m"
            "  \033[2m·\033[0m  \033[1m%s\033[0m \033[2mq\033[0m quit"
            "  \033[2m·\033[0m  \033[1m%s\033[0m \033[2m+/-\033[0m zoom"
            "  \033[2m·\033[0m  \033[1m%s\033[0m \033[2mz\033[0m suspend%s",
            proto, host, port, L, L, L, extra);
    } else if (s->show_suspend) {
        n = snprintf(
            line, sizeof line,
            "\033[38;5;81mfarsee:\033[0m \033[1m%s://%s:%u\033[0m"
            "  \033[2m·\033[0m  \033[1m%s\033[0m \033[2mq\033[0m quit"
            "  \033[2m·\033[0m  \033[1m%s\033[0m \033[2mz\033[0m suspend%s",
            proto, host, port, L, L, extra);
    } else if (s->show_zoom) {
        n = snprintf(
            line, sizeof line,
            "\033[38;5;81mfarsee:\033[0m \033[1m%s://%s:%u\033[0m"
            "  \033[2m·\033[0m  \033[1m%s\033[0m \033[2mq\033[0m quit"
            "  \033[2m·\033[0m  \033[1m%s\033[0m \033[2m+/-\033[0m zoom%s",
            proto, host, port, L, L, extra);
    } else {
        n = snprintf(
            line, sizeof line,
            "\033[38;5;81mfarsee:\033[0m \033[1m%s://%s:%u\033[0m"
            "  \033[2m·\033[0m  \033[1m%s\033[0m \033[2mq\033[0m quit%s",
            proto, host, port, L, extra);
    }
    // Compose park + clear + body (+ log park) into one write so a short
    // nonblocking write cannot land mid-CSI over the image (residual D4).
    {
        size_t wlen = farsee_live_shell_clamp_snprintf_len(n, sizeof line);
        if (n > 0 && (size_t)n >= sizeof line) {
            farsee_live_shell_ensure_ansi_reset(line, &wlen, sizeof line);
        }
        int lr = farsee_atomic_int_load(&s->log_row);
        unsigned status_row = lr > 0 ? (unsigned)lr : 1u;
        unsigned log_row = status_row;
        if (s->status_rows >= 2u) {
            log_row = status_row + 1u;
            uint16_t tr = 0u;
            (void)farsee_live_shell_get_term_geom(s, NULL, &tr, NULL, NULL);
            unsigned maxr = tr > 0u ? (unsigned)tr : 24u;
            if (log_row > maxr) {
                log_row = maxr;
            }
        }
        char band[512];
        size_t boff = 0u;
        if (s->status_resync) {
            // CAN aborts a partial CSI left by a prior short write.
            if (boff + 1u < sizeof band) {
                band[boff++] = '\x18';
            }
            s->status_resync = false;
        }
        int pn = snprintf(band + boff, sizeof band - boff, "\033[%u;1H\033[K",
                          status_row);
        if (pn > 0 && (size_t)pn < sizeof band - boff) {
            boff += (size_t)pn;
        }
        if (wlen > 0u && boff + wlen < sizeof band) {
            memcpy(band + boff, line, wlen);
            boff += wlen;
        }
        if (s->status_rows >= 2u) {
            pn = snprintf(band + boff, sizeof band - boff, "\033[%u;1H",
                          log_row);
            if (pn > 0 && (size_t)pn < sizeof band - boff) {
                boff += (size_t)pn;
            }
        }
        if (boff > 0u) {
            const size_t wrote =
                farsee_live_shell_write_all(STDOUT_FILENO, band, boff);
            if (wrote < boff) {
                s->status_resync = true;
            }
        }
    }
    shell_io_unlock(s);
}

// ---------------------------------------------------------------------------
// Layout / mouse
// ---------------------------------------------------------------------------

bool farsee_live_shell_refresh_layout(farsee_live_shell *s, bool apply_kitty)
{
    if (s == NULL || s->desk_w == 0u || s->desk_h == 0u) {
        return false;
    }
    // Layout shared with present (status park). Hold io_mu for place/disp/
    // origin/log_row writes; place also published as atomic pair.
    shell_io_lock(s);
    // Keep geometry atomics aligned with caches (writers should use
    // set_term_geom; this covers tests that touch caches only).
    {
        const uint16_t tc = s->term_cols > 0u ? s->term_cols : 80u;
        const uint16_t tr = s->term_rows > 0u ? s->term_rows : 24u;
        farsee_atomic_u64_store(&s->term_cells,
                                ((uint64_t)tc << 32) | (uint64_t)tr);
        farsee_atomic_u64_store(
            &s->term_px,
            ((uint64_t)s->term_pw << 32) | (uint64_t)s->term_ph);
    }
    const uint32_t old_pr = s->place_rows;
    const uint32_t old_pc = s->place_cols;
    farsee_term_layout L;
    memset(&L, 0, sizeof L);
    L.term_cols = s->term_cols > 0u ? s->term_cols : 80u;
    L.term_rows = s->term_rows > 0u ? s->term_rows : 24u;
    L.term_pw = s->term_pw;
    L.term_ph = s->term_ph;
    L.desk_w = s->desk_w;
    L.desk_h = s->desk_h;
    L.avail_cols = L.term_cols;
    if (L.term_rows > s->status_rows) {
        L.avail_rows = (uint16_t)(L.term_rows - s->status_rows);
    } else {
        L.avail_rows = 1u;
    }
    L.scale_pct = farsee_live_shell_view_scale(s);
    farsee_live_shell_set_view_scale(s, L.scale_pct);
    farsee_term_layout_aspect_fit(&L);
    s->place_cols = L.place_cols;
    s->place_rows = L.place_rows;
    {
        const uint64_t pack =
            ((uint64_t)L.place_cols << 32) | (uint64_t)L.place_rows;
        farsee_atomic_u64_store(&s->place_cells, pack);
    }
    s->disp_w_px = L.disp_w_px;
    s->disp_h_px = L.disp_h_px;
    s->img_origin_x = L.origin_x;
    s->img_origin_y = L.origin_y;
    farsee_live_shell_fix_status_rows(s);

    const bool changed =
        (old_pr != s->place_rows) || (old_pc != s->place_cols);

    // Always push place cells into the tile when attached (RDP resize path
    // used apply_kitty=false but still needs c/r updates).
    if (s->kitty != NULL) {
        rfb_kitty_tile_set_place_cells(s->kitty, s->place_cols, s->place_rows);
    }
    shell_io_unlock(s);
    if (apply_kitty) {
        if (s->kitty != NULL) {
            // Do not emit CSI while Kitty APC remainder is pending (T2).
            // Read length under io_mu directly — never call kitty_pending
            // while holding the lock (non-recursive; reaudit T1 deadlock).
            shell_io_lock(s);
            const bool pending =
                (s->kitty->out != NULL &&
                 rfb_buffer_length(s->kitty->out) > 0u);
            if (!pending) {
                if (changed || old_pr == 0u) {
                    static const char erase[] = "\033[1;1H\033[0J";
                    shell_write_all(STDOUT_FILENO, erase,
                                    sizeof(erase) - 1u);
                } else {
                    farsee_live_shell_home_cursor();
                }
            }
            shell_io_unlock(s);
        }
        // Always arm force_repaint on apply (zoom/layout), even before the
        // first Kitty attach — present loop re-shows same gen immediately.
        if (s->force_repaint != NULL) {
            farsee_atomic_int_store(s->force_repaint, 1);
        }
        if (s->ops != NULL && s->ops->on_layout_applied != NULL) {
            s->ops->on_layout_applied(s->ops_user);
        }
        if (s->layout_active) {
            farsee_live_shell_draw_status(s);
        }
    }
    return changed;
}

void farsee_live_shell_note_desk_size(farsee_live_shell *s, uint32_t w,
                                      uint32_t h)
{
    if (s == NULL || w == 0u || h == 0u) {
        return;
    }
    const uint64_t pack = ((uint64_t)w << 32) | (uint64_t)h;
    farsee_atomic_u64_store(&s->pending_desk, pack);
}

bool farsee_live_shell_apply_pending_desk(farsee_live_shell *s,
                                          bool apply_kitty)
{
    if (s == NULL) {
        return false;
    }
    // Claim pending pack with exchange so a concurrent note after load is
    // not wiped by store(0) (multi-review 2026-08-03 T5). If a newer note
    // races after exchange(0), it remains pending for the next apply.
    bool applied = false;
    for (int spins = 0; spins < 8; spins++) {
        const uint64_t pack = farsee_atomic_u64_exchange(&s->pending_desk, 0u);
        if (pack == 0u) {
            break;
        }
        const uint32_t w = (uint32_t)(pack >> 32);
        const uint32_t h = (uint32_t)(pack & 0xffffffffu);
        if (w == 0u || h == 0u) {
            continue;
        }
        if (s->desk_w == w && s->desk_h == h) {
            continue;
        }
        s->desk_w = w;
        s->desk_h = h;
        (void)farsee_live_shell_refresh_layout(s, apply_kitty);
        applied = true;
        // If present noted again while we refreshed, loop once more.
    }
    return applied;
}

bool farsee_live_shell_mouse_to_desktop(const farsee_live_shell *s, int32_t mx,
                                        int32_t my, int32_t *out_x,
                                        int32_t *out_y, bool *out_pixel_mode)
{
    if (out_x != NULL) {
        *out_x = 0;
    }
    if (out_y != NULL) {
        *out_y = 0;
    }
    if (out_pixel_mode != NULL) {
        *out_pixel_mode = false;
    }
    if (s == NULL) {
        return false;
    }
    farsee_term_layout L;
    memset(&L, 0, sizeof L);
    L.term_cols = s->term_cols;
    L.term_rows = s->term_rows;
    L.term_pw = s->term_pw;
    L.term_ph = s->term_ph;
    L.desk_w = s->desk_w;
    L.desk_h = s->desk_h;
    // Prefer packed place_cells so concurrent present cannot race plain
    // place_cols/rows caches (loop r1 T3).
    {
        const uint64_t packed = farsee_atomic_u64_load(&s->place_cells);
        const uint32_t pc = (uint32_t)(packed >> 32);
        const uint32_t pr = (uint32_t)(packed & 0xffffffffu);
        L.place_cols = (pc != 0u) ? pc : s->place_cols;
        L.place_rows = (pr != 0u) ? pr : s->place_rows;
    }
    L.disp_w_px = s->disp_w_px;
    L.disp_h_px = s->disp_h_px;
    L.origin_x = s->img_origin_x;
    L.origin_y = s->img_origin_y;
    // live_shell enables DECSET 1016 with mouse — reports are terminal pixels.
    L.sgr_pixel_coords = (s->mouse_enabled || s->want_mouse);
    farsee_term_layout_set_cell_size(&L);
    if (L.place_cols == 0u || L.place_rows == 0u || L.disp_w_px < 1 ||
        L.disp_h_px < 1) {
        L.avail_cols = s->term_cols > 0u ? s->term_cols : 80u;
        L.avail_rows = (s->term_rows > s->status_rows)
                           ? (uint16_t)(s->term_rows - s->status_rows)
                           : 1u;
        L.scale_pct = farsee_live_shell_view_scale(s);
        farsee_term_layout_aspect_fit(&L);
    }
    int32_t x = 0;
    int32_t y = 0;
    if (!farsee_term_mouse_to_desktop(&L, mx, my, &x, &y, out_pixel_mode)) {
        return false;
    }
    if (out_x != NULL) {
        *out_x = x;
    }
    if (out_y != NULL) {
        *out_y = y;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Leader / demux feed
// ---------------------------------------------------------------------------

void farsee_live_shell_do_leader_cmd(farsee_live_shell *s, rfb_leader_cmd cmd)
{
    if (s == NULL) {
        return;
    }
    // Demux already disarmed; product actions + status refresh.
    switch (cmd) {
    case RFB_LEADER_CMD_QUIT:
        if (s->ops != NULL && s->ops->request_quit != NULL) {
            s->ops->request_quit(s->ops_user);
        }
        break;
    case RFB_LEADER_CMD_PASS:
        if (s->ops != NULL && s->ops->inject_key != NULL && !s->view_only) {
            rfb_norm_key nk;
            memset(&nk, 0, sizeof nk);
            nk.keysym = s->leader.keysym;
            nk.modifiers = s->leader.mods;
            nk.down = true;
            nk.source = RFB_NORM_SOURCE_LEGACY;
            s->ops->inject_key(s->ops_user, &nk);
        }
        farsee_live_shell_draw_status(s);
        break;
    case RFB_LEADER_CMD_SUSPEND:
        if (s->ops != NULL && s->ops->suspend != NULL) {
            s->ops->suspend(s->ops_user);
        } else if (s->ops != NULL && s->ops->request_quit != NULL) {
            // Named residual: RFB has no job-control suspend — quit so the
            // session is never unescapable under a stuck present loop.
            s->ops->request_quit(s->ops_user);
        }
        farsee_live_shell_draw_status(s);
        break;
    case RFB_LEADER_CMD_ZOOM_IN:
        farsee_live_shell_zoom(s, (int)FARSEE_VIEW_SCALE_STEP_PCT);
        break;
    case RFB_LEADER_CMD_ZOOM_OUT:
        farsee_live_shell_zoom(s, -(int)FARSEE_VIEW_SCALE_STEP_PCT);
        break;
    case RFB_LEADER_CMD_CANCEL:
    case RFB_LEADER_CMD_NONE:
    default:
        farsee_live_shell_draw_status(s);
        break;
    }
}

void farsee_live_shell_zoom(farsee_live_shell *s, int delta_pct)
{
    if (s == NULL) {
        return;
    }
    if (s->ops != NULL && s->ops->zoom != NULL) {
        // Protocol owns scale policy when it supplies zoom (RFB).
        s->ops->zoom(s->ops_user, delta_pct);
        return;
    }
    // ops present but zoom NULL: status redraw only — do NOT mutate
    // view_scale_pct (protocol opted out of view-scale).
    if (s->ops != NULL) {
        farsee_live_shell_draw_status(s);
        return;
    }
    // Bare shell (no ops): adjust local view_scale + layout (unit/default).
    int32_t next =
        (int32_t)farsee_live_shell_view_scale(s) + delta_pct;
    if (next < (int32_t)FARSEE_VIEW_SCALE_MIN_PCT) {
        next = (int32_t)FARSEE_VIEW_SCALE_MIN_PCT;
    }
    if (next > (int32_t)FARSEE_VIEW_SCALE_MAX_PCT) {
        next = (int32_t)FARSEE_VIEW_SCALE_MAX_PCT;
    }
    if ((uint32_t)next == farsee_live_shell_view_scale(s)) {
        farsee_live_shell_draw_status(s);
        return;
    }
    farsee_live_shell_set_view_scale(s, (uint32_t)next);
    (void)farsee_live_shell_refresh_layout(s, /*apply_kitty=*/true);
}

static void shell_note_input(farsee_live_shell *s)
{
    if (s == NULL) {
        return;
    }
    uint64_t n = farsee_atomic_u64_fetch_add(&s->input_events, 1u) + 1u;
    // Throttled status redraw so link stats (RTT/KiB/s) refresh while the
    // user types/moves (present may not redraw every frame).
    if ((n % 8u) == 1u && s->layout_active) {
        farsee_live_shell_draw_status(s);
    }
}

static void shell_on_key(void *user, const rfb_norm_key *nk)
{
    farsee_live_shell *s = (farsee_live_shell *)user;
    if (s == NULL || nk == NULL) {
        return;
    }
    if (s->ops != NULL && s->ops->inject_key != NULL) {
        shell_note_input(s);
        s->ops->inject_key(s->ops_user, nk);
    }
}

static void shell_on_sgr(void *user, const rfb_sgr_event *ev, uint8_t buttons)
{
    farsee_live_shell *s = (farsee_live_shell *)user;
    if (s == NULL || ev == NULL || s->view_only) {
        return;
    }
    if (s->ops == NULL || s->ops->inject_pointer == NULL) {
        return;
    }
    int32_t x = 0;
    int32_t y = 0;
    if (!farsee_live_shell_mouse_to_desktop(s, ev->x, ev->y, &x, &y, NULL)) {
        // Outside place: never inject *presses* that clamp to the desk edge.
        // If buttons were held, still emit a release at the last good coords
        // so drag-out of the image does not leave the remote stuck.
        if (s->last_buttons != 0u) {
            shell_note_input(s);
            // Only clear last_buttons when release inject succeeds (T3).
            if (s->ops->inject_pointer(s->ops_user, s->last_desk_x,
                                       s->last_desk_y, 0u, 0, 0)) {
                s->last_buttons = 0u;
            }
        }
        return;
    }
    uint8_t btns = 0;
    if ((buttons & 1u) != 0u) {
        btns = (uint8_t)(btns | (uint8_t)FARSEE_BUTTON_LEFT);
    }
    if ((buttons & 2u) != 0u) {
        btns = (uint8_t)(btns | (uint8_t)FARSEE_BUTTON_MIDDLE);
    }
    if ((buttons & 4u) != 0u) {
        btns = (uint8_t)(btns | (uint8_t)FARSEE_BUTTON_RIGHT);
    }
    shell_note_input(s);
    if (s->ops->inject_pointer(s->ops_user, x, y, btns, (int)ev->wheel_v,
                               (int)ev->wheel_h)) {
        s->last_desk_x = x;
        s->last_desk_y = y;
        s->last_buttons = btns;
    }
}

static void shell_on_leader_cmd(void *user, rfb_leader_cmd cmd)
{
    farsee_live_shell_do_leader_cmd((farsee_live_shell *)user, cmd);
}

static void shell_on_leader_arm(void *user, bool armed)
{
    (void)armed;
    farsee_live_shell_draw_status((farsee_live_shell *)user);
}

static void shell_fill_ops(farsee_live_demux_ops *ops)
{
    memset(ops, 0, sizeof(*ops));
    ops->on_key = shell_on_key;
    ops->on_sgr = shell_on_sgr;
    ops->on_leader_cmd = shell_on_leader_cmd;
    ops->on_leader_arm = shell_on_leader_arm;
}

void farsee_live_shell_feed_tty(farsee_live_shell *s, const uint8_t *data,
                                size_t n, uint64_t now_ms)
{
    if (s == NULL) {
        return;
    }
    s->demux.view_only = s->view_only;
    farsee_live_demux_ops ops;
    shell_fill_ops(&ops);
    farsee_live_demux_feed(&s->demux, data, n, now_ms, &ops, s);
}

void farsee_live_shell_tick_timeout(farsee_live_shell *s, uint64_t now_ms)
{
    if (s == NULL) {
        return;
    }
    farsee_live_demux_ops ops;
    shell_fill_ops(&ops);
    farsee_live_demux_check_timeout(&s->demux, now_ms, &ops, s);
}
