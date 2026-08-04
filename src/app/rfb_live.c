// SPDX-License-Identifier: Apache-2.0
//
// Classic RFB live CLI: connect → MT (protocol / present / input).
// Shared TTY/demux/status/layout lives in live_shell; this file is inject
// ops + present + connect glue.

#include "app/rfb_live.h"
#include "app/live_shell.h"

#include "farsee/allocator.h"
#include "farsee/apple_postauth.h"
#include "farsee/buffer.h"
#include "farsee/error.h"
#include "farsee/cpu_probe.h"
#include "farsee/farsee_cmd_queue.h"
#include "farsee/farsee_frame_slot.h"
#include "farsee/farsee_input.h"
#include "farsee/farsee_mt_session.h"
#include "farsee/farsee_thread.h"
#include "farsee/kitty_tile.h"
#include "farsee/normalized_input.h"
#include "farsee/presenter.h"
#include "farsee/rfb_session.h"
#include "farsee/kitty_drain.h"
#include "farsee/secret.h"
#include "farsee/secret_fd.h"
#include "farsee/sgr_mouse.h"
#include "farsee/term_mouse_map.h"
#include "farsee/tty_posix.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

// Cooperative stop for SIGINT/SIGTERM (lock-free atomic; signal-safe store).
static farsee_atomic_int g_rfb_stop = 0;

// Async-signal-safe: atomic store only. TTY restore runs after the loop
// exits (farsee_live_shell_tty_guard_restore) and via atexit as a safety net.
void farsee_rfb_stop_flag_set(farsee_atomic_int *flag)
{
    farsee_atomic_int_store(flag, 1);
}

void farsee_rfb_request_stop(void)
{
    farsee_rfb_stop_flag_set(&g_rfb_stop);
}

static void rfb_on_signal(int sig)
{
    (void)sig;
    farsee_rfb_request_stop();
}

typedef enum {
    RFB_PRES_NULL = 0,
    RFB_PRES_DUMP,
    RFB_PRES_KITTY_SHM,
    RFB_PRES_KITTY_DIRECT,
} rfb_pres_kind;

static rfb_pres_kind resolve_presenter(const char *name, const char *dump_frame)
{
    if (dump_frame != NULL &&
        (name == NULL || strcmp(name, "auto") == 0 ||
         strcmp(name, "dump") == 0)) {
        return RFB_PRES_DUMP;
    }
    if (name == NULL || strcmp(name, "auto") == 0) {
        return isatty(STDOUT_FILENO) ? RFB_PRES_KITTY_SHM : RFB_PRES_NULL;
    }
    if (strcmp(name, "null") == 0) {
        return RFB_PRES_NULL;
    }
    if (strcmp(name, "dump") == 0) {
        return RFB_PRES_DUMP;
    }
    if (strcmp(name, "kitty-direct") == 0 || strcmp(name, "kitty") == 0) {
        return RFB_PRES_KITTY_DIRECT;
    }
    if (strcmp(name, "kitty-shm") == 0) {
        return RFB_PRES_KITTY_SHM;
    }
    return isatty(STDOUT_FILENO) ? RFB_PRES_KITTY_SHM : RFB_PRES_NULL;
}

// Live UI: shared shell + RFB inject state.
// RFB status_rows=2 (status + log). show_zoom; suspend → quit via NULL ops.
typedef struct rfb_live_ui {
    farsee_live_shell shell;
    farsee_live_shell_ops shell_ops;
    rfb_buffer *kitty_out;
    farsee_cmd_queue *cmds;
    uint16_t synth_mods;
    unsigned prev_buttons;
    farsee_frame_slot *slot;
    farsee_atomic_int *stop;
    rfb_session *sess; // borrowed; link snapshot only (T6)

} rfb_live_ui;

#define RFB_LIVE_STATUS_ROWS 2u

static bool rfb_input_debug(void)
{
    static int cached = -1;
    if (cached < 0) {
        const char *e = getenv("FARSEE_INPUT_DEBUG");
        cached = (e != NULL && e[0] != '\0') ? 1 : 0;
    }
    return cached != 0;
}

// Session setup / place / auth chatter (not errors). FARSEE_RFB_DEBUG or
// FARSEE_INPUT_DEBUG. Failures stay on stderr always.
static bool rfb_verbose_diag(void)
{
    static int cached = -1;
    if (cached < 0) {
        if (rfb_input_debug()) {
            cached = 1;
        } else {
            const char *e = getenv("FARSEE_RFB_DEBUG");
            cached = (e != NULL && e[0] != '\0') ? 1 : 0;
        }
    }
    return cached != 0;
}

static void rfb_live_log(rfb_live_ui *t, const char *fmt, ...)
#if defined(__GNUC__) || defined(__clang__)
    __attribute__((format(printf, 2, 3)))
#endif
    ;
static void rfb_live_log(rfb_live_ui *t, const char *fmt, ...)
{
    char body[384];
    va_list ap;
    va_start(ap, fmt);
    int bn = vsnprintf(body, sizeof body, fmt, ap);
    va_end(ap);
    if (bn < 0) {
        return;
    }
    while (bn > 0 && (body[bn - 1] == '\n' || body[bn - 1] == '\r')) {
        body[--bn] = '\0';
    }
    farsee_live_shell *sh = (t != NULL) ? &t->shell : NULL;
    if (sh != NULL && sh->layout_active && isatty(STDOUT_FILENO)) {
        // Prefer log band when Kitty is fully flushed; never drop the message
        // while APC is pending — fall through to stderr (post-t11 T6).
        // Read kitty length only under io_mu (non-recursive; do not call
        // kitty_pending while already holding the lock).
        bool wrote_stdout = false;
        if (sh->io_mu != NULL) {
            farsee_mutex_lock(sh->io_mu);
        }
        const bool pending =
            (sh->kitty != NULL && sh->kitty->out != NULL &&
             rfb_buffer_length(sh->kitty->out) > 0u);
        if (!pending) {
            farsee_live_shell_fix_status_rows(sh);
            farsee_live_shell_park_log_cursor(sh);
            char line[512];
            int ln = snprintf(line, sizeof line,
                              "\033[K\033[38;5;110m%s\033[0m", body);
            if (ln > 0 && (size_t)ln < sizeof line) {
                farsee_live_shell_write_all(STDOUT_FILENO, line, (size_t)ln);
                wrote_stdout = true;
            }
            farsee_live_shell_park_log_cursor(sh);
        }
        if (sh->io_mu != NULL) {
            farsee_mutex_unlock(sh->io_mu);
        }
        if (wrote_stdout) {
            return;
        }
        // Kitty pending: diagnostics on stderr under the same io_mu so we
        // do not race the drain's write(STDOUT) on a shared TTY (loop r1 T4).
        if (sh->io_mu != NULL) {
            farsee_mutex_lock(sh->io_mu);
        }
        flockfile(stderr);
        (void)fputs(body, stderr);
        if (bn == 0 || body[bn - 1] != '\n') {
            (void)fputc('\n', stderr);
        }
        (void)fflush(stderr);
        funlockfile(stderr);
        if (sh->io_mu != NULL) {
            farsee_mutex_unlock(sh->io_mu);
        }
        return;
    }
    flockfile(stderr);
    (void)fputs(body, stderr);
    if (bn == 0 || body[bn - 1] != '\n') {
        (void)fputc('\n', stderr);
    }
    (void)fflush(stderr);
    funlockfile(stderr);
}

static bool rfb_live_push_key(rfb_live_ui *t, uint32_t keysym, bool down)
{
    if (t == NULL || t->shell.view_only || t->cmds == NULL) {
        return false;
    }
    farsee_cmd c;
    memset(&c, 0, sizeof(c));
    c.kind = FARSEE_CMD_KEY;
    c.key.logical = keysym;
    c.key.action = down ? FARSEE_KEY_PRESS : FARSEE_KEY_RELEASE;
    c.key.quality = FARSEE_INPUT_QUALITY_INFERRED;
    const bool ok = farsee_cmd_queue_push(t->cmds, &c);
    if (rfb_input_debug()) {
        flockfile(stderr);
        fprintf(stderr, "farsee input: key %s keysym=0x%x ok=%d\n",
                down ? "down" : "up", (unsigned)keysym, ok ? 1 : 0);
        (void)fflush(stderr);
        funlockfile(stderr);
    }
    return ok;
}

static void rfb_live_synth_mods_down(rfb_live_ui *t, uint16_t need)
{
    if (t == NULL || need == 0u) {
        return;
    }
    // Only mark synth held after a successful push (T3).
    if ((need & RFB_MOD_SHIFT) != 0u &&
        (t->synth_mods & RFB_MOD_SHIFT) == 0u) {
        if (rfb_live_push_key(t, XK_Shift_L, true)) {
            t->synth_mods = (uint16_t)(t->synth_mods | RFB_MOD_SHIFT);
        }
    }
    if ((need & RFB_MOD_CONTROL) != 0u &&
        (t->synth_mods & RFB_MOD_CONTROL) == 0u) {
        if (rfb_live_push_key(t, XK_Control_L, true)) {
            t->synth_mods = (uint16_t)(t->synth_mods | RFB_MOD_CONTROL);
        }
    }
    if ((need & RFB_MOD_ALT) != 0u && (t->synth_mods & RFB_MOD_ALT) == 0u) {
        if (rfb_live_push_key(t, XK_Alt_L, true)) {
            t->synth_mods = (uint16_t)(t->synth_mods | RFB_MOD_ALT);
        }
    }
    if ((need & RFB_MOD_META) != 0u && (t->synth_mods & RFB_MOD_META) == 0u) {
        if (rfb_live_push_key(t, XK_Super_L, true)) {
            t->synth_mods = (uint16_t)(t->synth_mods | RFB_MOD_META);
        }
    }
}

static void rfb_live_synth_mods_up(rfb_live_ui *t)
{
    if (t == NULL || t->synth_mods == 0u) {
        return;
    }
    // Clear each bit only when the up push succeeds (T3).
    if ((t->synth_mods & RFB_MOD_META) != 0u) {
        if (rfb_live_push_key(t, XK_Super_L, false)) {
            t->synth_mods = (uint16_t)(t->synth_mods & ~RFB_MOD_META);
        }
    }
    if ((t->synth_mods & RFB_MOD_ALT) != 0u) {
        if (rfb_live_push_key(t, XK_Alt_L, false)) {
            t->synth_mods = (uint16_t)(t->synth_mods & ~RFB_MOD_ALT);
        }
    }
    if ((t->synth_mods & RFB_MOD_CONTROL) != 0u) {
        if (rfb_live_push_key(t, XK_Control_L, false)) {
            t->synth_mods = (uint16_t)(t->synth_mods & ~RFB_MOD_CONTROL);
        }
    }
    if ((t->synth_mods & RFB_MOD_SHIFT) != 0u) {
        if (rfb_live_push_key(t, XK_Shift_L, false)) {
            t->synth_mods = (uint16_t)(t->synth_mods & ~RFB_MOD_SHIFT);
        }
    }
}

// Inject a normalized key to RFB. Kitty CSI-u chords synthesize Left-Control
// (etc.) so the remote does not see plain 'a'/'e'.
static void rfb_live_inject_norm_key(rfb_live_ui *t, const rfb_norm_key *nk)
{
    if (t == NULL || nk == NULL) {
        return;
    }
    const rfb_modkey mk = rfb_norm_modkey_from_sym(nk->keysym);
    if (mk != RFB_MODKEY_NONE) {
        rfb_live_push_key(t, nk->keysym, nk->down);
        return;
    }

    const uint16_t physical = rfb_norm_mods_bits(&t->shell.demux.mods);
    const uint16_t held = (uint16_t)(physical | t->synth_mods);
    const uint16_t need = rfb_norm_mods_need_synth(nk->modifiers, held);

    if (nk->down) {
        rfb_live_synth_mods_down(t, need);
        rfb_live_push_key(t, nk->keysym, true);
        if (!nk->repeat && nk->source != RFB_NORM_SOURCE_KITTY) {
            rfb_live_push_key(t, nk->keysym, false);
            rfb_live_synth_mods_up(t);
        }
    } else {
        rfb_live_push_key(t, nk->keysym, false);
        rfb_live_synth_mods_up(t);
    }
}

static bool rfb_live_push_pointer(rfb_live_ui *t, int32_t x, int32_t y,
                                  unsigned buttons, int32_t wheel_v,
                                  int32_t wheel_h)
{
    if (t == NULL || t->shell.view_only || t->cmds == NULL) {
        return false;
    }
    farsee_cmd c;
    memset(&c, 0, sizeof(c));
    c.kind = FARSEE_CMD_POINTER;
    c.pe.abs_x = x;
    c.pe.abs_y = y;
    c.pe.buttons = buttons;
    c.pe.wheel_v = wheel_v;
    c.pe.wheel_h = wheel_h;
    c.pe.quality = FARSEE_INPUT_QUALITY_INFERRED;
    c.prev_buttons = t->prev_buttons;
    // Only advance local button state after a successful push so a refused
    // release under a full queue does not strand the remote drag (full2 T2).
    const bool ok = farsee_cmd_queue_push(t->cmds, &c);
    if (ok) {
        t->prev_buttons = buttons;
    }
    if (rfb_input_debug()) {
        flockfile(stderr);
        fprintf(stderr,
                "farsee input: pointer %d,%d buttons=0x%x wheel=%d,%d ok=%d\n",
                (int)x, (int)y, buttons, (int)wheel_v, (int)wheel_h, ok ? 1 : 0);
        (void)fflush(stderr);
        funlockfile(stderr);
    }
    return ok;
}

static void rfb_live_request_quit(rfb_live_ui *t)
{
    if (t != NULL && t->stop != NULL) {
        farsee_atomic_int_store(t->stop, 1);
    }
    farsee_atomic_int_store(&g_rfb_stop, 1);
}

static void rfb_live_zoom(rfb_live_ui *t, int delta_pct)
{
    if (t == NULL) {
        return;
    }
    farsee_live_shell *sh = &t->shell;
    int32_t next =
        (int32_t)farsee_live_shell_view_scale(sh) + delta_pct;
    if (next < (int32_t)FARSEE_VIEW_SCALE_MIN_PCT) {
        next = (int32_t)FARSEE_VIEW_SCALE_MIN_PCT;
    }
    if (next > (int32_t)FARSEE_VIEW_SCALE_MAX_PCT) {
        next = (int32_t)FARSEE_VIEW_SCALE_MAX_PCT;
    }
    if ((uint32_t)next == farsee_live_shell_view_scale(sh)) {
        rfb_live_log(t, "view scale already %u%%\n",
                     (unsigned)farsee_live_shell_view_scale(sh));
        return;
    }
    farsee_live_shell_set_view_scale(sh, (uint32_t)next);
    // Clear ops.zoom temporarily so shell_zoom default path is not used —
    // we call refresh directly (ops.zoom is this function).
    (void)farsee_live_shell_refresh_layout(sh, /*apply_kitty=*/true);
    rfb_live_log(t, "view scale %u%%  (%ux%u cells)\n",
                 (unsigned)farsee_live_shell_view_scale(sh), (unsigned)sh->place_cols,
                 (unsigned)sh->place_rows);
}

// --- shell ops -------------------------------------------------------------

static void rfb_shell_inject_key(void *u, const rfb_norm_key *nk)
{
    rfb_live_inject_norm_key((rfb_live_ui *)u, nk);
}

static bool rfb_shell_inject_pointer(void *u, int32_t x, int32_t y,
                                     uint8_t buttons, int wv, int wh)
{
    return rfb_live_push_pointer((rfb_live_ui *)u, x, y, buttons, wv, wh);
}

static void rfb_shell_request_quit(void *u)
{
    rfb_live_request_quit((rfb_live_ui *)u);
}

static void rfb_shell_zoom(void *u, int delta_pct)
{
    rfb_live_zoom((rfb_live_ui *)u, delta_pct);
}

// RFB has no job-control suspend — leave NULL so shell maps SUSPEND → quit
// (named product decision; see live_shell do_leader_cmd).

static void rfb_shell_status_extra(void *u, char *buf, size_t cap)
{
    rfb_live_ui *t = (rfb_live_ui *)u;
    if (t == NULL || buf == NULL || cap == 0u) {
        return;
    }
    uint32_t rtt = 0u;
    bool have_rtt = false;
    uint32_t rate_kib = 0u;
    bool have_rate = false;
    // Atomics only — rate latched on protocol thread (loop r3 T1).
    rfb_session_link_snapshot_ex(t->sess, &rtt, &have_rtt, NULL, NULL,
                                 &rate_kib, &have_rate);
    char link[96];
    farsee_live_shell_format_link_extra(
        link, sizeof link, farsee_live_shell_view_scale(&t->shell), rtt,
        have_rtt, rate_kib, have_rate);
    if (rfb_verbose_diag()) {
        (void)snprintf(buf, cap, "%s  \033[2min=%llu\033[0m", link,
                       (unsigned long long)farsee_atomic_u64_load(
                           &t->shell.input_events));
    } else {
        (void)snprintf(buf, cap, "%s", link);
    }
}

static void rfb_shell_on_layout_applied(void *u)
{
    rfb_live_ui *t = (rfb_live_ui *)u;
    if (t != NULL && t->slot != NULL) {
        farsee_frame_slot_kick(t->slot);
    }
}

static void rfb_live_bind_shell_ops(rfb_live_ui *t)
{
    memset(&t->shell_ops, 0, sizeof(t->shell_ops));
    t->shell_ops.inject_key = rfb_shell_inject_key;
    t->shell_ops.inject_pointer = rfb_shell_inject_pointer;
    t->shell_ops.request_quit = rfb_shell_request_quit;
    t->shell_ops.zoom = rfb_shell_zoom;
    t->shell_ops.suspend = NULL; // → quit via shell fallback
    t->shell_ops.status_extra = rfb_shell_status_extra;
    t->shell_ops.on_layout_applied = rfb_shell_on_layout_applied;
    t->shell.ops = &t->shell_ops;
    t->shell.ops_user = t;
}

static void rfb_live_process_input(rfb_live_ui *t, const uint8_t *data, size_t n)
{
    if (t == NULL) {
        return;
    }
    farsee_live_shell_feed_tty(&t->shell, data, n, farsee_thread_monotonic_ms());
}

static void rfb_live_input_fn(void *user, farsee_cmd_queue *cmds,
                              farsee_atomic_int *stop)
{
    rfb_live_ui *t = (rfb_live_ui *)user;
    if (t == NULL) {
        return;
    }
    t->cmds = cmds;
    t->stop = stop;
    uint64_t last_winsize_ms = 0;
    farsee_cpu_probe probe;
    farsee_cpu_probe_begin(&probe, "input");
    farsee_cpu_probe_attach(&probe);
    while (!farsee_atomic_int_load_nonzero(stop)) {
        if (farsee_atomic_int_load_nonzero(&g_rfb_stop)) {
            break;
        }
        farsee_live_shell *sh = &t->shell;
        const uint64_t now_in = farsee_thread_monotonic_ms();
        // DesktopSize + winsize + idle status without requiring input TTY (r4).
        (void)farsee_live_shell_apply_pending_desk(sh, /*apply_kitty=*/true);
        {
            if (last_winsize_ms == 0u || now_in - last_winsize_ms >= 250u) {
                last_winsize_ms = now_in;
                uint16_t cols = 0u;
                uint16_t rows = 0u;
                uint16_t pw = 0u;
                uint16_t ph = 0u;
                if (farsee_live_shell_probe_winsize(sh->tty_fd, &cols, &rows,
                                                    &pw, &ph)) {
                    const bool resized =
                        (sh->term_cols != cols || sh->term_rows != rows ||
                         sh->term_pw != pw || sh->term_ph != ph);
                    farsee_live_shell_set_term_geom(sh, cols, rows, pw, ph);
                    if (resized && sh->layout_active) {
                        (void)farsee_live_shell_refresh_layout(
                            sh, /*apply_kitty=*/true);
                    }
                }
            }
        }
        {
            static _Thread_local uint64_t last_link_status_ms;
            if (sh->layout_active &&
                (last_link_status_ms == 0u ||
                 now_in - last_link_status_ms >= 500u)) {
                last_link_status_ms = now_in;
                farsee_live_shell_draw_status(sh);
            }
        }
        if (sh->tty_fd < 0) {
            struct pollfd dummy;
            memset(&dummy, 0, sizeof(dummy));
            int pr = poll(&dummy, 0, 20);
            farsee_cpu_probe_poll(&probe, pr);
            farsee_cpu_probe_loop(&probe);
            continue;
        }
        farsee_live_shell_tick_timeout(sh, now_in);
        const int timeout_ms = 20;
        const uint64_t t0 = farsee_thread_monotonic_ms();
        struct pollfd pfd;
        memset(&pfd, 0, sizeof(pfd));
        pfd.fd = sh->tty_fd;
        pfd.events = POLLIN;
        int pr = poll(&pfd, 1, timeout_ms);
        farsee_cpu_probe_poll(&probe, pr);
        if (pr < 0) {
            if (errno == EINTR) {
                farsee_cpu_probe_loop(&probe);
                continue;
            }
            break;
        }
        size_t got = 0;
        if (pr > 0 && (pfd.revents & POLLIN) != 0) {
            uint8_t buf[1024];
            for (;;) {
                ssize_t n = read(sh->tty_fd, buf, sizeof(buf));
                if (n > 0) {
                    got += (size_t)n;
                    if (rfb_input_debug() && got == (size_t)n) {
                        fprintf(stderr,
                                "farsee input: read %zd bytes (first=0x%02x)\n",
                                n, (unsigned)buf[0]);
                        (void)fflush(stderr);
                    }
                    rfb_live_process_input(t, buf, (size_t)n);
                    continue;
                }
                if (n == -1 && errno == EINTR) {
                    continue;
                }
                break;
            }
        }
        if (got == 0u && timeout_ms > 0) {
            const uint64_t elapsed = farsee_thread_monotonic_ms() - t0;
            if (elapsed < (uint64_t)timeout_ms) {
                const int rem = (int)((uint64_t)timeout_ms - elapsed);
                (void)poll(NULL, 0, rem);
            }
        }
        if (pr > 0 && got == 0u &&
            (pfd.revents & (POLLHUP | POLLERR | POLLNVAL)) != 0) {
            (void)poll(NULL, 0, timeout_ms);
        }
        farsee_cpu_probe_loop(&probe);
    }
    farsee_cpu_probe_detach();
    t->cmds = NULL;
}

typedef struct rfb_live_present_ctx {
    rfb_presenter *presenter;
    rfb_buffer *kitty_out;
    rfb_live_ui *ui;
    bool opened;
    uint32_t open_w;
    uint32_t open_h;
    uint64_t last_gen; // present-thread only
    uint64_t present_count;
    uint32_t interval_ms;
    farsee_atomic_int force_repaint; // zoom/layout: re-show same gen
    // One home CSI per APC batch (D2 residual: no re-prepend after full home)
    bool need_home;
} rfb_live_present_ctx;

static bool rfb_live_on_frame(void *user, const farsee_frame_view *v)
{
    rfb_live_present_ctx *p = (rfb_live_present_ctx *)user;
    if (p == NULL || p->presenter == NULL || v == NULL || v->pixels == NULL) {
        return false;
    }
    if (v->format != FARSEE_PIXEL_RGBA8888 &&
        v->format != FARSEE_PIXEL_RGBX8888) {
        return false;
    }
    rfb_framebuffer fb;
    memset(&fb, 0, sizeof(fb));
    fb.rgba = (uint8_t *)(uintptr_t)v->pixels;
    fb.width = v->w;
    fb.height = v->h;
    fb.stride = v->stride;
    fb.generation = v->gen;
    if (!p->opened) {
        if (rfb_presenter_open(p->presenter, &fb) != 0) {
            return false;
        }
        p->opened = true;
        p->open_w = v->w;
        p->open_h = v->h;
    } else if (v->w != p->open_w || v->h != p->open_h) {
        if (rfb_presenter_resize(p->presenter, &fb) != 0) {
            return false;
        }
        p->open_w = v->w;
        p->open_h = v->h;
        // DesktopSize (or peer resize): present only notes geometry; input
        // thread applies desk + refresh (layout ownership T7).
        if (p->ui != NULL) {
            farsee_live_shell_note_desk_size(&p->ui->shell, v->w, v->h);
        }
    }
    rfb_rect full = {
        .x = 0,
        .y = 0,
        .width = v->w,
        .height = v->h,
    };
    rfb_damage_batch batch = {
        .rects = &full,
        .count = 1,
        .full_frame = true,
        .framebuffer_generation = v->gen,
    };
    // Arm home only when present starts from an empty buffer so a residual
    // ESC_G after a fully-written home is not re-homed (r3 F2). Continuous
    // non-empty residual relies on C=1 cursor keep / prior home.
    farsee_mutex *kmu =
        (p->ui != NULL) ? p->ui->shell.io_mu : NULL;
    if (kmu != NULL) {
        farsee_mutex_lock(kmu);
    }
    const size_t kitty_before =
        (p->kitty_out != NULL) ? rfb_buffer_length(p->kitty_out) : 0u;
    if (rfb_presenter_present(p->presenter, &fb, &batch) != 0) {
        if (kmu != NULL) {
            farsee_mutex_unlock(kmu);
        }
        if (p->present_count < 4u) {
            fprintf(stderr,
                    "farsee: Kitty present failed gen=%llu %ux%u "
                    "(SHM/direct encode error)\n",
                    (unsigned long long)v->gen, (unsigned)v->w,
                    (unsigned)v->h);
            (void)fflush(stderr);
        }
        return false;
    }
    if (kitty_before == 0u && p->kitty_out != NULL) {
        const uint8_t *d = rfb_buffer_data(p->kitty_out);
        const size_t n = rfb_buffer_length(p->kitty_out);
        if (d != NULL && n >= 3u && d[0] == 0x1Bu && d[1] == (uint8_t)'_' &&
            d[2] == (uint8_t)'G') {
            p->need_home = true;
        }
    }
    if (kmu != NULL) {
        farsee_mutex_unlock(kmu);
    }
    p->last_gen = v->gen;
    p->present_count++;
    // First-frame sample_nz only under verbose diag (log row; never bare
    // fprintf(stderr) — that lands on the status cursor and garbles it).
    if (rfb_verbose_diag() && p->present_count <= 3u && p->ui != NULL) {
        size_t nz = 0;
        const uint32_t step = 32u;
        for (uint32_t y = 0; y < v->h; y += step) {
            for (uint32_t x = 0; x < v->w; x += step) {
                const uint8_t *px =
                    v->pixels + (size_t)y * (size_t)v->stride +
                    (size_t)x * 4u;
                if (px[0] | px[1] | px[2]) {
                    nz++;
                }
            }
        }
        rfb_live_log(p->ui,
                     "Kitty present #%llu gen=%llu sample_nz=%zu\n",
                     (unsigned long long)p->present_count,
                     (unsigned long long)v->gen, nz);
    }
    return true;
}

static void rfb_live_after_present(void *user)
{
    rfb_live_present_ctx *p = (rfb_live_present_ctx *)user;
    if (p == NULL || p->kitty_out == NULL) {
        return;
    }
    farsee_live_shell *sh = (p->ui != NULL) ? &p->ui->shell : NULL;
    // Idle static desktop: no residual Kitty bytes → skip all CSI so we do
    // not spam home/status at present FPS (post-t11 T4). Length under io_mu
    // when available (reaudit T8).
    if (sh != NULL && sh->io_mu != NULL) {
        farsee_mutex_lock(sh->io_mu);
        const bool empty = rfb_buffer_length(p->kitty_out) == 0u;
        farsee_mutex_unlock(sh->io_mu);
        if (empty) {
            return;
        }
    } else if (rfb_buffer_length(p->kitty_out) == 0u) {
        return;
    }
    // One home per APC batch: prepend under lock only if need_home (D2
    // residual — do not re-home after full home write left ESC_G residual).
    farsee_live_shell_stdio_nonblock_arm(STDOUT_FILENO);
    static const char home[] = "\033[H";
    const char *prefix = NULL;
    size_t prefix_len = 0u;
    if (p->need_home) {
        prefix = home;
        prefix_len = sizeof(home) - 1u;
    }
    const bool drained = farsee_drain_kitty_out_with_prefix(
        p->kitty_out, STDOUT_FILENO, (sh != NULL) ? sh->io_mu : NULL, prefix,
        prefix_len);
    // Full drain → next APC batch needs home; partial residual → no re-home.
    p->need_home = drained;
    if (sh != NULL && sh->layout_active && drained) {
        const bool refresh_status =
            (p->present_count <= 3u) || ((p->present_count % 15u) == 0u);
        if (refresh_status) {
            farsee_live_shell_draw_status(sh);
            return;
        }
        if (sh->io_mu != NULL) {
            farsee_mutex_lock(sh->io_mu);
        }
        farsee_live_shell_fix_status_rows(sh);
        farsee_live_shell_park_log_cursor(sh);
        if (sh->io_mu != NULL) {
            farsee_mutex_unlock(sh->io_mu);
        }
    }
}

static void rfb_live_present_fn(void *user, farsee_frame_slot *slot,
                                farsee_atomic_int *stop)
{
    rfb_live_present_ctx *p = (rfb_live_present_ctx *)user;
    const uint32_t interval =
        (p != NULL && p->interval_ms > 0u) ? p->interval_ms : 33u;
    farsee_mt_present_loop(slot, stop, interval, rfb_live_on_frame, p,
                           rfb_live_after_present, p,
                           p != NULL ? &p->force_repaint : NULL);
}

static void rfb_live_protocol_fn(void *user, farsee_frame_slot *slot,
                                 farsee_cmd_queue *cmds,
                                 farsee_atomic_int *stop)
{
    rfb_session *s = (rfb_session *)user;
    (void)slot;
    (void)cmds;
    (void)stop;
    rfb_session_protocol_loop(s);
}

// Interactive password: controlling TTY + echo off.
static bool prompt_password_tty(char **out_buf, size_t *out_len)
{
    if (out_buf == NULL || out_len == NULL) {
        return false;
    }
    *out_buf = NULL;
    *out_len = 0;

    int tty = open("/dev/tty", O_RDWR | O_NOCTTY);
    if (tty < 0) {
        return false;
    }

    struct termios old_t;
    struct termios raw_t;
    bool attrs_ok = (tcgetattr(tty, &old_t) == 0);
    if (attrs_ok) {
        raw_t = old_t;
        raw_t.c_lflag &= (tcflag_t) ~(ECHO | ECHONL | ICANON);
        raw_t.c_cc[VMIN] = 1;
        raw_t.c_cc[VTIME] = 0;
        (void)tcsetattr(tty, TCSAFLUSH, &raw_t);
    }

    static const char prompt[] = "Password: ";
    (void)write(tty, prompt, sizeof(prompt) - 1u);

    char line[256];
    size_t n = 0;
    for (;;) {
        char ch = 0;
        ssize_t r = read(tty, &ch, 1);
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            n = 0;
            break;
        }
        if (r == 0) {
            break;
        }
        if (ch == '\n' || ch == '\r') {
            break;
        }
        if ((ch == 0x7f || ch == 0x08) && n > 0) {
            n--;
            continue;
        }
        if (ch < 0x20) {
            continue;
        }
        if (n + 1u < sizeof line) {
            line[n++] = ch;
        }
    }
    (void)write(tty, "\n", 1);

    if (attrs_ok) {
        (void)tcsetattr(tty, TCSAFLUSH, &old_t);
    }
    close(tty);

    char *buf = (char *)malloc(n + 1u);
    if (buf == NULL) {
        rfb_secret_zero(line, sizeof line);
        return false;
    }
    if (n > 0) {
        memcpy(buf, line, n);
    }
    buf[n] = '\0';
    rfb_secret_zero(line, sizeof line);
    *out_buf = buf;
    *out_len = n;
    return true;
}

static void desktop_label_from_server_name(const char *raw, char *out,
                                           size_t out_cap)
{
    if (out == NULL || out_cap == 0u) {
        return;
    }
    out[0] = '\0';
    if (raw == NULL) {
        return;
    }
    size_t best_i = 0;
    size_t best_n = 0;
    size_t i = 0;
    while (raw[i] != '\0') {
        while (raw[i] != '\0' &&
               ((unsigned char)raw[i] < 0x20u ||
                (unsigned char)raw[i] > 0x7eu)) {
            i++;
        }
        size_t start = i;
        while (raw[i] != '\0' && (unsigned char)raw[i] >= 0x20u &&
               (unsigned char)raw[i] <= 0x7eu) {
            i++;
        }
        size_t n = i - start;
        if (n > best_n) {
            best_n = n;
            best_i = start;
        }
    }
    if (best_n < 3u) {
        return;
    }
    if (best_n >= out_cap) {
        best_n = out_cap - 1u;
    }
    memcpy(out, raw + best_i, best_n);
    out[best_n] = '\0';
}

static bool prompt_apple_attach_tty(const char *desktop_name,
                                    const char *username, uint8_t *out_attach)
{
    if (out_attach == NULL) {
        return false;
    }
    *out_attach = APPLE_ATTACH_LOGIN;

    int tty = open("/dev/tty", O_RDWR | O_NOCTTY);
    if (tty < 0) {
        return false;
    }

    const char *user =
        (username != NULL && username[0] != '\0') ? username : "yourself";
    char owner[96];
    desktop_label_from_server_name(desktop_name, owner, sizeof owner);

    char prompt[512];
    int pn;
    if (owner[0] != '\0') {
        pn = snprintf(
            prompt, sizeof prompt,
            "\"%s\" is currently using the display.\n"
            "How would you like to connect?\n"
            "  [s] Share the display\n"
            "  [L] Log in as yourself: \"%s\"  (default)\n"
            "Choice [s/L]: ",
            owner, user);
    } else {
        pn = snprintf(
            prompt, sizeof prompt,
            "macOS display attach mode (like Screen Sharing):\n"
            "  [s] Share the display  (console session)\n"
            "  [L] Log in as \"%s\"  (your own virtual session — default)\n"
            "Choice [s/L]: ",
            user);
    }
    if (pn > 0) {
        (void)write(tty, prompt, (size_t)pn);
    }

    char ch = 0;
    for (;;) {
        ssize_t r = read(tty, &ch, 1);
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            close(tty);
            return false;
        }
        if (r == 0) {
            close(tty);
            return false;
        }
        if (ch == '\n' || ch == '\r') {
            *out_attach = APPLE_ATTACH_LOGIN;
            break;
        }
        if (ch == 's' || ch == 'S' || ch == '1') {
            *out_attach = APPLE_ATTACH_SHARE;
            (void)write(tty, "\n", 1);
            break;
        }
        if (ch == 'l' || ch == 'L' || ch == '2') {
            *out_attach = APPLE_ATTACH_LOGIN;
            (void)write(tty, "\n", 1);
            break;
        }
    }
    close(tty);
    return true;
}

static bool apple_attach_choose_cb(void *ctx, const char *desktop_name,
                                   const char *username, uint8_t *out_attach)
{
    (void)ctx;
    if (!prompt_apple_attach_tty(desktop_name, username, out_attach)) {
        return false;
    }
    if (rfb_verbose_diag()) {
        fprintf(stderr, "farsee: apple-attach=%s\n",
                (out_attach != NULL && *out_attach == APPLE_ATTACH_LOGIN)
                    ? "login"
                    : "share");
        (void)fflush(stderr);
    }
    return true;
}

int farsee_run_rfb(const char *host, uint16_t port,
                   const char *username,
                   int password_fd,
                   const char *password_inline, bool allow_none_auth,
                   bool shared, uint8_t apple_attach,
                   farsee_rfb_auth_mode auth_mode,
                   const char *presenter_name, const char *dump_frame,
                   uint32_t max_fps, bool view_only,
                   const farsee_cli_leader *leader,
                   uint32_t view_scale_pct,
                   uint32_t connect_timeout_ms)
{
    if (host == NULL || host[0] == '\0') {
        fprintf(stderr, "farsee: missing host argument\n");
        return 2;
    }
    if (port == 0) {
        port = 5900;
    }

    const bool apple_likely =
        (auth_mode == FARSEE_AUTH_MODE_APPLE ||
         auth_mode == FARSEE_AUTH_MODE_AUTO);

    char *pwbuf = NULL;
    size_t pwlen = 0;
    size_t pw_alloc = 0; // full allocation capacity for wipe-before-free
    if (password_fd >= 0) {
        long n = farsee_read_fd_secret(password_fd, &pwbuf,
                                       FARSEE_SECRET_FD_DEFAULT_CAP);
        if (n < 0) {
            fprintf(stderr, "farsee: failed to read password from fd %d\n",
                    password_fd);
            return 2;
        }
        pwlen = (size_t)n;
        pw_alloc = FARSEE_SECRET_FD_DEFAULT_CAP;
        if (!apple_likely) {
            pwlen = rfb_secret_trunc_vnc8(pwbuf, pwlen, pw_alloc);
        }
    } else if (password_inline != NULL && password_inline[0] != '\0') {
        size_t raw_len = strlen(password_inline);
        if (raw_len > 256u) {
            raw_len = 256u;
        }
        pw_alloc = raw_len + 1u;
        pwbuf = (char *)malloc(pw_alloc);
        if (pwbuf == NULL) {
            return 2;
        }
        memcpy(pwbuf, password_inline, raw_len);
        pwbuf[raw_len] = '\0';
        pwlen = raw_len;
        if (!apple_likely) {
            pwlen = rfb_secret_trunc_vnc8(pwbuf, pwlen, pw_alloc);
        }
    } else if (!allow_none_auth) {
        if (!prompt_password_tty(&pwbuf, &pwlen)) {
            fprintf(stderr, "farsee: password required "
                            "(prompt on /dev/tty failed — try "
                            "--password-fd or interactive TTY prompt)\n");
            return 2;
        }
        // prompt_password_tty allocates n+1; track full capacity for wipe.
        pw_alloc = pwlen + 1u;
        if (pwlen == 0) {
            fprintf(stderr, "farsee: empty password refused "
                            "(use --allow-none-auth only for security type "
                            "None)\n");
            rfb_secret_wipe_free(pwbuf, pw_alloc);
            pwbuf = NULL;
            return 2;
        }
        if (!apple_likely) {
            pwlen = rfb_secret_trunc_vnc8(pwbuf, pwlen, pw_alloc);
        }
    }

    const rfb_pres_kind pkind = resolve_presenter(presenter_name, dump_frame);
    const bool live_kitty =
        (pkind == RFB_PRES_KITTY_SHM || pkind == RFB_PRES_KITTY_DIRECT);
    bool live_interactive = false;
    if (live_kitty && isatty(STDOUT_FILENO)) {
        int t = open("/dev/tty", O_RDWR | O_NOCTTY);
        if (t >= 0) {
            live_interactive = true;
            close(t);
        }
    }

    rfb_presenter_dump dump;
    rfb_presenter_null nul;
    rfb_kitty_tile kitty;
    rfb_buffer kitty_out;
    bool kitty_out_live = false;
    rfb_presenter v1;
    memset(&v1, 0, sizeof(v1));

    if (pkind == RFB_PRES_DUMP) {
        if (dump_frame == NULL) {
            fprintf(stderr, "farsee: --dump-frame required for dump presenter\n");
            rfb_secret_wipe_free(pwbuf, pw_alloc > 0u ? pw_alloc : pwlen + 1u);
            pwbuf = NULL;
            return 2;
        }
        rfb_presenter_dump_init(&dump, dump_frame, false);
        v1 = (rfb_presenter){.ops = &rfb_presenter_dump_ops, .ctx = &dump};
        if (rfb_verbose_diag()) {
            fprintf(stderr, "farsee: dump presenter path=%s\n", dump_frame);
            (void)fflush(stderr);
        }
    } else if (live_kitty) {
        rfb_buffer_init(&kitty_out, rfb_default_allocator(),
                        64u * 1024u * 1024u);
        kitty_out_live = true;
        const bool use_shm = (pkind == RFB_PRES_KITTY_SHM);
        rfb_kitty_tile_init(&kitty, rfb_default_allocator(), &kitty_out,
                            /*tile_edge=*/8192u, use_shm,
                            /*request_ack=*/false);
        v1 = (rfb_presenter){.ops = &rfb_kitty_tile_ops, .ctx = &kitty};
        {
            static const char home[] = "\033[2J\033[H";
            (void)write(STDOUT_FILENO, home, sizeof(home) - 1);
        }
    } else {
        rfb_presenter_null_init(&nul);
        v1 = (rfb_presenter){.ops = &rfb_presenter_null_ops, .ctx = &nul};
    }

    farsee_frame_slot slot;
    farsee_cmd_queue cmds;
    memset(&slot, 0, sizeof(slot));
    memset(&cmds, 0, sizeof(cmds));
    if (!farsee_frame_slot_init(&slot) || !farsee_cmd_queue_init(&cmds)) {
        fprintf(stderr, "farsee: frame slot / cmd queue init failed\n");
        if (kitty_out_live) {
            rfb_buffer_destroy(&kitty_out);
        }
        rfb_secret_wipe_free(pwbuf, pw_alloc > 0u ? pw_alloc : pwlen + 1u);
        pwbuf = NULL;
        return 3;
    }

    const size_t sess_sz = rfb_session_size();
    rfb_session *sess = (rfb_session *)calloc(1, sess_sz);
    if (sess == NULL) {
        farsee_frame_slot_destroy(&slot);
        farsee_cmd_queue_destroy(&cmds);
        if (kitty_out_live) {
            rfb_buffer_destroy(&kitty_out);
        }
        rfb_secret_wipe_free(pwbuf, pw_alloc > 0u ? pw_alloc : pwlen + 1u);
        pwbuf = NULL;
        return 3;
    }
    rfb_session_clear(sess);

    farsee_atomic_int_store(&g_rfb_stop, 0);
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = rfb_on_signal;
    sigemptyset(&sa.sa_mask);
    struct sigaction old_int, old_term;
    (void)sigaction(SIGINT, &sa, &old_int);
    (void)sigaction(SIGTERM, &sa, &old_term);

    rfb_session_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host = host;
    cfg.port = port;
    if (username != NULL && username[0] != '\0') {
        cfg.username = (const uint8_t *)username;
        cfg.username_len = strlen(username);
    }
    cfg.password = (const uint8_t *)pwbuf;
    cfg.password_len = pwlen;
    cfg.allow_none_auth = allow_none_auth;
    cfg.shared = shared;
    if (apple_attach == APPLE_ATTACH_SHARE ||
        apple_attach == APPLE_ATTACH_LOGIN) {
        cfg.apple_attach = apple_attach;
    } else if (live_interactive) {
        cfg.apple_attach = APPLE_ATTACH_ASK;
        cfg.apple_attach_choose = apple_attach_choose_cb;
        cfg.apple_attach_choose_ctx = NULL;
    } else {
        cfg.apple_attach = APPLE_ATTACH_LOGIN;
    }
    cfg.auth_mode = auth_mode;
    cfg.slot = &slot;
    cfg.cmds = &cmds;
    cfg.stop_flag = &g_rfb_stop;
    cfg.max_fps = max_fps;
    cfg.view_only = view_only;
    cfg.connect_timeout_ms =
        (connect_timeout_ms == 0u) ? 30000u : connect_timeout_ms;

    rfb_error ce = rfb_session_connect(sess, &cfg);
    // Handshake no longer needs the password: wipe the full allocation now
    // so it does not sit in the heap for the live session lifetime.
    if (pwbuf != NULL) {
        rfb_secret_wipe_free(pwbuf, pw_alloc > 0u ? pw_alloc : (pwlen > 0u ? pwlen : 1u));
        pwbuf = NULL;
        pw_alloc = 0;
        pwlen = 0;
        cfg.password = NULL;
        cfg.password_len = 0;
    }
    if (ce != RFB_OK) {
        fprintf(stderr, "farsee: RFB connect/auth failed");
        if (ce == RFB_ERR_UNSUPPORTED) {
            fprintf(stderr,
                    "\n"
                    "  No mutually supported security type was available.\n"
                    "\n"
                    "  macOS Screen Sharing usually offers Apple type 33\n"
                    "  (local-user RSA/SRP). Use:\n"
                    "    farsee vnc://user@mac-host\n"
                    "  (URL user / --user is the macOS account name; the\n"
                    "  password is the account password, not a VNC password).\n"
                    "\n"
                    "  Or enable \"VNC viewers may control screen with password\"\n"
                    "  and connect with that VNC password via --auth=vnc.\n"
                    "\n"
                    "  Note: --cert ignore is RDP-only and is ignored for VNC.\n");
        } else if (ce == RFB_ERR_AUTH) {
            fprintf(stderr,
                    " (authentication rejected — wrong user/password, "
                    "or missing username for type-33?)");
        } else if (ce == RFB_ERR_IO || ce == RFB_ERR_EOF) {
            fprintf(stderr, " (network / peer closed)");
        } else if (ce == RFB_ERR_TIMEOUT) {
            fprintf(stderr, " (timeout during handshake)");
        }
        fprintf(stderr, " [err=%d]\n", (int)ce);
        rfb_session_destroy(sess);
        free(sess);
        farsee_frame_slot_destroy(&slot);
        farsee_cmd_queue_destroy(&cmds);
        if (kitty_out_live) {
            rfb_buffer_destroy(&kitty_out);
        }
        rfb_secret_wipe_free(pwbuf, pw_alloc > 0u ? pw_alloc : (pwlen > 0u ? pwlen : 1u));
        pwbuf = NULL;
        (void)sigaction(SIGINT, &old_int, NULL);
        (void)sigaction(SIGTERM, &old_term, NULL);
        return 4;
    }

    // T6 honesty: wrap_key presence is not wire encryption. Warn once so
    // operators do not treat type-33 as confidential AEAD.
    if (rfb_session_has_wrap_key(sess)) {
        fprintf(stderr,
                "farsee: warning: Apple type-33 session is cleartext MVP "
                "(no AEAD). Framebuffer and input are NOT confidential on "
                "the wire. Prefer loopback or a user-managed tunnel until "
                "record encryption ships.\n");
        if (rfb_verbose_diag()) {
            fprintf(stderr,
                    "farsee: Apple type-33 authenticated "
                    "(wrap_key derived; session still cleartext)\n");
        }
        (void)fflush(stderr);
    }

    const rfb_framebuffer *fb = rfb_session_framebuffer(sess);

    rfb_live_ui ui;
    memset(&ui, 0, sizeof(ui));
    farsee_live_shell_init(&ui.shell, leader, RFB_LIVE_STATUS_ROWS);
    ui.sess = sess;
    rfb_live_bind_shell_ops(&ui);
    ui.shell.view_only = view_only;
    ui.shell.show_zoom = true;
    ui.shell.show_suspend = false;
    (void)snprintf(ui.shell.status_proto, sizeof ui.shell.status_proto, "vnc");
    if (host != NULL) {
        (void)snprintf(ui.shell.status_host, sizeof ui.shell.status_host, "%s",
                       host);
    }
    ui.shell.status_port = port;
    ui.shell.desk_w = fb != NULL ? fb->width : 0;
    ui.shell.desk_h = fb != NULL ? fb->height : 0;
    farsee_live_shell_set_view_scale(&ui.shell,
        (view_scale_pct == 0u) ? FARSEE_VIEW_SCALE_DEFAULT_PCT
                               : farsee_view_scale_clamp(view_scale_pct));
    ui.kitty_out = kitty_out_live ? &kitty_out : NULL;

    if (live_kitty && fb != NULL && fb->width > 0u && fb->height > 0u) {
        farsee_live_shell_set_term_geom(&ui.shell, 80u, 24u, 0u, 0u);
        {
            uint16_t cols = 0u;
            uint16_t rows = 0u;
            uint16_t pw = 0u;
            uint16_t ph = 0u;
            bool got =
                farsee_live_shell_probe_winsize(-1, &cols, &rows, &pw, &ph);
            if (!got) {
                int tfd = open("/dev/tty", O_RDONLY | O_NOCTTY);
                if (tfd >= 0) {
                    got = farsee_live_shell_probe_winsize(tfd, &cols, &rows,
                                                          &pw, &ph);
                    close(tfd);
                }
            }
            if (got) {
                farsee_live_shell_set_term_geom(&ui.shell, cols, rows, pw, ph);
            }
        }
        ui.shell.kitty = &kitty;
        ui.shell.layout_active = true;
        (void)farsee_live_shell_refresh_layout(&ui.shell, /*apply_kitty=*/false);
        rfb_kitty_tile_set_place_cells(
            &kitty, ui.shell.place_cols,
            ui.shell.place_rows > 0u ? ui.shell.place_rows : 1u);
        if (rfb_verbose_diag()) {
            flockfile(stderr);
            fprintf(stderr,
                    "farsee: Kitty place %ux%u cells (disp %dx%d px) scale "
                    "%u%% for desktop %ux%u  ·  C-] +/- zoom, C-] q quit\n",
                    (unsigned)rfb_kitty_tile_place_cols(&kitty),
                    (unsigned)rfb_kitty_tile_place_rows(&kitty),
                    (int)ui.shell.disp_w_px, (int)ui.shell.disp_h_px,
                    (unsigned)farsee_live_shell_view_scale(&ui.shell), (unsigned)fb->width,
                    (unsigned)fb->height);
            (void)fflush(stderr);
            funlockfile(stderr);
        }
    }

    rfb_live_present_ctx pctx;
    memset(&pctx, 0, sizeof(pctx));
    pctx.presenter = &v1;
    pctx.kitty_out = kitty_out_live ? &kitty_out : NULL;
    pctx.ui = &ui;
    pctx.interval_ms = (max_fps > 0u) ? (1000u / max_fps) : 33u;
    if (pctx.interval_ms == 0u) {
        pctx.interval_ms = 1u;
    }
    ui.shell.force_repaint = &pctx.force_repaint;
    ui.slot = &slot;

    int rc = 0;
    ui.shell.tty_fd = -1;
    ui.shell.tty_fd_owned = false;
    if (live_kitty) {
        // Serialize status/log/Kitty drain across present + input threads.
        // Serialize status/log/Kitty drain (loop r1 T2 fail-closed).
        ui.shell.io_mu = farsee_mutex_create();
        if (ui.shell.io_mu == NULL) {
            fprintf(stderr,
                    "farsee: error: io mutex alloc failed "
                    "(cannot run multi-thread live status band)\n");
            (void)fflush(stderr);
            (void)sigaction(SIGINT, &old_int, NULL);
            (void)sigaction(SIGTERM, &old_term, NULL);
            if (pctx.opened) {
                rfb_presenter_close(&v1);
            }
            if (kitty_out_live) {
                rfb_buffer_destroy(&kitty_out);
            }
            rfb_session_destroy(sess);
            free(sess);
            farsee_frame_slot_destroy(&slot);
            farsee_cmd_queue_destroy(&cmds);
            rfb_secret_wipe_free(
                pwbuf, pw_alloc > 0u ? pw_alloc : (pwlen > 0u ? pwlen : 1u));
            return 3;
        }
        if (!farsee_tty_open_input(&ui.shell.tty_fd, &ui.shell.tty_fd_owned)) {
            fprintf(stderr,
                    "farsee: warning: no TTY for input — keyboard/mouse "
                    "inject disabled (stdin not a tty and /dev/tty failed)\n");
            (void)fflush(stderr);
        } else {
            if (!farsee_live_shell_quiet_enter(&ui.shell)) {
                fprintf(stderr,
                        "farsee: warning: could not put input fd in raw mode "
                        "(keyboard may require Enter)\n");
                (void)fflush(stderr);
            }
            if (!view_only) {
                ui.shell.want_mouse = true;
                ui.shell.want_kitty_kb = true;
                farsee_live_shell_input_enable(&ui.shell);
                if (rfb_verbose_diag()) {
                    fprintf(stderr,
                            "farsee: input armed on %s (SGR mouse + Kitty "
                            "CSI-u) desk=%ux%u place=%ux%u scale=%u%%\n",
                            farsee_tty_input_label(ui.shell.tty_fd,
                                                   ui.shell.tty_fd_owned),
                            (unsigned)ui.shell.desk_w,
                            (unsigned)ui.shell.desk_h,
                            (unsigned)ui.shell.place_cols,
                            (unsigned)ui.shell.place_rows,
                            (unsigned)farsee_live_shell_view_scale(&ui.shell));
                    (void)fflush(stderr);
                }
            }
            farsee_live_shell_tty_guard_arm(
                ui.shell.tty_fd, ui.shell.tty_attrs_saved, &ui.shell.tty_saved,
                ui.shell.mouse_enabled, ui.shell.want_kitty_kb);
        }
        farsee_live_shell_draw_status(&ui.shell);
    }
    farsee_mt_config mtc;
    memset(&mtc, 0, sizeof(mtc));
    mtc.slot = &slot;
    mtc.cmds = &cmds;
    mtc.stop_flag = &g_rfb_stop;
    mtc.protocol_fn = rfb_live_protocol_fn;
    mtc.protocol_user = sess;
    mtc.present_fn = rfb_live_present_fn;
    mtc.present_user = &pctx;
    mtc.input_fn = rfb_live_input_fn;
    mtc.input_user = &ui;
    (void)farsee_mt_run(&mtc);

    // Protocol thread already best-effort releases on loop exit; call again
    // while the session is still open for any residual held state (T5).
    rfb_session_release_held_inputs(sess);

    (void)sigaction(SIGINT, &old_int, NULL);
    (void)sigaction(SIGTERM, &old_term, NULL);

    {
        const rfb_error pe = rfb_session_last_error(sess);
        const uint8_t unexpected = rfb_session_last_unexpected_type(sess);
        if (pe == RFB_ERR_PROTOCOL) {
            if (unexpected != 0u) {
                fprintf(stderr,
                        "farsee: protocol loop ended: unexpected server "
                        "message type=0x%02x (err=%d). On type-33 peers "
                        "this may be an Apple-specific type.\n",
                        (unsigned)unexpected, (int)pe);
            } else {
                fprintf(stderr,
                        "farsee: protocol loop ended: framebuffer decode "
                        "failed (err=%d). Often ZRLE/pixel-format; try "
                        "FARSEE_RFB_DEBUG=1 for rect details.\n",
                        (int)pe);
            }
            rc = 5;
        } else if (pe == RFB_ERR_LIMIT) {
            fprintf(stderr,
                    "farsee: protocol loop ended: input/size limit exceeded "
                    "(err=%d — e.g. framebuffer or compressed rect too "
                    "large for policy)\n",
                    (int)pe);
            rc = 5;
        } else if (pe == RFB_ERR_UNSUPPORTED) {
            fprintf(stderr,
                    "farsee: protocol loop ended: unsupported encoding or "
                    "feature (err=%d",
                    (int)pe);
            if (unexpected != 0u) {
                fprintf(stderr, ", type=0x%02x", (unsigned)unexpected);
            }
            fprintf(stderr, ")\n");
            rc = 5;
        } else if (pe == RFB_ERR_EOF || pe == RFB_ERR_IO) {
            flockfile(stderr);
            fprintf(stderr,
                    "farsee: peer closed the connection [err=%d]\n",
                    (int)pe);
            fprintf(stderr,
                    "farsee: note: Apple Screen Sharing often closes the "
                    "socket after a console login / user switch — reconnect "
                    "with the same command if the host is still up.\n");
            (void)fflush(stderr);
            funlockfile(stderr);
            rc = 5;
        } else if (pe != RFB_OK && pe != RFB_ERR_CANCELLED) {
            flockfile(stderr);
            fprintf(stderr, "farsee: protocol loop ended [err=%d]\n", (int)pe);
            (void)fflush(stderr);
            funlockfile(stderr);
            rc = 5;
        } else if (farsee_atomic_int_load_nonzero(&g_rfb_stop)) {
            flockfile(stderr);
            fprintf(stderr, "farsee: disconnected (signal / leader quit)");
            if (pctx.present_count > 0u) {
                fprintf(stderr, " after %llu present(s)",
                        (unsigned long long)pctx.present_count);
            }
            fprintf(stderr, "\n");
            (void)fflush(stderr);
            funlockfile(stderr);
        } else if (pctx.present_count > 0u) {
            flockfile(stderr);
            fprintf(stderr,
                    "farsee: session ended after %llu present(s)\n",
                    (unsigned long long)pctx.present_count);
            (void)fflush(stderr);
            funlockfile(stderr);
        }
    }

    farsee_live_shell_tty_guard_restore();
    ui.shell.mouse_enabled = false;
    if (pctx.opened) {
        rfb_presenter_close(&v1);
    }
    farsee_drain_kitty_out(ui.kitty_out, STDOUT_FILENO, ui.shell.io_mu);
    farsee_live_shell_quiet_restore(&ui.shell);
    farsee_tty_close_input(ui.shell.tty_fd, ui.shell.tty_fd_owned);
    if (ui.shell.io_mu != NULL) {
        farsee_mutex_destroy(&ui.shell.io_mu);
    }

    rfb_session_destroy(sess);
    free(sess);
    farsee_frame_slot_destroy(&slot);
    farsee_cmd_queue_destroy(&cmds);
    if (kitty_out_live) {
        rfb_buffer_destroy(&kitty_out);
    }
    rfb_secret_wipe_free(pwbuf, pw_alloc > 0u ? pw_alloc : (pwlen > 0u ? pwlen : 1u));
    pwbuf = NULL;

    return rc;
}
