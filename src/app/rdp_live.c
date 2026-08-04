// SPDX-License-Identifier: Apache-2.0
//
// RDP live CLI: connect → MT (protocol / present / input) or dump settle.
// Shared TTY/demux/status/layout lives in live_shell; this file is inject
// ops + FreeRDP connect glue.

#include "app/rdp_live.h"

#ifdef FARSEE_WITH_RDP

#include "app/live_shell.h"
#include "farsee/allocator.h"
#include "farsee/buffer.h"
#include "farsee/cli_target.h"
#include "farsee/farsee_atomic.h"
#include "farsee/farsee_clipboard.h"
#include "farsee/farsee_input.h"
#include "farsee/farsee_security.h"
#include "farsee/farsee_thread.h"
#include "farsee/kitty_drain.h"
#include "farsee/kitty_tile.h"
#include "farsee/live_demux.h"
#include "farsee/normalized_input.h"
#include "farsee/presenter.h"
#include "farsee/presenter_v1_adapter.h"
#include "farsee/secret_fd.h"
#include "farsee/sgr_mouse.h"
#include "farsee/socket_posix.h"
#include "farsee/term_mouse_map.h"
#include "farsee/tty_posix.h"
#include "protocol/rdp/rdp_callbacks.h"
#include "protocol/rdp/rdp_frame_slot.h"
#include "protocol/rdp/rdp_freerdp_facade.h"
#include "protocol/rdp/rdp_inj_queue.h"
#include "protocol/rdp/rdp_input_bridge.h"
#include "protocol/rdp/rdp_input_inject.h"
#include "protocol/rdp/rdp_mt_session.h"
#include "protocol/rdp/rdp_settings.h"

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

// Cooperative stop for SIGINT/SIGTERM during a live RDP session.
static farsee_atomic_int g_rdp_stop = 0;

static void rdp_on_signal(int sig)
{
    (void)sig;
    farsee_atomic_int_store(&g_rdp_stop, 1);
}

// Live-session tick: shared shell + FreeRDP inject state.
// RDP status_rows=1; show_suspend + show_zoom (Kitty place scale).
typedef struct rdp_live_tick {
    farsee_live_shell shell;
    farsee_live_shell_ops shell_ops;
    rfb_buffer *kitty_out;
    rdp_freerdp_ctx *ctx;
    farsee_key_ledger ledger;
    unsigned prev_buttons;
    rdp_display_sink *sink;
    bool input_debug;
    bool verbose;
    bool log_flowing;
    rdp_inj_queue *inj;
    // Protocol-owned button mask (updated only after FreeRDP inject OK).
    unsigned wire_buttons;
    // One home CSI per APC batch (D2 residual).
    bool need_home;
    // Protocol-published link atomics (T6); rate is producer-latched (r3 T1).
    farsee_atomic_u64 link_meta;
    farsee_atomic_u64 link_rx_bytes;
    farsee_atomic_u64 link_rate_pub;
    // Kitty CSI-u chords: synthesized modifier downs that must be released
    // on key-up (T21; stuck Control_L otherwise).
    uint16_t synth_mods;
    // Zoom/layout: re-present same gen with new Kitty place cells.
    farsee_atomic_int force_repaint;
    rdp_frame_slot *slot; // kick present wait on layout (may be NULL)
} rdp_live_tick;

#define RDP_STATUS_ROWS 1u

static void rdp_live_log(rdp_live_tick *t, const char *fmt, ...)
#if defined(__GNUC__) || defined(__clang__)
    __attribute__((format(printf, 2, 3)))
#endif
    ;
static void rdp_live_log(rdp_live_tick *t, const char *fmt, ...)
{
    // Always log to stderr only. Do NOT touch stdout/status here: the present
    // thread may hold io_mu across a blocking Kitty write, and redrawing
    // status from the input thread would deadlock — killing keyboard/mouse.
    (void)t;
    char line[512];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(line, sizeof line, fmt, ap);
    va_end(ap);
    if (n < 0) {
        return;
    }
    if ((size_t)n >= sizeof line) {
        line[sizeof line - 1u] = '\0';
    }
    flockfile(stderr);
    (void)fputs(line, stderr);
    (void)fflush(stderr);
    funlockfile(stderr);
}

// Home+drain Kitty APC (prefix under same lock) → redraw status under image.
static void rdp_live_drain_graphics(rdp_live_tick *t)
{
    if (t == NULL || t->kitty_out == NULL) {
        return;
    }
    // Idle: no residual APC → no CSI (post-t11 T4). Length under io_mu.
    // Arm need_home for the next APC batch when fully empty (D2 residual).
    if (t->shell.io_mu != NULL) {
        farsee_mutex_lock(t->shell.io_mu);
        const bool empty = rfb_buffer_length(t->kitty_out) == 0u;
        farsee_mutex_unlock(t->shell.io_mu);
        if (empty) {
            t->need_home = true;
            return;
        }
    } else if (rfb_buffer_length(t->kitty_out) == 0u) {
        t->need_home = true;
        return;
    }
    const bool need_status = t->shell.layout_active;
    // Peer desktop resize: present only notes geometry (T7 ownership).
    if (t->sink != NULL && t->sink->last_width > 0u &&
        t->sink->last_height > 0u) {
        farsee_live_shell_note_desk_size(&t->shell, t->sink->last_width,
                                         t->sink->last_height);
    }
    // Present must NOT refresh_layout: place_*/disp_* are input-thread
    // caches (live_shell.h). note_desk + input apply_pending_desk own geometry
    // (loop r1 T3 / claude F1). need_status only draws after drain.
    (void)need_status;
    // One home per batch: clear need_home even if residual is still ESC_G.
    farsee_live_shell_stdio_nonblock_arm(STDOUT_FILENO);
    static const char home[] = "\033[H";
    const char *prefix = NULL;
    size_t prefix_len = 0u;
    if (t->need_home) {
        prefix = home;
        prefix_len = sizeof(home) - 1u;
    }
    const bool drained = farsee_drain_kitty_out_with_prefix(
        t->kitty_out, STDOUT_FILENO, t->shell.io_mu, prefix, prefix_len);
    // Next batch needs home after a full flush (claude r3 F1); residual
    // after partial keeps need_home false so we do not double-home.
    t->need_home = drained;
    if (need_status && drained) {
        farsee_live_shell_draw_status(&t->shell);
    }
}

static void rdp_live_request_quit(rdp_live_tick *t);
static void rdp_live_inject_key(rdp_live_tick *t, const rfb_norm_key *nk);

// Leave interactive TTY mode so the shell can own the terminal while stopped.
static void rdp_live_tty_yield(rdp_live_tick *t)
{
    if (t == NULL) {
        return;
    }
    farsee_live_shell_input_disable(&t->shell);
    farsee_live_shell_quiet_restore(&t->shell);
    if (t->shell.tty_fd >= 0) {
        uint8_t junk[512];
        for (;;) {
            ssize_t n = read(t->shell.tty_fd, junk, sizeof junk);
            if (n <= 0) {
                break;
            }
        }
    }
    t->shell.demux.residual_len = 0;
    farsee_atomic_int_store(&t->shell.demux.leader_armed, 0);
    t->shell.demux.leader_deadline_ms = 0;
}

// Reclaim the TTY after SIGCONT.
static void rdp_live_tty_reclaim(rdp_live_tick *t)
{
    if (t == NULL) {
        return;
    }
    if (t->shell.tty_fd >= 0) {
        (void)farsee_live_shell_quiet_enter(&t->shell);
        uint16_t cols = 0u;
        uint16_t rows = 0u;
        uint16_t pw = 0u;
        uint16_t ph = 0u;
        if (farsee_live_shell_probe_winsize(t->shell.tty_fd, &cols, &rows, &pw,
                                            &ph)) {
            {

                uint16_t opw = t->shell.term_pw;

                uint16_t oph = t->shell.term_ph;

                farsee_live_shell_set_term_geom(&t->shell, cols, rows,

                                                pw != 0u ? pw : opw,

                                                ph != 0u ? ph : oph);

            }
        }
    }
    farsee_live_shell_input_enable(&t->shell);
    if (t->shell.layout_active) {
        (void)farsee_live_shell_refresh_layout(&t->shell, /*apply_kitty=*/true);
        farsee_live_shell_home_cursor();
        farsee_live_shell_draw_status(&t->shell);
    }
    if (t->sink != NULL) {
        farsee_atomic_int_store(&t->sink->present_pending, 1);
    }
}

static void rdp_live_suspend(rdp_live_tick *t)
{
    if (t == NULL) {
        return;
    }
    rdp_live_tty_yield(t);
    fprintf(stderr, "farsee: suspended — type 'fg' to resume\n");
    (void)fflush(stderr);
    {
        struct sigaction sa_dfl;
        struct sigaction sa_old;
        memset(&sa_dfl, 0, sizeof(sa_dfl));
        sa_dfl.sa_handler = SIG_DFL;
        sigemptyset(&sa_dfl.sa_mask);
        (void)sigaction(SIGTSTP, &sa_dfl, &sa_old);
        (void)raise(SIGTSTP);
        (void)sigaction(SIGTSTP, &sa_old, NULL);
    }
    rdp_live_tty_reclaim(t);
}

static void rdp_live_request_quit(rdp_live_tick *t)
{
    farsee_atomic_int_store(&g_rdp_stop, 1);
    if (t != NULL && t->ctx != NULL) {
        rdp_freerdp_request_stop(t->ctx);
    }
}

// Returns true when the key was accepted (queued or injected). Ledger and
// synth_mods must only update on success (multi-review 2026-08-03 T3).
static bool rdp_live_send_key(rdp_live_tick *t, uint32_t keysym, uint32_t unicode,
                              bool down, bool repeat)
{
    if (t == NULL) {
        return false;
    }
    if (t->inj != NULL) {
        rdp_inj_cmd c;
        memset(&c, 0, sizeof(c));
        c.kind = RDP_INJ_KEY;
        c.keysym = keysym;
        c.unicode = unicode;
        c.down = down;
        c.repeat = repeat;
        return rdp_inj_queue_push(t->inj, &c);
    }
    if (t->ctx != NULL) {
        return rdp_input_inject_key_from_keysym(t->ctx, keysym, unicode, down,
                                                repeat);
    }
    return false;
}

// ST path only (inj == NULL): ledger tracks after inject. MT path: protocol
// thread owns ledger after wire success (reaudit T4/T7).
static void rdp_live_ledger_key(rdp_live_tick *t, uint32_t keysym, bool down)
{
    if (t == NULL || t->inj != NULL) {
        return;
    }
    farsee_key_event ke;
    if (!rdp_input_key_event_from_keysym(&ke, keysym, 0u, down,
                                         /*repeat=*/false)) {
        return;
    }
    if (farsee_key_ledger_apply(&t->ledger, &ke)) {
        return;
    }
    // Overflow on press: emit ups for held; never wipe failed holds (loop r1 T2).
    if (!down || ke.physical == 0u || t->ctx == NULL) {
        return;
    }
    rdp_input_inject_release_all(t->ctx, &t->ledger);
    if (t->ledger.count < FARSEE_KEY_LEDGER_MAX) {
        (void)farsee_key_ledger_apply(&t->ledger, &ke);
    }
}

static void rdp_live_synth_mods_down(rdp_live_tick *t, uint16_t need)
{
    if (t == NULL || need == 0u) {
        return;
    }
    if ((need & RFB_MOD_SHIFT) != 0u &&
        (t->synth_mods & RFB_MOD_SHIFT) == 0u) {
        if (rdp_live_send_key(t, XK_Shift_L, 0, true, false)) {
            rdp_live_ledger_key(t, XK_Shift_L, true);
            t->synth_mods = (uint16_t)(t->synth_mods | RFB_MOD_SHIFT);
        }
    }
    if ((need & RFB_MOD_CONTROL) != 0u &&
        (t->synth_mods & RFB_MOD_CONTROL) == 0u) {
        if (rdp_live_send_key(t, XK_Control_L, 0, true, false)) {
            rdp_live_ledger_key(t, XK_Control_L, true);
            t->synth_mods = (uint16_t)(t->synth_mods | RFB_MOD_CONTROL);
        }
    }
    if ((need & RFB_MOD_ALT) != 0u && (t->synth_mods & RFB_MOD_ALT) == 0u) {
        if (rdp_live_send_key(t, XK_Alt_L, 0, true, false)) {
            rdp_live_ledger_key(t, XK_Alt_L, true);
            t->synth_mods = (uint16_t)(t->synth_mods | RFB_MOD_ALT);
        }
    }
    if ((need & RFB_MOD_META) != 0u && (t->synth_mods & RFB_MOD_META) == 0u) {
        if (rdp_live_send_key(t, XK_Super_L, 0, true, false)) {
            rdp_live_ledger_key(t, XK_Super_L, true);
            t->synth_mods = (uint16_t)(t->synth_mods | RFB_MOD_META);
        }
    }
}

static void rdp_live_synth_mods_up(rdp_live_tick *t)
{
    if (t == NULL || t->synth_mods == 0u) {
        return;
    }
    if ((t->synth_mods & RFB_MOD_META) != 0u) {
        if (rdp_live_send_key(t, XK_Super_L, 0, false, false)) {
            rdp_live_ledger_key(t, XK_Super_L, false);
            t->synth_mods = (uint16_t)(t->synth_mods & ~RFB_MOD_META);
        }
    }
    if ((t->synth_mods & RFB_MOD_ALT) != 0u) {
        if (rdp_live_send_key(t, XK_Alt_L, 0, false, false)) {
            rdp_live_ledger_key(t, XK_Alt_L, false);
            t->synth_mods = (uint16_t)(t->synth_mods & ~RFB_MOD_ALT);
        }
    }
    if ((t->synth_mods & RFB_MOD_CONTROL) != 0u) {
        if (rdp_live_send_key(t, XK_Control_L, 0, false, false)) {
            rdp_live_ledger_key(t, XK_Control_L, false);
            t->synth_mods = (uint16_t)(t->synth_mods & ~RFB_MOD_CONTROL);
        }
    }
    if ((t->synth_mods & RFB_MOD_SHIFT) != 0u) {
        if (rdp_live_send_key(t, XK_Shift_L, 0, false, false)) {
            rdp_live_ledger_key(t, XK_Shift_L, false);
            t->synth_mods = (uint16_t)(t->synth_mods & ~RFB_MOD_SHIFT);
        }
    }
}

static void rdp_live_inject_key(rdp_live_tick *t, const rfb_norm_key *nk)
{
    if (t == NULL || nk == NULL || t->shell.view_only) {
        return;
    }
    if (t->inj == NULL && t->ctx == NULL) {
        return;
    }
    if (t->input_debug) {
        rdp_live_log(t,
                     "farsee rdp: key %s keysym=0x%x src=%u mods=0x%x "
                     "inj=%c\n",
                     nk->down ? "down" : "up", (unsigned)nk->keysym,
                     (unsigned)nk->source, (unsigned)nk->modifiers,
                     t->inj != NULL ? 'Y' : 'N');
    }

    // Physical modifier keys: pass through; ledger only after inject (T3).
    const rfb_modkey mk = rfb_norm_modkey_from_sym(nk->keysym);
    if (mk != RFB_MODKEY_NONE) {
        if (rdp_live_send_key(t, nk->keysym, nk->text, nk->down, nk->repeat)) {
            rdp_live_ledger_key(t, nk->keysym, nk->down);
        }
        return;
    }

    // Kitty CSI-u (and legacy chords) may report modifiers without a
    // physical Control_L down. Synthesize Left-Control/etc. so the remote
    // does not see plain 'a', then release on key-up (T21).
    const uint16_t physical = rfb_norm_mods_bits(&t->shell.demux.mods);
    const uint16_t held = (uint16_t)(physical | t->synth_mods);
    const uint16_t need = rfb_norm_mods_need_synth(nk->modifiers, held);

    if (nk->down) {
        rdp_live_synth_mods_down(t, need);
        if (rdp_live_send_key(t, nk->keysym, nk->text, true, nk->repeat)) {
            rdp_live_ledger_key(t, nk->keysym, true);
        }
        // Non-Kitty sources: synthetic press+release (legacy single-shot).
        if (!nk->repeat && nk->source != RFB_NORM_SOURCE_KITTY) {
            if (rdp_live_send_key(t, nk->keysym, nk->text, false, false)) {
                rdp_live_ledger_key(t, nk->keysym, false);
            }
            rdp_live_synth_mods_up(t);
        }
    } else {
        if (rdp_live_send_key(t, nk->keysym, nk->text, false, false)) {
            rdp_live_ledger_key(t, nk->keysym, false);
        }
        rdp_live_synth_mods_up(t);
    }
}

// --- shell ops -------------------------------------------------------------

static void rdp_shell_inject_key(void *u, const rfb_norm_key *nk)
{
    rdp_live_inject_key((rdp_live_tick *)u, nk);
}

static bool rdp_shell_inject_pointer(void *u, int32_t x, int32_t y,
                                     uint8_t buttons, int wv, int wh)
{
    rdp_live_tick *t = (rdp_live_tick *)u;
    if (t == NULL || t->shell.view_only) {
        return false;
    }
    if (t->ctx == NULL && t->inj == NULL) {
        return false;
    }
    farsee_pointer_event pe;
    memset(&pe, 0, sizeof(pe));
    pe.abs_x = x;
    pe.abs_y = y;
    pe.quality = FARSEE_INPUT_QUALITY_INFERRED;
    pe.wheel_v = wv;
    pe.wheel_h = wh;
    pe.buttons = buttons;
    if (t->sink != NULL) {
        farsee_atomic_int_store(&t->sink->cursor_x, (int)pe.abs_x);
        farsee_atomic_int_store(&t->sink->cursor_y, (int)pe.abs_y);
        farsee_atomic_int_store(&t->sink->cursor_visible, 1);
    }
    if (t->verbose || t->input_debug) {
        rdp_live_log(t,
                     "farsee rdp: mouse desk=(%d,%d) buttons=0x%x "
                     "wheel=%d,%d\n",
                     (int)x, (int)y, (unsigned)buttons, wv, wh);
    }
    bool ok = false;
    if (t->inj != NULL) {
        rdp_inj_cmd c;
        memset(&c, 0, sizeof(c));
        c.kind = RDP_INJ_POINTER;
        c.pe = pe;
        c.prev_buttons = t->prev_buttons;
        ok = rdp_inj_queue_push(t->inj, &c);
        if (ok) {
            // Queue-chain for consecutive cmds before protocol runs.
            // Wire truth is tick.wire_buttons (protocol-only; D1/D3).
            t->prev_buttons = buttons;
        }
    } else if (t->ctx != NULL) {
        unsigned reached = t->prev_buttons;
        ok = rdp_input_inject_pointer(t->ctx, &pe, t->prev_buttons, &reached);
        t->prev_buttons = reached;
        if (ok) {
            t->prev_buttons = buttons;
        }
    }
    return ok;
}

static void rdp_shell_request_quit(void *u)
{
    rdp_live_request_quit((rdp_live_tick *)u);
}

static void rdp_shell_suspend(void *u)
{
    rdp_live_suspend((rdp_live_tick *)u);
}

static void rdp_live_zoom(rdp_live_tick *t, int delta_pct)
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
        rdp_live_log(t, "farsee rdp: view scale already %u%%\n",
                     (unsigned)farsee_live_shell_view_scale(sh));
        return;
    }
    farsee_live_shell_set_view_scale(sh, (uint32_t)next);
    if (sh->layout_active) {
        (void)farsee_live_shell_refresh_layout(sh, /*apply_kitty=*/true);
    }
    rdp_live_log(t, "farsee rdp: view scale %u%%  (%ux%u cells)\n",
                 (unsigned)farsee_live_shell_view_scale(sh), (unsigned)sh->place_cols,
                 (unsigned)sh->place_rows);
}

static void rdp_shell_zoom(void *u, int delta_pct)
{
    rdp_live_zoom((rdp_live_tick *)u, delta_pct);
}

static void rdp_shell_status_extra(void *u, char *buf, size_t cap)
{
    rdp_live_tick *t = (rdp_live_tick *)u;
    if (t == NULL || buf == NULL || cap == 0u) {
        return;
    }
    // Atomics only — FreeRDP/fd sampled on protocol thread (T6 / r3 T1).
    const uint64_t meta = farsee_atomic_u64_load(&t->link_meta);
    uint32_t rtt = 0u;
    bool have_rtt = false;
    bool have_rx = false;
    farsee_link_meta_unpack(meta, &rtt, &have_rtt, &have_rx);
    (void)have_rx;
    uint32_t rate_kib = 0u;
    bool have_rate = false;
    farsee_link_rate_unpack(farsee_atomic_u64_load(&t->link_rate_pub),
                            &rate_kib, &have_rate);
    char link[96];
    farsee_live_shell_format_link_extra(link, sizeof link,
                                        farsee_live_shell_view_scale(&t->shell), rtt, have_rtt,
                                        rate_kib, have_rate);
    if (t->verbose && t->sink != NULL) {
        (void)snprintf(buf, cap,
                       "%s  \033[2min=%llu paint=%llu show=%llu\033[0m", link,
                       (unsigned long long)farsee_atomic_u64_load(
                           &t->shell.input_events),
                       (unsigned long long)farsee_atomic_u64_load(
                           &t->sink->end_paint_count),
                       (unsigned long long)farsee_atomic_u64_load(
                           &t->sink->frame_count));
    } else {
        (void)snprintf(buf, cap, "%s", link);
    }
}

static void rdp_shell_on_layout_applied(void *u)
{
    rdp_live_tick *t = (rdp_live_tick *)u;
    if (t == NULL) {
        return;
    }
    // refresh_layout already stores force_repaint=1 when shell.force_repaint
    // is set; kick the slot so present wakes without waiting for a new gen.
    if (t->slot != NULL) {
        rdp_frame_slot_kick(t->slot);
    }
}

static void rdp_live_bind_shell_ops(rdp_live_tick *t)
{
    memset(&t->shell_ops, 0, sizeof(t->shell_ops));
    t->shell_ops.inject_key = rdp_shell_inject_key;
    t->shell_ops.inject_pointer = rdp_shell_inject_pointer;
    t->shell_ops.request_quit = rdp_shell_request_quit;
    t->shell_ops.zoom = rdp_shell_zoom;
    t->shell_ops.suspend = rdp_shell_suspend;
    t->shell_ops.status_extra = rdp_shell_status_extra;
    t->shell_ops.on_layout_applied = rdp_shell_on_layout_applied;
    t->shell.ops = &t->shell_ops;
    t->shell.ops_user = t;
}

static void rdp_live_process_input(rdp_live_tick *t, const uint8_t *data,
                                   size_t n)
{
    if (t == NULL) {
        return;
    }
    farsee_live_shell_feed_tty(&t->shell, data, n, farsee_thread_monotonic_ms());
}

// ST dump/null settle path intentionally has no on_tick: live Kitty always
// uses MT (protocol/present/input). Graphics drain is after_present only.

static void rdp_live_after_present(void *user)
{
    rdp_live_drain_graphics((rdp_live_tick *)user);
}

static void rdp_live_input_fn(void *user, rdp_inj_queue *inj,
                              farsee_atomic_int *stop)
{
    rdp_live_tick *t = (rdp_live_tick *)user;
    if (t == NULL) {
        return;
    }
    t->inj = inj;
    if (t->input_debug) {
        rdp_live_log(t, "farsee rdp: input thread start tty_fd=%d\n",
                     t->shell.tty_fd);
    }
    unsigned loop_n = 0;
    while (!farsee_atomic_int_load_nonzero(stop)) {
        if (farsee_atomic_int_load_nonzero(&g_rdp_stop)) {
            break;
        }
        farsee_live_shell *sh = &t->shell;
        // DesktopSize + winsize + idle status without requiring input TTY (r4).
        (void)farsee_live_shell_apply_pending_desk(sh, /*apply_kitty=*/true);
        {
            static _Thread_local uint64_t last_winsize_ms;
            const uint64_t now = farsee_thread_monotonic_ms();
            if (last_winsize_ms == 0u || now - last_winsize_ms >= 250u) {
                last_winsize_ms = now;
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
                        farsee_live_shell_draw_status(sh);
                    }
                }
            }
        }
        {
            static _Thread_local uint64_t last_link_status_ms;
            const uint64_t now = farsee_thread_monotonic_ms();
            if (sh->layout_active &&
                (last_link_status_ms == 0u ||
                 now - last_link_status_ms >= 500u)) {
                last_link_status_ms = now;
                farsee_live_shell_draw_status(sh);
            }
        }
        if (sh->tty_fd < 0) {
            if (t->input_debug && (loop_n++ % 50u) == 0u) {
                rdp_live_log(t, "farsee rdp: input thread: no tty_fd\n");
            }
            struct pollfd dummy;
            memset(&dummy, 0, sizeof(dummy));
            (void)poll(&dummy, 0, 20);
            continue;
        }
        struct pollfd pfd;
        memset(&pfd, 0, sizeof(pfd));
        pfd.fd = sh->tty_fd;
        pfd.events = POLLIN;
        int pr = poll(&pfd, 1, 20);
        if (pr < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (t->input_debug) {
                rdp_live_log(t, "farsee rdp: poll error errno=%d\n", errno);
            }
            break;
        }
        size_t got = 0u;
        if (pr > 0 &&
            (pfd.revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL)) != 0) {
            uint8_t buf[1024];
            for (;;) {
                ssize_t n = read(sh->tty_fd, buf, sizeof(buf));
                if (n > 0) {
                    got += (size_t)n;
                    // TTY read chatter only under FARSEE_RDP_INPUT_DEBUG.
                    if (t->input_debug) {
                        static unsigned s_rdp_read_logs;
                        s_rdp_read_logs++;
                        if (s_rdp_read_logs <= 5u ||
                            (s_rdp_read_logs % 50u) == 0u) {
                            rdp_live_log(
                                t,
                                "farsee rdp: tty read #%u n=%zd first=0x%02x "
                                "residual=%zu\n",
                                s_rdp_read_logs, n, (unsigned)buf[0],
                                (size_t)sh->demux.residual_len);
                        }
                    }
                    rdp_live_process_input(t, buf, (size_t)n);
                    continue;
                }
                if (n == -1 && errno == EINTR) {
                    continue;
                }
                if (t->input_debug && n < 0 &&
                    (errno == EAGAIN || errno == EWOULDBLOCK)) {
                    // poll said ready but nonblocking read empty — common
                    // on some PTYs; not fatal.
                }
                break;
            }
        }
        // Mirror RFB: HUP/ERR/NVAL with no data → brief backoff (loop r1 T7).
        if (pr > 0 && got == 0u &&
            (pfd.revents & (POLLHUP | POLLERR | POLLNVAL)) != 0) {
            (void)poll(NULL, 0, 20);
        }
        farsee_live_shell_tick_timeout(sh, farsee_thread_monotonic_ms());
        // pending_desk applied above the no-TTY gate (loop r3 T4 / r2 T4).
    }
    t->inj = NULL;
}

static void drain_tty_responses(int tty_fd)
{
    if (tty_fd < 0) {
        return;
    }
    uint8_t buf[4096];
    for (;;) {
        ssize_t n = read(tty_fd, buf, sizeof(buf));
        if (n > 0) {
            continue;
        }
        if (n == -1 && errno == EINTR) {
            continue;
        }
        break;
    }
}

typedef enum {
    RDP_PRES_NULL = 0,
    RDP_PRES_DUMP,
    RDP_PRES_KITTY_DIRECT,
    RDP_PRES_KITTY_SHM,
} rdp_presenter_kind;

static rdp_presenter_kind resolve_rdp_presenter(const char *name,
                                                const char *dump_frame)
{
    if (dump_frame != NULL &&
        (name == NULL || strcmp(name, "auto") == 0 ||
         strcmp(name, "dump") == 0)) {
        return RDP_PRES_DUMP;
    }
    if (name == NULL || strcmp(name, "auto") == 0) {
        if (isatty(STDOUT_FILENO)) {
            return RDP_PRES_KITTY_SHM;
        }
        return dump_frame != NULL ? RDP_PRES_DUMP : RDP_PRES_NULL;
    }
    if (strcmp(name, "dump") == 0) {
        return RDP_PRES_DUMP;
    }
    if (strcmp(name, "null") == 0) {
        return RDP_PRES_NULL;
    }
    if (strcmp(name, "kitty") == 0 || strcmp(name, "kitty-shm") == 0) {
        return RDP_PRES_KITTY_SHM;
    }
    if (strcmp(name, "kitty-direct") == 0) {
        return RDP_PRES_KITTY_DIRECT;
    }
    return RDP_PRES_NULL;
}

int farsee_run_rdp(const char *host, uint16_t port,
                   const char *user, const char *domain,
                   const char *cert_policy, int password_fd,
                   const char *password_inline,
                   uint32_t desk_w, uint32_t desk_h,
                   const char *presenter_name, const char *dump_frame,
                   uint64_t connect_timeout_ms,
                   bool view_only, bool clipboard_on,
                   rdp_liblog_level liblog,
                   const farsee_cli_leader *leader_spec)
{
    rdp_freerdp_set_library_log_level(liblog);

    if (port == 0) {
        port = 3389;
    }
    if (desk_w == 0) {
        desk_w = 1280;
    }
    if (desk_h == 0) {
        desk_h = 800;
    }
    if (user == NULL) {
        fprintf(stderr, "farsee rdp: --user is required\n");
        return 2;
    }
    if (connect_timeout_ms == 0) {
        connect_timeout_ms = 30000;
    }

    const rdp_presenter_kind pkind =
        resolve_rdp_presenter(presenter_name, dump_frame);
    const bool live = (pkind == RDP_PRES_KITTY_DIRECT ||
                       pkind == RDP_PRES_KITTY_SHM);

    // Connecting banner is verbose-only (errors stay always-on).
    if (liblog >= RDP_LIBLOG_INFO) {
        fprintf(stderr, "farsee rdp: connecting to %s:%u (user=%s)\n",
                host, (unsigned)port, user);
    }

    farsee_rdp_settings s;
    if (!farsee_rdp_settings_init_for_host(&s, host, port, user, domain)) {
        fprintf(stderr, "farsee rdp: invalid endpoint\n");
        return 2;
    }
    s.desktop_width = desk_w;
    s.desktop_height = desk_h;
    // Bound freerdp_connect (T23). Cap to UINT32 for FreeRDP setting.
    if (connect_timeout_ms > 0u &&
        connect_timeout_ms <= (uint64_t)UINT32_MAX) {
        s.connect_timeout_ms = (uint32_t)connect_timeout_ms;
    } else if (connect_timeout_ms > (uint64_t)UINT32_MAX) {
        s.connect_timeout_ms = UINT32_MAX;
    }
    if (clipboard_on && !view_only) {
        s.channels.clipboard_text = true;
    }

    farsee_security_policy policy = farsee_security_policy_default_rdp();
    bool ignore_cert =
        (cert_policy != NULL && strcmp(cert_policy, "ignore") == 0);
    bool pin_cert = (cert_policy != NULL && strcmp(cert_policy, "pin") == 0);
    if (ignore_cert) {
        // Session-only approve; does not write TOFU (T9).
        policy.allow_insecure_cert = true;
        policy.tofu_pin_store = false;
    } else if (pin_cert) {
        // Explicit TOFU pin: approve first use and store fingerprint.
        policy.allow_insecure_cert = false;
        policy.tofu_pin_store = true;
    }

    farsee_credential_response cred;
    farsee_credential_response_init(&cred);
    cred.username = user;
    cred.domain = domain;
    if (password_fd >= 0) {
        char *pwbuf = NULL;
        long pwlen = farsee_read_fd_secret(password_fd, &pwbuf,
                                           FARSEE_SECRET_FD_DEFAULT_CAP);
        if (pwlen < 0) {
            fprintf(stderr, "farsee rdp: failed to read password from fd %d\n",
                    password_fd);
            farsee_credential_response_destroy(&cred);
            return 2;
        }
        cred.password.data = (uint8_t *)pwbuf;
        cred.password.len = (size_t)pwlen;
        cred.password.cap = FARSEE_SECRET_FD_DEFAULT_CAP;
    } else if (password_inline != NULL && password_inline[0] != '\0') {
        size_t plen = strlen(password_inline);
        uint8_t *pwbuf = (uint8_t *)calloc(1, plen + 1u);
        if (pwbuf == NULL) {
            fprintf(stderr, "farsee rdp: out of memory for password\n");
            farsee_credential_response_destroy(&cred);
            return 2;
        }
        memcpy(pwbuf, password_inline, plen);
        cred.password.data = pwbuf;
        cred.password.len = plen;
        cred.password.cap = plen + 1u;
    } else {
        fprintf(stderr,
                "farsee rdp: password required "
                "(--password-fd N or interactive TTY prompt)\n");
        farsee_credential_response_destroy(&cred);
        return 2;
    }

    rfb_presenter_dump dump;
    rfb_presenter_null nul;
    rfb_kitty_tile kitty;
    rfb_buffer kitty_out;
    bool kitty_out_live = false;
    rfb_presenter v1;

    if (pkind == RDP_PRES_DUMP) {
        if (dump_frame == NULL) {
            fprintf(stderr, "farsee rdp: --dump-frame required for dump presenter\n");
            farsee_credential_response_destroy(&cred);
            return 2;
        }
        rfb_presenter_dump_init(&dump, dump_frame, false);
        v1 = (rfb_presenter){.ops = &rfb_presenter_dump_ops, .ctx = &dump};
    } else if (pkind == RDP_PRES_KITTY_DIRECT || pkind == RDP_PRES_KITTY_SHM) {
        // Match RFB 64 MiB so 2560×1440 direct base64 fits (claude r3 F3).
        rfb_buffer_init(&kitty_out, rfb_default_allocator(),
                        64u * 1024u * 1024u);
        kitty_out_live = true;
        const uint32_t whole_edge = (desk_w > desk_h ? desk_w : desk_h);
        const uint32_t tile_edge = whole_edge < 64u ? 64u : whole_edge;
        const bool use_shm = (pkind == RDP_PRES_KITTY_SHM);
        rfb_kitty_tile_init(&kitty, rfb_default_allocator(), &kitty_out,
                            tile_edge, use_shm, /*request_ack=*/false);
        v1 = (rfb_presenter){.ops = &rfb_kitty_tile_ops, .ctx = &kitty};
        {
            static const char home[] = "\033[2J\033[H";
            (void)write(STDOUT_FILENO, home, sizeof(home) - 1);
        }
    } else {
        rfb_presenter_null_init(&nul);
        v1 = (rfb_presenter){.ops = &rfb_presenter_null_ops, .ctx = &nul};
    }

    rdp_live_tick tick;
    memset(&tick, 0, sizeof(tick));
    tick.need_home = true; // first APC batch needs placement home (claude r3 F1)
    farsee_live_shell_init(&tick.shell, leader_spec, RDP_STATUS_ROWS);
    rdp_live_bind_shell_ops(&tick);
    tick.shell.view_only = view_only;
    tick.shell.show_zoom = true;
    tick.shell.show_suspend = true;
    // Full fit by default; C-] +/- scales Kitty place (same as RFB).
    farsee_live_shell_set_view_scale(&tick.shell, FARSEE_VIEW_SCALE_MAX_PCT);
    tick.kitty_out = kitty_out_live ? &kitty_out : NULL;
    tick.shell.kitty = kitty_out_live ? &kitty : NULL;
    tick.shell.desk_w = desk_w;
    tick.shell.desk_h = desk_h;
    tick.shell.layout_active = kitty_out_live;
    tick.input_debug = (getenv("FARSEE_RDP_INPUT_DEBUG") != NULL);
    tick.verbose = (liblog >= RDP_LIBLOG_INFO);
    (void)snprintf(tick.shell.status_proto, sizeof tick.shell.status_proto,
                   "rdp");
    (void)snprintf(tick.shell.status_host, sizeof tick.shell.status_host, "%s",
                   host != NULL ? host : "");
    tick.shell.status_port = port != 0 ? port : 3389;
    // Do not draw_status here: it arms O_NONBLOCK on stdout and early setup
    // failures below would leave the shell's stdout nonblocking (loop r2 T1).
    // Layout is refreshed; first status draw runs after successful connect /
    // TTY arm later in this function.
    if (tick.shell.layout_active) {
        (void)farsee_live_shell_refresh_layout(&tick.shell, false);
    }

    // ADR-0012: freeze v1 widgets + single v2 adapter at FreeRDP edge
    // (BGRA capability). Not a second product presenter stack.
    farsee_presenter_v1_adapter adapter;
    farsee_presenter_v1_adapter_init(&adapter, v1, 256u * 1024u * 1024u);
    farsee_presenter *presenter = (farsee_presenter *)&adapter;
    presenter->ops = farsee_presenter_v1_adapter_ops();
    farsee_presenter_caps caps;
    if (farsee_presenter_open(presenter, &caps).code != FARSEE_E_OK) {
        fprintf(stderr, "farsee rdp: presenter open failed\n");
        if (kitty_out_live) {
            rfb_buffer_destroy(&kitty_out);
        }
        farsee_credential_response_destroy(&cred);
        return 2;
    }
    if (!caps.accepts_bgra8888) {
        fprintf(stderr, "farsee rdp: presenter does not accept BGRA8888\n");
        farsee_presenter_close(&presenter);
        if (kitty_out_live) {
            rfb_buffer_destroy(&kitty_out);
        }
        farsee_credential_response_destroy(&cred);
        return 2;
    }

    rdp_freerdp_ctx *ctx = rdp_freerdp_create();
    if (ctx == NULL) {
        fprintf(stderr, "farsee rdp: freerdp create failed\n");
        farsee_presenter_close(&presenter);
        if (kitty_out_live) {
            rfb_buffer_destroy(&kitty_out);
        }
        farsee_credential_response_destroy(&cred);
        return 3;
    }
    rdp_display_sink sink;
    rdp_display_sink_init(&sink);
    rdp_frame_slot frame_slot;
    rdp_inj_queue inj_q;
    bool mt_live = false;
    memset(&frame_slot, 0, sizeof(frame_slot));
    memset(&inj_q, 0, sizeof(inj_q));
    if (live) {
        farsee_atomic_int_store(&sink.cursor_visible, 1);
        farsee_atomic_int_store(&sink.cursor_x, (int)(desk_w / 2u));
        farsee_atomic_int_store(&sink.cursor_y, (int)(desk_h / 2u));
        if (!rdp_frame_slot_init(&frame_slot) || !rdp_inj_queue_init(&inj_q)) {
            fprintf(stderr, "farsee rdp: MT session init failed\n");
            rdp_freerdp_destroy(&ctx);
            farsee_presenter_close(&presenter);
            if (kitty_out_live) {
                rfb_buffer_destroy(&kitty_out);
            }
            farsee_credential_response_destroy(&cred);
            return 3;
        }
        mt_live = true;
        sink.frame_slot = &frame_slot;
        tick.inj = &inj_q;
        tick.slot = &frame_slot;
        farsee_atomic_int_store(&tick.force_repaint, 0);
        tick.shell.force_repaint = &tick.force_repaint;
        tick.shell.io_mu = farsee_mutex_create();
        if (tick.shell.io_mu == NULL) {
            fprintf(stderr, "farsee rdp: io mutex alloc failed\n");
            rdp_frame_slot_destroy(&frame_slot);
            rdp_inj_queue_destroy(&inj_q);
            rdp_freerdp_destroy(&ctx);
            farsee_presenter_close(&presenter);
            if (kitty_out_live) {
                rfb_buffer_destroy(&kitty_out);
            }
            farsee_credential_response_destroy(&cred);
            return 3;
        }
    } else {
        sink.defer_present = false;
        sink.min_present_interval_ms =
            (pkind == RDP_PRES_KITTY_DIRECT) ? 33u : 0u;
    }
    rdp_callbacks_set_presenter(ctx, presenter, &sink);

    // TOFU store for peer cert fingerprints (SHA-256 of DER). Kept alive
    // for the session (stack buffer is fine — path is short).
    char kh_path[512];
    kh_path[0] = '\0';
    {
        const char *home = getenv("HOME");
        if (home != NULL && home[0] != '\0') {
            (void)snprintf(kh_path, sizeof kh_path,
                           "%s/.farsee/rdp_known_hosts", home);
        }
    }
    // Default trust REJECT. FreeRDP only invokes VerifyX509 for untrusted
    // peers; that path must approve (TOFU match / --cert ignore) before
    // credentials. System-CA peers skip the callback; Authenticate then
    // promotes trust. --cert ignore seeds APPROVE_ONCE (may skip verify).
    const farsee_trust_decision initial_trust =
        policy.allow_insecure_cert ? FARSEE_TRUST_DECISION_APPROVE_ONCE
                                   : FARSEE_TRUST_DECISION_REJECT;
    if (!rdp_freerdp_apply_settings(ctx, &s, &policy, &cred, initial_trust,
                                   kh_path[0] != '\0' ? kh_path : NULL)) {
        fprintf(stderr, "farsee rdp: settings apply failed (unsafe posture?)\n");
        if (mt_live) {
            sink.frame_slot = NULL;
            tick.inj = NULL;
            if (tick.shell.io_mu != NULL) {
                farsee_mutex_destroy(&tick.shell.io_mu);
            }
            rdp_frame_slot_destroy(&frame_slot);
            rdp_inj_queue_destroy(&inj_q);
        }
        rdp_freerdp_destroy(&ctx);
        farsee_presenter_close(&presenter);
        if (kitty_out_live) {
            rfb_buffer_destroy(&kitty_out);
        }
        farsee_credential_response_destroy(&cred);
        return 3;
    }

    // T23: install cancel handlers before blocking freerdp_connect so
    // SIGINT/SIGTERM arm g_rdp_stop early (TcpConnectTimeout also bounds stall).
    farsee_atomic_int_store(&g_rdp_stop, 0);
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = rdp_on_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    struct sigaction old_int, old_term;
    (void)sigaction(SIGINT, &sa, &old_int);
    (void)sigaction(SIGTERM, &sa, &old_term);

    // Cooperative stop during blocking connect (full2 T5).
    if (!rdp_freerdp_connect_with_stop(ctx, &g_rdp_stop)) {
        fprintf(stderr, "farsee rdp: connect failed: %s\n",
                rdp_freerdp_last_error_name(ctx));
        (void)sigaction(SIGINT, &old_int, NULL);
        (void)sigaction(SIGTERM, &old_term, NULL);
        if (mt_live) {
            sink.frame_slot = NULL;
            tick.inj = NULL;
            if (tick.shell.io_mu != NULL) {
                farsee_mutex_destroy(&tick.shell.io_mu);
            }
            rdp_frame_slot_destroy(&frame_slot);
            rdp_inj_queue_destroy(&inj_q);
        }
        rdp_freerdp_destroy(&ctx);
        farsee_presenter_close(&presenter);
        if (kitty_out_live) {
            rfb_buffer_destroy(&kitty_out);
        }
        farsee_credential_response_destroy(&cred);
        return 4;
    }
    // FreeRDP has copied credentials for NLA; wipe our buffer so the
    // password does not sit on the heap for the whole interactive session.
    farsee_credential_response_destroy(&cred);
    farsee_credential_response_init(&cred);
    // Hygiene: callback must not re-enter Authenticate on wiped storage.
    if (ctx != NULL) {
        rdp_freerdp_clear_credentials(ctx);
    }
    if (live && tick.shell.layout_active) {
        farsee_live_shell_draw_status(&tick.shell);
    }

    tick.ctx = ctx;
    tick.sink = &sink;
    farsee_key_ledger_init(&tick.ledger);
    if (kitty_out_live || live) {
        tick.shell.tty_fd = -1;
        tick.shell.tty_fd_owned = false;
        // Geometry for Kitty layout without input TTY yet (r3 T2 / r4).
        {
            uint16_t cols = 0u;
            uint16_t rows = 0u;
            uint16_t pw = 0u;
            uint16_t ph = 0u;
            if (farsee_live_shell_probe_winsize(-1, &cols, &rows, &pw, &ph)) {
                farsee_live_shell_set_term_geom(&tick.shell, cols, rows, pw, ph);
            } else {
                int tfd = open("/dev/tty", O_RDONLY | O_NOCTTY);
                if (tfd >= 0) {
                    if (farsee_live_shell_probe_winsize(tfd, &cols, &rows, &pw,
                                                        &ph)) {
                        farsee_live_shell_set_term_geom(&tick.shell, cols, rows, pw, ph);
                    }
                    close(tfd);
                }
            }
        }
        if (!farsee_tty_open_input(&tick.shell.tty_fd,
                                   &tick.shell.tty_fd_owned)) {
            fprintf(stderr,
                    "farsee rdp: warning: no TTY for input (%s)\n",
                    strerror(errno));
            if (tick.shell.layout_active) {
                (void)farsee_live_shell_refresh_layout(&tick.shell, true);
                farsee_live_shell_draw_status(&tick.shell);
            }
        } else {
            if (!farsee_live_shell_quiet_enter(&tick.shell)) {
                rdp_live_log(&tick,
                             "farsee rdp: warning: could not disable TTY echo "
                             "(Kitty replies may print as text)\n");
            }
            // Refresh winsize from input fd; merge non-zero pixels only.
            {
                uint16_t cols = 0u;
                uint16_t rows = 0u;
                uint16_t pw = 0u;
                uint16_t ph = 0u;
                if (farsee_live_shell_probe_winsize(tick.shell.tty_fd, &cols,
                                                    &rows, &pw, &ph)) {
                    {

                        uint16_t opw = tick.shell.term_pw;

                        uint16_t oph = tick.shell.term_ph;

                        farsee_live_shell_set_term_geom(&tick.shell, cols, rows,

                                                        pw != 0u ? pw : opw,

                                                        ph != 0u ? ph : oph);

                    }
                }
            }
            (void)farsee_live_shell_refresh_layout(&tick.shell, true);
            farsee_live_shell_draw_status(&tick.shell);
            if (live && !view_only) {
                tick.shell.want_mouse = true;
                tick.shell.want_kitty_kb = true;
                farsee_live_shell_input_enable(&tick.shell);
                // Peer often drops scancodes until FocusIn (session focus).
                (void)rdp_input_inject_focus_in(ctx);
                // Armed banner: FARSEE_RDP_INPUT_DEBUG or --verbose.
                if (tick.verbose || tick.input_debug) {
                    fprintf(stderr,
                            "farsee rdp: input armed on %s fd=%d owned=%d "
                            "mouse=%d kitty_kb=%d\n",
                            farsee_tty_input_label(tick.shell.tty_fd,
                                                   tick.shell.tty_fd_owned),
                            tick.shell.tty_fd,
                            tick.shell.tty_fd_owned ? 1 : 0,
                            tick.shell.mouse_enabled ? 1 : 0,
                            tick.shell.want_kitty_kb ? 1 : 0);
                    (void)fflush(stderr);
                }
            }
            // atexit TTY guard parity with RFB.
            farsee_live_shell_tty_guard_arm(
                tick.shell.tty_fd, tick.shell.tty_attrs_saved,
                &tick.shell.tty_saved, tick.shell.mouse_enabled,
                tick.shell.want_kitty_kb);
        }
    }

    bool got_frame = false;
    farsee_error re = farsee_error_make(FARSEE_E_OK, FARSEE_SUB_NONE,
                                        FARSEE_PHASE_ACTIVE);
    if (mt_live) {
        rdp_mt_config mtc;
        memset(&mtc, 0, sizeof(mtc));
        mtc.ctx = ctx;
        mtc.sink = &sink;
        mtc.presenter = presenter;
        mtc.slot = &frame_slot;
        mtc.inj = &inj_q;
        mtc.ledger = &tick.ledger; // RELEASE_ALL path (T9)
        mtc.wire_buttons = &tick.wire_buttons;
        mtc.stop_flag = &g_rdp_stop;
        mtc.present_interval_ms =
            (pkind == RDP_PRES_KITTY_DIRECT) ? 33u : 16u;
        mtc.input_fn = rdp_live_input_fn;
        mtc.input_user = &tick;
        mtc.after_present_fn = rdp_live_after_present;
        mtc.after_present_user = &tick;
        mtc.force_repaint = &tick.force_repaint;
        mtc.io_mu = tick.shell.io_mu;
        mtc.link_meta = &tick.link_meta;
        mtc.link_rx_bytes = &tick.link_rx_bytes;
        mtc.link_rate_pub = &tick.link_rate_pub;
        if (tick.verbose) {
            rdp_live_log(&tick,
                         "farsee rdp: multi-thread live (protocol / present "
                         "%u ms / input)\n",
                         (unsigned)mtc.present_interval_ms);
        }
        re = rdp_mt_run(&mtc, &got_frame);
    } else {
        rdp_run_budget budget;
        memset(&budget, 0, sizeof(budget));
        budget.sink = &sink;
        budget.stop_flag = &g_rdp_stop;
        // No on_tick: dump/null settle has no interactive shell; live Kitty
        // is always MT (rdp_live_on_tick removed as unreachable).
        budget.deadline_monotonic_ms =
            farsee_thread_monotonic_ms() + connect_timeout_ms + 4000u;
        budget.stop_on_first_frame = true;
        budget.settle_ms_after_first = 4000u;
        re = rdp_freerdp_run_until(ctx, &budget, &got_frame);
    }

    (void)sigaction(SIGINT, &old_int, NULL);
    (void)sigaction(SIGTERM, &old_term, NULL);

    if (kitty_out_live) {
        rdp_live_drain_graphics(&tick);
        drain_tty_responses(tick.shell.tty_fd);
        tick.log_flowing = false;
    }

    int rc = 0;
    const bool peer_clean = rdp_freerdp_is_clean_peer_disconnect(ctx);
    if (farsee_atomic_int_load_nonzero(&g_rdp_stop)) {
        rdp_live_log(&tick, "farsee rdp: disconnected (Ctrl-] / signal)\n");
    } else if (peer_clean &&
               (got_frame ||
                farsee_atomic_u64_load(&sink.frame_count) > 0u)) {
        const char *ename = rdp_freerdp_last_error_name(ctx);
        rdp_live_log(&tick,
                     "farsee rdp: session ended by server (%s) after %llu "
                     "frame(s) (%ux%u)\n",
                     ename,
                     (unsigned long long)farsee_atomic_u64_load(
                         &sink.frame_count),
                     (unsigned)sink.last_width, (unsigned)sink.last_height);
        if (ename != NULL && strstr(ename, "LOGOFF") != NULL) {
            rdp_live_log(
                &tick,
                "farsee rdp: Windows signed this session out (not a farsee "
                "disconnect). Common causes:\n");
            rdp_live_log(
                &tick,
                "  • Start → Sign out (or accidental click with bad mouse "
                "map)\n");
            rdp_live_log(
                &tick,
                "  • Hyper-V/VMware console or another RDP client as the "
                "same user\n");
            rdp_live_log(
                &tick,
                "  • Host policy: max session / idle time ending in logoff\n");
            rdp_live_log(
                &tick,
                "  Check Event Viewer → Windows Logs → Security/System on "
                "the VM.\n");
        } else if (ename != NULL &&
                   strstr(ename, "DISCONNECTED_BY_OTHER") != NULL) {
            rdp_live_log(
                &tick,
                "farsee rdp: another connection took over this user session "
                "(reconnect elsewhere or exclusive console login).\n");
        } else if (ename != NULL && strstr(ename, "IDLE") != NULL) {
            rdp_live_log(
                &tick,
                "farsee rdp: server idle-timeout ended the session "
                "(RDS/GPO MaxIdleTime).\n");
        } else {
            rdp_live_log(
                &tick,
                "farsee rdp: (peer disconnect — logoff, takeover, or "
                "admin-initiated end)\n");
        }
    } else if (got_frame) {
        rdp_live_log(&tick,
                     "farsee rdp: desktop frames delivered (%ux%u, n=%llu)%s%s\n",
                     (unsigned)sink.last_width, (unsigned)sink.last_height,
                     (unsigned long long)farsee_atomic_u64_load(
                         &sink.frame_count),
                     pkind == RDP_PRES_DUMP && dump_frame != NULL ? " -> " : "",
                     pkind == RDP_PRES_DUMP && dump_frame != NULL ? dump_frame
                                                                  : "");
    } else {
        rdp_live_log(&tick, "farsee rdp: no frame (%s)\n",
                     re.code == FARSEE_ERR_TIMEOUT ? "timeout"
                     : rdp_freerdp_last_error_name(ctx));
        rc = 5;
    }
    if (kitty_out_live &&
        (pkind == RDP_PRES_KITTY_SHM || pkind == RDP_PRES_KITTY_DIRECT)) {
        rdp_live_log(&tick,
                     "farsee rdp: kitty transport: shm=%llu "
                     "direct_fallback=%llu presents=%llu\n",
                     (unsigned long long)kitty.metrics.shm_transfers,
                     (unsigned long long)kitty.metrics.shm_fallbacks,
                     (unsigned long long)kitty.metrics.presents);
        if (pkind == RDP_PRES_KITTY_SHM && kitty.metrics.shm_transfers == 0 &&
            kitty.metrics.presents > 0) {
            rdp_live_log(&tick,
                         "farsee rdp: warning: SHM path never succeeded; all "
                         "frames used base64-over-TTY (t=d)\n");
        }
    }

    tick.inj = NULL;
    if (!view_only) {
        // Keys + held mouse buttons (reaudit T5; RFB release_held parity).
        int32_t rx = 0;
        int32_t ry = 0;
        if (tick.sink != NULL) {
            rx = farsee_atomic_int_load(&tick.sink->cursor_x);
            ry = farsee_atomic_int_load(&tick.sink->cursor_y);
        }
        // MT: wire_buttons is authoritative (may be 0 after real release).
        // ST: prev_buttons only (deferred D3 / grok F4).
        unsigned held = mt_live ? tick.wire_buttons : tick.prev_buttons;
        (void)rdp_input_inject_release_buttons(ctx, &held, rx, ry);
        tick.wire_buttons = 0u;
        tick.prev_buttons = 0u;
        rdp_input_inject_release_all(ctx, &tick.ledger);
    }
    farsee_live_shell_tty_guard_restore();
    tick.shell.mouse_enabled = false;
    rdp_freerdp_request_stop(ctx);
    rdp_freerdp_disconnect(ctx);
    rdp_freerdp_destroy(&ctx);
    tick.ctx = NULL;
    if (mt_live) {
        sink.frame_slot = NULL;
        if (tick.shell.io_mu != NULL) {
            farsee_mutex_destroy(&tick.shell.io_mu);
        }
        rdp_frame_slot_destroy(&frame_slot);
        rdp_inj_queue_destroy(&inj_q);
    }
    farsee_presenter_close(&presenter);
    if (kitty_out_live) {
        farsee_drain_kitty_out(&kitty_out, STDOUT_FILENO, tick.shell.io_mu);
        drain_tty_responses(tick.shell.tty_fd);
        rfb_buffer_destroy(&kitty_out);
        tick.shell.layout_active = false;
    }
    farsee_live_shell_quiet_restore(&tick.shell);
    if (tick.shell.tty_fd >= 0) {
        drain_tty_responses(tick.shell.tty_fd);
        farsee_tty_close_input(tick.shell.tty_fd, tick.shell.tty_fd_owned);
        tick.shell.tty_fd = -1;
        tick.shell.tty_fd_owned = false;
    }
    farsee_credential_response_destroy(&cred);
    return rc;
}

#endif /* FARSEE_WITH_RDP */
