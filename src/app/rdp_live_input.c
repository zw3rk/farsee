// SPDX-License-Identifier: Apache-2.0
//
// RDP live input, terminal suspension, and shared-shell operations.

#include "app/rdp_live_input.h"
#include "app/rdp_live_input_internal.h"
#include "app/live_signal_scope.h"

#ifdef FARSEE_WITH_RDP

#include "farsee/kitty_tile.h"
#include "farsee/term_mouse_map.h"
#include "protocol/rdp/rdp_input_bridge.h"
#include "protocol/rdp/rdp_input_inject.h"

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void rdp_live_request_quit(rdp_live_tick *tick);
static void rdp_live_inject_key(rdp_live_tick *tick,
                                const rfb_norm_key *key);

static void rdp_live_tty_yield(rdp_live_tick *tick)
{
    if (tick == NULL) {
        return;
    }
    farsee_live_shell_input_disable(&tick->shell);
    farsee_live_shell_quiet_restore(&tick->shell);
    if (tick->shell.tty_fd >= 0) {
        uint8_t junk[512];
        for (;;) {
            const ssize_t count =
                read(tick->shell.tty_fd, junk, sizeof junk);
            if (count <= 0) {
                break;
            }
        }
    }
    tick->shell.demux.residual_len = 0u;
    farsee_atomic_int_store(&tick->shell.demux.leader_armed, 0);
    tick->shell.demux.leader_deadline_ms = 0u;
}

static void rdp_live_tty_reclaim(rdp_live_tick *tick)
{
    if (tick == NULL) {
        return;
    }
    if (tick->shell.tty_fd >= 0) {
        (void)farsee_live_shell_quiet_enter(&tick->shell);
        uint16_t cols = 0u;
        uint16_t rows = 0u;
        uint16_t pixel_width = 0u;
        uint16_t pixel_height = 0u;
        if (farsee_live_shell_probe_winsize(
                tick->shell.tty_fd, &cols, &rows, &pixel_width,
                &pixel_height)) {
            const uint16_t old_pixel_width = tick->shell.term_pw;
            const uint16_t old_pixel_height = tick->shell.term_ph;
            farsee_live_shell_set_term_geom(
                &tick->shell, cols, rows,
                pixel_width != 0u ? pixel_width : old_pixel_width,
                pixel_height != 0u ? pixel_height : old_pixel_height);
        }
    }
    farsee_live_shell_input_enable(&tick->shell);
    if (tick->shell.layout_active) {
        (void)farsee_live_shell_refresh_layout(&tick->shell, true);
        farsee_live_shell_home_cursor();
        farsee_live_shell_draw_status(&tick->shell);
    }
    if (tick->sink != NULL) {
        farsee_atomic_int_store(&tick->sink->present_pending, 1);
    }
}

static void rdp_live_suspend(rdp_live_tick *tick)
{
    if (tick == NULL) {
        return;
    }
    rdp_live_tty_yield(tick);
    fprintf(stderr, "farsee: suspended — type 'fg' to resume\n");
    (void)fflush(stderr);

    const int stop_signal = SIGTSTP;
    farsee_live_signal_scope signal_scope;
    farsee_live_signal_scope_init(&signal_scope);
    if (farsee_live_signal_scope_arm(
            &signal_scope, &stop_signal, 1u, SIG_DFL)) {
        (void)raise(SIGTSTP);
        farsee_live_signal_scope_restore(&signal_scope);
    }

    rdp_live_tty_reclaim(tick);
}

static void rdp_live_request_quit(rdp_live_tick *tick)
{
    if (tick != NULL && tick->process_stop != NULL) {
        farsee_atomic_int_store(tick->process_stop, 1);
    }
    if (tick != NULL && tick->ctx != NULL) {
        rdp_freerdp_request_stop(tick->ctx);
    }
}

static bool rdp_live_deliver_direct(
    void *user, const farsee_modifier_synth_action *action)
{
    rdp_live_tick *tick = (rdp_live_tick *)user;
    if (tick == NULL || action == NULL || tick->ctx == NULL) {
        return false;
    }
    return rdp_input_inject_key_from_keysym(
        tick->ctx, action->keysym, action->text, action->down,
        action->repeat);
}

// The direct path updates the ledger after injection. The MT protocol thread
// owns the ledger when an injection queue is present.
static void rdp_live_ledger_key(rdp_live_tick *tick, uint32_t keysym,
                                bool down)
{
    if (tick == NULL || tick->inj != NULL) {
        return;
    }
    farsee_key_event key_event;
    if (!rdp_input_key_event_from_keysym(&key_event, keysym, 0u, down,
                                         false)) {
        return;
    }
    if (farsee_key_ledger_apply(&tick->ledger, &key_event)) {
        return;
    }
    if (!down || key_event.physical == 0u || tick->ctx == NULL) {
        return;
    }
    rdp_input_inject_release_all(tick->ctx, &tick->ledger);
    if (tick->ledger.count < FARSEE_KEY_LEDGER_MAX) {
        (void)farsee_key_ledger_apply(&tick->ledger, &key_event);
    }
}

static void rdp_live_accept_direct(
    void *user, const farsee_modifier_synth_action *action)
{
    rdp_live_tick *tick = (rdp_live_tick *)user;
    if (tick != NULL && action != NULL) {
        rdp_live_ledger_key(tick, action->keysym, action->down);
    }
}

static bool rdp_live_send_key_action(
    void *user, const farsee_modifier_synth_action *action)
{
    rdp_live_tick *tick = (rdp_live_tick *)user;
    if (tick == NULL || action == NULL) {
        return false;
    }
    if (tick->inj != NULL) {
        return farsee_modifier_synth_rdp_queue_send(tick->inj, action);
    }
    farsee_modifier_synth_rdp_direct_adapter adapter = {
        .user = tick,
        .deliver = rdp_live_deliver_direct,
        .ledger = rdp_live_accept_direct,
    };
    return farsee_modifier_synth_rdp_direct_send(&adapter, action);
}

static void rdp_live_inject_key(rdp_live_tick *tick,
                                const rfb_norm_key *key)
{
    if (tick == NULL || key == NULL || tick->shell.view_only) {
        return;
    }
    if (tick->inj == NULL && tick->ctx == NULL) {
        return;
    }
    const uint16_t physical =
        rfb_norm_mods_bits(&tick->shell.demux.mods);
    if (farsee_modifier_synth_inject(
            &tick->synth_mods, key, physical, rdp_live_send_key_action,
            tick)) {
        return;
    }
    if (farsee_modifier_synth_requires_stop(&tick->synth_mods)) {
        rdp_live_log(tick,
                     "farsee rdp: key modifier delivery failed; closing\n");
        rdp_live_request_quit(tick);
    } else {
        rdp_live_log(
            tick, "farsee rdp: key delivery failed; recovery pending\n");
    }
}

static void rdp_shell_inject_key(void *user, const rfb_norm_key *key)
{
    rdp_live_inject_key((rdp_live_tick *)user, key);
}

static bool rdp_shell_inject_pointer(void *user, int32_t x, int32_t y,
                                     uint8_t buttons, int wheel_vertical,
                                     int wheel_horizontal)
{
    rdp_live_tick *tick = (rdp_live_tick *)user;
    if (tick == NULL || tick->shell.view_only) {
        return false;
    }
    if (tick->ctx == NULL && tick->inj == NULL) {
        return false;
    }
    farsee_pointer_event pointer_event;
    memset(&pointer_event, 0, sizeof pointer_event);
    pointer_event.abs_x = x;
    pointer_event.abs_y = y;
    pointer_event.quality = FARSEE_INPUT_QUALITY_INFERRED;
    pointer_event.wheel_v = wheel_vertical;
    pointer_event.wheel_h = wheel_horizontal;
    pointer_event.buttons = buttons;
    if (tick->sink != NULL) {
        farsee_atomic_int_store(&tick->sink->cursor_x, (int)pointer_event.abs_x);
        farsee_atomic_int_store(&tick->sink->cursor_y, (int)pointer_event.abs_y);
        farsee_atomic_int_store(&tick->sink->cursor_visible, 1);
    }

    bool accepted = false;
    if (tick->inj != NULL) {
        rdp_inj_cmd command;
        memset(&command, 0, sizeof command);
        command.kind = RDP_INJ_POINTER;
        command.pe = pointer_event;
        command.prev_buttons = tick->prev_buttons;
        accepted = rdp_inj_queue_push(tick->inj, &command);
        if (accepted) {
            tick->prev_buttons = buttons;
        }
    }
    if (tick->inj == NULL && tick->ctx != NULL) {
        unsigned reached = tick->prev_buttons;
        accepted = rdp_input_inject_pointer(
            tick->ctx, &pointer_event, tick->prev_buttons, &reached);
        tick->prev_buttons = reached;
        if (accepted) {
            tick->prev_buttons = buttons;
        }
    }
    return accepted;
}

static void rdp_shell_request_quit(void *user)
{
    rdp_live_request_quit((rdp_live_tick *)user);
}

static void rdp_shell_suspend(void *user)
{
    rdp_live_suspend((rdp_live_tick *)user);
}

static void rdp_live_zoom(rdp_live_tick *tick, int delta_pct)
{
    if (tick == NULL) {
        return;
    }
    farsee_live_shell *shell = &tick->shell;
    int32_t next =
        (int32_t)farsee_live_shell_view_scale(shell) + delta_pct;
    if (next < (int32_t)FARSEE_VIEW_SCALE_MIN_PCT) {
        next = (int32_t)FARSEE_VIEW_SCALE_MIN_PCT;
    }
    if (next > (int32_t)FARSEE_VIEW_SCALE_MAX_PCT) {
        next = (int32_t)FARSEE_VIEW_SCALE_MAX_PCT;
    }
    if ((uint32_t)next == farsee_live_shell_view_scale(shell)) {
        rdp_live_log(tick, "farsee rdp: view scale already %u%%\n",
                     (unsigned)farsee_live_shell_view_scale(shell));
        return;
    }
    farsee_live_shell_set_view_scale(shell, (uint32_t)next);
    if (shell->layout_active) {
        (void)farsee_live_shell_refresh_layout(shell, true);
    }
    rdp_live_log(tick, "farsee rdp: view scale %u%%  (%ux%u cells)\n",
                 (unsigned)farsee_live_shell_view_scale(shell),
                 (unsigned)shell->place_cols, (unsigned)shell->place_rows);
}

static void rdp_shell_zoom(void *user, int delta_pct)
{
    rdp_live_zoom((rdp_live_tick *)user, delta_pct);
}

static void rdp_shell_status_extra(void *user, char *buf, size_t cap)
{
    rdp_live_tick *tick = (rdp_live_tick *)user;
    if (tick == NULL || buf == NULL || cap == 0u) {
        return;
    }
    const uint64_t meta = farsee_atomic_u64_load(&tick->link_meta);
    uint32_t rtt = 0u;
    bool have_rtt = false;
    bool have_rx = false;
    farsee_link_meta_unpack(meta, &rtt, &have_rtt, &have_rx);
    (void)have_rx;
    uint32_t rate_kib = 0u;
    bool have_rate = false;
    farsee_link_rate_unpack(
        farsee_atomic_u64_load(&tick->link_rate_pub), &rate_kib,
        &have_rate);
    char link[96];
    farsee_live_shell_format_link_extra(
        link, sizeof link, farsee_live_shell_view_scale(&tick->shell), rtt,
        have_rtt, rate_kib, have_rate);
    if (tick->verbose && tick->sink != NULL) {
        (void)snprintf(
            buf, cap,
            "%s  \033[2min=%llu paint=%llu show=%llu\033[0m", link,
            (unsigned long long)farsee_atomic_u64_load(
                &tick->shell.input_events),
            (unsigned long long)farsee_atomic_u64_load(
                &tick->sink->end_paint_count),
            (unsigned long long)farsee_atomic_u64_load(
                &tick->sink->frame_count));
    } else {
        (void)snprintf(buf, cap, "%s", link);
    }
}

static void rdp_shell_on_layout_applied(void *user)
{
    rdp_live_tick *tick = (rdp_live_tick *)user;
    if (tick != NULL && tick->slot != NULL) {
        rdp_frame_slot_kick(tick->slot);
    }
}

void rdp_live_bind_shell_ops(rdp_live_tick *tick)
{
    if (tick == NULL) {
        return;
    }
    memset(&tick->shell_ops, 0, sizeof tick->shell_ops);
    tick->shell_ops.inject_key = rdp_shell_inject_key;
    tick->shell_ops.inject_pointer = rdp_shell_inject_pointer;
    tick->shell_ops.request_quit = rdp_shell_request_quit;
    tick->shell_ops.zoom = rdp_shell_zoom;
    tick->shell_ops.suspend = rdp_shell_suspend;
    tick->shell_ops.status_extra = rdp_shell_status_extra;
    tick->shell_ops.on_layout_applied = rdp_shell_on_layout_applied;
    tick->shell.ops = &tick->shell_ops;
    tick->shell.ops_user = tick;
}

static void rdp_live_process_input(rdp_live_tick *tick,
                                   const uint8_t *data, size_t size,
                                   uint64_t now_ms)
{
    if (tick != NULL) {
        farsee_live_shell_feed_tty(&tick->shell, data, size, now_ms);
    }
}

static uint64_t rdp_live_input_monotonic_ms(void *user)
{
    (void)user;
    return farsee_thread_monotonic_ms();
}

static bool rdp_live_input_probe_winsize(
    void *user, int fd, uint16_t *cols, uint16_t *rows,
    uint16_t *pixel_width, uint16_t *pixel_height)
{
    (void)user;
    return farsee_live_shell_probe_winsize(
        fd, cols, rows, pixel_width, pixel_height);
}

static bool rdp_live_input_refresh_layout(void *user,
                                          farsee_live_shell *shell,
                                          bool apply_kitty)
{
    (void)user;
    return farsee_live_shell_refresh_layout(shell, apply_kitty);
}

static void rdp_live_input_draw_status(void *user, farsee_live_shell *shell)
{
    (void)user;
    farsee_live_shell_draw_status(shell);
}

static int rdp_live_input_poll(void *user, int fd, int timeout_ms,
                               short *out_revents, int *out_error)
{
    (void)user;
    *out_revents = 0;
    *out_error = 0;
    struct pollfd pfd;
    memset(&pfd, 0, sizeof pfd);
    nfds_t count = 0;
    if (fd >= 0) {
        pfd.fd = fd;
        pfd.events = POLLIN;
        count = 1;
    }
    const int result = poll(&pfd, count, timeout_ms);
    if (result < 0) {
        *out_error = errno;
    }
    *out_revents = pfd.revents;
    return result;
}

static ssize_t rdp_live_input_read(void *user, int fd, uint8_t *buffer,
                                   size_t capacity, int *out_error)
{
    (void)user;
    *out_error = 0;
    const ssize_t result = read(fd, buffer, capacity);
    if (result < 0) {
        *out_error = errno;
    }
    return result;
}

static const rdp_live_input_ops rdp_live_input_default_ops = {
    .user = NULL,
    .monotonic_ms = rdp_live_input_monotonic_ms,
    .probe_winsize = rdp_live_input_probe_winsize,
    .refresh_layout = rdp_live_input_refresh_layout,
    .draw_status = rdp_live_input_draw_status,
    .poll_input = rdp_live_input_poll,
    .read_input = rdp_live_input_read,
};

static bool rdp_live_input_ops_complete(const rdp_live_input_ops *ops)
{
    return ops != NULL && ops->monotonic_ms != NULL &&
           ops->probe_winsize != NULL && ops->refresh_layout != NULL &&
           ops->draw_status != NULL && ops->poll_input != NULL &&
           ops->read_input != NULL;
}

farsee_mt_terminal_kind rdp_live_input_run(
    rdp_live_tick *tick, rdp_inj_queue *inj, farsee_atomic_int *stop,
    farsee_mt_terminal *terminal, const rdp_live_input_ops *ops)
{
    if (tick == NULL || !rdp_live_input_ops_complete(ops)) {
        (void)farsee_mt_terminal_report(
            terminal, FARSEE_MT_TERMINAL_INTERNAL_FAILURE);
        return FARSEE_MT_TERMINAL_INTERNAL_FAILURE;
    }
    tick->inj = inj;
    uint64_t last_winsize_ms = 0u;
    uint64_t last_link_status_ms = 0u;
    while (!farsee_atomic_int_load_nonzero(stop)) {
        if (tick->process_stop != NULL &&
            farsee_atomic_int_load_nonzero(tick->process_stop)) {
            break;
        }
        farsee_live_shell *shell = &tick->shell;
        (void)farsee_live_shell_apply_pending_desk(shell, true);

        const uint64_t winsize_now = ops->monotonic_ms(ops->user);
        if (last_winsize_ms == 0u ||
            winsize_now - last_winsize_ms >= 250u) {
            last_winsize_ms = winsize_now;
            uint16_t cols = 0u;
            uint16_t rows = 0u;
            uint16_t pixel_width = 0u;
            uint16_t pixel_height = 0u;
            if (ops->probe_winsize(ops->user, shell->tty_fd, &cols,
                                   &rows, &pixel_width, &pixel_height)) {
                const bool resized =
                    shell->term_cols != cols || shell->term_rows != rows ||
                    shell->term_pw != pixel_width ||
                    shell->term_ph != pixel_height;
                farsee_live_shell_set_term_geom(
                    shell, cols, rows, pixel_width, pixel_height);
                if (resized && shell->layout_active) {
                    (void)ops->refresh_layout(ops->user, shell, true);
                    ops->draw_status(ops->user, shell);
                }
            }
        }

        const uint64_t link_now = ops->monotonic_ms(ops->user);
        if (shell->layout_active &&
            (last_link_status_ms == 0u ||
             link_now - last_link_status_ms >= 500u)) {
            last_link_status_ms = link_now;
            ops->draw_status(ops->user, shell);
        }

        if (shell->tty_fd < 0) {
            short revents = 0;
            int poll_error = 0;
            (void)ops->poll_input(ops->user, -1, 20, &revents,
                                  &poll_error);
            continue;
        }
        short revents = 0;
        int poll_error = 0;
        const int poll_result = ops->poll_input(
            ops->user, shell->tty_fd, 20, &revents, &poll_error);
        if (poll_result < 0) {
            if (poll_error == EINTR) {
                continue;
            }
            if (tick->verbose) {
                rdp_live_log(tick, "farsee rdp: input polling failed\n");
            }
            (void)farsee_mt_terminal_report(
                terminal, FARSEE_MT_TERMINAL_INPUT_FAILURE);
            tick->inj = NULL;
            return FARSEE_MT_TERMINAL_INPUT_FAILURE;
        }
        size_t received = 0u;
        if (poll_result > 0 &&
            (revents & (POLLIN | POLLHUP | POLLERR | POLLNVAL)) != 0) {
            uint8_t buffer[1024];
            for (;;) {
                int read_error = 0;
                const ssize_t count = ops->read_input(
                    ops->user, shell->tty_fd, buffer, sizeof buffer,
                    &read_error);
                if (count > 0) {
                    received += (size_t)count;
                    rdp_live_process_input(
                        tick, buffer, (size_t)count,
                        ops->monotonic_ms(ops->user));
                    continue;
                }
                if (count == -1 && read_error == EINTR) {
                    continue;
                }
                if (count == -1 &&
                    (read_error == EAGAIN ||
                     read_error == EWOULDBLOCK)) {
                    break;
                }
                if (count == -1) {
                    (void)farsee_mt_terminal_report(
                        terminal, FARSEE_MT_TERMINAL_INPUT_FAILURE);
                    tick->inj = NULL;
                    return FARSEE_MT_TERMINAL_INPUT_FAILURE;
                }
                break;
            }
        }
        if (poll_result > 0 && received == 0u &&
            (revents & (POLLHUP | POLLERR | POLLNVAL)) != 0) {
            (void)farsee_mt_terminal_report(
                terminal, FARSEE_MT_TERMINAL_INPUT_FAILURE);
            tick->inj = NULL;
            return FARSEE_MT_TERMINAL_INPUT_FAILURE;
        }
        farsee_live_shell_tick_timeout(
            shell, ops->monotonic_ms(ops->user));
    }
    tick->inj = NULL;
    (void)farsee_mt_terminal_report(
        terminal, FARSEE_MT_TERMINAL_REQUESTED_STOP);
    return FARSEE_MT_TERMINAL_REQUESTED_STOP;
}

farsee_mt_terminal_kind rdp_live_input_fn(
    void *user, rdp_inj_queue *inj, farsee_atomic_int *stop,
    farsee_mt_terminal *terminal)
{
    return rdp_live_input_run((rdp_live_tick *)user, inj, stop, terminal,
                              &rdp_live_input_default_ops);
}

#endif  // FARSEE_WITH_RDP
