// SPDX-License-Identifier: Apache-2.0
//
// RFB live logging, input injection, and shared-shell operations.

#include "app/rfb_live_ui.h"

#include "farsee/kitty_tile.h"
#include "farsee/term_mouse_map.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void rfb_live_request_quit(rfb_live_ui *ui);

static void rfb_live_log(rfb_live_ui *ui, const char *fmt, ...)
#if defined(__GNUC__) || defined(__clang__)
    __attribute__((format(printf, 2, 3)))
#endif
    ;

static void rfb_live_log(rfb_live_ui *ui, const char *fmt, ...)
{
    char body[384];
    va_list args;
    va_start(args, fmt);
    int length = vsnprintf(body, sizeof body, fmt, args);
    va_end(args);
    if (length < 0) {
        return;
    }
    while (length > 0 &&
           (body[length - 1] == '\n' || body[length - 1] == '\r')) {
        body[--length] = '\0';
    }
    farsee_live_shell *shell = ui != NULL ? &ui->shell : NULL;
    if (shell != NULL && shell->layout_active && isatty(STDOUT_FILENO)) {
        bool wrote_stdout = false;
        if (shell->io_mu != NULL) {
            farsee_mutex_lock(shell->io_mu);
        }
        const bool pending =
            shell->kitty != NULL && shell->kitty->out != NULL &&
            rfb_buffer_length(shell->kitty->out) > 0u;
        if (!pending) {
            farsee_live_shell_fix_status_rows(shell);
            farsee_live_shell_park_log_cursor(shell);
            char line[512];
            const int line_length = snprintf(
                line, sizeof line, "\033[K\033[38;5;110m%s\033[0m", body);
            if (line_length > 0 && (size_t)line_length < sizeof line) {
                (void)farsee_live_shell_write_all(
                    STDOUT_FILENO, line, (size_t)line_length);
                wrote_stdout = true;
            }
            farsee_live_shell_park_log_cursor(shell);
        }
        if (shell->io_mu != NULL) {
            farsee_mutex_unlock(shell->io_mu);
        }
        if (wrote_stdout) {
            return;
        }
        if (shell->io_mu != NULL) {
            farsee_mutex_lock(shell->io_mu);
        }
        flockfile(stderr);
        (void)fputs(body, stderr);
        if (length == 0 || body[length - 1] != '\n') {
            (void)fputc('\n', stderr);
        }
        (void)fflush(stderr);
        funlockfile(stderr);
        if (shell->io_mu != NULL) {
            farsee_mutex_unlock(shell->io_mu);
        }
        return;
    }
    flockfile(stderr);
    (void)fputs(body, stderr);
    if (length == 0 || body[length - 1] != '\n') {
        (void)fputc('\n', stderr);
    }
    (void)fflush(stderr);
    funlockfile(stderr);
}

static bool rfb_live_send_key_action(
    void *user, const farsee_modifier_synth_action *action)
{
    rfb_live_ui *ui = (rfb_live_ui *)user;
    if (ui == NULL || action == NULL || ui->shell.view_only ||
        ui->cmds == NULL) {
        return false;
    }
    return farsee_modifier_synth_rfb_queue_send(ui->cmds, action);
}

static void rfb_live_inject_norm_key(rfb_live_ui *ui,
                                     const rfb_norm_key *key)
{
    if (ui == NULL || key == NULL) {
        return;
    }
    const uint16_t physical =
        rfb_norm_mods_bits(&ui->shell.demux.mods);
    if (farsee_modifier_synth_inject(
            &ui->synth_mods, key, physical, rfb_live_send_key_action, ui)) {
        return;
    }
    if (farsee_modifier_synth_requires_stop(&ui->synth_mods)) {
        rfb_live_log(ui, "key modifier delivery failed; closing session\n");
        rfb_live_request_quit(ui);
    } else {
        rfb_live_log(ui,
                     "key delivery failed; recovery will precede input\n");
    }
}

static bool rfb_live_push_pointer(rfb_live_ui *ui, int32_t x, int32_t y,
                                  unsigned buttons, int32_t wheel_vertical,
                                  int32_t wheel_horizontal)
{
    if (ui == NULL || ui->shell.view_only || ui->cmds == NULL) {
        return false;
    }
    farsee_cmd command;
    memset(&command, 0, sizeof command);
    command.kind = FARSEE_CMD_POINTER;
    command.pe.abs_x = x;
    command.pe.abs_y = y;
    command.pe.buttons = buttons;
    command.pe.wheel_v = wheel_vertical;
    command.pe.wheel_h = wheel_horizontal;
    command.pe.quality = FARSEE_INPUT_QUALITY_INFERRED;
    command.prev_buttons = ui->prev_buttons;
    const bool accepted = farsee_cmd_queue_push(ui->cmds, &command);
    if (accepted) {
        ui->prev_buttons = buttons;
    }
    return accepted;
}

static void rfb_live_request_quit(rfb_live_ui *ui)
{
    if (ui != NULL && ui->stop != NULL) {
        farsee_atomic_int_store(ui->stop, 1);
    }
    if (ui != NULL && ui->session_stop != NULL) {
        farsee_atomic_int_store(ui->session_stop, 1);
    }
}

static void rfb_live_zoom(rfb_live_ui *ui, int delta_pct)
{
    if (ui == NULL) {
        return;
    }
    farsee_live_shell *shell = &ui->shell;
    int32_t next =
        (int32_t)farsee_live_shell_view_scale(shell) + delta_pct;
    if (next < (int32_t)FARSEE_VIEW_SCALE_MIN_PCT) {
        next = (int32_t)FARSEE_VIEW_SCALE_MIN_PCT;
    }
    if (next > (int32_t)FARSEE_VIEW_SCALE_MAX_PCT) {
        next = (int32_t)FARSEE_VIEW_SCALE_MAX_PCT;
    }
    if ((uint32_t)next == farsee_live_shell_view_scale(shell)) {
        rfb_live_log(ui, "view scale already %u%%\n",
                     (unsigned)farsee_live_shell_view_scale(shell));
        return;
    }
    farsee_live_shell_set_view_scale(shell, (uint32_t)next);
    (void)farsee_live_shell_refresh_layout(shell, true);
    rfb_live_log(ui, "view scale %u%%  (%ux%u cells)\n",
                 (unsigned)farsee_live_shell_view_scale(shell),
                 (unsigned)shell->place_cols, (unsigned)shell->place_rows);
}

static void rfb_shell_inject_key(void *user, const rfb_norm_key *key)
{
    rfb_live_inject_norm_key((rfb_live_ui *)user, key);
}

static bool rfb_shell_inject_pointer(void *user, int32_t x, int32_t y,
                                     uint8_t buttons, int wheel_vertical,
                                     int wheel_horizontal)
{
    return rfb_live_push_pointer(
        (rfb_live_ui *)user, x, y, buttons, wheel_vertical,
        wheel_horizontal);
}

static void rfb_shell_request_quit(void *user)
{
    rfb_live_request_quit((rfb_live_ui *)user);
}

static void rfb_shell_zoom(void *user, int delta_pct)
{
    rfb_live_zoom((rfb_live_ui *)user, delta_pct);
}

static void rfb_shell_status_extra(void *user, char *buf, size_t cap)
{
    rfb_live_ui *ui = (rfb_live_ui *)user;
    if (ui == NULL || buf == NULL || cap == 0u) {
        return;
    }
    uint32_t rtt = 0u;
    bool have_rtt = false;
    uint32_t rate_kib = 0u;
    bool have_rate = false;
    rfb_session_link_snapshot_ex(ui->sess, &rtt, &have_rtt, NULL, NULL,
                                 &rate_kib, &have_rate);
    char link[96];
    farsee_live_shell_format_link_extra(
        link, sizeof link, farsee_live_shell_view_scale(&ui->shell), rtt,
        have_rtt, rate_kib, have_rate);
    (void)snprintf(buf, cap, "%s", link);
}

static void rfb_shell_on_layout_applied(void *user)
{
    rfb_live_ui *ui = (rfb_live_ui *)user;
    if (ui != NULL && ui->slot != NULL) {
        farsee_frame_slot_kick(ui->slot);
    }
}

void rfb_live_ui_bind_shell_ops(rfb_live_ui *ui)
{
    if (ui == NULL) {
        return;
    }
    memset(&ui->shell_ops, 0, sizeof ui->shell_ops);
    ui->shell_ops.inject_key = rfb_shell_inject_key;
    ui->shell_ops.inject_pointer = rfb_shell_inject_pointer;
    ui->shell_ops.request_quit = rfb_shell_request_quit;
    ui->shell_ops.zoom = rfb_shell_zoom;
    ui->shell_ops.suspend = NULL;
    ui->shell_ops.status_extra = rfb_shell_status_extra;
    ui->shell_ops.on_layout_applied = rfb_shell_on_layout_applied;
    ui->shell.ops = &ui->shell_ops;
    ui->shell.ops_user = ui;
}

void rfb_live_ui_process_input(rfb_live_ui *ui,
                               const uint8_t *data, size_t size)
{
    if (ui != NULL) {
        farsee_live_shell_feed_tty(
            &ui->shell, data, size, farsee_thread_monotonic_ms());
    }
}
