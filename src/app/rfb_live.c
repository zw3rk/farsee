// SPDX-License-Identifier: Apache-2.0
//
// Classic RFB live CLI: connect → MT (protocol / present / input).
// Shared TTY/demux/status/layout lives in live_shell. RFB UI operations have
// a private owner; this file owns workers, presentation, and connection.

#include "app/rfb_live.h"
#include "app/rfb_live_internal.h"
#include "app/live_signal_scope.h"
#include "app/live_presenter.h"
#include "app/live_shell.h"
#include "app/rfb_live_ui.h"
#include "io/host_clipboard.h"

#include "farsee/allocator.h"
#include "farsee/apple_postauth.h"
#include "farsee/buffer.h"
#include "farsee/credential_acquire.h"
#include "farsee/error.h"
#include "farsee/farsee_cmd_queue.h"
#include "farsee/farsee_frame_slot.h"
#include "farsee/farsee_input.h"
#include "farsee/farsee_mt_session.h"
#include "farsee/farsee_thread.h"
#include "farsee/kitty_tile.h"
#include "farsee/memory_budget.h"
#include "farsee/modifier_synth.h"
#include "farsee/normalized_input.h"
#include "farsee/presenter.h"
#include "farsee/rfb_session.h"
#include "farsee/kitty_drain.h"
#include "farsee/sgr_mouse.h"
#include "farsee/term_mouse_map.h"

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

static long rfb_live_clipboard_read(void *ctx, char *out, size_t capacity)
{
    (void)ctx;
    return farsee_host_clipboard_get_utf8(out, capacity);
}

static bool rfb_live_clipboard_write(void *ctx, const char *text,
                                     size_t length)
{
    (void)ctx;
    return farsee_host_clipboard_set_utf8(text, length);
}

static void rfb_on_signal(int sig)
{
    (void)sig;
    farsee_atomic_int_store(&g_rfb_stop, 1);
}

static farsee_mt_terminal_kind rfb_live_input_fn(
    void *user, farsee_cmd_queue *cmds, farsee_atomic_int *stop,
    farsee_mt_terminal *terminal)
{
    rfb_live_ui *t = (rfb_live_ui *)user;
    if (t == NULL) {
        return FARSEE_MT_TERMINAL_INTERNAL_FAILURE;
    }
    t->cmds = cmds;
    t->stop = stop;
    uint64_t last_winsize_ms = 0;
    farsee_mt_terminal_kind result = FARSEE_MT_TERMINAL_REQUESTED_STOP;
    while (!farsee_atomic_int_load_nonzero(stop)) {
        if (farsee_atomic_int_load_nonzero(&g_rfb_stop)) {
            break;
        }
        farsee_live_shell *sh = &t->shell;
        const uint64_t now_in = farsee_thread_monotonic_ms();
        // Handle DesktopSize, winsize, and idle status without an input TTY.
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
            (void)poll(&dummy, 0, 20);
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
        if (pr < 0) {
            if (errno == EINTR) {
                continue;
            }
            result = FARSEE_MT_TERMINAL_INPUT_FAILURE;
            (void)farsee_mt_terminal_report(terminal, result);
            break;
        }
        size_t got = 0;
        if (pr > 0 && (pfd.revents & POLLIN) != 0) {
            uint8_t buf[1024];
            for (;;) {
                ssize_t n = read(sh->tty_fd, buf, sizeof(buf));
                if (n > 0) {
                    got += (size_t)n;
                    rfb_live_ui_process_input(t, buf, (size_t)n);
                    continue;
                }
                if (n == -1 && errno == EINTR) {
                    continue;
                }
                if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                    result = FARSEE_MT_TERMINAL_INPUT_FAILURE;
                    (void)farsee_mt_terminal_report(terminal, result);
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
            result = FARSEE_MT_TERMINAL_INPUT_FAILURE;
            (void)farsee_mt_terminal_report(terminal, result);
            break;
        }
        if (result == FARSEE_MT_TERMINAL_INPUT_FAILURE) {
            break;
        }
    }
    t->cmds = NULL;
    return result;
}

typedef struct rfb_live_present_ctx {
    farsee_live_presenter *presenter;
    rfb_buffer *kitty_out;
    rfb_live_ui *ui;
    bool opened;
    uint32_t open_w;
    uint32_t open_h;
    uint64_t last_gen; // present-thread only
    uint64_t present_count;
    uint32_t interval_ms;
    farsee_atomic_int force_repaint; // zoom/layout: re-show same gen
    // Emit one home CSI per APC batch; do not prepend another after full home.
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
        if (farsee_live_presenter_rfb_open(p->presenter, &fb) != 0) {
            return false;
        }
        p->opened = true;
        p->open_w = v->w;
        p->open_h = v->h;
    } else if (v->w != p->open_w || v->h != p->open_h) {
        if (farsee_live_presenter_rfb_resize(p->presenter, &fb) != 0) {
            return false;
        }
        p->open_w = v->w;
        p->open_h = v->h;
        // DesktopSize (or peer resize): present only notes geometry; input
        // thread applies desk + refresh (layout ownership ).
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
    // ESC_G after a fully written home is not re-homed. A continuously
    // non-empty residual relies on C=1 cursor keep or the prior home.
    farsee_mutex *kmu =
        (p->ui != NULL) ? p->ui->shell.io_mu : NULL;
    if (kmu != NULL) {
        farsee_mutex_lock(kmu);
    }
    const size_t kitty_before =
        (p->kitty_out != NULL) ? rfb_buffer_length(p->kitty_out) : 0u;
    if (farsee_live_presenter_rfb_present(p->presenter, &fb, &batch) != 0) {
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
    return true;
}

static void rfb_live_after_present(void *user)
{
    rfb_live_present_ctx *p = (rfb_live_present_ctx *)user;
    if (p == NULL || p->kitty_out == NULL) {
        return;
    }
    farsee_live_shell *sh = (p->ui != NULL) ? &p->ui->shell : NULL;
    // Idle static desktop: no Kitty bytes → skip all CSI so we do
    // not spam home/status at present FPS. Length under io_mu
    // when available.
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
    // One home per APC batch: prepend under lock only if need_home. Do not
    // re-home after a full home write leaves an ESC_G residual.
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
    // A full drain means the next APC batch needs home; a partial residual
    // must not be re-homed.
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

static farsee_mt_terminal_kind rfb_live_present_fn(
    void *user, farsee_frame_slot *slot, farsee_atomic_int *stop,
    farsee_mt_terminal *terminal)
{
    rfb_live_present_ctx *p = (rfb_live_present_ctx *)user;
    const uint32_t interval =
        (p != NULL && p->interval_ms > 0u) ? p->interval_ms : 33u;
    return farsee_mt_present_loop(
        slot, stop, interval, rfb_live_on_frame, p, rfb_live_after_present, p,
        p != NULL ? &p->force_repaint : NULL, terminal);
}

static farsee_mt_terminal_kind rfb_live_protocol_fn(
    void *user, farsee_frame_slot *slot, farsee_cmd_queue *cmds,
    farsee_atomic_int *stop, farsee_mt_terminal *terminal)
{
    rfb_session *s = (rfb_session *)user;
    (void)slot;
    (void)cmds;
    if (s == NULL) {
        return FARSEE_MT_TERMINAL_INTERNAL_FAILURE;
    }
    rfb_session_protocol_loop(s);
    const rfb_error error = rfb_session_last_error(s);
    farsee_mt_terminal_kind result = FARSEE_MT_TERMINAL_PROTOCOL_FAILURE;
    if (error == RFB_ERR_NOMEM) {
        result = FARSEE_MT_TERMINAL_ALLOCATION_FAILURE;
    } else if (error == RFB_OK || error == RFB_ERR_CANCELLED) {
        result = farsee_atomic_int_load_nonzero(stop)
               ? FARSEE_MT_TERMINAL_REQUESTED_STOP
               : FARSEE_MT_TERMINAL_PEER_CLOSED;
    } else if ((error == RFB_ERR_EOF || error == RFB_ERR_IO) &&
               farsee_atomic_int_load_nonzero(stop)) {
        result = FARSEE_MT_TERMINAL_REQUESTED_STOP;
    } else if (error == RFB_ERR_EOF || error == RFB_ERR_IO) {
        result = FARSEE_MT_TERMINAL_PEER_CLOSED;
    }
    (void)farsee_mt_terminal_report(terminal, result);
    return result;
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
    return true;
}

int farsee_rfb_live_report_outcome(
    farsee_mt_terminal_kind terminal_kind, farsee_error mt_error,
    rfb_error protocol_error, uint8_t unexpected_type, bool stop_requested,
    uint64_t present_count, FILE *diagnostic)
{
    FILE *output = diagnostic;
    if (output == NULL) {
        output = stderr;
    }
    if (output == NULL) {
        return 5;
    }
    int rc = 0;
    if (terminal_kind == FARSEE_MT_TERMINAL_ALLOCATION_FAILURE) {
        fprintf(output, "farsee: live session stopped: out of memory\n");
        rc = 5;
    } else if (terminal_kind == FARSEE_MT_TERMINAL_PRESENTER_FAILURE) {
        fprintf(output, "farsee: live session stopped: presenter failed\n");
        rc = 5;
    } else if (terminal_kind == FARSEE_MT_TERMINAL_INPUT_FAILURE) {
        fprintf(output, "farsee: live session stopped: input failed\n");
        rc = 5;
    } else if (terminal_kind == FARSEE_MT_TERMINAL_THREAD_CREATION_FAILURE ||
               (mt_error.code != FARSEE_E_OK && protocol_error == RFB_OK)) {
        fprintf(output, "farsee: live session stopped: %s\n",
                farsee_error_message_or_default(mt_error));
        rc = 5;
    } else if (protocol_error == RFB_ERR_PROTOCOL) {
        if (unexpected_type != 0u) {
            fprintf(output,
                    "farsee: protocol loop ended: unexpected server "
                    "message type=0x%02x (err=%d).\n",
                    (unsigned)unexpected_type, (int)protocol_error);
        } else {
            fprintf(output,
                    "farsee: protocol loop ended: framebuffer decode "
                    "failed (err=%d).\n",
                    (int)protocol_error);
        }
        rc = 5;
    } else if (protocol_error == RFB_ERR_LIMIT) {
        fprintf(output,
                "farsee: protocol loop ended: input/size limit exceeded "
                "(err=%d — e.g. framebuffer or compressed rect too "
                "large for policy)\n",
                (int)protocol_error);
        rc = 5;
    } else if (protocol_error == RFB_ERR_UNSUPPORTED) {
        fprintf(output,
                "farsee: protocol loop ended: unsupported encoding or "
                "feature (err=%d",
                (int)protocol_error);
        if (unexpected_type != 0u) {
            fprintf(output, ", type=0x%02x", (unsigned)unexpected_type);
        }
        fprintf(output, ")\n");
        rc = 5;
    } else if (protocol_error == RFB_ERR_EOF ||
               protocol_error == RFB_ERR_IO) {
        flockfile(output);
        fprintf(output, "farsee: peer closed the connection [err=%d]\n",
                (int)protocol_error);
        fprintf(output, "farsee: reconnect if the peer remains available.\n");
        (void)fflush(output);
        funlockfile(output);
        rc = 5;
    } else if (protocol_error != RFB_OK &&
               protocol_error != RFB_ERR_CANCELLED) {
        flockfile(output);
        fprintf(output, "farsee: protocol loop ended [err=%d]\n",
                (int)protocol_error);
        (void)fflush(output);
        funlockfile(output);
        rc = 5;
    } else if (stop_requested) {
        flockfile(output);
        fprintf(output, "farsee: disconnected (signal / leader quit)");
        if (present_count > 0u) {
            fprintf(output, " after %llu present(s)",
                    (unsigned long long)present_count);
        }
        fprintf(output, "\n");
        (void)fflush(output);
        funlockfile(output);
    } else if (present_count > 0u) {
        flockfile(output);
        fprintf(output, "farsee: session ended after %llu present(s)\n",
                (unsigned long long)present_count);
        (void)fflush(output);
        funlockfile(output);
    }
    return rc;
}

int farsee_run_rfb(const char *host, uint16_t port,
                   const char *username,
                   int password_fd, bool allow_none_auth,
                   bool shared, uint8_t apple_attach,
                   farsee_rfb_auth_mode auth_mode,
                   rfb_apple_postauth_mode apple_postauth_mode,
                   bool apple_send_viewer_info,
                   bool apple_disable_wake_keys,
                   const char *presenter_name,
                   uint32_t max_fps, bool view_only, bool clipboard_on,
                   const farsee_cli_leader *leader,
                   uint32_t view_scale_pct,
                   uint32_t connect_timeout_ms,
                   bool accept_new_host,
                   bool apple_require_type_36)
{
    if (host == NULL || host[0] == '\0') {
        fprintf(stderr, "farsee: missing host argument\n");
        (void)farsee_credential_close_password_fd(password_fd);
        return 2;
    }
    if (port == 0) {
        port = 5900;
    }

    farsee_credential_response credential;
    farsee_credential_response_init(&credential);
    credential.username = username;
    const farsee_credential_acquire_config credential_config = {
        .password_fd = password_fd,
        .password_inline = NULL,
        .required = !allow_none_auth,
    };
    int credential_signal = 0;
    const farsee_credential_acquire_status credential_status =
        farsee_credential_acquire_password(
            &credential_config, &credential.password, &credential_signal);
    if (credential_status == FARSEE_CREDENTIAL_ACQUIRE_TERMINAL_SIGNAL) {
        farsee_credential_response_destroy(&credential);
        farsee_credential_reraise_terminal_signal(credential_signal);
        return 2;
    }
    if (credential_status != FARSEE_CREDENTIAL_ACQUIRE_OK) {
        if (credential_status == FARSEE_CREDENTIAL_ACQUIRE_EMPTY) {
            fprintf(stderr, "farsee: empty password refused "
                            "(use --allow-none-auth only for security type "
                            "None)\n");
        } else if (password_fd >= 0) {
            fprintf(stderr, "farsee: failed to read password from fd %d\n",
                    password_fd);
        } else {
            fprintf(stderr, "farsee: password required "
                            "(prompt on /dev/tty failed — try "
                            "--password-fd or interactive TTY prompt)\n");
        }
        farsee_credential_response_destroy(&credential);
        return 2;
    }

    farsee_memory_budget memory_budget;
    if (!farsee_memory_budget_init(&memory_budget, rfb_default_allocator(),
                                   0u)) {
        farsee_credential_response_destroy(&credential);
        return 3;
    }
    rfb_allocator *session_allocator =
        farsee_memory_budget_allocator(&memory_budget);

    farsee_live_presenter presenter;
    memset(&presenter, 0, sizeof presenter);
    const bool stdout_is_tty = isatty(STDOUT_FILENO) != 0;
    if (farsee_live_presenter_init(
            &presenter, FARSEE_LIVE_PRESENTER_RFB, presenter_name,
            stdout_is_tty, 0u, 0u, session_allocator) !=
        FARSEE_LIVE_PRESENTER_INIT_OK) {
        farsee_credential_response_destroy(&credential);
        return 3;
    }
    const bool live_kitty = farsee_live_presenter_is_kitty(&presenter);
    bool live_interactive = false;
    if (live_kitty && stdout_is_tty) {
        int t = open("/dev/tty", O_RDWR | O_NOCTTY);
        if (t >= 0) {
            live_interactive = true;
            close(t);
        }
    }
    if (live_kitty) {
        {
            static const char home[] = "\033[2J\033[H";
            (void)write(STDOUT_FILENO, home, sizeof(home) - 1);
        }
    }

    farsee_frame_slot slot;
    farsee_cmd_queue cmds;
    memset(&slot, 0, sizeof(slot));
    memset(&cmds, 0, sizeof(cmds));
    const bool slot_live =
        farsee_frame_slot_init_with_allocator(&slot, session_allocator);
    const bool cmds_live = slot_live && farsee_cmd_queue_init(&cmds);
    if (!slot_live || !cmds_live) {
        fprintf(stderr, "farsee: frame slot / cmd queue init failed\n");
        if (slot_live) {
            farsee_frame_slot_destroy(&slot);
        }
        farsee_live_presenter_destroy(&presenter);
        farsee_credential_response_destroy(&credential);
        return 3;
    }

    const size_t sess_sz = rfb_session_size();
    rfb_session *sess = (rfb_session *)calloc(1, sess_sz);
    if (sess == NULL) {
        farsee_frame_slot_destroy(&slot);
        farsee_cmd_queue_destroy(&cmds);
        farsee_live_presenter_destroy(&presenter);
        farsee_credential_response_destroy(&credential);
        return 3;
    }
    rfb_session_clear(sess);

    farsee_atomic_int_store(&g_rfb_stop, 0);
    farsee_live_signal_scope signal_scope;
    farsee_live_signal_scope_init(&signal_scope);
    if (!farsee_live_signal_scope_arm_terminal(
            &signal_scope, rfb_on_signal)) {
        fprintf(stderr, "farsee: cannot install session signal handlers\n");
        rfb_session_destroy(sess);
        free(sess);
        farsee_frame_slot_destroy(&slot);
        farsee_cmd_queue_destroy(&cmds);
        farsee_live_presenter_destroy(&presenter);
        farsee_credential_response_destroy(&credential);
        return 3;
    }

    rfb_session_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.allocator = session_allocator;
    cfg.host = host;
    cfg.port = port;
    if (username != NULL && username[0] != '\0') {
        cfg.username = (const uint8_t *)username;
        cfg.username_len = strlen(username);
    }
    cfg.password = credential.password.data;
    cfg.password_len = credential.password.len;
    cfg.allow_none_auth = allow_none_auth;
    cfg.accept_new_host = accept_new_host;  // first-use policy
    cfg.apple_prefer_type_36 = apple_require_type_36;
    cfg.apple_postauth_mode = apple_postauth_mode;
    cfg.apple_send_viewer_info = apple_send_viewer_info;
    cfg.apple_disable_wake_keys = apple_disable_wake_keys;
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
    cfg.clipboard_enabled = clipboard_on && !view_only;
    if (cfg.clipboard_enabled) {
        cfg.clipboard_read_utf8 = rfb_live_clipboard_read;
        cfg.clipboard_write_utf8 = rfb_live_clipboard_write;
    }
    cfg.publish_black_frames = false;
    cfg.connect_timeout_ms =
        (connect_timeout_ms == 0u) ? 30000u : connect_timeout_ms;

    rfb_error ce = rfb_session_connect(sess, &cfg);
    // Handshake no longer needs the password: wipe the full allocation now
    // so it does not sit in the heap for the live session lifetime.
    farsee_credential_response_destroy(&credential);
    cfg.password = NULL;
    cfg.password_len = 0u;
    if (ce != RFB_OK) {
        fprintf(stderr, "farsee: RFB connect/auth failed");
        if (ce == RFB_ERR_UNSUPPORTED) {
            fprintf(stderr,
                    "\n"
                    "  No usable live security path completed.\n"
                    "\n"
                    "  The Apple policy supports security types 33 and 36.\n"
                    "  Auto mode prefers type 33. To require type 36, use\n"
                    "  --apple-security=36. Supply the macOS account with:\n"
                    "    farsee vnc://user@mac-host\n"
                    "  (URL user / --user is the macOS account name; the\n"
                    "  password is the account password.)\n"
                    "\n"
                    "  Or enable \"VNC viewers may control screen with password\"\n"
                    "  and connect with that VNC password via --auth=vnc.\n"
                    "\n"
                    "  Note: --cert ignore is RDP-only and is ignored for VNC.\n");
        } else if (ce == RFB_ERR_AUTH) {
            fprintf(stderr,
                    " (authentication failed; verify credentials and "
                    "security policy)");
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
        farsee_live_presenter_destroy(&presenter);
        farsee_credential_response_destroy(&credential);
        farsee_live_signal_scope_restore(&signal_scope);
        return 4;
    }

    // Report the active post-auth record state.
    if (rfb_session_apple_records_active(sess)) {
        fprintf(stderr,
                "farsee: Apple AES-CBC record layer active "
                "(0x044f rekey; AES-CBC records on wire).\n");
        (void)fflush(stderr);
    } else if (rfb_session_has_wrap_key(sess)) {
        fprintf(stderr,
                "farsee: warning: Apple wrap_key is present but the record "
                "layer is not active; post-auth traffic uses cleartext.\n");
        (void)fflush(stderr);
    }

    const rfb_framebuffer *fb = rfb_session_framebuffer(sess);

    rfb_live_ui ui;
    memset(&ui, 0, sizeof(ui));
    ui.session_stop = &g_rfb_stop;
    farsee_modifier_synth_init(&ui.synth_mods);
    farsee_live_shell_init(&ui.shell, leader, RFB_LIVE_STATUS_ROWS);
    ui.sess = sess;
    rfb_live_ui_bind_shell_ops(&ui);
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
    ui.kitty_out = farsee_live_presenter_kitty_out(&presenter);

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
        ui.shell.kitty = farsee_live_presenter_kitty(&presenter);
        ui.shell.layout_active = true;
        (void)farsee_live_shell_refresh_layout(&ui.shell, /*apply_kitty=*/false);
        rfb_kitty_tile_set_place_cells(
            ui.shell.kitty, ui.shell.place_cols,
            ui.shell.place_rows > 0u ? ui.shell.place_rows : 1u);
    }

    rfb_live_present_ctx pctx;
    memset(&pctx, 0, sizeof(pctx));
    pctx.presenter = &presenter;
    pctx.kitty_out = farsee_live_presenter_kitty_out(&presenter);
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
        // Serialize status, log, and Kitty drain output across present and
        // input threads.
        ui.shell.io_mu = farsee_mutex_create();
        if (ui.shell.io_mu == NULL) {
            fprintf(stderr,
                    "farsee: error: io mutex alloc failed "
                    "(cannot run multi-thread live status band)\n");
            (void)fflush(stderr);
            farsee_live_presenter_destroy(&presenter);
            rfb_session_destroy(sess);
            free(sess);
            farsee_frame_slot_destroy(&slot);
            farsee_cmd_queue_destroy(&cmds);
            farsee_credential_response_destroy(&credential);
            farsee_live_signal_scope_restore(&signal_scope);
            return 3;
        }
        farsee_live_shell_stdio_nonblock_arm(STDOUT_FILENO);
        if (!farsee_live_shell_tty_open_input(
                &ui.shell.tty_fd, &ui.shell.tty_fd_owned)) {
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
    farsee_mt_outcome mt_outcome;
    farsee_error mt_error = farsee_mt_run(&mtc, &mt_outcome);

    // Protocol thread already best-effort releases on loop exit; call again
    // while the session is still open for any remaining held input state.
    rfb_session_release_held_inputs(sess);

    rc = farsee_rfb_live_report_outcome(
        mt_outcome.kind, mt_error, rfb_session_last_error(sess),
        rfb_session_last_unexpected_type(sess),
        farsee_atomic_int_load_nonzero(&g_rfb_stop), pctx.present_count,
        stderr);

    farsee_live_shell_tty_guard_restore();
    ui.shell.mouse_enabled = false;
    farsee_live_presenter_close(&presenter);
    farsee_drain_kitty_out(ui.kitty_out, STDOUT_FILENO, ui.shell.io_mu);
    farsee_live_shell_quiet_restore(&ui.shell);
    farsee_live_shell_tty_close_input(
        ui.shell.tty_fd, ui.shell.tty_fd_owned);
    if (ui.shell.io_mu != NULL) {
        farsee_mutex_destroy(&ui.shell.io_mu);
    }

    rfb_session_destroy(sess);
    free(sess);
    farsee_frame_slot_destroy(&slot);
    farsee_cmd_queue_destroy(&cmds);
    farsee_live_presenter_destroy(&presenter);
    farsee_credential_response_destroy(&credential);
    farsee_live_signal_scope_restore(&signal_scope);

    return rc;
}
