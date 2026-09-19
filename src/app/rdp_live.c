// SPDX-License-Identifier: Apache-2.0
//
// RDP live CLI: connect → MT (protocol / present / input) or null settle.
// Shared TTY/demux/status/layout lives in live_shell. RDP input operations
// have a private owner; this file owns FreeRDP connection and teardown.

#include "app/rdp_live.h"

#ifdef FARSEE_WITH_RDP

#include "app/live_signal_scope.h"
#include "app/live_presenter.h"
#include "app/rdp_live_internal.h"
#include "app/rdp_live_input.h"
#include "app/live_shell.h"
#include "farsee/allocator.h"
#include "farsee/buffer.h"
#include "farsee/cli_target.h"
#include "farsee/credential_acquire.h"
#include "farsee/farsee_atomic.h"
#include "farsee/farsee_clipboard.h"
#include "farsee/farsee_input.h"
#include "farsee/farsee_security.h"
#include "farsee/farsee_thread.h"
#include "farsee/kitty_drain.h"
#include "farsee/kitty_tile.h"
#include "farsee/live_demux.h"
#include "farsee/memory_budget.h"
#include "farsee/modifier_synth.h"
#include "farsee/normalized_input.h"
#include "farsee/presenter.h"
#include "farsee/presenter_v1_adapter.h"
#include "farsee/sgr_mouse.h"
#include "farsee/socket_posix.h"
#include "farsee/term_mouse_map.h"
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

#define RDP_STATUS_ROWS 1u

void rdp_live_log(rdp_live_tick *t, const char *fmt, ...)
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
void rdp_live_flush_pending_graphics(rdp_live_tick *t)
{
    if (t == NULL || t->kitty_out == NULL) {
        return;
    }
    // Idle: no APC means no CSI. Length is under io_mu.
    // Arm need_home for the next APC batch when fully empty.
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
    // The presenter only records peer desktop geometry.
    if (t->sink != NULL) {
        uint32_t dw = 0;
        uint32_t dh = 0;
        rdp_desk_size_unpack(
            farsee_atomic_u64_load(&t->sink->last_desk_size), &dw, &dh);
        if (dw > 0u && dh > 0u) {
            farsee_live_shell_note_desk_size(&t->shell, dw, dh);
        }
    }
    // Present must NOT refresh_layout: place_*/disp_* are input-thread
    // caches (live_shell.h). note_desk + input apply_pending_desk own geometry
    // need_status only draws after the drain completes.
    (void)need_status;
    // One home per batch: clear need_home even if the residual is still ESC_G.
    static const char home[] = "\033[H";
    const char *prefix = NULL;
    size_t prefix_len = 0u;
    if (t->need_home) {
        prefix = home;
        prefix_len = sizeof(home) - 1u;
    }
    const bool drained = farsee_drain_kitty_out_with_prefix(
        t->kitty_out, STDOUT_FILENO, t->shell.io_mu, prefix, prefix_len);
    // The next batch needs home after a full flush. A residual after a partial
    // flush keeps need_home false so we do not send the home sequence twice.
    t->need_home = drained;
    if (need_status && drained) {
        farsee_live_shell_draw_status(&t->shell);
    }
}

// ST null settle path intentionally has no on_tick: live Kitty always
// uses MT (protocol/present/input). Graphics drain is after_present only.

static void rdp_live_after_present(void *user)
{
    rdp_live_flush_pending_graphics((rdp_live_tick *)user);
}

void rdp_live_discard_tty_responses(int tty_fd)
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

static void rdp_live_presenter_dispose(farsee_live_presenter *presenter,
                                       farsee_mutex *io_mu)
{
    if (presenter == NULL) {
        return;
    }
    // close() can append Kitty image-delete commands. Keep the output buffer
    // alive until those bytes have received their final serialized drain.
    farsee_live_presenter_close(presenter);
    farsee_drain_kitty_out(farsee_live_presenter_kitty_out(presenter),
                           STDOUT_FILENO, io_mu);
    farsee_live_presenter_destroy(presenter);
}

static bool rdp_live_log_level_valid(rdp_liblog_level level)
{
    switch (level) {
    case RDP_LIBLOG_OFF:
    case RDP_LIBLOG_ERROR:
    case RDP_LIBLOG_WARN:
    case RDP_LIBLOG_INFO:
    case RDP_LIBLOG_DEBUG:
    case RDP_LIBLOG_TRACE:
        return true;
    default:
        return false;
    }
}

static const rdp_live_facade_ops rdp_live_default_facade_ops = {
    .set_library_log_level = rdp_freerdp_set_library_log_level,
    .create = rdp_freerdp_create,
    .destroy = rdp_freerdp_destroy,
    .set_presenter = rdp_callbacks_set_presenter,
    .apply_settings_with_memory_budget =
        rdp_freerdp_apply_settings_with_memory_budget,
    .connect_with_stop = rdp_freerdp_connect_with_stop,
    .clear_credentials = rdp_freerdp_clear_credentials,
    .run_until = rdp_freerdp_run_until,
    .request_stop = rdp_freerdp_request_stop,
    .disconnect = rdp_freerdp_disconnect,
    .last_error_name = rdp_freerdp_last_error_name,
    .is_clean_peer_disconnect = rdp_freerdp_is_clean_peer_disconnect,
};

static bool rdp_live_facade_ops_complete(const rdp_live_facade_ops *ops)
{
    return ops != NULL &&
           ops->set_library_log_level != NULL &&
           ops->create != NULL &&
           ops->destroy != NULL &&
           ops->set_presenter != NULL &&
           ops->apply_settings_with_memory_budget != NULL &&
           ops->connect_with_stop != NULL &&
           ops->clear_credentials != NULL &&
           ops->run_until != NULL &&
           ops->request_stop != NULL &&
           ops->disconnect != NULL &&
           ops->last_error_name != NULL &&
           ops->is_clean_peer_disconnect != NULL;
}

uint64_t rdp_live_deadline_after(uint64_t now, uint64_t timeout,
                                 uint64_t settle)
{
    if (timeout > UINT64_MAX - now) {
        return UINT64_MAX;
    }
    const uint64_t after_timeout = now + timeout;
    if (settle > UINT64_MAX - after_timeout) {
        return UINT64_MAX;
    }
    return after_timeout + settle;
}

int farsee_run_rdp_with_facade_ops(
    const char *host, uint16_t port, const char *user, const char *domain,
    const char *cert_policy, int password_fd, uint32_t desk_w,
    uint32_t desk_h, const char *presenter_name,
    uint64_t connect_timeout_ms, bool view_only, bool clipboard_on,
    rdp_liblog_level liblog, const farsee_cli_leader *leader_spec,
    const rdp_live_facade_ops *facade_ops)
{
    const rdp_live_facade_ops *ops =
        facade_ops != NULL ? facade_ops : &rdp_live_default_facade_ops;
    if (!rdp_live_facade_ops_complete(ops)) {
        fprintf(stderr, "farsee rdp: invalid FreeRDP facade\n");
        (void)farsee_credential_close_password_fd(password_fd);
        return 2;
    }
    if (!ops->set_library_log_level(liblog)) {
        if (rdp_live_log_level_valid(liblog)) {
            fprintf(stderr,
                    "farsee rdp: FreeRDP/WinPR log controls are available "
                    "only in developer builds\n");
        } else {
            fprintf(stderr, "farsee rdp: invalid FreeRDP/WinPR log level\n");
        }
        (void)farsee_credential_close_password_fd(password_fd);
        return 2;
    }

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
        (void)farsee_credential_close_password_fd(password_fd);
        return 2;
    }
    if (connect_timeout_ms == 0) {
        connect_timeout_ms = 30000;
    }

    const bool stdout_is_tty = isatty(STDOUT_FILENO) != 0;

    // Connecting banner is verbose-only (errors stay always-on).
    if (liblog >= RDP_LIBLOG_INFO) {
        fprintf(stderr, "farsee rdp: connecting to %s:%u (user=%s)\n",
                host, (unsigned)port, user);
    }

    farsee_rdp_settings s;
    if (!farsee_rdp_settings_init_for_host(&s, host, port, user, domain)) {
        fprintf(stderr, "farsee rdp: invalid endpoint\n");
        (void)farsee_credential_close_password_fd(password_fd);
        return 2;
    }
    s.desktop_width = desk_w;
    s.desktop_height = desk_h;
    // Bound freerdp_connect. Cap the FreeRDP setting to UINT32_MAX.
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
        // Session-only approval does not write trust-on-first-use state.
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
    const farsee_credential_acquire_config credential_config = {
        .password_fd = password_fd,
        .password_inline = NULL,
        .required = true,
    };
    int credential_signal = 0;
    const farsee_credential_acquire_status credential_status =
        farsee_credential_acquire_password(
            &credential_config, &cred.password, &credential_signal);
    if (credential_status == FARSEE_CREDENTIAL_ACQUIRE_TERMINAL_SIGNAL) {
        farsee_credential_response_destroy(&cred);
        farsee_credential_reraise_terminal_signal(credential_signal);
        return 2;
    }
    if (credential_status != FARSEE_CREDENTIAL_ACQUIRE_OK) {
        if (credential_status == FARSEE_CREDENTIAL_ACQUIRE_EMPTY) {
            fprintf(stderr, "farsee rdp: empty password refused\n");
        }
        if (credential_status != FARSEE_CREDENTIAL_ACQUIRE_EMPTY &&
            password_fd >= 0) {
            fprintf(stderr, "farsee rdp: failed to read password from fd %d\n",
                    password_fd);
        }
        if (credential_status != FARSEE_CREDENTIAL_ACQUIRE_EMPTY &&
            password_fd < 0) {
            fprintf(stderr,
                    "farsee rdp: password required "
                    "(prompt on /dev/tty failed; use --password-fd N)\n");
        }
        farsee_credential_response_destroy(&cred);
        return 2;
    }

    farsee_memory_budget memory_budget;
    if (!farsee_memory_budget_init(&memory_budget, rfb_default_allocator(),
                                   0u)) {
        farsee_credential_response_destroy(&cred);
        return 3;
    }
    rfb_allocator *session_allocator =
        farsee_memory_budget_allocator(&memory_budget);

    farsee_live_presenter live_presenter;
    memset(&live_presenter, 0, sizeof live_presenter);
    const farsee_live_presenter_init_result presenter_result =
        farsee_live_presenter_init(
            &live_presenter, FARSEE_LIVE_PRESENTER_RDP, presenter_name,
            stdout_is_tty, desk_w, desk_h, session_allocator);
    if (presenter_result != FARSEE_LIVE_PRESENTER_INIT_OK) {
        if (presenter_result == FARSEE_LIVE_PRESENTER_INIT_CAPABILITY_FAILED) {
            fprintf(stderr,
                    "farsee rdp: presenter does not accept BGRA8888\n");
        } else {
            fprintf(stderr, "farsee rdp: presenter open failed\n");
        }
        farsee_credential_response_destroy(&cred);
        return 2;
    }
    const farsee_live_presenter_kind pkind = live_presenter.kind;
    const bool live = farsee_live_presenter_is_kitty(&live_presenter);
    rfb_buffer *kitty_out =
        farsee_live_presenter_kitty_out(&live_presenter);
    rfb_kitty_tile *kitty = farsee_live_presenter_kitty(&live_presenter);
    const bool kitty_out_live = kitty_out != NULL;
    if (kitty_out_live) {
        {
            static const char home[] = "\033[2J\033[H";
            (void)write(STDOUT_FILENO, home, sizeof(home) - 1);
        }
    }

    rdp_live_tick tick;
    memset(&tick, 0, sizeof(tick));
    tick.process_stop = &g_rdp_stop;
    farsee_modifier_synth_init(&tick.synth_mods);
    tick.need_home = true; // first APC batch needs placement home
    farsee_live_shell_init(&tick.shell, leader_spec, RDP_STATUS_ROWS);
    rdp_live_bind_shell_ops(&tick);
    tick.shell.view_only = view_only;
    tick.shell.show_zoom = true;
    tick.shell.show_suspend = true;
    // Full fit by default; C-] +/- scales Kitty place (same as RFB).
    farsee_live_shell_set_view_scale(&tick.shell, FARSEE_VIEW_SCALE_MAX_PCT);
    tick.kitty_out = kitty_out;
    tick.shell.kitty = kitty;
    tick.shell.desk_w = desk_w;
    tick.shell.desk_h = desk_h;
    tick.shell.layout_active = kitty_out_live;
    tick.verbose = (liblog >= RDP_LIBLOG_INFO);
    (void)snprintf(tick.shell.status_proto, sizeof tick.shell.status_proto,
                   "rdp");
    (void)snprintf(tick.shell.status_host, sizeof tick.shell.status_host, "%s",
                   host != NULL ? host : "");
    tick.shell.status_port = port != 0 ? port : 3389;
    // Do not draw_status here: it arms O_NONBLOCK on stdout and early setup
    // failures below would leave the shell's stdout nonblocking.
    // Layout is refreshed; first status draw runs after successful connect /
    // TTY arm later in this function.
    if (tick.shell.layout_active) {
        (void)farsee_live_shell_refresh_layout(&tick.shell, false);
    }

    // ADR-0012: the owner keeps the one v1-through-v2 adapter at the
    // FreeRDP edge. This is not a second product presenter stack.
    farsee_presenter *presenter =
        farsee_live_presenter_v2(&live_presenter);

    rdp_freerdp_ctx *ctx = ops->create();
    if (ctx == NULL) {
        fprintf(stderr, "farsee rdp: freerdp create failed\n");
        rdp_live_presenter_dispose(&live_presenter, tick.shell.io_mu);
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
        const bool slot_live =
            rdp_frame_slot_init_with_allocator(&frame_slot,
                                               session_allocator);
        const bool inj_live = slot_live && rdp_inj_queue_init(&inj_q);
        if (!slot_live || !inj_live) {
            fprintf(stderr, "farsee rdp: MT session init failed\n");
            if (slot_live) {
                rdp_frame_slot_destroy(&frame_slot);
            }
            ops->destroy(&ctx);
            rdp_live_presenter_dispose(&live_presenter, tick.shell.io_mu);
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
            ops->destroy(&ctx);
            rdp_live_presenter_dispose(&live_presenter, tick.shell.io_mu);
            farsee_credential_response_destroy(&cred);
            return 3;
        }
    } else {
        sink.defer_present = false;
        sink.min_present_interval_ms =
            (pkind == FARSEE_LIVE_PRESENTER_KITTY_DIRECT) ? 33u : 0u;
    }
    ops->set_presenter(ctx, presenter, &sink);

    // TOFU store for peer cert fingerprints (SHA-256 of FreeRDP's full-chain
    // PEM callback bytes). Kept alive for the session (stack buffer is fine —
    // path is short). A HOME that does not fit means no store: fail closed
    // instead of using a truncated path that could alias an unrelated file.
    char kh_path[512];
    kh_path[0] = '\0';
    {
        const char *home = getenv("HOME");
        if (home != NULL && home[0] != '\0') {
            int hn = snprintf(kh_path, sizeof kh_path,
                              "%s/.farsee/rdp_known_hosts", home);
            if (hn < 0 || (size_t)hn >= sizeof kh_path) {
                kh_path[0] = '\0';
            }
        }
    }
    // Default trust REJECT. Pin mode requires VerifyX509 for every peer and
    // must approve a TOFU first use or match before credentials. Other modes
    // let system-CA peers skip the callback; Authenticate then promotes trust.
    // --cert ignore seeds APPROVE_ONCE because FreeRDP can skip verification.
    const farsee_trust_decision initial_trust =
        policy.allow_insecure_cert ? FARSEE_TRUST_DECISION_APPROVE_ONCE
                                   : FARSEE_TRUST_DECISION_REJECT;
    if (!ops->apply_settings_with_memory_budget(
            ctx, &s, &policy, &cred, initial_trust,
            kh_path[0] != '\0' ? kh_path : NULL, &memory_budget)) {
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
        ops->destroy(&ctx);
        rdp_live_presenter_dispose(&live_presenter, tick.shell.io_mu);
        farsee_credential_response_destroy(&cred);
        return 3;
    }

    // Install cancel handlers before blocking in freerdp_connect so terminal
    // signals arm g_rdp_stop early (TcpConnectTimeout also bounds stall).
    farsee_atomic_int_store(&g_rdp_stop, 0);
    farsee_live_signal_scope signal_scope;
    farsee_live_signal_scope_init(&signal_scope);
    if (!farsee_live_signal_scope_arm_terminal(
            &signal_scope, rdp_on_signal)) {
        fprintf(stderr, "farsee rdp: cannot install session signal handlers\n");
        if (mt_live) {
            sink.frame_slot = NULL;
            tick.inj = NULL;
            if (tick.shell.io_mu != NULL) {
                farsee_mutex_destroy(&tick.shell.io_mu);
            }
            rdp_frame_slot_destroy(&frame_slot);
            rdp_inj_queue_destroy(&inj_q);
        }
        ops->destroy(&ctx);
        rdp_live_presenter_dispose(&live_presenter, tick.shell.io_mu);
        farsee_credential_response_destroy(&cred);
        return 3;
    }

    // Keep cooperative stop active during blocking connect.
    if (!ops->connect_with_stop(ctx, &g_rdp_stop)) {
        const bool requested_stop =
            farsee_atomic_int_load_nonzero(&g_rdp_stop);
        if (!requested_stop) {
            fprintf(stderr, "farsee rdp: connect failed: %s\n",
                    ops->last_error_name(ctx));
        }
        if (mt_live) {
            sink.frame_slot = NULL;
            tick.inj = NULL;
            if (tick.shell.io_mu != NULL) {
                farsee_mutex_destroy(&tick.shell.io_mu);
            }
            rdp_frame_slot_destroy(&frame_slot);
            rdp_inj_queue_destroy(&inj_q);
        }
        ops->destroy(&ctx);
        rdp_live_presenter_dispose(&live_presenter, tick.shell.io_mu);
        farsee_credential_response_destroy(&cred);
        farsee_live_signal_scope_restore(&signal_scope);
        return requested_stop ? 0 : 4;
    }
    // FreeRDP has copied credentials for NLA; wipe our buffer so the
    // password does not sit on the heap for the whole interactive session.
    farsee_credential_response_destroy(&cred);
    farsee_credential_response_init(&cred);
    // Hygiene: callback must not re-enter Authenticate on wiped storage.
    if (ctx != NULL) {
        ops->clear_credentials(ctx);
    }
    if (kitty_out_live) {
        farsee_live_shell_stdio_nonblock_arm(STDOUT_FILENO);
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
        // Establish Kitty layout geometry before an input TTY is available.
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
        if (!farsee_live_shell_tty_open_input(
                &tick.shell.tty_fd, &tick.shell.tty_fd_owned)) {
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
                if (tick.verbose) {
                    fprintf(stderr,
                            "farsee rdp: input armed on %s fd=%d owned=%d "
                            "mouse=%d kitty_kb=%d\n",
                            farsee_live_shell_tty_input_label(
                                tick.shell.tty_fd,
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
    farsee_error re;
    farsee_mt_outcome mt_outcome;
    memset(&mt_outcome, 0, sizeof(mt_outcome));
    if (mt_live) {
        rdp_mt_config mtc;
        memset(&mtc, 0, sizeof(mtc));
        mtc.ctx = ctx;
        mtc.sink = &sink;
        mtc.presenter = presenter;
        mtc.slot = &frame_slot;
        mtc.inj = &inj_q;
        mtc.ledger = &tick.ledger; // RELEASE_ALL uses the shared ledger.
        mtc.wire_buttons = &tick.wire_buttons;
        mtc.stop_flag = &g_rdp_stop;
        mtc.present_interval_ms =
            (pkind == FARSEE_LIVE_PRESENTER_KITTY_DIRECT) ? 33u : 16u;
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
        re = rdp_mt_run(&mtc, &got_frame, &mt_outcome);
    } else {
        rdp_run_budget budget;
        memset(&budget, 0, sizeof(budget));
        budget.sink = &sink;
        budget.stop_flag = &g_rdp_stop;
        // No on_tick: null settle has no interactive shell; live Kitty
        // is always MT. Saturate the complete absolute-deadline calculation.
        budget.deadline_monotonic_ms = rdp_live_deadline_after(
            farsee_thread_monotonic_ms(), connect_timeout_ms, 4000u);
        budget.stop_on_first_frame = true;
        budget.settle_ms_after_first = 4000u;
        re = ops->run_until(ctx, &budget, &got_frame);
    }

    if (kitty_out_live) {
        rdp_live_flush_pending_graphics(&tick);
        rdp_live_discard_tty_responses(tick.shell.tty_fd);
        tick.log_flowing = false;
    }

    int rc = 0;
    const bool peer_clean = ops->is_clean_peer_disconnect(ctx);
    if (farsee_atomic_int_load_nonzero(&g_rdp_stop) &&
        (!mt_live ||
         mt_outcome.kind == FARSEE_MT_TERMINAL_REQUESTED_STOP)) {
        rdp_live_log(&tick, "farsee rdp: disconnected (Ctrl-] / signal)\n");
    } else if (mt_live &&
               mt_outcome.kind == FARSEE_MT_TERMINAL_ALLOCATION_FAILURE) {
        rdp_live_log(&tick, "farsee rdp: frame allocation failed\n");
        rc = 5;
    } else if (mt_live &&
               mt_outcome.kind == FARSEE_MT_TERMINAL_PRESENTER_FAILURE) {
        rdp_live_log(&tick, "farsee rdp: presenter failed\n");
        rc = 5;
    } else if (mt_live &&
               mt_outcome.kind == FARSEE_MT_TERMINAL_INPUT_FAILURE) {
        rdp_live_log(&tick, "farsee rdp: local input failed\n");
        rc = 5;
    } else if (mt_live &&
               mt_outcome.kind ==
                   FARSEE_MT_TERMINAL_THREAD_CREATION_FAILURE) {
        rdp_live_log(&tick, "farsee rdp: worker thread creation failed\n");
        rc = 5;
    } else if (mt_live && farsee_error_failed(re)) {
        rdp_live_log(&tick, "farsee rdp: session failed: %s\n",
                     farsee_error_message_or_default(re));
        rc = 5;
    } else if (peer_clean &&
               (got_frame ||
                farsee_atomic_u64_load(&sink.frame_count) > 0u)) {
        const char *ename = ops->last_error_name(ctx);
        uint32_t end_w = 0;
        uint32_t end_h = 0;
        rdp_desk_size_unpack(
            farsee_atomic_u64_load(&sink.last_desk_size), &end_w, &end_h);
        rdp_live_log(&tick,
                     "farsee rdp: session ended by server (%s) after %llu "
                     "frame(s) (%ux%u)\n",
                     ename,
                     (unsigned long long)farsee_atomic_u64_load(
                         &sink.frame_count),
                     (unsigned)end_w, (unsigned)end_h);
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
        uint32_t gf_w = 0;
        uint32_t gf_h = 0;
        rdp_desk_size_unpack(
            farsee_atomic_u64_load(&sink.last_desk_size), &gf_w, &gf_h);
        rdp_live_log(&tick,
                     "farsee rdp: desktop frames delivered (%ux%u, n=%llu)\n",
                     (unsigned)gf_w, (unsigned)gf_h,
                     (unsigned long long)farsee_atomic_u64_load(
                         &sink.frame_count));
    } else {
        rdp_live_log(&tick, "farsee rdp: no frame (%s)\n",
                     re.code == FARSEE_ERR_TIMEOUT ? "timeout"
                     : ops->last_error_name(ctx));
        rc = 5;
    }
    if (kitty_out_live &&
        (pkind == FARSEE_LIVE_PRESENTER_KITTY_SHM ||
         pkind == FARSEE_LIVE_PRESENTER_KITTY_DIRECT)) {
        rdp_live_log(&tick,
                     "farsee rdp: kitty transport: shm=%llu "
                     "direct_fallback=%llu presents=%llu\n",
                     (unsigned long long)kitty->metrics.shm_transfers,
                     (unsigned long long)kitty->metrics.shm_fallbacks,
                     (unsigned long long)kitty->metrics.presents);
        if (pkind == FARSEE_LIVE_PRESENTER_KITTY_SHM &&
            kitty->metrics.shm_transfers == 0 &&
            kitty->metrics.presents > 0) {
            rdp_live_log(&tick,
                         "farsee rdp: warning: SHM path never succeeded; all "
                         "frames used base64-over-TTY (t=d)\n");
        }
    }

    tick.inj = NULL;
    if (!view_only) {
        // Release keys and held mouse buttons, matching the RFB path.
        int32_t rx = 0;
        int32_t ry = 0;
        if (tick.sink != NULL) {
            rx = farsee_atomic_int_load(&tick.sink->cursor_x);
            ry = farsee_atomic_int_load(&tick.sink->cursor_y);
        }
        // MT: wire_buttons is authoritative (may be 0 after real release).
        // The single-thread path owns only prev_buttons here.
        unsigned held = mt_live ? tick.wire_buttons : tick.prev_buttons;
        (void)rdp_input_inject_release_buttons(ctx, &held, rx, ry);
        tick.wire_buttons = 0u;
        tick.prev_buttons = 0u;
        rdp_input_inject_release_all(ctx, &tick.ledger);
    }
    farsee_live_shell_tty_guard_restore();
    tick.shell.mouse_enabled = false;
    ops->request_stop(ctx);
    ops->disconnect(ctx);
    ops->destroy(&ctx);
    tick.ctx = NULL;
    if (mt_live) {
        sink.frame_slot = NULL;
        if (tick.shell.io_mu != NULL) {
            farsee_mutex_destroy(&tick.shell.io_mu);
        }
        rdp_frame_slot_destroy(&frame_slot);
        rdp_inj_queue_destroy(&inj_q);
    }
    farsee_live_presenter_close(&live_presenter);
    if (kitty_out_live) {
        farsee_drain_kitty_out(kitty_out, STDOUT_FILENO, tick.shell.io_mu);
        rdp_live_discard_tty_responses(tick.shell.tty_fd);
        tick.shell.layout_active = false;
    }
    farsee_live_presenter_destroy(&live_presenter);
    farsee_live_shell_quiet_restore(&tick.shell);
    if (tick.shell.tty_fd >= 0) {
        rdp_live_discard_tty_responses(tick.shell.tty_fd);
        farsee_live_shell_tty_close_input(
            tick.shell.tty_fd, tick.shell.tty_fd_owned);
        tick.shell.tty_fd = -1;
        tick.shell.tty_fd_owned = false;
    }
    farsee_credential_response_destroy(&cred);
    farsee_live_signal_scope_restore(&signal_scope);
    return rc;
}

int farsee_run_rdp(const char *host, uint16_t port,
                   const char *user, const char *domain,
                   const char *cert_policy, int password_fd,
                   uint32_t desk_w, uint32_t desk_h,
                   const char *presenter_name,
                   uint64_t connect_timeout_ms,
                   bool view_only, bool clipboard_on,
                   rdp_liblog_level liblog,
                   const farsee_cli_leader *leader_spec)
{
    return farsee_run_rdp_with_facade_ops(
        host, port, user, domain, cert_policy, password_fd, desk_w, desk_h,
        presenter_name, connect_timeout_ms, view_only, clipboard_on, liblog,
        leader_spec, &rdp_live_default_facade_ops);
}

#endif /* FARSEE_WITH_RDP */
