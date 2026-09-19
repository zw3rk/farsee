// SPDX-License-Identifier: Apache-2.0
//
// Multi-thread live RDP session: FreeRDP-specific protocol/present/input
// wrappers around the shared farsee_mt_run / farsee_mt_present_loop.

#include "rdp_mt_session_internal.h"
#include "rdp_input_bridge.h"
#include "rdp_input_inject.h"

#include "farsee/farsee_atomic.h"
#include "farsee/farsee_mt_session.h"
#include "farsee/farsee_thread.h"
#include "farsee/socket_posix.h"

#include <freerdp/freerdp.h>
#include <winpr/synch.h>

#include <limits.h>
#include <string.h>
#include <sys/socket.h>

#define RDP_MT_MAX_HANDLES 64

typedef struct rdp_mt_shared {
    const rdp_mt_config *cfg;
    const rdp_mt_session_ops *ops;
    farsee_atomic_int peer_dead;
    // Present-loop cursor / gen tracking (present thread only).
    uint64_t last_gen;
    int32_t last_cx;
    int32_t last_cy;
    // Protocol-owned button sync retries wire→desired mid-session.
    rdp_button_wire_state buttons;
    // Link sample throttle + rate latch (protocol thread only).
    uint64_t next_link_ms;
    farsee_link_rate link_rate;
} rdp_mt_shared;

static void *ops_user(const rdp_mt_shared *sh)
{
    return sh->ops != NULL ? sh->ops->user : NULL;
}

static uint64_t op_monotonic_ms(const rdp_mt_shared *sh)
{
    if (sh->ops != NULL && sh->ops->monotonic_ms != NULL) {
        return sh->ops->monotonic_ms(ops_user(sh));
    }
    return farsee_thread_monotonic_ms();
}

static bool op_key_event_from_keysym(const rdp_mt_shared *sh,
                                     farsee_key_event *out,
                                     const rdp_inj_cmd *cmd)
{
    if (sh->ops != NULL && sh->ops->key_event_from_keysym != NULL) {
        return sh->ops->key_event_from_keysym(
            ops_user(sh), out, cmd->keysym, cmd->unicode, cmd->down,
            cmd->repeat);
    }
    return rdp_input_key_event_from_keysym(
        out, cmd->keysym, cmd->unicode, cmd->down, cmd->repeat);
}

static bool op_inject_key_from_keysym(const rdp_mt_shared *sh,
                                      rdp_freerdp_ctx *ctx,
                                      const rdp_inj_cmd *cmd)
{
    if (sh->ops != NULL && sh->ops->inject_key_from_keysym != NULL) {
        return sh->ops->inject_key_from_keysym(
            ops_user(sh), ctx, cmd->keysym, cmd->unicode, cmd->down,
            cmd->repeat);
    }
    return rdp_input_inject_key_from_keysym(
        ctx, cmd->keysym, cmd->unicode, cmd->down, cmd->repeat);
}

static bool op_inject_pointer(const rdp_mt_shared *sh,
                              rdp_freerdp_ctx *ctx,
                              const farsee_pointer_event *event,
                              unsigned previous_buttons,
                              unsigned *out_reached)
{
    if (sh->ops != NULL && sh->ops->inject_pointer != NULL) {
        return sh->ops->inject_pointer(ops_user(sh), ctx, event,
                                       previous_buttons, out_reached);
    }
    return rdp_input_inject_pointer(ctx, event, previous_buttons,
                                    out_reached);
}

static void op_release_all(const rdp_mt_shared *sh, rdp_freerdp_ctx *ctx,
                           farsee_key_ledger *ledger)
{
    if (sh->ops != NULL && sh->ops->release_all != NULL) {
        sh->ops->release_all(ops_user(sh), ctx, ledger);
        return;
    }
    rdp_input_inject_release_all(ctx, ledger);
}

// Attempt inject wire→desired; publish progressive mask to cfg->wire_buttons.
static void try_button_sync(rdp_mt_shared *sh)
{
    if (sh == NULL || sh->cfg == NULL || sh->cfg->ctx == NULL) {
        return;
    }
    if (!rdp_button_wire_needs_sync(&sh->buttons)) {
        return;
    }
    farsee_pointer_event pe;
    memset(&pe, 0, sizeof pe);
    pe.abs_x = sh->buttons.abs_x;
    pe.abs_y = sh->buttons.abs_y;
    pe.buttons = sh->buttons.desired;
    pe.quality = FARSEE_INPUT_QUALITY_INFERRED;
    unsigned reached = sh->buttons.wire;
    (void)op_inject_pointer(sh, sh->cfg->ctx, &pe, sh->buttons.wire,
                            &reached);
    rdp_button_wire_note_inject(&sh->buttons, reached);
    if (sh->cfg->wire_buttons != NULL) {
        *sh->cfg->wire_buttons = sh->buttons.wire;
    }
}

static void apply_inj(rdp_mt_shared *sh, const rdp_inj_cmd *c)
{
    if (sh == NULL || sh->cfg == NULL || c == NULL) {
        return;
    }
    rdp_freerdp_ctx *ctx = sh->cfg->ctx;
    farsee_key_ledger *ledger = sh->cfg->ledger;
    if (ctx == NULL) {
        return;
    }
    switch (c->kind) {
    case RDP_INJ_KEY: {
        // Reserve ledger capacity before injecting a new key-down.
        // If already held, leave ledger alone through inject (do not undo).
        farsee_key_event ke;
        if (!op_key_event_from_keysym(sh, &ke, c)) {
            break;
        }
        bool provisional_new = false;
        if (c->down && ledger != NULL && ke.physical != 0u) {
            const size_t before = ledger->count;
            if (!farsee_key_ledger_apply(ledger, &ke)) {
                op_release_all(sh, ctx, ledger);
                if (!farsee_key_ledger_apply(ledger, &ke)) {
                    break; // refuse untracked remote hold
                }
                // Added after overflow release; count may not exceed `before`
                // when `before` was already the maximum.
                provisional_new = true;
            } else if (ledger->count > before) {
                provisional_new = true;
            }
            if (provisional_new) {
                // Undo until inject succeeds.
                farsee_key_event up = ke;
                up.action = FARSEE_KEY_RELEASE;
                (void)farsee_key_ledger_apply(ledger, &up);
            }
            // already held (count unchanged, not provisional): leave ledger.
        }
        const bool ok = op_inject_key_from_keysym(sh, ctx, c);
        if (!ok || ledger == NULL) {
            break;
        }
        if (!c->down || provisional_new || ke.physical == 0u) {
            (void)farsee_key_ledger_apply(ledger, &ke);
        }
        // already-held down: ledger already correct
        break;
    }
    case RDP_INJ_POINTER: {
        // Always inject the original event (motion, wheel, buttons). Sticky
        // retry is only for incomplete button edges.
        // Using try_button_sync alone dropped motion/scroll when mask unchanged.
        const unsigned prev = sh->buttons.wire;
        unsigned reached = prev;
        (void)op_inject_pointer(sh, ctx, &c->pe, prev, &reached);
        sh->buttons.abs_x = c->pe.abs_x;
        sh->buttons.abs_y = c->pe.abs_y;
        sh->buttons.desired = c->pe.buttons;
        rdp_button_wire_note_inject(&sh->buttons, reached);
        if (sh->cfg->wire_buttons != NULL) {
            *sh->cfg->wire_buttons = sh->buttons.wire;
        }
        // If button edges incomplete, pump will retry via try_button_sync.
        break;
    }
    case RDP_INJ_RELEASE_ALL:
        // Release through the ledger when configured; never report a silent no-op success.
        if (ledger != NULL) {
            op_release_all(sh, ctx, ledger);
        }
        // Clear held mouse buttons mid-session.
        rdp_button_wire_note_cmd(&sh->buttons, 0u, sh->buttons.abs_x,
                                 sh->buttons.abs_y);
        try_button_sync(sh);
        break;
    default:
        break;
    }
}

// --- protocol (FreeRDP pump + inject drain) --------------------------------

static void *op_protocol_context(const rdp_mt_shared *sh,
                                 rdp_freerdp_ctx *ctx)
{
    if (sh->ops != NULL && sh->ops->protocol_context != NULL) {
        return sh->ops->protocol_context(ops_user(sh), ctx);
    }
    freerdp *instance = (freerdp *)rdp_freerdp_instance_opaque(ctx);
    return instance != NULL ? instance->context : NULL;
}

static bool op_shall_disconnect(const rdp_mt_shared *sh, void *context)
{
    if (sh->ops != NULL && sh->ops->shall_disconnect != NULL) {
        return sh->ops->shall_disconnect(ops_user(sh), context);
    }
    return freerdp_shall_disconnect_context((rdpContext *)context);
}

static rdp_mt_pump_result op_pump_once(const rdp_mt_shared *sh,
                                       void *opaque_context)
{
    if (sh->ops != NULL && sh->ops->pump_once != NULL) {
        return sh->ops->pump_once(ops_user(sh), opaque_context);
    }
    rdpContext *context = (rdpContext *)opaque_context;
    HANDLE handles[RDP_MT_MAX_HANDLES];
    const HANDLE abort_event = freerdp_abort_event(context);
    DWORD count = freerdp_get_event_handles(
        context, handles, RDP_MT_MAX_HANDLES - 1);
    if (count == 0) {
        return RDP_MT_PUMP_TRANSPORT_FAILURE;
    }
    DWORD wait_count = count;
    if (abort_event != NULL && count < RDP_MT_MAX_HANDLES - 1) {
        handles[wait_count++] = abort_event;
    }
    const DWORD wait_result =
        WaitForMultipleObjects(wait_count, handles, FALSE, 5);
    if (wait_result == WAIT_FAILED) {
        return RDP_MT_PUMP_TRANSPORT_FAILURE;
    }
    if (wait_result == WAIT_TIMEOUT) {
        return RDP_MT_PUMP_IDLE;
    }
    return freerdp_check_event_handles(context)
               ? RDP_MT_PUMP_PROGRESS
               : RDP_MT_PUMP_DISPATCH_FAILURE;
}

static bool op_clean_peer_disconnect(const rdp_mt_shared *sh,
                                     rdp_freerdp_ctx *ctx)
{
    if (sh->ops != NULL && sh->ops->clean_peer_disconnect != NULL) {
        return sh->ops->clean_peer_disconnect(ops_user(sh), ctx);
    }
    return rdp_freerdp_is_clean_peer_disconnect(ctx);
}

static bool op_wire_stats(const rdp_mt_shared *sh, rdp_freerdp_ctx *ctx,
                          uint64_t *in_bytes, uint64_t *out_bytes)
{
    if (sh->ops != NULL && sh->ops->wire_stats != NULL) {
        return sh->ops->wire_stats(ops_user(sh), ctx, in_bytes, out_bytes);
    }
    return rdp_freerdp_wire_stats(ctx, in_bytes, out_bytes);
}

static int op_wire_fd(const rdp_mt_shared *sh, rdp_freerdp_ctx *ctx)
{
    if (sh->ops != NULL && sh->ops->wire_fd != NULL) {
        return sh->ops->wire_fd(ops_user(sh), ctx);
    }
    return rdp_freerdp_wire_fd(ctx);
}

static uint32_t op_tcp_stats(const rdp_mt_shared *sh, int fd,
                             uint32_t *out_rtt_ms)
{
    if (sh->ops != NULL && sh->ops->tcp_stats != NULL) {
        return sh->ops->tcp_stats(ops_user(sh), fd, out_rtt_ms);
    }
    return farsee_socket_tcp_stats(fd, out_rtt_ms, NULL, NULL);
}

static farsee_mt_terminal_kind rdp_protocol_fn(
    void *user, farsee_frame_slot *slot, farsee_cmd_queue *cmds,
    farsee_atomic_int *stop, farsee_mt_terminal *terminal)
{
    rdp_mt_shared *sh = (rdp_mt_shared *)user;
    const rdp_mt_config *cfg = sh->cfg;
    (void)slot;
    (void)cmds;
    if (cfg == NULL || cfg->ctx == NULL) {
        return FARSEE_MT_TERMINAL_INTERNAL_FAILURE;
    }
    void *context = op_protocol_context(sh, cfg->ctx);
    if (context == NULL) {
        return FARSEE_MT_TERMINAL_INTERNAL_FAILURE;
    }
    farsee_mt_terminal_kind terminal_kind =
        FARSEE_MT_TERMINAL_REQUESTED_STOP;

    while (!farsee_atomic_int_load_nonzero(stop)) {
        if (op_shall_disconnect(sh, context)) {
            farsee_atomic_int_store(&sh->peer_dead, 1);
            terminal_kind = op_clean_peer_disconnect(sh, cfg->ctx)
                          ? FARSEE_MT_TERMINAL_PEER_CLOSED
                          : FARSEE_MT_TERMINAL_PROTOCOL_FAILURE;
            break;
        }

        // Drain inject queue (non-blocking pop with short deadline).
        // Cap each tick so FreeRDP WaitForMultipleObjects stays reachable
        // under sustained pointer input. The RFB path uses a cap of 32.
        {
            const uint64_t now = op_monotonic_ms(sh);
            rdp_inj_cmd cmd;
            unsigned n = 0u;
            while (n < 64u && rdp_inj_queue_pop(cfg->inj, &cmd, now, stop)) {
                apply_inj(sh, &cmd);
                n++;
            }
        }
        // Sync buttons mid-session without waiting for the next user event.
        try_button_sync(sh);

        const rdp_mt_pump_result pump = op_pump_once(sh, context);
        if (pump == RDP_MT_PUMP_TRANSPORT_FAILURE) {
            farsee_atomic_int_store(&sh->peer_dead, 1);
            terminal_kind = FARSEE_MT_TERMINAL_PROTOCOL_FAILURE;
            break;
        }
        if (pump == RDP_MT_PUMP_DISPATCH_FAILURE) {
            const farsee_frame_publish_result publish_failure =
                (farsee_frame_publish_result)farsee_atomic_int_load(
                    &cfg->sink->frame_publish_failure);
            if (publish_failure == FARSEE_FRAME_PUBLISH_OUT_OF_MEMORY) {
                terminal_kind = FARSEE_MT_TERMINAL_ALLOCATION_FAILURE;
            } else if (publish_failure != FARSEE_FRAME_PUBLISH_OK) {
                terminal_kind = FARSEE_MT_TERMINAL_PROTOCOL_FAILURE;
            } else {
                farsee_atomic_int_store(&sh->peer_dead, 1);
                terminal_kind = op_clean_peer_disconnect(sh, cfg->ctx)
                                    ? FARSEE_MT_TERMINAL_PEER_CLOSED
                                    : FARSEE_MT_TERMINAL_PROTOCOL_FAILURE;
            }
            break;
        }
        // Publish status-band link metrics from the protocol thread only.
        // Throttle samples and retain FreeRDP receive counts. RTT comes only
        // from the kernel.
        if (cfg->link_meta != NULL && cfg->link_rx_bytes != NULL) {
            const uint64_t now_link = op_monotonic_ms(sh);
            if (farsee_link_sample_due(now_link, &sh->next_link_ms,
                                       FARSEE_LINK_RATE_WINDOW_MS)) {
                uint64_t in_b = 0u;
                uint64_t out_b = 0u;
                uint64_t rx = 0u;
                bool have_rx = false;
                bool have_rtt = false;
                uint32_t rtt = 0u;
                if (op_wire_stats(sh, cfg->ctx, &in_b, &out_b)) {
                    rx = in_b;
                    have_rx = true;
                }
                // Kernel RTT only — do not flip rx source mid-session.
                const int wfd = op_wire_fd(sh, cfg->ctx);
                if (wfd >= 0) {
                    const uint32_t m = op_tcp_stats(sh, wfd, &rtt);
                    if ((m & FARSEE_TCP_STAT_RTT) != 0u) {
                        have_rtt = true;
                    }
                }
                const uint64_t rate_pub = farsee_link_rate_step(
                    &sh->link_rate, rx, have_rx, now_link,
                    FARSEE_LINK_RATE_WINDOW_MS);
                const uint64_t meta =
                    farsee_link_meta_pack(rtt, have_rtt, have_rx);
                farsee_atomic_u64_store(cfg->link_rx_bytes, rx);
                if (cfg->link_rate_pub != NULL) {
                    farsee_atomic_u64_store(cfg->link_rate_pub, rate_pub);
                }
                farsee_atomic_u64_store(cfg->link_meta, meta);
            }
        }
    }
    (void)farsee_mt_terminal_report(terminal, terminal_kind);
    // Signal stop first so input stops enqueueing, then do a bounded final
    // drain to avoid a drain-until-empty livelock.
    farsee_atomic_int_store(stop, 1);
    rdp_inj_queue_kick(cfg->inj);
    if (cfg->inj != NULL && cfg->ctx != NULL) {
        const uint64_t now = op_monotonic_ms(sh);
        rdp_inj_cmd cmd;
        farsee_atomic_int drained_stop = 1; // do not block on empty
        unsigned guard = 0;
        while (guard < 4096u &&
               rdp_inj_queue_pop(cfg->inj, &cmd, now, &drained_stop)) {
            apply_inj(sh, &cmd);
            guard++;
        }
        try_button_sync(sh);
    }
    rdp_frame_slot_kick(cfg->slot);
    rdp_inj_queue_kick(cfg->inj);
    return terminal_kind;
}

// --- present (fixed FPS + Kitty) -------------------------------------------

static bool op_present_bgra(const rdp_mt_shared *sh,
                            const farsee_frame_view *view,
                            bool cursor_visible, int32_t cursor_x,
                            int32_t cursor_y)
{
    if (sh->ops != NULL && sh->ops->present_bgra != NULL) {
        return sh->ops->present_bgra(
            ops_user(sh), sh->cfg->ctx, view->pixels, view->w, view->h,
            view->stride, cursor_visible, cursor_x, cursor_y);
    }
    return rdp_callbacks_present_bgra(
        sh->cfg->ctx, view->pixels, view->w, view->h, view->stride,
        cursor_visible, cursor_x, cursor_y);
}

static bool rdp_on_frame(void *user, const farsee_frame_view *v)
{
    rdp_mt_shared *sh = (rdp_mt_shared *)user;
    const rdp_mt_config *cfg = sh->cfg;
    if (v == NULL || cfg == NULL) {
        return false;
    }
    bool cur_vis = false;
    int32_t cx = 0;
    int32_t cy = 0;
    if (cfg->sink != NULL) {
        // Snapshot cursor atomics published by the input thread.
        cur_vis = farsee_atomic_int_load_nonzero(&cfg->sink->cursor_visible);
        cx = farsee_atomic_int_load(&cfg->sink->cursor_x);
        cy = farsee_atomic_int_load(&cfg->sink->cursor_y);
    }
    // The present loop only invokes us for a new gen or force_repaint (zoom
    // / layout). Always present: skipping same-gen here made C-] +/- update
    // place cells without redraw until the next FreeRDP paint (e.g. mouse
    // move). Cursor overlay is composed at present time either way.
    // Hold io_mu across Kitty out append so status cannot observe a torn buffer.
    if (cfg->io_mu != NULL) {
        farsee_mutex_lock(cfg->io_mu);
    }
    const bool ok = op_present_bgra(sh, v, cur_vis, cx, cy);
    if (cfg->io_mu != NULL) {
        farsee_mutex_unlock(cfg->io_mu);
    }
    if (!ok) {
        return false;
    }
    // Mark the first threshold-admitted successful present as delivered.
    if (cfg->sink != NULL) {
        farsee_atomic_int_store(&cfg->sink->first_frame_delivered, 1);
    }
    sh->last_gen = v->gen;
    sh->last_cx = cx;
    sh->last_cy = cy;
    return true;
}

static void rdp_after_present(void *user)
{
    rdp_mt_shared *sh = (rdp_mt_shared *)user;
    const rdp_mt_config *cfg = sh->cfg;
    if (cfg != NULL && cfg->after_present_fn != NULL) {
        cfg->after_present_fn(cfg->after_present_user);
    }
}

static farsee_mt_terminal_kind rdp_present_fn(
    void *user, farsee_frame_slot *slot, farsee_atomic_int *stop,
    farsee_mt_terminal *terminal)
{
    rdp_mt_shared *sh = (rdp_mt_shared *)user;
    const rdp_mt_config *cfg = sh->cfg;
    uint32_t interval = (cfg != NULL) ? cfg->present_interval_ms : 16u;
    sh->last_gen = 0;
    sh->last_cx = INT32_MIN;
    sh->last_cy = INT32_MIN;
    if (sh->ops != NULL && sh->ops->present_loop != NULL) {
        return sh->ops->present_loop(
            ops_user(sh), slot, stop, interval, rdp_on_frame, sh,
            rdp_after_present, sh,
            cfg != NULL ? cfg->force_repaint : NULL, terminal);
    }
    return farsee_mt_present_loop(slot, stop, interval, rdp_on_frame, sh,
                                  rdp_after_present, sh,
                                  cfg != NULL ? cfg->force_repaint : NULL,
                                  terminal);
}

// --- input -----------------------------------------------------------------

static farsee_mt_terminal_kind rdp_input_fn_wrap(
    void *user, farsee_cmd_queue *cmds, farsee_atomic_int *stop,
    farsee_mt_terminal *terminal)
{
    rdp_mt_shared *sh = (rdp_mt_shared *)user;
    const rdp_mt_config *cfg = sh->cfg;
    (void)cmds;
    if (cfg == NULL || cfg->input_fn == NULL) {
        return FARSEE_MT_TERMINAL_INTERNAL_FAILURE;
    }
    farsee_mt_terminal_kind kind = cfg->input_fn(
        cfg->input_user, cfg->inj, stop, terminal);
    (void)farsee_mt_terminal_report(terminal, kind);
    farsee_atomic_int_store(stop, 1);
    if (sh->ops != NULL && sh->ops->request_stop != NULL) {
        sh->ops->request_stop(ops_user(sh), cfg->ctx);
    } else {
        rdp_freerdp_request_stop(cfg->ctx);
    }
    rdp_frame_slot_kick(cfg->slot);
    rdp_inj_queue_kick(cfg->inj);
    return kind;
}

// --- entry -----------------------------------------------------------------

farsee_error rdp_mt_run_with_ops(const rdp_mt_config *cfg,
                                 bool *out_got_frame,
                                 farsee_mt_outcome *outcome,
                                 const rdp_mt_session_ops *ops)
{
    if (out_got_frame != NULL) {
        *out_got_frame = false;
    }
    if (outcome != NULL) {
        memset(outcome, 0, sizeof *outcome);
    }
    if (cfg == NULL || cfg->ctx == NULL || cfg->sink == NULL ||
        cfg->slot == NULL || cfg->inj == NULL || cfg->stop_flag == NULL ||
        cfg->input_fn == NULL) {
        farsee_error error = farsee_error_make(
            FARSEE_ERR_STATE, FARSEE_SUB_RDP, FARSEE_PHASE_ACTIVE);
        if (outcome != NULL) {
            outcome->kind = FARSEE_MT_TERMINAL_INTERNAL_FAILURE;
            outcome->error = error;
        }
        return error;
    }
    farsee_atomic_int_store(&cfg->sink->frame_publish_failure,
                            FARSEE_FRAME_PUBLISH_OK);
    cfg->sink->frame_slot = cfg->slot;

    rdp_mt_shared sh;
    memset(&sh, 0, sizeof(sh));
    sh.cfg = cfg;
    sh.ops = ops;
    sh.last_cx = INT32_MIN;
    sh.last_cy = INT32_MIN;
    rdp_button_wire_init(&sh.buttons);
    if (cfg->wire_buttons != NULL) {
        sh.buttons.wire = *cfg->wire_buttons;
    }

    farsee_mt_config mtc;
    memset(&mtc, 0, sizeof(mtc));
    mtc.slot = cfg->slot;
    mtc.cmds = cfg->inj;
    mtc.stop_flag = cfg->stop_flag;
    mtc.protocol_fn = rdp_protocol_fn;
    mtc.protocol_user = &sh;
    mtc.present_fn = rdp_present_fn;
    mtc.present_user = &sh;
    mtc.input_fn = rdp_input_fn_wrap;
    mtc.input_user = &sh;

    farsee_mt_outcome core_outcome;
    farsee_error re;
    if (ops != NULL && ops->run_threads != NULL) {
        re = ops->run_threads(ops->user, &mtc, &core_outcome);
    } else {
        re = farsee_mt_run(&mtc, &core_outcome);
    }

    cfg->sink->frame_slot = NULL;
    if (out_got_frame != NULL) {
        *out_got_frame =
            farsee_atomic_int_load_nonzero(&cfg->sink->first_frame_delivered);
    }
    if (re.code != FARSEE_E_OK) {
        if (re.subsystem == FARSEE_SUB_CORE) {
            re.subsystem = FARSEE_SUB_RDP;
        }
        core_outcome.error = re;
        if (outcome != NULL) {
            *outcome = core_outcome;
        }
        return re;
    }
    if (farsee_atomic_int_load_nonzero(&sh.peer_dead) &&
        !farsee_atomic_int_load_nonzero(&cfg->sink->first_frame_delivered)) {
        re = farsee_error_make(FARSEE_ERR_CONNECT_FAILURE, FARSEE_SUB_RDP,
                               FARSEE_PHASE_ACTIVE);
        core_outcome.error = re;
        if (outcome != NULL) {
            *outcome = core_outcome;
        }
        return re;
    }
    if (outcome != NULL) {
        *outcome = core_outcome;
    }
    return farsee_error_make(FARSEE_E_OK, FARSEE_SUB_NONE,
                             FARSEE_PHASE_ACTIVE);
}

farsee_error rdp_mt_run(const rdp_mt_config *cfg, bool *out_got_frame,
                        farsee_mt_outcome *outcome)
{
    return rdp_mt_run_with_ops(cfg, out_got_frame, outcome, NULL);
}
