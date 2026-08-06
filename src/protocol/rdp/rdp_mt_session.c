// SPDX-License-Identifier: Apache-2.0
//
// Multi-thread live RDP session: FreeRDP-specific protocol/present/input
// wrappers around the shared farsee_mt_run / farsee_mt_present_loop.

#include "rdp_mt_session.h"
#include "rdp_input_bridge.h"
#include "rdp_input_inject.h"

#include "farsee/farsee_atomic.h"
#include "farsee/farsee_mt_session.h"
#include "farsee/farsee_thread.h"
#include "farsee/socket_posix.h"

#include <freerdp/freerdp.h>
#include <winpr/synch.h>

#include <limits.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>

#define RDP_MT_MAX_HANDLES 64

typedef struct rdp_mt_shared {
    const rdp_mt_config *cfg;
    farsee_atomic_int peer_dead;
    // Present-loop cursor / gen tracking (present thread only).
    uint64_t last_gen;
    int32_t last_cx;
    int32_t last_cy;
    // Protocol-owned button sync (D3): retry wire→desired mid-session.
    rdp_button_wire_state buttons;
    // Link sample throttle + rate latch (protocol thread only).
    uint64_t next_link_ms;
    farsee_link_rate link_rate;
} rdp_mt_shared;

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
    (void)rdp_input_inject_pointer(sh->cfg->ctx, &pe, sh->buttons.wire,
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
        // Capacity before inject for *new* downs (loop r3 F2 / r4 F1).
        // If already held, leave ledger alone through inject (do not undo).
        farsee_key_event ke;
        const bool have_ke = rdp_input_key_event_from_keysym(
            &ke, c->keysym, c->unicode, c->down, c->repeat);
        bool provisional_new = false;
        if (c->down && ledger != NULL && have_ke && ke.physical != 0u) {
            const size_t before = ledger->count;
            if (!farsee_key_ledger_apply(ledger, &ke)) {
                rdp_input_inject_release_all(ctx, ledger);
                if (!farsee_key_ledger_apply(ledger, &ke)) {
                    break; // refuse untracked remote hold
                }
                // Added after overflow release (count may not exceed `before`
                // if before was MAX — loop r4 codex P2).
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
        const bool ok = rdp_input_inject_key_from_keysym(
            ctx, c->keysym, c->unicode, c->down, c->repeat);
        if (!ok || ledger == NULL || !have_ke) {
            break;
        }
        if (!c->down || provisional_new || ke.physical == 0u) {
            (void)farsee_key_ledger_apply(ledger, &ke);
        }
        // already-held down: ledger already correct
        break;
    }
    case RDP_INJ_POINTER: {
        // Always inject the original event (motion, wheel, buttons) — D3
        // sticky retry is only for incomplete *button* edges (codex r1 P1).
        // Using try_button_sync alone dropped motion/scroll when mask unchanged.
        const unsigned prev = sh->buttons.wire;
        unsigned reached = prev;
        (void)rdp_input_inject_pointer(ctx, &c->pe, prev, &reached);
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
        // T9: release via ledger when configured; never silent no-op success.
        if (ledger != NULL) {
            rdp_input_inject_release_all(ctx, ledger);
        }
        // Clear held mouse buttons mid-session (D3 sticky release).
        rdp_button_wire_note_cmd(&sh->buttons, 0u, sh->buttons.abs_x,
                                 sh->buttons.abs_y);
        try_button_sync(sh);
        break;
    default:
        break;
    }
}

// --- server redirection ----------------------------------------------------
//
// GNOME "Remote Login" does not serve the desktop from the daemon you first
// authenticate against. Once NLA succeeds it sends an RDP server-redirection
// PDU -- same host, carrying a load-balance cookie, a redirection GUID and
// PK-encrypted credentials -- pointing at the user session's own endpoint.
// FreeRDP consumes the PDU, drops the transport and resets the state machine
// to CONNECTION_STATE_INITIAL, then expects the client to dial again; it does
// not reconnect by itself. Without this the session ends immediately after the
// greeter frame and looks exactly like a peer disconnect.
//
// Only INITIAL is treated as a redirect: a genuine logoff or takeover leaves
// the state elsewhere and must still end the session. One attempt only, so a
// server that keeps redirecting cannot spin us.
static bool rdp_mt_follow_redirect(freerdp *inst, rdpContext *context,
                                   bool *retried)
{
    if (inst == NULL || context == NULL || retried == NULL || *retried) {
        return false;
    }
    if (freerdp_get_state(context) != CONNECTION_STATE_INITIAL) {
        return false;
    }
    *retried = true;
    return freerdp_reconnect(inst) ? true : false;
}

// --- protocol (FreeRDP pump + inject drain) --------------------------------

static void rdp_protocol_fn(void *user, farsee_frame_slot *slot,
                            farsee_cmd_queue *cmds, farsee_atomic_int *stop)
{
    rdp_mt_shared *sh = (rdp_mt_shared *)user;
    const rdp_mt_config *cfg = sh->cfg;
    (void)slot;
    (void)cmds;
    if (cfg == NULL || cfg->ctx == NULL) {
        return;
    }
    freerdp *inst = (freerdp *)rdp_freerdp_instance_opaque(cfg->ctx);
    if (inst == NULL || inst->context == NULL) {
        return;
    }
    rdpContext *context = inst->context;
    HANDLE handles[RDP_MT_MAX_HANDLES];
    const HANDLE abortEvt = freerdp_abort_event(context);
    bool redirect_retried = false;

    while (!farsee_atomic_int_load_nonzero(stop)) {
        if (freerdp_shall_disconnect_context(context)) {
            if (rdp_mt_follow_redirect(inst, context, &redirect_retried)) {
                continue;
            }
            farsee_atomic_int_store(&sh->peer_dead, 1);
            break;
        }

        // Drain inject queue (non-blocking pop with short deadline).
        // Cap per tick so FreeRDP WaitForMultipleObjects stays reachable
        // under sustained pointer flood (loop r1 T8; RFB caps at 32).
        {
            const uint64_t now = farsee_thread_monotonic_ms();
            rdp_inj_cmd cmd;
            unsigned n = 0u;
            while (n < 64u && rdp_inj_queue_pop(cfg->inj, &cmd, now, stop)) {
                apply_inj(sh, &cmd);
                n++;
            }
        }
        // Mid-session button sync without waiting for next user event (D3).
        try_button_sync(sh);

        DWORD n = freerdp_get_event_handles(context, handles,
                                            RDP_MT_MAX_HANDLES - 1);
        if (n == 0) {
            if (rdp_mt_follow_redirect(inst, context, &redirect_retried)) {
                continue;
            }
            farsee_atomic_int_store(&sh->peer_dead, 1);
            break;
        }
        DWORD waitCount = n;
        if (abortEvt != NULL && n < RDP_MT_MAX_HANDLES - 1) {
            handles[waitCount++] = abortEvt;
        }
        DWORD wr = WaitForMultipleObjects(waitCount, handles, FALSE, 5);
        if (wr == WAIT_FAILED) {
            farsee_atomic_int_store(&sh->peer_dead, 1);
            break;
        }
        if (wr != WAIT_TIMEOUT) {
            if (!freerdp_check_event_handles(context)) {
                if (rdp_mt_follow_redirect(inst, context, &redirect_retried)) {
                    continue;
                }
                farsee_atomic_int_store(&sh->peer_dead, 1);
                break;
            }
        }
        // Publish link metrics for status band (protocol thread only — T6).
        // Throttle + sticky FreeRDP rx (kernel for RTT only — loop r2 T2/T5/T6).
        if (cfg->link_meta != NULL && cfg->link_rx_bytes != NULL) {
            const uint64_t now_link = farsee_thread_monotonic_ms();
            if (farsee_link_sample_due(now_link, &sh->next_link_ms,
                                       FARSEE_LINK_RATE_WINDOW_MS)) {
                uint64_t in_b = 0u;
                uint64_t out_b = 0u;
                uint64_t rx = 0u;
                bool have_rx = false;
                bool have_rtt = false;
                uint32_t rtt = 0u;
                if (rdp_freerdp_wire_stats(cfg->ctx, &in_b, &out_b)) {
                    rx = in_b;
                    have_rx = true;
                }
                // Kernel RTT only — do not flip rx source mid-session.
                const int wfd = rdp_freerdp_wire_fd(cfg->ctx);
                if (wfd >= 0) {
                    const uint32_t m =
                        farsee_socket_tcp_stats(wfd, &rtt, NULL, NULL);
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
    // Signal stop first so input stops enqueueing, then bounded final drain
    // (loop r2 codex P2 — avoid drain-until-empty livelock).
    farsee_atomic_int_store(stop, 1);
    rdp_inj_queue_kick(cfg->inj);
    if (cfg->inj != NULL && cfg->ctx != NULL) {
        const uint64_t now = farsee_thread_monotonic_ms();
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
}

// --- present (fixed FPS + Kitty) -------------------------------------------

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
    const bool ok = rdp_callbacks_present_bgra(
        cfg->ctx, v->pixels, v->w, v->h, v->stride, cur_vis, cx, cy);
    if (cfg->io_mu != NULL) {
        farsee_mutex_unlock(cfg->io_mu);
    }
    if (!ok) {
        return false;
    }
    // Successful present: first real frame for dump/settle budgets.
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

static void rdp_present_fn(void *user, farsee_frame_slot *slot,
                           farsee_atomic_int *stop)
{
    rdp_mt_shared *sh = (rdp_mt_shared *)user;
    const rdp_mt_config *cfg = sh->cfg;
    uint32_t interval = (cfg != NULL) ? cfg->present_interval_ms : 16u;
    sh->last_gen = 0;
    sh->last_cx = INT32_MIN;
    sh->last_cy = INT32_MIN;
    farsee_mt_present_loop(slot, stop, interval, rdp_on_frame, sh,
                           rdp_after_present, sh,
                           cfg != NULL ? cfg->force_repaint : NULL);
}

// --- input -----------------------------------------------------------------

static void rdp_input_fn_wrap(void *user, farsee_cmd_queue *cmds,
                              farsee_atomic_int *stop)
{
    rdp_mt_shared *sh = (rdp_mt_shared *)user;
    const rdp_mt_config *cfg = sh->cfg;
    (void)cmds;
    if (cfg == NULL || cfg->input_fn == NULL) {
        return;
    }
    cfg->input_fn(cfg->input_user, cfg->inj, stop);
    farsee_atomic_int_store(stop, 1);
    rdp_freerdp_request_stop(cfg->ctx);
    rdp_frame_slot_kick(cfg->slot);
    rdp_inj_queue_kick(cfg->inj);
}

// --- entry -----------------------------------------------------------------

farsee_error rdp_mt_run(const rdp_mt_config *cfg, bool *out_got_frame)
{
    if (out_got_frame != NULL) {
        *out_got_frame = false;
    }
    if (cfg == NULL || cfg->ctx == NULL || cfg->sink == NULL ||
        cfg->slot == NULL || cfg->inj == NULL || cfg->stop_flag == NULL ||
        cfg->input_fn == NULL) {
        return farsee_error_make(FARSEE_ERR_STATE, FARSEE_SUB_RDP,
                                 FARSEE_PHASE_ACTIVE);
    }
    cfg->sink->frame_slot = cfg->slot;

    rdp_mt_shared sh;
    memset(&sh, 0, sizeof(sh));
    sh.cfg = cfg;
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

    farsee_error re = farsee_mt_run(&mtc);

    cfg->sink->frame_slot = NULL;
    if (out_got_frame != NULL) {
        *out_got_frame =
            farsee_atomic_int_load_nonzero(&cfg->sink->first_frame_delivered);
    }
    if (re.code != FARSEE_E_OK) {
        // Map generic core state errors to RDP subsystem for callers.
        if (re.code == FARSEE_ERR_STATE) {
            return farsee_error_make(FARSEE_ERR_STATE, FARSEE_SUB_RDP,
                                     FARSEE_PHASE_ACTIVE);
        }
        return re;
    }
    if (farsee_atomic_int_load_nonzero(&sh.peer_dead) &&
        !farsee_atomic_int_load_nonzero(&cfg->sink->first_frame_delivered)) {
        return farsee_error_make(FARSEE_ERR_CONNECT_FAILURE, FARSEE_SUB_RDP,
                                 FARSEE_PHASE_ACTIVE);
    }
    return farsee_error_make(FARSEE_E_OK, FARSEE_SUB_NONE, FARSEE_PHASE_ACTIVE);
}
