// SPDX-License-Identifier: Apache-2.0
//
// Pure live-input demux FSM shared by RFB/RDP shells (quality Q1).
// Derived from the product demux behaviour in rdp_live / rfb_live; no I/O.

#include "farsee/live_demux.h"
#include "farsee/live_input_buf.h"

#include <string.h>

static void demux_notify_arm(farsee_live_demux *d, bool armed,
                             const farsee_live_demux_ops *ops, void *user)
{
    if (ops != NULL && ops->on_leader_arm != NULL) {
        ops->on_leader_arm(user, armed);
    }
    (void)d;
}

static void demux_arm(farsee_live_demux *d, uint64_t clock_ms,
                      const farsee_live_demux_ops *ops, void *user)
{
    if (d == NULL) {
        return;
    }
    farsee_atomic_int_store(&d->leader_armed, 1);
    if (clock_ms != 0u) {
        d->leader_deadline_ms = clock_ms + (uint64_t)FARSEE_LIVE_LEADER_ARM_MS;
    } else if (d->leader_deadline_ms == 0u) {
        // No clock: leave deadline unset (timeout needs a later clocked feed).
        d->leader_deadline_ms = 0u;
    }
    demux_notify_arm(d, true, ops, user);
}

static void demux_disarm(farsee_live_demux *d, bool notify,
                         const farsee_live_demux_ops *ops, void *user)
{
    if (d == NULL || !farsee_live_demux_leader_is_armed(d)) {
        if (d != NULL) {
            d->leader_deadline_ms = 0u;
        }
        return;
    }
    farsee_atomic_int_store(&d->leader_armed, 0);
    d->leader_deadline_ms = 0u;
    if (notify) {
        demux_notify_arm(d, false, ops, user);
    }
}

static void demux_do_cmd(farsee_live_demux *d, rfb_leader_cmd cmd,
                         const farsee_live_demux_ops *ops, void *user)
{
    if (d == NULL) {
        return;
    }
    // Disarm before callback so nested feeds see a clear prefix.
    demux_disarm(d, /*notify=*/true, ops, user);
    if (ops != NULL && ops->on_leader_cmd != NULL &&
        cmd != RFB_LEADER_CMD_NONE) {
        ops->on_leader_cmd(user, cmd);
    }
}

static void demux_emit_key(farsee_live_demux *d, const rfb_norm_key *nk,
                           const farsee_live_demux_ops *ops, void *user)
{
    if (d == NULL || nk == NULL || d->view_only) {
        return;
    }
    if (ops != NULL && ops->on_key != NULL) {
        ops->on_key(user, nk);
    }
}

static void demux_emit_sgr(farsee_live_demux *d, const rfb_sgr_event *ev,
                           uint8_t buttons, const farsee_live_demux_ops *ops,
                           void *user)
{
    if (d == NULL || ev == NULL || d->view_only) {
        return;
    }
    if (ops != NULL && ops->on_sgr != NULL) {
        ops->on_sgr(user, ev, buttons);
    }
}

// Classic Ctrl-C (ETX) with ISIG off → remote interrupt chord (not local quit).
static void demux_emit_ctrl_c(farsee_live_demux *d,
                              const farsee_live_demux_ops *ops, void *user)
{
    rfb_norm_key nk;
    memset(&nk, 0, sizeof(nk));
    nk.keysym = (uint32_t)'c';
    nk.modifiers = RFB_MOD_CONTROL;
    nk.down = true;
    nk.source = RFB_NORM_SOURCE_LEGACY;
    demux_emit_key(d, &nk, ops, user);
}

void farsee_live_demux_init(farsee_live_demux *d, const farsee_cli_leader *L)
{
    if (d == NULL) {
        return;
    }
    memset(d, 0, sizeof(*d));
    if (L != NULL) {
        d->leader = *L;
    } else {
        farsee_cli_leader_default(&d->leader);
    }
    rfb_kb_init(&d->kb);
    rfb_norm_mods_init(&d->mods);
    rfb_sgr_mouse_init(&d->sgr);
}

static void demux_expire_residual(farsee_live_demux *d, uint64_t clock_ms)
{
    if (d == NULL || clock_ms == 0u || d->residual_len == 0u ||
        d->residual_deadline_ms == 0u) {
        return;
    }
    if (clock_ms < d->residual_deadline_ms) {
        return;
    }
    // Drop stuck incomplete ESC / SGR / APC and reset CSI parser so keys
    // after a partial sequence are not absorbed forever.
    d->residual_len = 0u;
    d->residual_deadline_ms = 0u;
    rfb_kb_init(&d->kb);
    rfb_sgr_mouse_init(&d->sgr);
}

void farsee_live_demux_check_timeout(farsee_live_demux *d, uint64_t clock_ms,
                                     const farsee_live_demux_ops *ops,
                                     void *user)
{
    if (d == NULL || clock_ms == 0u) {
        return;
    }
    demux_expire_residual(d, clock_ms);
    if (farsee_live_demux_leader_is_armed(d) && d->leader_deadline_ms != 0u &&
        clock_ms >= d->leader_deadline_ms) {
        demux_disarm(d, /*notify=*/true, ops, user);
    }
}

void farsee_live_demux_feed(farsee_live_demux *d, const uint8_t *data, size_t n,
                            uint64_t clock_ms, const farsee_live_demux_ops *ops,
                            void *user)
{
    if (d == NULL) {
        return;
    }

    // Expire leader arm + stuck residual before processing.
    farsee_live_demux_check_timeout(d, clock_ms, ops, user);

    if (data == NULL && n > 0u) {
        return;
    }
    if (n == 0u && d->residual_len == 0u) {
        return;
    }
    // Stale incomplete ESC prefix + a *new* ESC-starting chunk: drop the
    // prefix so we do not build ESC[ ESC[<… (SGR never matches).
    if (d->residual_len > 0u && d->residual_len <= 2u &&
        d->residual[0] == 0x1Bu && n > 0u && data != NULL &&
        data[0] == 0x1Bu) {
        d->residual_len = 0u;
        d->residual_deadline_ms = 0u;
        rfb_kb_init(&d->kb);
    }
    // Allow n==0 with residual only when data is non-NULL or residual drains
    // alone — residual reprocess needs a fill with empty data.
    if (data == NULL) {
        data = (const uint8_t *)"";
        n = 0u;
    }

    size_t data_off = 0;
    while (data_off < n || d->residual_len > 0u) {
        uint8_t work[FARSEE_LIVE_DEMUX_WORK_CAP];
        size_t wlen = 0;
        size_t used = 0;
        // Keep the original residual deadline across re-stashes so continuous
        // pollution cannot refresh the TTL forever.
        const uint64_t prior_residual_deadline = d->residual_deadline_ms;
        if (!farsee_live_input_fill(work, sizeof work, d->residual,
                                    d->residual_len, data, n, data_off, &wlen,
                                    &used)) {
            return;
        }
        d->residual_len = 0u;
        d->residual_deadline_ms = 0u;
        data_off += used;
        if (wlen == 0u) {
            break;
        }

        size_t i = 0;
        while (i < wlen) {
            // Leader C0 (e.g. GS for C-]) or second chord while armed.
            if (rfb_byte_matches_leader(work[i], d->leader.c0_byte,
                                        d->leader.has_c0)) {
                if (farsee_live_demux_leader_is_armed(d)) {
                    demux_do_cmd(d, RFB_LEADER_CMD_PASS, ops, user);
                } else {
                    demux_arm(d, clock_ms, ops, user);
                }
                i++;
                continue;
            }
            // Armed leader + legacy plain second byte only while kb is IDLE.
            // Mid-CSI bytes must not cancel the prefix.
            if (farsee_live_demux_leader_is_armed(d) && d->kb.state == RFB_KB_IDLE &&
                work[i] != 0x1Bu) {
                rfb_leader_cmd cmd = rfb_leader_cmd_from_byte(
                    work[i], d->leader.c0_byte, d->leader.has_c0);
                if (cmd != RFB_LEADER_CMD_NONE) {
                    demux_do_cmd(d, cmd, ops, user);
                    i++;
                    continue;
                }
                if (work[i] >= 0x20u && work[i] < 0x7Fu) {
                    demux_disarm(d, /*notify=*/true, ops, user);
                }
            }
            // Classic Ctrl-C (ETX) with ISIG off → inject to remote, not quit.
            if (rfb_byte_is_intr(work[i])) {
                demux_emit_ctrl_c(d, ops, user);
                i++;
                continue;
            }
            // Incomplete ESC prefixes must residual BEFORE kb_feed. If we
            // feed ESC / ESC[ into the keyboard CSI parser and the next
            // read starts with "<Pb;Px;PyM" (SGR), the mouse stream is
            // swallowed as CSI params and never injects (live: in=0 while
            // Kitty keeps emitting SGR). Same for ESC alone then "[<…".
            if (work[i] == 0x1Bu) {
                if (i + 1u >= wlen) {
                    break; // residual lone ESC
                }
                if (work[i + 1u] == '[' && i + 2u >= wlen) {
                    break; // residual ESC [  (SGR or CSI-u TBD)
                }
            }
            // Kitty graphics reply: ESC _ G ... ESC ST — discard.
            if (work[i] == 0x1Bu && i + 1u < wlen && work[i + 1u] == '_') {
                size_t j = i + 2u;
                while (j + 1u < wlen &&
                       !(work[j] == 0x1Bu && work[j + 1u] == '\\')) {
                    j++;
                }
                if (j + 1u >= wlen) {
                    break; // incomplete APC → residual
                }
                i = j + 2u;
                continue;
            }
            // SGR mouse: ESC [ < …
            if (work[i] == 0x1Bu && i + 2u < wlen && work[i + 1u] == '[' &&
                work[i + 2u] == '<') {
                size_t j = i + 3u;
                while (j < wlen && work[j] != 'M' && work[j] != 'm') {
                    j++;
                }
                if (j >= wlen) {
                    break; // incomplete SGR
                }
                size_t seq_len = j - i + 1u;
                rfb_sgr_event evs[8];
                size_t ne = rfb_sgr_mouse_feed(&d->sgr, work + i, seq_len, evs,
                                               8);
                for (size_t k = 0; k < ne; k++) {
                    demux_emit_sgr(d, &evs[k], d->sgr.buttons, ops, user);
                }
                i = j + 1u;
                continue;
            }
            // Keyboard (Kitty CSI-u + legacy). Always feed so residual CSI
            // state stays coherent.
            {
                rfb_norm_key nk;
                rfb_norm_source src =
                    rfb_kb_feed(&d->kb, work[i], &d->mods, &nk);
                if (src != RFB_NORM_SOURCE_NONE) {
                    // Swallow leader chord press+release (never inject leak).
                    if (rfb_norm_key_is_leader_chord(&nk, d->leader.keysym,
                                                     d->leader.mods)) {
                        if (nk.down) {
                            if (farsee_live_demux_leader_is_armed(d)) {
                                demux_do_cmd(d, RFB_LEADER_CMD_PASS, ops,
                                             user);
                            } else {
                                demux_arm(d, clock_ms, ops, user);
                            }
                        }
                        i++;
                        continue;
                    }
                    if (farsee_live_demux_leader_is_armed(d)) {
                        // Only complete key *presses* resolve the prefix.
                        if (!nk.down) {
                            i++;
                            continue;
                        }
                        rfb_leader_cmd cmd = rfb_leader_cmd_from_key(
                            &nk, d->leader.keysym, d->leader.mods);
                        if (cmd != RFB_LEADER_CMD_NONE) {
                            demux_do_cmd(d, cmd, ops, user);
                            i++;
                            continue;
                        }
                        demux_disarm(d, /*notify=*/true, ops, user);
                    }
                    (void)rfb_norm_mods_apply(&d->mods, nk.keysym, nk.down);
                    demux_emit_key(d, &nk, ops, user);
                }
            }
            i++;
        }
        // Stash incomplete tail for the next fill.
        if (i < wlen) {
            size_t rem = wlen - i;
            if (rem > sizeof(d->residual)) {
                rem = sizeof(d->residual);
            }
            memcpy(d->residual, work + i, rem);
            d->residual_len = rem;
            if (prior_residual_deadline != 0u) {
                d->residual_deadline_ms = prior_residual_deadline;
            } else if (clock_ms != 0u) {
                d->residual_deadline_ms =
                    clock_ms + (uint64_t)FARSEE_LIVE_RESIDUAL_MS;
            } else {
                // Tests that pass clock 0 still carry residual without
                // auto-expire until a clocked feed/check_timeout runs.
                d->residual_deadline_ms = 0u;
            }
            if (data_off >= n) {
                break;
            }
            // Pathological: residual full and no progress — drop residual
            // so we cannot spin (mirrors RFB APC overflow reset).
            if (used == 0u && d->residual_len == sizeof(d->residual)) {
                d->residual_len = 0u;
                d->residual_deadline_ms = 0u;
            }
        }
    }
}
