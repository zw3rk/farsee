// SPDX-License-Identifier: Apache-2.0
//
// farsee — pure live-input demux FSM (RFB/RDP shared).
//
// Consumes TTY byte slices (Kitty APC, SGR mouse, keyboard / CSI-u, leader
// prefix) and emits callbacks. No sockets, FreeRDP, layout, or desktop
// coordinate mapping — shells map SGR → desktop and inject.
//
// The multi-fill loop never silently drops a large paste. Incomplete
// ESC sequences are stashed in the residual across feed() calls.
//
// clock_ms: absolute monotonic ms for leader-arm timeout. Pass 0 to skip the
// timeout check on that feed (tests may inject exact deadlines).

#ifndef FARSEE_INCLUDE_FARSEE_LIVE_DEMUX_H
#define FARSEE_INCLUDE_FARSEE_LIVE_DEMUX_H

#include "farsee/cli_target.h"
#include "farsee/farsee_atomic.h"
#include "farsee/normalized_input.h"
#include "farsee/sgr_mouse.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// The residual stash must hold a full work fill so a large paste is never
// silently truncated mid-sequence.
#define FARSEE_LIVE_DEMUX_WORK_CAP     1024u
#define FARSEE_LIVE_DEMUX_RESIDUAL_CAP FARSEE_LIVE_DEMUX_WORK_CAP
#define FARSEE_LIVE_LEADER_ARM_MS      8000u
// Incomplete ESC / SGR / APC stashes expire so a stuck residual cannot
// swallow subsequent key/mouse bytes forever (Kitty APC pollution, split
// reads that never complete).
#define FARSEE_LIVE_RESIDUAL_MS        250u

// Callbacks. Any pointer may be NULL (event is then discarded).
// on_key / on_sgr are suppressed when demux->view_only is true.
// Leader arm/disarm and on_leader_cmd always fire (local control plane).
typedef struct farsee_live_demux_ops {
    void (*on_key)(void *user, const rfb_norm_key *nk);
    // Raw SGR event (terminal cell/pixel coords) + button mask after apply.
    void (*on_sgr)(void *user, const rfb_sgr_event *ev, uint8_t buttons);
    void (*on_leader_cmd)(void *user, rfb_leader_cmd cmd);
    // Optional: arm state changed (status band). armed=true on arm, false
    // on disarm (cmd, cancel printable, timeout).
    void (*on_leader_arm)(void *user, bool armed);
} farsee_live_demux_ops;

typedef struct farsee_live_demux {
    farsee_cli_leader leader;
    // Atomic: present/status may load while input feeds demux (C11 race).
    // Non-zero = armed. Input thread is the only writer.
    farsee_atomic_int leader_armed;
    uint64_t          leader_deadline_ms; // 0 = none
    rfb_kb            kb;
    rfb_norm_mods     mods;
    rfb_sgr_mouse     sgr;
    uint8_t           residual[FARSEE_LIVE_DEMUX_RESIDUAL_CAP];
    size_t            residual_len;
    uint64_t          residual_deadline_ms; // 0 = none; set when residual is stashed
    bool              view_only;
} farsee_live_demux;

// Convenience for demux/input (same thread as writer) and status readers.
static inline bool farsee_live_demux_leader_is_armed(const farsee_live_demux *d)
{
    return d != NULL && farsee_atomic_int_load_nonzero(&d->leader_armed);
}

// Init parsers + copy leader (default C-] when L is NULL).
void farsee_live_demux_init(farsee_live_demux *d, const farsee_cli_leader *L);

// Feed TTY bytes. clock_ms used for leader timeout; 0 disables the check
// for this call only (does not clear an existing deadline).
void farsee_live_demux_feed(farsee_live_demux *d, const uint8_t *data, size_t n,
                            uint64_t clock_ms, const farsee_live_demux_ops *ops,
                            void *user);

// Explicit disarm (e.g. idle-loop timeout without bytes). Notifies
// on_leader_arm(false) when previously armed. ops may be NULL.
void farsee_live_demux_check_timeout(farsee_live_demux *d, uint64_t clock_ms,
                                     const farsee_live_demux_ops *ops,
                                     void *user);

#ifdef __cplusplus
}
#endif

#endif /* FARSEE_INCLUDE_FARSEE_LIVE_DEMUX_H */
