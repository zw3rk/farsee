// SPDX-License-Identifier: Apache-2.0
//
// Multi-thread live session skeleton (see farsee_mt_session.h).

#include "farsee/farsee_mt_session.h"
#include "farsee/cpu_probe.h"
#include "farsee/farsee_thread.h"

#include <string.h>

typedef struct farsee_mt_shared {
    const farsee_mt_config *cfg;
} farsee_mt_shared;

static void *protocol_thread_main(void *arg)
{
    farsee_mt_shared *sh = (farsee_mt_shared *)arg;
    const farsee_mt_config *cfg = sh->cfg;
    if (cfg == NULL || cfg->protocol_fn == NULL) {
        return NULL;
    }
    cfg->protocol_fn(cfg->protocol_user, cfg->slot, cfg->cmds, cfg->stop_flag);
    if (cfg->stop_flag != NULL) {
        farsee_atomic_int_store(cfg->stop_flag, 1);
    }
    farsee_frame_slot_kick(cfg->slot);
    farsee_cmd_queue_kick(cfg->cmds);
    return NULL;
}

static void *present_thread_main(void *arg)
{
    farsee_mt_shared *sh = (farsee_mt_shared *)arg;
    const farsee_mt_config *cfg = sh->cfg;
    if (cfg == NULL || cfg->present_fn == NULL) {
        return NULL;
    }
    cfg->present_fn(cfg->present_user, cfg->slot, cfg->stop_flag);
    return NULL;
}

static void *input_thread_main(void *arg)
{
    farsee_mt_shared *sh = (farsee_mt_shared *)arg;
    const farsee_mt_config *cfg = sh->cfg;
    if (cfg == NULL || cfg->input_fn == NULL) {
        return NULL;
    }
    cfg->input_fn(cfg->input_user, cfg->cmds, cfg->stop_flag);
    if (cfg->stop_flag != NULL) {
        farsee_atomic_int_store(cfg->stop_flag, 1);
    }
    farsee_frame_slot_kick(cfg->slot);
    farsee_cmd_queue_kick(cfg->cmds);
    return NULL;
}

farsee_error farsee_mt_run(const farsee_mt_config *cfg)
{
    if (cfg == NULL || cfg->slot == NULL || cfg->cmds == NULL ||
        cfg->stop_flag == NULL || cfg->protocol_fn == NULL ||
        cfg->present_fn == NULL || cfg->input_fn == NULL) {
        return farsee_error_make(FARSEE_ERR_STATE, FARSEE_SUB_CORE,
                                 FARSEE_PHASE_ACTIVE);
    }

    farsee_mt_shared sh;
    memset(&sh, 0, sizeof(sh));
    sh.cfg = cfg;

    farsee_thread *t_proto = farsee_thread_create(protocol_thread_main, &sh);
    farsee_thread *t_pres = farsee_thread_create(present_thread_main, &sh);
    farsee_thread *t_inp = farsee_thread_create(input_thread_main, &sh);
    if (t_proto == NULL || t_pres == NULL || t_inp == NULL) {
        farsee_atomic_int_store(cfg->stop_flag, 1);
        farsee_frame_slot_kick(cfg->slot);
        farsee_cmd_queue_kick(cfg->cmds);
        if (t_proto != NULL) {
            farsee_thread_join(&t_proto, NULL);
        }
        if (t_pres != NULL) {
            farsee_thread_join(&t_pres, NULL);
        }
        if (t_inp != NULL) {
            farsee_thread_join(&t_inp, NULL);
        }
        return farsee_error_make(FARSEE_ERR_STATE, FARSEE_SUB_CORE,
                                 FARSEE_PHASE_ACTIVE);
    }

    // Join protocol first: when the engine is done, stop the others.
    farsee_thread_join(&t_proto, NULL);
    farsee_atomic_int_store(cfg->stop_flag, 1);
    farsee_frame_slot_kick(cfg->slot);
    farsee_cmd_queue_kick(cfg->cmds);
    farsee_thread_join(&t_pres, NULL);
    farsee_thread_join(&t_inp, NULL);

    return farsee_error_make(FARSEE_E_OK, FARSEE_SUB_NONE, FARSEE_PHASE_ACTIVE);
}

void farsee_mt_present_loop(farsee_frame_slot *slot,
                            farsee_atomic_int *stop, uint32_t interval_ms,
                            farsee_mt_on_frame_fn on_frame, void *on_frame_user,
                            farsee_mt_after_present_fn after_present,
                            void *after_present_user,
                            farsee_atomic_int *force_repaint)
{
    if (slot == NULL || on_frame == NULL) {
        return;
    }
    uint32_t interval = interval_ms;
    if (interval == 0) {
        interval = 16u;  // ~60 fps default
    }
    // last_shown: successfully presented. last_attempted: last gen we called
    // on_frame for (success or fail). Waiting on last_attempted prevents the
    // §3.1 retry storm: on_frame fail must not re-wake instantly on the same
    // gen via acquire_wait(gen > last_shown) while last_shown is stale.
    // Present-thread-only: input never writes these; set force_repaint + kick.
    uint64_t last_shown = 0;
    uint64_t last_attempted = 0;
    uint64_t next_ms = farsee_thread_monotonic_ms();

    farsee_cpu_probe probe;
    farsee_cpu_probe_begin(&probe, "present");
    farsee_cpu_probe_attach(&probe);

    while (!farsee_atomic_int_load_nonzero(stop)) {
        const uint64_t now = farsee_thread_monotonic_ms();
        farsee_frame_view v;
        memset(&v, 0, sizeof(v));
        const bool forced =
            farsee_atomic_int_load_nonzero(force_repaint);
        if (now < next_ms && !forced) {
            // Sleep until cadence or a gen newer than last_attempted.
            // Kick (zoom/layout) wakes wait early; then we re-acquire.
            if (farsee_frame_slot_acquire_wait(slot, last_attempted, next_ms,
                                               stop, &v)) {
                // Got a new frame early — fall through and show it.
            } else {
                if (farsee_atomic_int_load_nonzero(stop)) {
                    break;
                }
                if (!farsee_frame_slot_acquire(slot, &v)) {
                    // Idle empty cadence tick: always invoke after_present so
                    // residual drains / cooperative stop can progress. Skipping
                    // this and only advancing next_ms left force_repaint-empty
                    // loops stuck forever after the first forced tick (after_n
                    // never reached stop) — flaky hang under Linux Clang CI.
                    next_ms = farsee_thread_monotonic_ms() + (uint64_t)interval;
                    if (after_present != NULL) {
                        after_present(after_present_user);
                    }
                    farsee_cpu_probe_loop(&probe);
                    continue;
                }
            }
        } else if (!farsee_frame_slot_acquire(slot, &v)) {
            // Empty slot: still clear force_repaint so we do not busy-spin
            // at 100% CPU until the first publish (loop r1 T4 / RDP start).
            (void)farsee_atomic_int_exchange(force_repaint, 0);
            next_ms = farsee_thread_monotonic_ms() + (uint64_t)interval;
            // Drain residual Kitty APC even with no frame (idle residual path).
            if (after_present != NULL) {
                after_present(after_present_user);
            }
            // Bounded wait for a frame or stop instead of tight continue.
            if (farsee_frame_slot_acquire_wait(slot, last_attempted, next_ms,
                                               stop, &v)) {
                // Fall through with a view.
            } else {
                farsee_cpu_probe_loop(&probe);
                continue;
            }
        }

        // Clear force_repaint with exchange so a concurrent store is not lost
        // as a bare non-atomic write race, and we still see the prior request.
        const bool force_now =
            (farsee_atomic_int_exchange(force_repaint, 0) != 0);

        if (v.gen <= last_attempted && !force_now) {
            // Already attempted this generation; cadence re-acquire is idle.
            farsee_cpu_probe_present_skip(&probe);
            // Still drain residual Kitty APC on idle ticks (T6).
            if (after_present != NULL) {
                after_present(after_present_user);
            }
        } else {
            if (v.gen > last_attempted) {
                last_attempted = v.gen;
            }
            const bool shown = on_frame(on_frame_user, &v);
            if (shown) {
                last_shown = v.gen;
                farsee_cpu_probe_present_ok(&probe);
            } else {
                // Failed present: do not leave last_attempted behind the
                // slot gen (that re-enters acquire_wait immediately).
                farsee_cpu_probe_present_fail(&probe);
            }
            // Always after_present so remainder drains even on failed present.
            if (after_present != NULL) {
                after_present(after_present_user);
            }
        }
        (void)last_shown;
        farsee_frame_slot_release(slot, &v);

        next_ms += (uint64_t)interval;
        {
            const uint64_t tnow = farsee_thread_monotonic_ms();
            if (next_ms < tnow) {
                // Fell behind: realign so we do not catch up by spinning.
                next_ms = tnow + (uint64_t)interval;
            }
        }
        farsee_cpu_probe_loop(&probe);
    }

    farsee_cpu_probe_detach();
}
