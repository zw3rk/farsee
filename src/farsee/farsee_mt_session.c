// SPDX-License-Identifier: Apache-2.0
//
// Multi-thread live session skeleton (see farsee_mt_session.h).

#include "farsee/farsee_mt_session.h"
#include "farsee/farsee_thread.h"

#include <string.h>

typedef struct farsee_mt_shared {
    const farsee_mt_config *cfg;
    farsee_mt_terminal terminal;
    farsee_atomic_int start;
} farsee_mt_shared;

enum farsee_mt_start_state {
    FARSEE_MT_START_ABORT = -1,
    FARSEE_MT_START_WAIT = 0,
    FARSEE_MT_START_RUN = 1,
};

void farsee_mt_terminal_init(farsee_mt_terminal *terminal)
{
    if (terminal != NULL) {
        farsee_atomic_int_store(&terminal->kind, FARSEE_MT_TERMINAL_NONE);
    }
}

bool farsee_mt_terminal_report(farsee_mt_terminal *terminal,
                               farsee_mt_terminal_kind kind)
{
    if (terminal == NULL || kind <= FARSEE_MT_TERMINAL_NONE ||
        kind > FARSEE_MT_TERMINAL_INTERNAL_FAILURE) {
        return false;
    }
    int expected = FARSEE_MT_TERMINAL_NONE;
    return farsee_atomic_int_compare_exchange(&terminal->kind, &expected,
                                              (int)kind);
}

farsee_mt_terminal_kind farsee_mt_terminal_load(
    const farsee_mt_terminal *terminal)
{
    return terminal == NULL ? FARSEE_MT_TERMINAL_NONE
                            : (farsee_mt_terminal_kind)farsee_atomic_int_load(
                                  &terminal->kind);
}

farsee_error farsee_mt_terminal_error(farsee_mt_terminal_kind kind)
{
    switch (kind) {
    case FARSEE_MT_TERMINAL_REQUESTED_STOP:
    case FARSEE_MT_TERMINAL_PEER_CLOSED:
        return farsee_error_make(FARSEE_E_OK, FARSEE_SUB_NONE,
                                 FARSEE_PHASE_CLOSED);
    case FARSEE_MT_TERMINAL_PROTOCOL_FAILURE:
        return farsee_error_make(FARSEE_ERR_PROTOCOL_VIOLATION,
                                 FARSEE_SUB_CORE, FARSEE_PHASE_ACTIVE);
    case FARSEE_MT_TERMINAL_PRESENTER_FAILURE:
        return farsee_error_make(FARSEE_ERR_PRESENTER_FAILURE,
                                 FARSEE_SUB_PRESENTER, FARSEE_PHASE_ACTIVE);
    case FARSEE_MT_TERMINAL_INPUT_FAILURE:
        return farsee_error_make(FARSEE_ERR_LOCAL_IO_FAILURE,
                                 FARSEE_SUB_INPUT, FARSEE_PHASE_ACTIVE);
    case FARSEE_MT_TERMINAL_THREAD_CREATION_FAILURE:
        return farsee_error_make(FARSEE_ERR_INTERNAL, FARSEE_SUB_CORE,
                                 FARSEE_PHASE_ACTIVE);
    case FARSEE_MT_TERMINAL_ALLOCATION_FAILURE:
        return farsee_error_make(FARSEE_ERR_OUT_OF_MEMORY, FARSEE_SUB_CORE,
                                 FARSEE_PHASE_ACTIVE);
    case FARSEE_MT_TERMINAL_NONE:
    case FARSEE_MT_TERMINAL_INTERNAL_FAILURE:
        return farsee_error_make(FARSEE_ERR_INTERNAL, FARSEE_SUB_CORE,
                                 FARSEE_PHASE_ACTIVE);
    }
    return farsee_error_make(FARSEE_ERR_INTERNAL, FARSEE_SUB_CORE,
                             FARSEE_PHASE_ACTIVE);
}

static void stop_and_kick(const farsee_mt_config *cfg)
{
    farsee_atomic_int_store(cfg->stop_flag, 1);
    farsee_frame_slot_kick(cfg->slot);
    farsee_cmd_queue_kick(cfg->cmds);
}

static bool wait_for_start(const farsee_mt_shared *sh)
{
    int state = 0;
    while ((state = farsee_atomic_int_load(&sh->start)) ==
           FARSEE_MT_START_WAIT) {
        // Startup gate: callbacks cannot terminate before all threads exist.
    }
    return state > 0;
}

static void *protocol_thread_main(void *arg)
{
    farsee_mt_shared *sh = (farsee_mt_shared *)arg;
    const farsee_mt_config *cfg = sh->cfg;
    if (cfg == NULL || cfg->protocol_fn == NULL) {
        return NULL;
    }
    if (!wait_for_start(sh)) {
        return NULL;
    }
    farsee_mt_terminal_kind kind = cfg->protocol_fn(
        cfg->protocol_user, cfg->slot, cfg->cmds, cfg->stop_flag,
        &sh->terminal);
    (void)farsee_mt_terminal_report(&sh->terminal, kind);
    stop_and_kick(cfg);
    return NULL;
}

static void *present_thread_main(void *arg)
{
    farsee_mt_shared *sh = (farsee_mt_shared *)arg;
    const farsee_mt_config *cfg = sh->cfg;
    if (cfg == NULL || cfg->present_fn == NULL) {
        return NULL;
    }
    if (!wait_for_start(sh)) {
        return NULL;
    }
    farsee_mt_terminal_kind kind = cfg->present_fn(
        cfg->present_user, cfg->slot, cfg->stop_flag, &sh->terminal);
    (void)farsee_mt_terminal_report(&sh->terminal, kind);
    stop_and_kick(cfg);
    return NULL;
}

static void *input_thread_main(void *arg)
{
    farsee_mt_shared *sh = (farsee_mt_shared *)arg;
    const farsee_mt_config *cfg = sh->cfg;
    if (cfg == NULL || cfg->input_fn == NULL) {
        return NULL;
    }
    if (!wait_for_start(sh)) {
        return NULL;
    }
    farsee_mt_terminal_kind kind = cfg->input_fn(
        cfg->input_user, cfg->cmds, cfg->stop_flag, &sh->terminal);
    (void)farsee_mt_terminal_report(&sh->terminal, kind);
    stop_and_kick(cfg);
    return NULL;
}

static farsee_error finish_outcome(farsee_mt_terminal_kind kind,
                                   farsee_mt_outcome *outcome)
{
    farsee_error error = farsee_mt_terminal_error(kind);
    if (outcome != NULL) {
        outcome->kind = kind;
        outcome->error = error;
    }
    return error;
}

farsee_error farsee_mt_run(const farsee_mt_config *cfg,
                           farsee_mt_outcome *outcome)
{
    if (outcome != NULL) {
        memset(outcome, 0, sizeof *outcome);
    }
    if (cfg == NULL || cfg->slot == NULL || cfg->cmds == NULL ||
        cfg->stop_flag == NULL || cfg->protocol_fn == NULL ||
        cfg->present_fn == NULL || cfg->input_fn == NULL) {
        farsee_error error = farsee_error_make(
            FARSEE_ERR_STATE, FARSEE_SUB_CORE, FARSEE_PHASE_ACTIVE);
        if (outcome != NULL) {
            outcome->kind = FARSEE_MT_TERMINAL_INTERNAL_FAILURE;
            outcome->error = error;
        }
        return error;
    }

    farsee_mt_shared sh;
    memset(&sh, 0, sizeof(sh));
    sh.cfg = cfg;
    farsee_mt_terminal_init(&sh.terminal);
    farsee_atomic_int_store(&sh.start, FARSEE_MT_START_WAIT);

    farsee_mt_thread_create_fn create = cfg->thread_create != NULL
                                     ? cfg->thread_create
                                     : farsee_thread_create;
    farsee_thread *t_proto = create(protocol_thread_main, &sh);
    farsee_thread *t_pres = NULL;
    farsee_thread *t_inp = NULL;
    if (t_proto != NULL) {
        t_pres = create(present_thread_main, &sh);
    }
    if (t_pres != NULL) {
        t_inp = create(input_thread_main, &sh);
    }
    if (t_proto == NULL || t_pres == NULL || t_inp == NULL) {
        (void)farsee_mt_terminal_report(
            &sh.terminal, FARSEE_MT_TERMINAL_THREAD_CREATION_FAILURE);
        stop_and_kick(cfg);
        // Release any successfully created workers without invoking callbacks.
        farsee_atomic_int_store(&sh.start, FARSEE_MT_START_ABORT);
        if (t_proto != NULL) {
            farsee_thread_join(&t_proto, NULL);
        }
        if (t_pres != NULL) {
            farsee_thread_join(&t_pres, NULL);
        }
        if (t_inp != NULL) {
            farsee_thread_join(&t_inp, NULL);
        }
        return finish_outcome(farsee_mt_terminal_load(&sh.terminal), outcome);
    }

    farsee_atomic_int_store(&sh.start, FARSEE_MT_START_RUN);
    // Join protocol first: when the engine is done, stop the others.
    farsee_thread_join(&t_proto, NULL);
    stop_and_kick(cfg);
    farsee_thread_join(&t_pres, NULL);
    farsee_thread_join(&t_inp, NULL);

    farsee_mt_terminal_kind kind = farsee_mt_terminal_load(&sh.terminal);
    if (kind == FARSEE_MT_TERMINAL_NONE) {
        kind = FARSEE_MT_TERMINAL_INTERNAL_FAILURE;
    }
    return finish_outcome(kind, outcome);
}

farsee_mt_terminal_kind farsee_mt_present_loop(
    farsee_frame_slot *slot, farsee_atomic_int *stop, uint32_t interval_ms,
    farsee_mt_on_frame_fn on_frame, void *on_frame_user,
    farsee_mt_after_present_fn after_present, void *after_present_user,
    farsee_atomic_int *force_repaint, farsee_mt_terminal *terminal)
{
    if (slot == NULL || stop == NULL || on_frame == NULL) {
        return FARSEE_MT_TERMINAL_INTERNAL_FAILURE;
    }
    uint32_t interval = interval_ms;
    if (interval == 0) {
        interval = 16u;  // ~60 fps default
    }
    // last_shown records a successful present; last_attempted records every
    // generation passed to on_frame. Waiting on last_attempted prevents a
    // failed callback from immediately reacquiring the same generation.
    // Both values are owned by this present thread.
    uint64_t last_shown = 0;
    uint64_t last_attempted = 0;
    uint64_t next_ms = farsee_thread_monotonic_ms();

    bool presenter_failed = false;

    while (!farsee_atomic_int_load_nonzero(stop)) {
        const uint64_t now = farsee_thread_monotonic_ms();
        farsee_frame_view v;
        memset(&v, 0, sizeof(v));
        const bool forced =
            farsee_atomic_int_load_nonzero(force_repaint);
        if (now < next_ms && !forced) {
            // Sleep until cadence or a generation newer than last_attempted.
            // A kick can wake the wait early; then the loop reacquires.
            if (farsee_frame_slot_acquire_wait(slot, last_attempted, next_ms,
                                               stop, &v)) {
                // Got a new frame early; continue to the callback path.
            } else {
                if (farsee_atomic_int_load_nonzero(stop)) {
                    break;
                }
                if (!farsee_frame_slot_acquire(slot, &v)) {
                    // An empty cadence tick invokes the optional callback before
                    // continuing.
                    next_ms = farsee_thread_monotonic_ms() + (uint64_t)interval;
                    if (after_present != NULL) {
                        after_present(after_present_user);
                    }
                    continue;
                }
            }
        } else if (!farsee_frame_slot_acquire(slot, &v)) {
            // Clear one force-repaint request even when the slot is empty before
            // scheduling the next cadence wait.
            (void)farsee_atomic_int_exchange(force_repaint, 0);
            next_ms = farsee_thread_monotonic_ms() + (uint64_t)interval;
            // Run the optional post-cadence callback even with no frame.
            if (after_present != NULL) {
                after_present(after_present_user);
            }
            // Bounded wait for a frame or stop instead of tight continue.
            if (farsee_frame_slot_acquire_wait(slot, last_attempted, next_ms,
                                               stop, &v)) {
                // Fall through with a view.
            } else {
                continue;
            }
        }

        // Clear force_repaint with exchange so a concurrent store is not lost
        // as a bare non-atomic write race, and we still see the prior request.
        const bool force_now =
            (farsee_atomic_int_exchange(force_repaint, 0) != 0);

        if (v.gen <= last_attempted && !force_now) {
            // Already attempted this generation; cadence re-acquire is idle.
            // Run the optional post-cadence callback on this idle tick.
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
            } else {
                // Failed present: do not leave last_attempted behind the
                // slot gen (that re-enters acquire_wait immediately).
                (void)farsee_mt_terminal_report(
                    terminal, FARSEE_MT_TERMINAL_PRESENTER_FAILURE);
                presenter_failed = true;
                farsee_atomic_int_store(stop, 1);
            }
            // Run the optional callback after either present result.
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
        if (presenter_failed) {
            break;
        }
    }

    return presenter_failed ? FARSEE_MT_TERMINAL_PRESENTER_FAILURE
                            : FARSEE_MT_TERMINAL_REQUESTED_STOP;
}
