// SPDX-License-Identifier: Apache-2.0
//
// farsee — parser progress-invariant helper (plan.md §10.6, §G1:
// "parser loop rejects progress-without-progress").
//
// The session parser must never report PROGRESS without actually making
// progress (consuming input, producing output, emitting an event, or
// changing state). Otherwise the poll loop would busy-spin. This helper
// makes the invariant testable: a parser step reports the concrete deltas
// it observed, and `rfb_progress_is_real` returns false if none moved.

#ifndef FARSEE_INCLUDE_FARSEE_PROGRESS_H
#define FARSEE_INCLUDE_FARSEE_PROGRESS_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// A snapshot of what a parser step changed. The parser fills this in;
// the runner / fuzzer checks it.
typedef struct rfb_progress {
    size_t input_consumed;
    size_t output_produced;
    size_t events_emitted;
    bool   state_changed;
} rfb_progress;

static inline rfb_progress rfb_progress_make(void)
{
    rfb_progress p = { .input_consumed = 0, .output_produced = 0,
                       .events_emitted = 0, .state_changed = false };
    return p;
}

// True iff the step actually made progress (plan.md §10.6 invariant).
static inline bool rfb_progress_is_real(const rfb_progress *p)
{
    if (p == NULL) {
        return false;
    }
    return p->input_consumed > 0
        || p->output_produced > 0
        || p->events_emitted > 0
        || p->state_changed;
}

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_PROGRESS_H
