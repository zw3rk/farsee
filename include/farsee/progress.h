// SPDX-License-Identifier: Apache-2.0
//
// farsee — parser progress snapshot helper (plan.md §10.6, §G1).
//
// A caller can record input, output, event, and state deltas for one parser
// step. `rfb_progress_is_real` reports whether at least one recorded value
// changed. The current production parser loops do not call this helper;
// unit tests cover its standalone classification behavior.
//
// This type does not by itself enforce parser-loop progress.

#ifndef FARSEE_INCLUDE_FARSEE_PROGRESS_H
#define FARSEE_INCLUDE_FARSEE_PROGRESS_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// A snapshot of deltas supplied by a caller. Standalone unit tests exercise
// the helper; production parsers use their own progress checks.
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
