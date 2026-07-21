// SPDX-License-Identifier: Apache-2.0
//
// G1 — parser progress-invariant helper tests (plan.md §G1, §10.6:
// "parser loop rejects progress-without-progress"). RED step.

#include "rfb_test.h"
#include "farsee/progress.h"

RFB_TEST(progress, progress__empty__is_not_real) {
    rfb_progress p = rfb_progress_make();
    RFB_CHECK(!rfb_progress_is_real(&p));
}

RFB_TEST(progress, progress__consumed_input__is_real) {
    rfb_progress p = rfb_progress_make();
    p.input_consumed = 1;
    RFB_CHECK(rfb_progress_is_real(&p));
}

RFB_TEST(progress, progress__produced_output__is_real) {
    rfb_progress p = rfb_progress_make();
    p.output_produced = 1;
    RFB_CHECK(rfb_progress_is_real(&p));
}

RFB_TEST(progress, progress__emitted_event__is_real) {
    rfb_progress p = rfb_progress_make();
    p.events_emitted = 1;
    RFB_CHECK(rfb_progress_is_real(&p));
}

RFB_TEST(progress, progress__changed_state__is_real) {
    rfb_progress p = rfb_progress_make();
    p.state_changed = true;
    RFB_CHECK(rfb_progress_is_real(&p));
}

RFB_TEST(progress, progress__null_pointer__is_not_real) {
    RFB_CHECK(!rfb_progress_is_real(NULL));
}
