// SPDX-License-Identifier: Apache-2.0

#ifndef FARSEE_RFB_CAPTURE_SCHEDULER_INTERNAL_H
#define FARSEE_RFB_CAPTURE_SCHEDULER_INTERNAL_H

#include "farsee/rfb_capture_scheduler.h"

// Record the first scheduler failure and its terminal observation. This is the
// private seam between state transitions and lifecycle monitoring.
rfb_error rfb_capture_scheduler_record_failure(
    rfb_capture_scheduler *scheduler, rfb_capture_failure failure,
    rfb_error error, uint64_t now_ms);

#endif
