// SPDX-License-Identifier: Apache-2.0
//
// Timeout, activity, and terminal-state lifecycle for the capture scheduler.

#include "farsee/rfb_capture_scheduler.h"

#include "rfb/rfb_capture_scheduler_internal.h"

static rfb_error record_failure(
    rfb_capture_scheduler *scheduler, rfb_capture_failure failure,
    rfb_error error, uint64_t now_ms)
{
    return rfb_capture_scheduler_record_failure(
        scheduler, failure, error, now_ms);
}

rfb_error rfb_capture_scheduler_note_activity(
    rfb_capture_scheduler *scheduler, uint64_t now_ms)
{
    if (scheduler == NULL) {
        return RFB_ERR_INTERNAL;
    }
    if (scheduler->state == RFB_CAPTURE_SCHEDULER_FAILED) {
        return scheduler->error;
    }
    if (scheduler->state != RFB_CAPTURE_SCHEDULER_QUIET_INITIAL &&
        scheduler->state != RFB_CAPTURE_SCHEDULER_QUIET_RESPONSE) {
        return RFB_OK;
    }
    if (now_ms < scheduler->quiet_started_ms) {
        return record_failure(scheduler, RFB_CAPTURE_FAILURE_SEQUENCE,
                              RFB_ERR_PROTOCOL, now_ms);
    }
    if (now_ms - scheduler->quiet_phase_started_ms >=
        (uint64_t)scheduler->response_timeout_ms) {
        return record_failure(scheduler, RFB_CAPTURE_FAILURE_TIMEOUT,
                              RFB_ERR_TIMEOUT, now_ms);
    }
    scheduler->quiet_started_ms = now_ms;
    return RFB_OK;
}

rfb_error rfb_capture_scheduler_note_control_activity(
    rfb_capture_scheduler *scheduler, uint64_t now_ms)
{
    if (scheduler == NULL) {
        return RFB_ERR_INTERNAL;
    }
    if (scheduler->state == RFB_CAPTURE_SCHEDULER_FAILED) {
        return scheduler->error;
    }
    if (scheduler->state != RFB_CAPTURE_SCHEDULER_QUIET_INITIAL &&
        scheduler->state != RFB_CAPTURE_SCHEDULER_QUIET_RESPONSE) {
        return RFB_OK;
    }
    if (now_ms < scheduler->quiet_started_ms) {
        return record_failure(scheduler, RFB_CAPTURE_FAILURE_SEQUENCE,
                              RFB_ERR_PROTOCOL, now_ms);
    }
    // Bound the run, but deliberately leave quiet_started_ms alone: damage-free
    // traffic is not a reason to believe the server is still painting.
    if (now_ms - scheduler->quiet_phase_started_ms >=
        (uint64_t)scheduler->response_timeout_ms) {
        return record_failure(scheduler, RFB_CAPTURE_FAILURE_TIMEOUT,
                              RFB_ERR_TIMEOUT, now_ms);
    }
    return RFB_OK;
}

rfb_error rfb_capture_scheduler_tick(rfb_capture_scheduler *scheduler,
                                     uint64_t now_ms)
{
    if (scheduler == NULL) {
        return RFB_ERR_INTERNAL;
    }
    if (scheduler->state == RFB_CAPTURE_SCHEDULER_FAILED) {
        return scheduler->error;
    }
    const bool quiet =
        scheduler->state == RFB_CAPTURE_SCHEDULER_QUIET_INITIAL ||
        scheduler->state == RFB_CAPTURE_SCHEDULER_QUIET_RESPONSE;
    if (quiet) {
        if (now_ms < scheduler->quiet_phase_started_ms) {
            return record_failure(scheduler, RFB_CAPTURE_FAILURE_SEQUENCE,
                                  RFB_ERR_PROTOCOL, now_ms);
        }
        if (now_ms - scheduler->quiet_phase_started_ms >=
            (uint64_t)scheduler->response_timeout_ms) {
            return record_failure(scheduler, RFB_CAPTURE_FAILURE_TIMEOUT,
                                  RFB_ERR_TIMEOUT, now_ms);
        }
        return RFB_OK;
    }
    if (scheduler->state == RFB_CAPTURE_SCHEDULER_MUTATION_HOLD) {
        if (now_ms < scheduler->mutation_started_ms) {
            return record_failure(scheduler, RFB_CAPTURE_FAILURE_SEQUENCE,
                                  RFB_ERR_PROTOCOL, now_ms);
        }
        if (now_ms - scheduler->mutation_started_ms >=
            (uint64_t)scheduler->mutation_timeout_ms) {
            return record_failure(scheduler, RFB_CAPTURE_FAILURE_TIMEOUT,
                                  RFB_ERR_TIMEOUT, now_ms);
        }
        return RFB_OK;
    }
    if (scheduler->state == RFB_CAPTURE_SCHEDULER_REQUEST_QUEUED ||
        scheduler->state == RFB_CAPTURE_SCHEDULER_REQUEST_DRAINING) {
        if (now_ms < scheduler->request_queued_ms) {
            return record_failure(scheduler, RFB_CAPTURE_FAILURE_SEQUENCE,
                                  RFB_ERR_PROTOCOL, now_ms);
        }
        if (now_ms - scheduler->request_queued_ms >=
            (uint64_t)scheduler->response_timeout_ms) {
            return record_failure(
                scheduler, RFB_CAPTURE_FAILURE_REQUEST_DRAIN,
                RFB_ERR_TIMEOUT, now_ms);
        }
        return RFB_OK;
    }
    if (scheduler->state != RFB_CAPTURE_SCHEDULER_WAIT_INITIAL &&
        scheduler->state != RFB_CAPTURE_SCHEDULER_RECEIVING_INITIAL &&
        scheduler->state != RFB_CAPTURE_SCHEDULER_OUTSTANDING &&
        scheduler->state != RFB_CAPTURE_SCHEDULER_RECEIVING) {
        return RFB_OK;
    }
    if (now_ms < scheduler->request_started_ms) {
        return record_failure(scheduler, RFB_CAPTURE_FAILURE_SEQUENCE,
                              RFB_ERR_PROTOCOL, now_ms);
    }
    if (now_ms - scheduler->request_started_ms >=
        (uint64_t)scheduler->response_timeout_ms) {
        return record_failure(scheduler, RFB_CAPTURE_FAILURE_TIMEOUT,
                              RFB_ERR_TIMEOUT, now_ms);
    }
    return RFB_OK;
}

rfb_error rfb_capture_scheduler_note_eof(rfb_capture_scheduler *scheduler)
{
    if (scheduler == NULL) {
        return RFB_ERR_INTERNAL;
    }
    if (scheduler->state == RFB_CAPTURE_SCHEDULER_FAILED) {
        return scheduler->error;
    }
    if (scheduler->state == RFB_CAPTURE_SCHEDULER_DONE) {
        return RFB_OK;
    }
    return record_failure(
        scheduler, RFB_CAPTURE_FAILURE_EOF, RFB_ERR_EOF, 0u);
}

rfb_error rfb_capture_scheduler_fail(rfb_capture_scheduler *scheduler,
                                     rfb_capture_failure failure,
                                     rfb_error error)
{
    if (failure == RFB_CAPTURE_FAILURE_NONE || error == RFB_OK) {
        return RFB_ERR_INTERNAL;
    }
    return record_failure(scheduler, failure, error, 0u);
}

bool rfb_capture_scheduler_active(const rfb_capture_scheduler *scheduler)
{
    return scheduler != NULL &&
           scheduler->state != RFB_CAPTURE_SCHEDULER_CLEAR;
}

bool rfb_capture_scheduler_done(const rfb_capture_scheduler *scheduler)
{
    return scheduler != NULL &&
           scheduler->state == RFB_CAPTURE_SCHEDULER_DONE;
}
