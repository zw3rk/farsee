// SPDX-License-Identifier: Apache-2.0
//
// RFB session capture scheduling, mutation control, and admission ownership.

#include "rfb/rfb_session_internal.h"

#include "farsee/buffer.h"
#include "farsee/rfb_io_pump.h"

#if defined(FARSEE_ENABLE_CAPTURE_DIAGNOSTICS) || \
    defined(FARSEE_TEST_CAPTURE_DIAGNOSTICS)
#include "farsee/rfb_capture_control.h"

#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#endif

static uint64_t session_transport_tx_bytes(const rfb_session *session)
{
    if (session == NULL || session->transport_tx_bytes == NULL) {
        return 0u;
    }
    return farsee_atomic_u64_load(session->transport_tx_bytes);
}

// --- protocol loop ---------------------------------------------------------

#if defined(FARSEE_ENABLE_CAPTURE_DIAGNOSTICS) || \
    defined(FARSEE_TEST_CAPTURE_DIAGNOSTICS)
static rfb_error capture_control_fail(rfb_session *s, rfb_error error)
{
    const rfb_error result = rfb_capture_scheduler_fail(
        &s->capture, RFB_CAPTURE_FAILURE_CONTROL, error);
    s->last_error = result;
    return result;
}

static rfb_error capture_control_step(rfb_session *s)
{
    if (!s->capture_enabled || !s->cfg.capture_require_mutation_ack) {
        return RFB_OK;
    }
    bool accepted = false;
    if (s->capture.state != RFB_CAPTURE_SCHEDULER_MUTATION_HOLD) {
        const rfb_error error = rfb_capture_control_drain_ack(
            s->cfg.capture_control_fd, false, s->cfg.capture_slot_nonce,
            s->cfg.capture_transition_id,
            s->cfg.capture_source_b_binding, &accepted);
        return error == RFB_OK ? RFB_OK : capture_control_fail(s, error);
    }
    if (!s->capture_control_ready_sent) {
        // An ACK already queued before READY is observably early and invalid.
        rfb_error error = rfb_capture_control_drain_ack(
            s->cfg.capture_control_fd, false, s->cfg.capture_slot_nonce,
            s->cfg.capture_transition_id,
            s->cfg.capture_source_b_binding, &accepted);
        if (error != RFB_OK) {
            return capture_control_fail(s, error);
        }
        rfb_capture_control_message ready;
        memset(&ready, 0, sizeof ready);
        ready.kind = RFB_CAPTURE_CONTROL_READY_FOR_MUTATION;
        ready.slot_nonce = s->cfg.capture_slot_nonce;
        ready.transition_id = s->cfg.capture_transition_id;
        uint8_t wire[RFB_CAPTURE_CONTROL_WIRE_SIZE];
        size_t wire_length = 0u;
        error = rfb_capture_control_encode(&ready, wire, sizeof wire,
                                           &wire_length);
        if (error != RFB_OK) {
            return capture_control_fail(s, error);
        }
        const ssize_t sent = send(s->cfg.capture_control_fd, wire, wire_length,
                                  MSG_DONTWAIT);
        if (sent != (ssize_t)wire_length) {
            return capture_control_fail(
                s, sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK
                       ? RFB_ERR_IO
                       : RFB_ERR_PROTOCOL);
        }
        s->capture_control_ready_sent = true;
    }
    rfb_error error = rfb_capture_control_drain_ack(
        s->cfg.capture_control_fd, true, s->cfg.capture_slot_nonce,
        s->cfg.capture_transition_id, s->cfg.capture_source_b_binding,
        &accepted);
    if (error != RFB_OK) {
        return capture_control_fail(s, error);
    }
    if (!accepted) {
        return RFB_OK;
    }
    error = rfb_capture_scheduler_mutation_acknowledged(
        &s->capture, rfb_session_internal_capture_now(s));
    if (error != RFB_OK) {
        s->last_error = error;
    }
    return error;
}
#else
static rfb_error capture_control_step(rfb_session *s)
{
    return s->cfg.capture_require_mutation_ack ? RFB_ERR_UNSUPPORTED : RFB_OK;
}
#endif

static rfb_error capture_mark_request_drained(rfb_session *s)
{
    if (!s->capture_enabled ||
        s->capture.state != RFB_CAPTURE_SCHEDULER_REQUEST_DRAINING ||
        rfb_buffer_length(&s->out) != 0u) {
        return RFB_OK;
    }
    const rfb_error error = rfb_capture_scheduler_request_drained(
        &s->capture, rfb_session_internal_capture_now(s),
        session_transport_tx_bytes(s), true);
    if (error != RFB_OK) {
        s->last_error = error;
    }
    return error;
}

static uint64_t capture_mono_clock(void *opaque)
{
    (void)opaque;
    return rfb_io_mono_ms();
}

static rfb_error capture_refresh_now(
    rfb_session *s, rfb_session_capture_clock_fn clock_now_ms,
    void *clock_opaque, uint64_t *out_now_ms)
{
    if (s == NULL || clock_now_ms == NULL || out_now_ms == NULL) {
        return RFB_ERR_INTERNAL;
    }
    const uint64_t now_ms = clock_now_ms(clock_opaque);
    if (now_ms == 0u) {
        s->last_error = RFB_ERR_INTERNAL;
        return RFB_ERR_INTERNAL;
    }
    s->capture_now_ms = now_ms;
    *out_now_ms = now_ms;
    return RFB_OK;
}

static rfb_error capture_read_failure(rfb_session *s, rfb_error error)
{
    if (error == RFB_ERR_EOF || error == RFB_ERR_IO) {
        (void)rfb_capture_scheduler_note_eof(&s->capture);
        if (s->capture.error != RFB_OK) {
            error = s->capture.error;
        }
    }
    s->last_error = error;
    return error;
}

static bool capture_inbound_pending(const rfb_session *s)
{
    return s != NULL &&
           (rfb_buffer_length(&s->in) != 0u ||
            rfb_buffer_length(&s->apple_plain) != 0u ||
            s->eng.in_fbupdate);
}

// Route inbound progress by content. Framebuffer damage restarts the quiet
// interval; damage-free typed control activity leaves its start unchanged.
static rfb_error session_capture_note_progress(rfb_session *s, uint64_t now_ms)
{
    const bool damage = s->capture_frame_progress;
    s->capture_frame_progress = false;
    return damage ? rfb_capture_scheduler_note_activity(&s->capture, now_ms)
                  : rfb_capture_scheduler_note_control_activity(&s->capture,
                                                                now_ms);
}

static rfb_error session_capture_step_core(
    rfb_session *s, rfb_session_capture_clock_fn clock_now_ms,
    void *clock_opaque, int poll_ms);

// A trailing update is tolerated only pending inspection of its rectangle.
// If a step ends with that inspection unresolved, the update never proved
// itself a benign announcement, so it reverts to the unsolicited
// classification the scheduler deferred rather than leaving the run dangling
// in a tolerant state.
rfb_error rfb_session_capture_step_with_clock(
    rfb_session *s, rfb_session_capture_clock_fn clock_now_ms,
    void *clock_opaque, int poll_ms)
{
    const rfb_error e =
        session_capture_step_core(s, clock_now_ms, clock_opaque, poll_ms);
    if (s != NULL && s->capture_enabled &&
        s->capture.state == RFB_CAPTURE_SCHEDULER_RECEIVING_ANNOUNCEMENT) {
        const rfb_error cause = e != RFB_OK ? e : RFB_ERR_PROTOCOL;
        (void)rfb_capture_scheduler_fail(
            &s->capture, RFB_CAPTURE_FAILURE_UNSOLICITED_FBU, cause);
        return cause;
    }
    return e;
}

static rfb_error session_capture_step_core(
    rfb_session *s, rfb_session_capture_clock_fn clock_now_ms,
    void *clock_opaque, int poll_ms)
{
    if (s == NULL || !s->active || !s->capture_enabled ||
        clock_now_ms == NULL || poll_ms < 0) {
        return RFB_ERR_INTERNAL;
    }

    s->capture_clock_now_ms = clock_now_ms;
    s->capture_clock_opaque = clock_opaque;

    uint64_t now_ms = 0u;
    rfb_error e = capture_refresh_now(s, clock_now_ms, clock_opaque,
                                      &now_ms);
    if (e != RFB_OK) {
        return e;
    }

    e = capture_control_step(s);
    if (e != RFB_OK) {
        return e;
    }

    e = capture_refresh_now(s, clock_now_ms, clock_opaque, &now_ms);
    if (e != RFB_OK) {
        return e;
    }
    bool progress = false;
    e = rfb_session_internal_process_in(s, &progress);
    if (e != RFB_OK) {
        s->last_error = e;
        return e;
    }
    if (progress) {
        e = capture_refresh_now(s, clock_now_ms, clock_opaque, &now_ms);
        if (e != RFB_OK) {
            return e;
        }
        e = session_capture_note_progress(s, now_ms);
        if (e != RFB_OK) {
            s->last_error = e;
            return e;
        }
    }
    if (rfb_capture_scheduler_done(&s->capture)) {
        return RFB_OK;
    }

    rfb_capture_query query;
    if (rfb_capture_scheduler_next_request(&s->capture, &query)) {
        e = capture_refresh_now(s, clock_now_ms, clock_opaque, &now_ms);
        if (e != RFB_OK) {
            return e;
        }
        const uint64_t tx_before = session_transport_tx_bytes(s);
        e = rfb_capture_scheduler_request_queue_started(
            &s->capture, now_ms, tx_before,
            rfb_buffer_length(&s->out) == 0u);
        if (e == RFB_OK) {
            e = session_send_fbur_rect(s, query.incremental, query.x,
                                       query.y, query.width, query.height);
        }
        if (e == RFB_OK) {
            e = capture_refresh_now(s, clock_now_ms, clock_opaque,
                                    &now_ms);
        }
        if (e == RFB_OK) {
            const uint64_t tx_after = session_transport_tx_bytes(s);
            const size_t outbound = rfb_buffer_length(&s->out);
            if (tx_after < tx_before ||
                UINT64_MAX - (tx_after - tx_before) < outbound) {
                e = rfb_capture_scheduler_fail(
                    &s->capture, RFB_CAPTURE_FAILURE_REQUEST_DRAIN,
                    RFB_ERR_LIMIT);
            } else {
                e = rfb_capture_scheduler_request_queued(
                    &s->capture, now_ms, 10u,
                    (tx_after - tx_before) + (uint64_t)outbound);
            }
        }
        // session_send_fbur_rect queues through rfb_io_queue_bytes, which
        // drains what it appends. When that admitted the whole request, the
        // request is outstanding *now* — the peer already has it and may
        // already have answered. Close the state here, before anything reads,
        // or the response to this very request is read while the scheduler
        // still believes nothing is outstanding and is rejected as an
        // unsolicited update. A short write leaves the request incomplete, so
        // it stays draining: no peer can answer a request it has not received.
        if (e == RFB_OK) {
            e = capture_mark_request_drained(s);
        }
        if (e != RFB_OK) {
            if (s->capture.state != RFB_CAPTURE_SCHEDULER_FAILED) {
                e = rfb_capture_scheduler_fail(
                    &s->capture, RFB_CAPTURE_FAILURE_REQUEST_DRAIN, e);
            }
            s->last_error = e;
            return e;
        }
    }

    rfb_io_pump pump = rfb_session_internal_pump(s);

    // At the final-write boundary, already-readable inbound data is earlier
    // than transport admission. Read it without allowing the pump to perform
    // any hidden outbound drain, then classify it while still pre-drain.
    const int pre_drain_poll_ms =
        capture_inbound_pending(s) ? poll_ms : 0;
    size_t wire_input_before = rfb_buffer_length(&s->in);
    e = rfb_io_read_some_no_drain(&pump, pre_drain_poll_ms);
    if (e != RFB_OK && e != RFB_ERR_TIMEOUT) {
        return capture_read_failure(s, e);
    }
    bool read_activity = rfb_buffer_length(&s->in) > wire_input_before;
    if (read_activity) {
        e = capture_refresh_now(s, clock_now_ms, clock_opaque, &now_ms);
        if (e != RFB_OK) {
            return e;
        }
        e = rfb_capture_scheduler_tick(&s->capture, now_ms);
        if (e != RFB_OK) {
            s->last_error = e;
            return e;
        }
        bool pre_drain_progress = false;
        e = rfb_session_internal_process_in(s, &pre_drain_progress);
        if (e != RFB_OK) {
            s->last_error = e;
            return e;
        }
        if (pre_drain_progress) {
            progress = true;
            e = capture_refresh_now(s, clock_now_ms, clock_opaque,
                                    &now_ms);
            if (e != RFB_OK) {
                return e;
            }
            e = session_capture_note_progress(s, now_ms);
            if (e != RFB_OK) {
                s->last_error = e;
                return e;
            }
        }
        if (rfb_capture_scheduler_done(&s->capture)) {
            return RFB_OK;
        }
    }

    // Any successful pre-drain read requires a following no-input preflight
    // before transport admission. This closes the complete-record boundary:
    // an allowed record may consume all parser state while a following FBU is
    // still readable. Partial records and FBUs likewise retain precedence
    // until classified. The next iteration waits POLLIN without draining,
    // bounded by the scheduler's request-drain deadline.
    if (s->capture.state == RFB_CAPTURE_SCHEDULER_REQUEST_DRAINING &&
        (read_activity || capture_inbound_pending(s))) {
        e = capture_refresh_now(s, clock_now_ms, clock_opaque, &now_ms);
        if (e == RFB_OK) {
            e = rfb_capture_scheduler_tick(&s->capture, now_ms);
        }
        if (e != RFB_OK) {
            s->last_error = e;
        }
        return e;
    }

    e = rfb_io_drain_out(&pump, 0);
    if (e != RFB_OK) {
        if (s->capture.state == RFB_CAPTURE_SCHEDULER_REQUEST_QUEUED ||
            s->capture.state == RFB_CAPTURE_SCHEDULER_REQUEST_DRAINING) {
            e = rfb_capture_scheduler_fail(
                &s->capture, RFB_CAPTURE_FAILURE_REQUEST_DRAIN, e);
        }
        s->last_error = e;
        return e;
    }

    e = capture_refresh_now(s, clock_now_ms, clock_opaque, &now_ms);
    if (e != RFB_OK) {
        return e;
    }
    // Enforce the queue-to-drain deadline using the time after the write,
    // before a late final byte can start a fresh response deadline.
    e = rfb_capture_scheduler_tick(&s->capture, now_ms);
    if (e != RFB_OK) {
        s->last_error = e;
        return e;
    }
    e = capture_mark_request_drained(s);
    if (e != RFB_OK) {
        return e;
    }

    wire_input_before = rfb_buffer_length(&s->in);
    e = rfb_io_read_some_no_drain(&pump, poll_ms);
    const rfb_error read_result = e;
    if (e != RFB_OK && e != RFB_ERR_TIMEOUT) {
        return capture_read_failure(s, e);
    }
    read_activity = rfb_buffer_length(&s->in) > wire_input_before;

    e = capture_refresh_now(s, clock_now_ms, clock_opaque, &now_ms);
    if (e != RFB_OK) {
        return e;
    }
    // A deadline crossed while poll/read was in progress is terminal before
    // the newly arrived ACK or FBU can be admitted.
    e = rfb_capture_scheduler_tick(&s->capture, now_ms);
    if (e != RFB_OK) {
        s->last_error = e;
        return e;
    }

    e = capture_control_step(s);
    if (e != RFB_OK) {
        return e;
    }

    if (read_activity) {
        bool post_read_progress = false;
        e = rfb_session_internal_process_in(s, &post_read_progress);
        if (e != RFB_OK) {
            s->last_error = e;
            return e;
        }
        if (post_read_progress) {
            progress = true;
        }
    }

    if (e == RFB_OK && (read_activity || progress)) {
        e = capture_refresh_now(s, clock_now_ms, clock_opaque, &now_ms);
    }
    if (e == RFB_OK && (read_activity || progress)) {
        e = session_capture_note_progress(s, now_ms);
    }

    const bool quiet_poll =
        (read_result == RFB_OK || read_result == RFB_ERR_TIMEOUT) &&
        !read_activity;
    if (e == RFB_OK && quiet_poll && !s->eng.in_fbupdate &&
        rfb_buffer_length(&s->in) == 0u &&
        rfb_buffer_length(&s->apple_plain) == 0u &&
        (s->capture.state == RFB_CAPTURE_SCHEDULER_QUIET_INITIAL ||
         s->capture.state == RFB_CAPTURE_SCHEDULER_QUIET_RESPONSE)) {
        e = rfb_capture_scheduler_note_quiet(&s->capture, now_ms);
    }
    if (e != RFB_OK) {
        s->last_error = e;
    }
    return e;
}


rfb_error rfb_session_internal_capture_step(rfb_session *session, int poll_ms)
{
    return rfb_session_capture_step_with_clock(
        session, capture_mono_clock, NULL, poll_ms);
}
