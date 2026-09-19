// SPDX-License-Identifier: Apache-2.0
//
// farsee — bounded capture-only FramebufferUpdateRequest scheduler.

#ifndef FARSEE_INCLUDE_FARSEE_RFB_CAPTURE_SCHEDULER_H
#define FARSEE_INCLUDE_FARSEE_RFB_CAPTURE_SCHEDULER_H

#include "farsee/error.h"
#include "farsee/fbupdate.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RFB_CAPTURE_QUERY_MAX ((size_t)4096u)
#define RFB_CAPTURE_OBSERVATION_VERSION_1 ((uint16_t)1u)

typedef enum rfb_capture_geometry_policy {
    RFB_CAPTURE_GEOMETRY_EXACT = 0,
    RFB_CAPTURE_GEOMETRY_WITHIN_REQUEST
} rfb_capture_geometry_policy;

typedef struct rfb_capture_query {
    uint32_t id;
    bool incremental;
    rfb_capture_geometry_policy geometry_policy;
    uint16_t x;
    uint16_t y;
    uint16_t width;
    uint16_t height;
} rfb_capture_query;

typedef enum rfb_capture_scheduler_state {
    RFB_CAPTURE_SCHEDULER_CLEAR = 0,
    RFB_CAPTURE_SCHEDULER_WAIT_INITIAL,
    RFB_CAPTURE_SCHEDULER_RECEIVING_INITIAL,
    RFB_CAPTURE_SCHEDULER_QUIET_INITIAL,
    RFB_CAPTURE_SCHEDULER_READY,
    RFB_CAPTURE_SCHEDULER_OUTSTANDING,
    RFB_CAPTURE_SCHEDULER_RECEIVING,
    RFB_CAPTURE_SCHEDULER_QUIET_RESPONSE,
    RFB_CAPTURE_SCHEDULER_DONE,
    RFB_CAPTURE_SCHEDULER_FAILED,
    RFB_CAPTURE_SCHEDULER_MUTATION_HOLD,
    RFB_CAPTURE_SCHEDULER_MUTATION_ACKED,
    RFB_CAPTURE_SCHEDULER_REQUEST_QUEUED,
    RFB_CAPTURE_SCHEDULER_REQUEST_DRAINING,
    // Appended deliberately: renumbering the states above would silently
    // change any value already compared or recorded elsewhere.
    // A completed response can be followed by a desktop-size announcement.
    // It carries no paint, so it is inspected rather than rejected on sight;
    // a paint rectangle here still fails closed.
    RFB_CAPTURE_SCHEDULER_RECEIVING_ANNOUNCEMENT
} rfb_capture_scheduler_state;

typedef enum rfb_capture_failure {
    RFB_CAPTURE_FAILURE_NONE = 0,
    RFB_CAPTURE_FAILURE_UNSOLICITED_FBU,
    RFB_CAPTURE_FAILURE_RECT_COUNT,
    RFB_CAPTURE_FAILURE_RECT_GEOMETRY,
    RFB_CAPTURE_FAILURE_RECT_ENCODING,
    RFB_CAPTURE_FAILURE_MVS_GRAMMAR,
    RFB_CAPTURE_FAILURE_TIMEOUT,
    RFB_CAPTURE_FAILURE_EOF,
    RFB_CAPTURE_FAILURE_SEQUENCE,
    RFB_CAPTURE_FAILURE_CONTROL,
    RFB_CAPTURE_FAILURE_OBSERVATION_LIMIT,
    RFB_CAPTURE_FAILURE_REQUEST_DRAIN
} rfb_capture_failure;

typedef enum rfb_capture_phase {
    RFB_CAPTURE_PHASE_INITIAL = 1,
    RFB_CAPTURE_PHASE_TARGET
} rfb_capture_phase;

typedef enum rfb_capture_geometry_class {
    RFB_CAPTURE_GEOMETRY_CLASS_EXACT = 1,
    RFB_CAPTURE_GEOMETRY_CLASS_CONTAINED,
    RFB_CAPTURE_GEOMETRY_CLASS_OUTSIDE
} rfb_capture_geometry_class;

typedef enum rfb_capture_final_classification {
    RFB_CAPTURE_FINAL_QUARANTINED_INITIAL = 1,
    RFB_CAPTURE_FINAL_ASSOCIATION_CLOSED,
    RFB_CAPTURE_FINAL_REJECTED,
    RFB_CAPTURE_FINAL_CONTROL_CLOSED
} rfb_capture_final_classification;

// Payload-free response classification. Natural wire bytes remain inside the
// session; callbacks receive only bounded structural facts.
typedef struct rfb_capture_result {
    bool initial;
    rfb_capture_query requested;
    uint16_t rectangle_count;
    rfb_rect_header actual;
    bool has_actual;
    bool mvs_type0;
    uint16_t mvs_normal_count;
    uint8_t mvs_large_count;
    uint32_t mvs_payload_len;
    uint32_t mvs_image_offset;
    uint32_t mvs_command_records;
    uint32_t mvs_command_marker_end_bits;
    uint8_t mvs_command_padding_bits;
    uint32_t mvs_image_marker_start_bits;
    uint32_t mvs_image_marker_end_bits;
    uint8_t mvs_image_padding_bits;
    uint8_t mvs_first_command;
    uint32_t mvs_first_run;
    bool direct_one_record_run_one;
} rfb_capture_result;

typedef void (*rfb_capture_result_fn)(void *ctx,
                                      const rfb_capture_result *result);

// Fixed-size, payload-free observations. The caller owns storage for the
// scheduler lifetime and serializes it only after the protocol loop exits.
typedef struct rfb_capture_rect_observation_v1 {
    uint16_t version;
    uint16_t size;
    uint64_t sequence;
    rfb_capture_phase phase;
    bool has_request;
    rfb_capture_query requested;
    uint32_t fbu_ordinal;
    uint16_t declared_rectangle_count;
    uint16_t rectangle_index;
    rfb_rect_header actual;
    rfb_capture_geometry_class geometry;
    bool structure_checked;
    bool structure_valid;
    rfb_capture_failure structure_failure;
    bool mvs_type0;
    uint16_t mvs_normal_count;
    uint8_t mvs_large_count;
    uint32_t mvs_payload_len;
    uint32_t mvs_image_offset;
    uint32_t mvs_command_records;
    uint32_t mvs_command_marker_end_bits;
    uint8_t mvs_command_padding_bits;
    uint32_t mvs_image_marker_start_bits;
    uint32_t mvs_image_marker_end_bits;
    uint8_t mvs_image_padding_bits;
    uint8_t mvs_first_command;
    uint32_t mvs_first_run;
    bool structural_one_record_run_one;
} rfb_capture_rect_observation_v1;

typedef struct rfb_capture_final_observation_v1 {
    uint16_t version;
    uint16_t size;
    uint64_t sequence;
    bool present;
    bool terminal;
    rfb_capture_phase phase;
    bool has_request;
    rfb_capture_query requested;
    uint32_t fbu_ordinal;
    uint16_t declared_rectangle_count;
    uint16_t rectangles_seen;
    bool fbu_complete;
    bool quiet_complete;
    rfb_capture_final_classification classification;
    rfb_capture_failure failure;
    uint32_t rectangle_observation_count;
    uint64_t queue_to_drain_ms;
    uint64_t drain_to_fbu_ms;
    uint64_t quiet_duration_ms;
} rfb_capture_final_observation_v1;

typedef struct rfb_capture_scheduler_config {
    const rfb_capture_query *queries;
    size_t query_count;
    uint16_t framebuffer_width;
    uint16_t framebuffer_height;
    uint32_t response_timeout_ms;
    uint32_t quiet_ms;
    // One bounded nonincremental full-screen response, then DONE after quiet.
    // This mode has no target queries and admits only ZRLE plus the frozen
    // cursor/no-op DesktopSize pseudo-rectangles.
    bool initial_only;
    bool initial_zrle_only;
    bool require_mutation_ack;
    uint32_t mutation_timeout_ms;
    size_t initial_rectangle_max;
    rfb_capture_rect_observation_v1 *rect_observations;
    size_t rect_observation_capacity;
    rfb_capture_final_observation_v1 *final_observations;
    size_t final_observation_capacity;
    rfb_capture_result_fn on_result;
    void *on_result_ctx;
} rfb_capture_scheduler_config;

// Protocol-thread-owned state. The query array is borrowed and immutable for
// the scheduler lifetime.
typedef struct rfb_capture_scheduler {
    const rfb_capture_query *queries;
    size_t query_count;
    size_t query_index;
    uint16_t framebuffer_width;
    uint16_t framebuffer_height;
    uint32_t response_timeout_ms;
    uint32_t quiet_ms;
    uint32_t mutation_timeout_ms;
    uint64_t request_started_ms;
    uint64_t mutation_started_ms;
    uint64_t request_queued_ms;
    uint64_t request_tx_before;
    uint64_t request_wire_length;
    uint64_t target_fbu_started_ms;
    uint64_t quiet_started_ms;
    uint64_t quiet_phase_started_ms;
    rfb_capture_scheduler_state state;
    rfb_capture_failure failure;
    rfb_error error;
    uint16_t rectangles_seen;
    rfb_capture_result current_result;
    rfb_capture_result last_result;
    bool has_last_result;
    bool initial_only;
    bool initial_zrle_only;
    bool require_mutation_ack;
    uint16_t initial_zrle_rectangles;
    bool initial_desktop_size_seen;
    // Quiet phase to resume once an announcement update has been inspected.
    rfb_capture_scheduler_state announcement_resume_state;
    size_t initial_rectangle_max;
    rfb_capture_rect_observation_v1 *rect_observations;
    size_t rect_observation_capacity;
    size_t rect_observation_count;
    rfb_capture_final_observation_v1 *final_observations;
    size_t final_observation_capacity;
    size_t final_observation_count;
    uint64_t observation_sequence;
    uint32_t fbu_ordinal;
    rfb_capture_result_fn on_result;
    void *on_result_ctx;
} rfb_capture_scheduler;

// Validate and initialize atomically. All campaign queries must be non-empty,
// 8x8 aligned, inside the negotiated framebuffer, and use bounded response and
// continuous-quiet intervals.
rfb_error rfb_capture_scheduler_init(
    rfb_capture_scheduler *scheduler, const rfb_capture_query *queries,
    size_t query_count, uint16_t framebuffer_width,
    uint16_t framebuffer_height, uint32_t response_timeout_ms,
    uint32_t quiet_ms,
    rfb_capture_result_fn on_result, void *on_result_ctx);

rfb_error rfb_capture_scheduler_init_config(
    rfb_capture_scheduler *scheduler,
    const rfb_capture_scheduler_config *config);

bool rfb_capture_scheduler_next_request(
    const rfb_capture_scheduler *scheduler, rfb_capture_query *out);
rfb_error rfb_capture_scheduler_initial_request_sent(
    rfb_capture_scheduler *scheduler, uint64_t now_ms);
rfb_error rfb_capture_scheduler_request_sent(
    rfb_capture_scheduler *scheduler, uint64_t now_ms);
rfb_error rfb_capture_scheduler_mutation_acknowledged(
    rfb_capture_scheduler *scheduler, uint64_t now_ms);
rfb_error rfb_capture_scheduler_request_queue_started(
    rfb_capture_scheduler *scheduler, uint64_t now_ms,
    uint64_t transport_tx_before, bool application_outbound_empty);
rfb_error rfb_capture_scheduler_request_queued(
    rfb_capture_scheduler *scheduler, uint64_t now_ms,
    size_t plaintext_request_length, uint64_t exact_wire_length);
rfb_error rfb_capture_scheduler_request_drained(
    rfb_capture_scheduler *scheduler, uint64_t now_ms,
    uint64_t transport_tx_after, bool application_outbound_empty);
rfb_error rfb_capture_scheduler_fbu_begin(rfb_capture_scheduler *scheduler,
                                          uint16_t rectangle_count);
rfb_error rfb_capture_scheduler_fbu_begin_at(
    rfb_capture_scheduler *scheduler, uint16_t rectangle_count,
    uint64_t now_ms);
rfb_error rfb_capture_scheduler_record_rect(
    rfb_capture_scheduler *scheduler, const rfb_rect_header *actual,
    const uint8_t *payload, size_t payload_len);
rfb_error rfb_capture_scheduler_fbu_complete(
    rfb_capture_scheduler *scheduler, uint64_t now_ms);
rfb_error rfb_capture_scheduler_note_activity(
    rfb_capture_scheduler *scheduler, uint64_t now_ms);
// Inbound traffic that carries no framebuffer damage, such as Apple's typed
// control messages. It still bounds the run against the response timeout, but
// it must not restart the quiet window: a server that chatters faster than the
// window is wide would otherwise starve the window forever.
rfb_error rfb_capture_scheduler_note_control_activity(
    rfb_capture_scheduler *scheduler, uint64_t now_ms);

rfb_error rfb_capture_scheduler_note_quiet(
    rfb_capture_scheduler *scheduler, uint64_t now_ms);
rfb_error rfb_capture_scheduler_tick(rfb_capture_scheduler *scheduler,
                                     uint64_t now_ms);
rfb_error rfb_capture_scheduler_note_eof(rfb_capture_scheduler *scheduler);
rfb_error rfb_capture_scheduler_fail(rfb_capture_scheduler *scheduler,
                                     rfb_capture_failure failure,
                                     rfb_error error);

bool rfb_capture_scheduler_active(const rfb_capture_scheduler *scheduler);
bool rfb_capture_scheduler_done(const rfb_capture_scheduler *scheduler);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_RFB_CAPTURE_SCHEDULER_H
