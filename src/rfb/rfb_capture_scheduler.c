// SPDX-License-Identifier: Apache-2.0
//
// farsee — bounded capture-only FramebufferUpdateRequest scheduler.

#include "farsee/rfb_capture_scheduler.h"

#include "farsee/apple_wire_decode.h"
#include "farsee/encoding.h"
#include "rfb/rfb_capture_scheduler_internal.h"

#include <string.h>

#define RFB_CAPTURE_TIMEOUT_MAX_MS 600000u

typedef struct first_record {
    bool seen;
    uint8_t command;
    uint32_t run;
} first_record;

static bool capture_first_record(
    void *opaque, const apple_wire_mvs_command_record *record)
{
    first_record *first = (first_record *)opaque;
    if (first == NULL || record == NULL) {
        return false;
    }
    if (!first->seen) {
        first->seen = true;
        first->command = record->command;
        first->run = record->run;
    }
    return true;
}

static bool query_valid(const rfb_capture_query *query, uint16_t fb_width,
                        uint16_t fb_height)
{
    if (query == NULL || query->width == 0u || query->height == 0u) {
        return false;
    }
    if ((query->x % 8u) != 0u || (query->y % 8u) != 0u ||
        (query->width % 8u) != 0u || (query->height % 8u) != 0u) {
        return false;
    }
    if (query->geometry_policy != RFB_CAPTURE_GEOMETRY_EXACT &&
        query->geometry_policy != RFB_CAPTURE_GEOMETRY_WITHIN_REQUEST) {
        return false;
    }
    const uint32_t x_end = (uint32_t)query->x + (uint32_t)query->width;
    const uint32_t y_end = (uint32_t)query->y + (uint32_t)query->height;
    return x_end <= (uint32_t)fb_width && y_end <= (uint32_t)fb_height;
}

static rfb_capture_phase current_phase(
    const rfb_capture_scheduler *scheduler)
{
    return scheduler->final_observation_count == 0u
               ? RFB_CAPTURE_PHASE_INITIAL
               : RFB_CAPTURE_PHASE_TARGET;
}

static bool terminal_final_present(
    const rfb_capture_scheduler *scheduler)
{
    return scheduler->final_observation_count > 0u &&
           scheduler->final_observations != NULL &&
           scheduler->final_observations[
               scheduler->final_observation_count - 1u].terminal;
}

static void store_final_observation(rfb_capture_scheduler *scheduler,
                                    bool terminal,
                                    rfb_capture_final_classification classification,
                                    bool fbu_complete, bool quiet_complete,
                                    rfb_capture_failure failure,
                                    uint64_t now_ms)
{
    if (scheduler->final_observations == NULL ||
        terminal_final_present(scheduler) ||
        scheduler->final_observation_count >=
            scheduler->final_observation_capacity) {
        return;
    }
    rfb_capture_final_observation_v1 *final =
        &scheduler->final_observations[scheduler->final_observation_count];
    memset(final, 0, sizeof *final);
    final->version = RFB_CAPTURE_OBSERVATION_VERSION_1;
    final->size = (uint16_t)sizeof *final;
    final->sequence = ++scheduler->observation_sequence;
    final->present = true;
    final->terminal = terminal;
    final->phase = current_phase(scheduler);
    final->has_request = final->phase == RFB_CAPTURE_PHASE_TARGET &&
                         scheduler->query_index < scheduler->query_count;
    if (final->has_request) {
        final->requested = scheduler->queries[scheduler->query_index];
    }
    final->fbu_ordinal = scheduler->fbu_ordinal;
    final->declared_rectangle_count =
        scheduler->current_result.rectangle_count;
    final->rectangles_seen = scheduler->rectangles_seen;
    final->fbu_complete = fbu_complete;
    final->quiet_complete = quiet_complete;
    final->classification = classification;
    final->failure = failure;
    final->rectangle_observation_count =
        (uint32_t)scheduler->rect_observation_count;
    if (scheduler->request_started_ms >= scheduler->request_queued_ms &&
        scheduler->request_queued_ms != 0u) {
        final->queue_to_drain_ms =
            scheduler->request_started_ms - scheduler->request_queued_ms;
    }
    if (scheduler->target_fbu_started_ms >= scheduler->request_started_ms &&
        scheduler->request_started_ms != 0u) {
        final->drain_to_fbu_ms =
            scheduler->target_fbu_started_ms - scheduler->request_started_ms;
    }
    if (quiet_complete && now_ms >= scheduler->quiet_phase_started_ms) {
        final->quiet_duration_ms = now_ms - scheduler->quiet_phase_started_ms;
    }
    scheduler->final_observation_count++;
}

rfb_error rfb_capture_scheduler_record_failure(
    rfb_capture_scheduler *scheduler, rfb_capture_failure failure,
    rfb_error error, uint64_t now_ms)
{
    if (scheduler == NULL) {
        return RFB_ERR_INTERNAL;
    }
    if (scheduler->state == RFB_CAPTURE_SCHEDULER_FAILED) {
        return scheduler->error;
    }
    const bool fbu_complete =
        scheduler->state == RFB_CAPTURE_SCHEDULER_QUIET_INITIAL ||
        scheduler->state == RFB_CAPTURE_SCHEDULER_QUIET_RESPONSE ||
        scheduler->state == RFB_CAPTURE_SCHEDULER_DONE;
    store_final_observation(scheduler, true, RFB_CAPTURE_FINAL_REJECTED,
                            fbu_complete, false, failure, now_ms);
    scheduler->failure = failure;
    scheduler->error = error;
    scheduler->state = RFB_CAPTURE_SCHEDULER_FAILED;
    return error;
}

static rfb_error fail_with_at(rfb_capture_scheduler *scheduler,
                              rfb_capture_failure failure, rfb_error error,
                              uint64_t now_ms)
{
    return rfb_capture_scheduler_record_failure(
        scheduler, failure, error, now_ms);
}

static rfb_error fail_with(rfb_capture_scheduler *scheduler,
                           rfb_capture_failure failure, rfb_error error)
{
    return fail_with_at(scheduler, failure, error, 0u);
}

rfb_error rfb_capture_scheduler_init_config(
    rfb_capture_scheduler *scheduler,
    const rfb_capture_scheduler_config *config)
{
    if (scheduler == NULL || config == NULL ||
        config->query_count > RFB_CAPTURE_QUERY_MAX ||
        config->framebuffer_width == 0u || config->framebuffer_height == 0u ||
        config->response_timeout_ms == 0u ||
        config->response_timeout_ms > RFB_CAPTURE_TIMEOUT_MAX_MS ||
        config->quiet_ms == 0u ||
        config->quiet_ms > RFB_CAPTURE_TIMEOUT_MAX_MS ||
        (config->require_mutation_ack &&
         (config->mutation_timeout_ms == 0u ||
            config->mutation_timeout_ms > RFB_CAPTURE_TIMEOUT_MAX_MS))) {
        return RFB_ERR_PROTOCOL;
    }
    if ((config->initial_only &&
         (config->queries != NULL || config->query_count != 0u ||
          !config->initial_zrle_only || config->require_mutation_ack)) ||
        (!config->initial_only &&
         (config->queries == NULL || config->query_count == 0u ||
          config->initial_zrle_only))) {
        return RFB_ERR_PROTOCOL;
    }
    const bool observations = config->rect_observations != NULL ||
                              config->rect_observation_capacity != 0u ||
                              config->final_observations != NULL ||
                              config->final_observation_capacity != 0u ||
                              config->initial_rectangle_max != 0u;
    if (observations &&
        (config->rect_observations == NULL ||
         config->final_observations == NULL ||
         config->initial_rectangle_max == 0u ||
         config->rect_observation_capacity <=
             config->initial_rectangle_max ||
         config->final_observation_capacity < 2u ||
         config->rect_observation_capacity > UINT32_MAX)) {
        return RFB_ERR_PROTOCOL;
    }
    if (config->require_mutation_ack &&
        (!observations || config->query_count != 1u ||
         !config->queries[0].incremental || config->queries[0].x != 0u ||
         config->queries[0].y != 0u ||
         config->queries[0].width != config->framebuffer_width ||
         config->queries[0].height != config->framebuffer_height ||
         config->queries[0].geometry_policy !=
             RFB_CAPTURE_GEOMETRY_WITHIN_REQUEST ||
         config->final_observation_capacity != 2u ||
         config->on_result != NULL)) {
        return RFB_ERR_PROTOCOL;
    }
    for (size_t i = 0u; i < config->query_count; i++) {
        if (!query_valid(&config->queries[i], config->framebuffer_width,
                         config->framebuffer_height)) {
            return RFB_ERR_PROTOCOL;
        }
        for (size_t j = i + 1u; j < config->query_count; j++) {
            if (config->queries[i].id == config->queries[j].id) {
                return RFB_ERR_PROTOCOL;
            }
        }
    }

    rfb_capture_scheduler initialized;
    memset(&initialized, 0, sizeof initialized);
    initialized.queries = config->queries;
    initialized.query_count = config->query_count;
    initialized.framebuffer_width = config->framebuffer_width;
    initialized.framebuffer_height = config->framebuffer_height;
    initialized.response_timeout_ms = config->response_timeout_ms;
    initialized.quiet_ms = config->quiet_ms;
    initialized.initial_only = config->initial_only;
    initialized.initial_zrle_only = config->initial_zrle_only;
    initialized.require_mutation_ack = config->require_mutation_ack;
    initialized.mutation_timeout_ms = config->mutation_timeout_ms;
    initialized.initial_rectangle_max = config->initial_rectangle_max;
    initialized.rect_observations = config->rect_observations;
    initialized.rect_observation_capacity =
        config->rect_observation_capacity;
    initialized.final_observations = config->final_observations;
    initialized.final_observation_capacity =
        config->final_observation_capacity;
    initialized.state = RFB_CAPTURE_SCHEDULER_WAIT_INITIAL;
    initialized.on_result = config->on_result;
    initialized.on_result_ctx = config->on_result_ctx;
    if (observations) {
        memset(config->rect_observations, 0,
               config->rect_observation_capacity *
                   sizeof *config->rect_observations);
        memset(config->final_observations, 0,
               config->final_observation_capacity *
                   sizeof *config->final_observations);
    }
    *scheduler = initialized;
    return RFB_OK;
}

rfb_error rfb_capture_scheduler_init(
    rfb_capture_scheduler *scheduler, const rfb_capture_query *queries,
    size_t query_count, uint16_t framebuffer_width,
    uint16_t framebuffer_height, uint32_t response_timeout_ms,
    uint32_t quiet_ms,
    rfb_capture_result_fn on_result, void *on_result_ctx)
{
    const rfb_capture_scheduler_config config = {
        .queries = queries,
        .query_count = query_count,
        .framebuffer_width = framebuffer_width,
        .framebuffer_height = framebuffer_height,
        .response_timeout_ms = response_timeout_ms,
        .quiet_ms = quiet_ms,
        .on_result = on_result,
        .on_result_ctx = on_result_ctx,
    };
    return rfb_capture_scheduler_init_config(scheduler, &config);
}

bool rfb_capture_scheduler_next_request(
    const rfb_capture_scheduler *scheduler, rfb_capture_query *out)
{
    if (scheduler == NULL || out == NULL ||
        (scheduler->state != RFB_CAPTURE_SCHEDULER_READY &&
         scheduler->state != RFB_CAPTURE_SCHEDULER_MUTATION_ACKED) ||
        scheduler->query_index >= scheduler->query_count) {
        return false;
    }
    *out = scheduler->queries[scheduler->query_index];
    return true;
}

rfb_error rfb_capture_scheduler_initial_request_sent(
    rfb_capture_scheduler *scheduler, uint64_t now_ms)
{
    if (scheduler == NULL) {
        return RFB_ERR_INTERNAL;
    }
    if (scheduler->state == RFB_CAPTURE_SCHEDULER_FAILED) {
        return scheduler->error;
    }
    if (scheduler->state != RFB_CAPTURE_SCHEDULER_WAIT_INITIAL) {
        return fail_with(scheduler, RFB_CAPTURE_FAILURE_SEQUENCE,
                         RFB_ERR_PROTOCOL);
    }
    scheduler->request_started_ms = now_ms;
    return RFB_OK;
}

rfb_error rfb_capture_scheduler_request_sent(
    rfb_capture_scheduler *scheduler, uint64_t now_ms)
{
    if (scheduler == NULL) {
        return RFB_ERR_INTERNAL;
    }
    if (scheduler->state == RFB_CAPTURE_SCHEDULER_FAILED) {
        return scheduler->error;
    }
    if (scheduler->state != RFB_CAPTURE_SCHEDULER_READY ||
        scheduler->query_index >= scheduler->query_count) {
        return fail_with(scheduler, RFB_CAPTURE_FAILURE_SEQUENCE,
                         RFB_ERR_PROTOCOL);
    }
    memset(&scheduler->current_result, 0, sizeof scheduler->current_result);
    scheduler->current_result.requested =
        scheduler->queries[scheduler->query_index];
    scheduler->request_started_ms = now_ms;
    scheduler->state = RFB_CAPTURE_SCHEDULER_OUTSTANDING;
    return RFB_OK;
}

rfb_error rfb_capture_scheduler_mutation_acknowledged(
    rfb_capture_scheduler *scheduler, uint64_t now_ms)
{
    if (scheduler == NULL) {
        return RFB_ERR_INTERNAL;
    }
    if (scheduler->state == RFB_CAPTURE_SCHEDULER_FAILED) {
        return scheduler->error;
    }
    if (scheduler->state != RFB_CAPTURE_SCHEDULER_MUTATION_HOLD ||
        now_ms < scheduler->mutation_started_ms) {
        return fail_with_at(scheduler, RFB_CAPTURE_FAILURE_CONTROL,
                            RFB_ERR_PROTOCOL, now_ms);
    }
    if (now_ms - scheduler->mutation_started_ms >=
        (uint64_t)scheduler->mutation_timeout_ms) {
        return fail_with_at(scheduler, RFB_CAPTURE_FAILURE_TIMEOUT,
                            RFB_ERR_TIMEOUT, now_ms);
    }
    scheduler->state = RFB_CAPTURE_SCHEDULER_MUTATION_ACKED;
    return RFB_OK;
}

rfb_error rfb_capture_scheduler_request_queue_started(
    rfb_capture_scheduler *scheduler, uint64_t now_ms,
    uint64_t transport_tx_before, bool application_outbound_empty)
{
    if (scheduler == NULL) {
        return RFB_ERR_INTERNAL;
    }
    if (scheduler->state == RFB_CAPTURE_SCHEDULER_FAILED) {
        return scheduler->error;
    }
    if ((scheduler->state != RFB_CAPTURE_SCHEDULER_MUTATION_ACKED &&
         scheduler->state != RFB_CAPTURE_SCHEDULER_READY) ||
        scheduler->query_index >= scheduler->query_count ||
        !application_outbound_empty) {
        return fail_with_at(scheduler, RFB_CAPTURE_FAILURE_REQUEST_DRAIN,
                            RFB_ERR_PROTOCOL, now_ms);
    }
    memset(&scheduler->current_result, 0, sizeof scheduler->current_result);
    scheduler->current_result.requested =
        scheduler->queries[scheduler->query_index];
    scheduler->request_queued_ms = now_ms;
    scheduler->request_tx_before = transport_tx_before;
    scheduler->request_started_ms = 0u;
    scheduler->target_fbu_started_ms = 0u;
    scheduler->state = RFB_CAPTURE_SCHEDULER_REQUEST_QUEUED;
    return RFB_OK;
}

rfb_error rfb_capture_scheduler_request_queued(
    rfb_capture_scheduler *scheduler, uint64_t now_ms,
    size_t plaintext_request_length, uint64_t exact_wire_length)
{
    if (scheduler == NULL) {
        return RFB_ERR_INTERNAL;
    }
    if (scheduler->state == RFB_CAPTURE_SCHEDULER_FAILED) {
        return scheduler->error;
    }
    if (scheduler->state != RFB_CAPTURE_SCHEDULER_REQUEST_QUEUED ||
        now_ms < scheduler->request_queued_ms ||
        plaintext_request_length != 10u || exact_wire_length < 10u) {
        return fail_with_at(scheduler, RFB_CAPTURE_FAILURE_REQUEST_DRAIN,
                            RFB_ERR_PROTOCOL, now_ms);
    }
    scheduler->request_wire_length = exact_wire_length;
    scheduler->state = RFB_CAPTURE_SCHEDULER_REQUEST_DRAINING;
    return RFB_OK;
}

rfb_error rfb_capture_scheduler_request_drained(
    rfb_capture_scheduler *scheduler, uint64_t now_ms,
    uint64_t transport_tx_after, bool application_outbound_empty)
{
    if (scheduler == NULL) {
        return RFB_ERR_INTERNAL;
    }
    if (scheduler->state == RFB_CAPTURE_SCHEDULER_FAILED) {
        return scheduler->error;
    }
    if (scheduler->state != RFB_CAPTURE_SCHEDULER_REQUEST_DRAINING ||
        now_ms < scheduler->request_queued_ms ||
        transport_tx_after < scheduler->request_tx_before ||
        !application_outbound_empty ||
        transport_tx_after - scheduler->request_tx_before !=
            scheduler->request_wire_length) {
        return fail_with_at(scheduler, RFB_CAPTURE_FAILURE_REQUEST_DRAIN,
                            RFB_ERR_PROTOCOL, now_ms);
    }
    scheduler->request_started_ms = now_ms;
    scheduler->state = RFB_CAPTURE_SCHEDULER_OUTSTANDING;
    return RFB_OK;
}

rfb_error rfb_capture_scheduler_fbu_begin_at(
    rfb_capture_scheduler *scheduler, uint16_t rectangle_count,
    uint64_t now_ms)
{
    if (scheduler == NULL) {
        return RFB_ERR_INTERNAL;
    }
    if (scheduler->state == RFB_CAPTURE_SCHEDULER_FAILED) {
        return scheduler->error;
    }
    if (scheduler->state == RFB_CAPTURE_SCHEDULER_WAIT_INITIAL) {
        if (now_ms < scheduler->request_started_ms) {
            return fail_with_at(scheduler, RFB_CAPTURE_FAILURE_SEQUENCE,
                                RFB_ERR_PROTOCOL, now_ms);
        }
        scheduler->fbu_ordinal++;
        memset(&scheduler->current_result, 0,
               sizeof scheduler->current_result);
        scheduler->current_result.initial = true;
        scheduler->current_result.rectangle_count = rectangle_count;
        scheduler->rectangles_seen = 0u;
        if (scheduler->rect_observations != NULL &&
            (size_t)rectangle_count > scheduler->initial_rectangle_max) {
            return fail_with_at(scheduler,
                                RFB_CAPTURE_FAILURE_OBSERVATION_LIMIT,
                                RFB_ERR_LIMIT, now_ms);
        }
        scheduler->state = RFB_CAPTURE_SCHEDULER_RECEIVING_INITIAL;
        return RFB_OK;
    }
    if (scheduler->state != RFB_CAPTURE_SCHEDULER_OUTSTANDING) {
        // A completed observation may be trailed by a single-rectangle
        // desktop-size announcement. Whether it is an announcement or an
        // unsolicited paint is only knowable from its rectangle, so defer the
        // decision to record_rect instead of guessing here. Every other state
        // still fails on sight.
        if ((scheduler->state == RFB_CAPTURE_SCHEDULER_QUIET_RESPONSE ||
             scheduler->state == RFB_CAPTURE_SCHEDULER_QUIET_INITIAL) &&
            rectangle_count == 1u) {
            scheduler->announcement_resume_state = scheduler->state;
            scheduler->rectangles_seen = 0u;
            scheduler->state = RFB_CAPTURE_SCHEDULER_RECEIVING_ANNOUNCEMENT;
            return RFB_OK;
        }
        return fail_with_at(scheduler, RFB_CAPTURE_FAILURE_UNSOLICITED_FBU,
                            RFB_ERR_PROTOCOL, now_ms);
    }
    if (now_ms < scheduler->request_started_ms) {
        return fail_with_at(scheduler, RFB_CAPTURE_FAILURE_SEQUENCE,
                            RFB_ERR_PROTOCOL, now_ms);
    }
    scheduler->fbu_ordinal++;
    scheduler->current_result.rectangle_count = rectangle_count;
    scheduler->rectangles_seen = 0u;
    scheduler->target_fbu_started_ms = now_ms;
    if (rectangle_count != 1u) {
        return fail_with_at(scheduler, RFB_CAPTURE_FAILURE_RECT_COUNT,
                            RFB_ERR_PROTOCOL, now_ms);
    }
    scheduler->state = RFB_CAPTURE_SCHEDULER_RECEIVING;
    return RFB_OK;
}

rfb_error rfb_capture_scheduler_fbu_begin(rfb_capture_scheduler *scheduler,
                                          uint16_t rectangle_count)
{
    const uint64_t now_ms = scheduler != NULL ? scheduler->request_started_ms
                                               : 0u;
    return rfb_capture_scheduler_fbu_begin_at(scheduler, rectangle_count,
                                              now_ms);
}

static bool rect_matches_query(const rfb_rect_header *actual,
                               const rfb_capture_query *query)
{
    return actual->x == query->x && actual->y == query->y &&
           actual->width == query->width && actual->height == query->height;
}

static rfb_capture_geometry_class classify_geometry(
    const rfb_rect_header *actual, const rfb_capture_query *query)
{
    if (rect_matches_query(actual, query)) {
        return RFB_CAPTURE_GEOMETRY_CLASS_EXACT;
    }
    const uint32_t actual_right =
        (uint32_t)actual->x + (uint32_t)actual->width;
    const uint32_t actual_bottom =
        (uint32_t)actual->y + (uint32_t)actual->height;
    const uint32_t query_right =
        (uint32_t)query->x + (uint32_t)query->width;
    const uint32_t query_bottom =
        (uint32_t)query->y + (uint32_t)query->height;
    if (actual->x >= query->x && actual->y >= query->y &&
        actual_right <= query_right && actual_bottom <= query_bottom) {
        return RFB_CAPTURE_GEOMETRY_CLASS_CONTAINED;
    }
    return RFB_CAPTURE_GEOMETRY_CLASS_OUTSIDE;
}

static rfb_capture_rect_observation_v1 *store_rect_observation(
    rfb_capture_scheduler *scheduler, bool initial,
    const rfb_rect_header *actual)
{
    if (scheduler->rect_observations == NULL) {
        return NULL;
    }
    const size_t index = initial ? (size_t)scheduler->rectangles_seen
                                 : scheduler->initial_rectangle_max;
    if (index >= scheduler->rect_observation_capacity ||
        scheduler->rect_observations[index].version != 0u) {
        return NULL;
    }
    rfb_capture_rect_observation_v1 *observation =
        &scheduler->rect_observations[index];
    memset(observation, 0, sizeof *observation);
    observation->version = RFB_CAPTURE_OBSERVATION_VERSION_1;
    observation->size = (uint16_t)sizeof *observation;
    observation->sequence = ++scheduler->observation_sequence;
    observation->phase = initial ? RFB_CAPTURE_PHASE_INITIAL
                                 : RFB_CAPTURE_PHASE_TARGET;
    observation->has_request = !initial;
    if (!initial) {
        observation->requested = scheduler->current_result.requested;
        observation->geometry = classify_geometry(
            actual, &scheduler->current_result.requested);
    }
    observation->fbu_ordinal = scheduler->fbu_ordinal;
    observation->declared_rectangle_count =
        scheduler->current_result.rectangle_count;
    observation->rectangle_index = scheduler->rectangles_seen;
    observation->actual = *actual;
    scheduler->rect_observation_count++;
    return observation;
}

static rfb_error reject_structure(
    rfb_capture_scheduler *scheduler,
    rfb_capture_rect_observation_v1 *observation,
    rfb_capture_failure failure, rfb_error error)
{
    if (observation != NULL) {
        observation->structure_checked = true;
        observation->structure_valid = false;
        observation->structure_failure = failure;
    }
    return fail_with(scheduler, failure, error);
}

static void copy_result_to_observation(
    const rfb_capture_result *result,
    rfb_capture_rect_observation_v1 *observation)
{
    if (observation == NULL) {
        return;
    }
    observation->structure_checked = true;
    observation->structure_valid = true;
    observation->structure_failure = RFB_CAPTURE_FAILURE_NONE;
    observation->mvs_type0 = result->mvs_type0;
    observation->mvs_normal_count = result->mvs_normal_count;
    observation->mvs_large_count = result->mvs_large_count;
    observation->mvs_payload_len = result->mvs_payload_len;
    observation->mvs_image_offset = result->mvs_image_offset;
    observation->mvs_command_records = result->mvs_command_records;
    observation->mvs_command_marker_end_bits =
        result->mvs_command_marker_end_bits;
    observation->mvs_command_padding_bits =
        result->mvs_command_padding_bits;
    observation->mvs_image_marker_start_bits =
        result->mvs_image_marker_start_bits;
    observation->mvs_image_marker_end_bits =
        result->mvs_image_marker_end_bits;
    observation->mvs_image_padding_bits = result->mvs_image_padding_bits;
    observation->mvs_first_command = result->mvs_first_command;
    observation->mvs_first_run = result->mvs_first_run;
    observation->structural_one_record_run_one =
        result->direct_one_record_run_one;
}

static rfb_error classify_target_rect(rfb_capture_scheduler *scheduler,
                                      const rfb_rect_header *actual,
                                      const uint8_t *payload,
                                      size_t payload_len,
                                      rfb_capture_rect_observation_v1 *observation)
{
    const rfb_capture_query *query = &scheduler->current_result.requested;
    if (actual->encoding != (int32_t)RFB_ENCODING_APPLE_MVS) {
        return reject_structure(scheduler, observation,
                                RFB_CAPTURE_FAILURE_RECT_ENCODING,
                                RFB_ERR_PROTOCOL);
    }

    apple_wire_mvs_rect_hdr header;
    if (!apple_wire_decode_mvs_rect_hdr(payload, payload_len, &header)) {
        return reject_structure(scheduler, observation,
                                RFB_CAPTURE_FAILURE_MVS_GRAMMAR,
                                RFB_ERR_PROTOCOL);
    }
    if (!header.is_low_quality_pair && !header.is_high_quality_pair) {
        return reject_structure(scheduler, observation,
                                RFB_CAPTURE_FAILURE_MVS_GRAMMAR,
                                RFB_ERR_PROTOCOL);
    }
    uint32_t expected_tiles = 0u;
    if (!apple_wire_mvs_tile_grid_checked(actual->width, actual->height,
                                          NULL, NULL, &expected_tiles)) {
        return reject_structure(scheduler, observation,
                                RFB_CAPTURE_FAILURE_MVS_GRAMMAR,
                                RFB_ERR_PROTOCOL);
    }
    first_record first;
    memset(&first, 0, sizeof first);
    apple_wire_mvs_command_stats commands;
    if (!apple_wire_walk_mvs_partial_commands(
            &header, expected_tiles, capture_first_record, &first,
            &commands)) {
        return reject_structure(scheduler, observation,
                                RFB_CAPTURE_FAILURE_MVS_GRAMMAR,
                                RFB_ERR_PROTOCOL);
    }
    apple_wire_mvs_image_stats image;
    if (!apple_wire_validate_mvs_partial_image_suffix(&header, &image)) {
        return reject_structure(scheduler, observation,
                                RFB_CAPTURE_FAILURE_MVS_GRAMMAR,
                                RFB_ERR_PROTOCOL);
    }
    rfb_capture_result *result = &scheduler->current_result;
    result->mvs_type0 = true;
    result->mvs_normal_count = header.normal_count;
    result->mvs_large_count = header.large_count;
    if (payload_len > UINT32_MAX || commands.marker_end_bits > UINT32_MAX ||
        image.marker_start_bits > UINT32_MAX ||
        image.marker_end_bits > UINT32_MAX || commands.padding_bits > 7u ||
        image.padding_bits > 7u) {
        return reject_structure(scheduler, observation,
                                RFB_CAPTURE_FAILURE_MVS_GRAMMAR,
                                RFB_ERR_LIMIT);
    }
    result->mvs_payload_len = (uint32_t)payload_len;
    result->mvs_image_offset = header.image_buffer_offset;
    result->mvs_command_records = commands.records;
    result->mvs_command_marker_end_bits =
        (uint32_t)commands.marker_end_bits;
    result->mvs_command_padding_bits = (uint8_t)commands.padding_bits;
    result->mvs_image_marker_start_bits =
        (uint32_t)image.marker_start_bits;
    result->mvs_image_marker_end_bits =
        (uint32_t)image.marker_end_bits;
    result->mvs_image_padding_bits = (uint8_t)image.padding_bits;
    if (first.seen) {
        result->mvs_first_command = first.command;
        result->mvs_first_run = first.run;
    }
    result->direct_one_record_run_one =
        actual->width == 8u && actual->height == 8u &&
        commands.records == 1u && first.seen && first.run == 1u;
    copy_result_to_observation(result, observation);
    const rfb_capture_geometry_class geometry =
        classify_geometry(actual, query);
    const bool geometry_ok =
        geometry == RFB_CAPTURE_GEOMETRY_CLASS_EXACT ||
        (query->geometry_policy == RFB_CAPTURE_GEOMETRY_WITHIN_REQUEST &&
         geometry == RFB_CAPTURE_GEOMETRY_CLASS_CONTAINED);
    if (!geometry_ok) {
        return fail_with(scheduler, RFB_CAPTURE_FAILURE_RECT_GEOMETRY,
                         RFB_ERR_PROTOCOL);
    }
    return RFB_OK;
}

static rfb_error classify_initial_mvs_rect(
    rfb_capture_scheduler *scheduler, const rfb_rect_header *actual,
    const uint8_t *payload, size_t payload_len,
    rfb_capture_rect_observation_v1 *observation)
{
    rfb_capture_scheduler scratch = *scheduler;
    scratch.rect_observations = NULL;
    scratch.rect_observation_capacity = 0u;
    scratch.final_observations = NULL;
    scratch.final_observation_capacity = 0u;
    scratch.final_observation_count = 0u;
    scratch.current_result.requested.id = 0u;
    scratch.current_result.requested.incremental = false;
    scratch.current_result.requested.geometry_policy =
        RFB_CAPTURE_GEOMETRY_EXACT;
    scratch.current_result.requested.x = actual->x;
    scratch.current_result.requested.y = actual->y;
    scratch.current_result.requested.width = actual->width;
    scratch.current_result.requested.height = actual->height;
    const rfb_error error = classify_target_rect(
        &scratch, actual, payload, payload_len, observation);
    if (error != RFB_OK) {
        return fail_with(scheduler, scratch.failure, scratch.error);
    }
    return RFB_OK;
}

rfb_error rfb_capture_scheduler_record_rect(
    rfb_capture_scheduler *scheduler, const rfb_rect_header *actual,
    const uint8_t *payload, size_t payload_len)
{
    if (scheduler == NULL || actual == NULL ||
        (payload == NULL && payload_len != 0u)) {
        return RFB_ERR_INTERNAL;
    }
    if (scheduler->state == RFB_CAPTURE_SCHEDULER_FAILED) {
        return scheduler->error;
    }
    if (scheduler->state == RFB_CAPTURE_SCHEDULER_RECEIVING_ANNOUNCEMENT) {
        // Only a desktop-size restatement is benign here. It must echo the
        // negotiated geometry exactly: a different size is a real resize, and
        // any paint encoding is the unsolicited update it appears to be.
        if (actual->encoding != (int32_t)RFB_ENCODING_DESKTOPSIZE) {
            return fail_with(scheduler, RFB_CAPTURE_FAILURE_UNSOLICITED_FBU,
                             RFB_ERR_PROTOCOL);
        }
        if (actual->x != 0u || actual->y != 0u ||
            actual->width != scheduler->framebuffer_width ||
            actual->height != scheduler->framebuffer_height) {
            return fail_with(scheduler, RFB_CAPTURE_FAILURE_RECT_GEOMETRY,
                             RFB_ERR_PROTOCOL);
        }
        scheduler->rectangles_seen++;
        return RFB_OK;
    }
    const bool initial =
        scheduler->state == RFB_CAPTURE_SCHEDULER_RECEIVING_INITIAL;
    if (!initial && scheduler->state != RFB_CAPTURE_SCHEDULER_RECEIVING) {
        return fail_with(scheduler, RFB_CAPTURE_FAILURE_SEQUENCE,
                         RFB_ERR_PROTOCOL);
    }
    if (scheduler->rectangles_seen >=
        scheduler->current_result.rectangle_count) {
        return fail_with(scheduler, RFB_CAPTURE_FAILURE_RECT_COUNT,
                         RFB_ERR_PROTOCOL);
    }
    if (!scheduler->current_result.has_actual) {
        scheduler->current_result.actual = *actual;
        scheduler->current_result.has_actual = true;
    }
    rfb_capture_rect_observation_v1 *observation =
        store_rect_observation(scheduler, initial, actual);
    if (scheduler->rect_observations != NULL && observation == NULL) {
        return fail_with(scheduler, RFB_CAPTURE_FAILURE_OBSERVATION_LIMIT,
                         RFB_ERR_LIMIT);
    }
    scheduler->rectangles_seen++;
    if (initial) {
        if (scheduler->initial_zrle_only) {
            if (actual->encoding == (int32_t)RFB_ENCODING_ZRLE) {
                if (scheduler->initial_zrle_rectangles != 0u ||
                    actual->x != 0u || actual->y != 0u ||
                    actual->width != scheduler->framebuffer_width ||
                    actual->height != scheduler->framebuffer_height) {
                    return reject_structure(
                        scheduler, observation,
                        RFB_CAPTURE_FAILURE_RECT_GEOMETRY,
                        RFB_ERR_PROTOCOL);
                }
                scheduler->initial_zrle_rectangles++;
                return RFB_OK;
            }
            if (actual->encoding == (int32_t)RFB_ENCODING_CURSOR) {
                const bool valid = actual->width != 0u &&
                                   actual->height != 0u &&
                                   actual->x < actual->width &&
                                   actual->y < actual->height;
                return valid
                    ? RFB_OK
                    : reject_structure(
                          scheduler, observation,
                          RFB_CAPTURE_FAILURE_RECT_GEOMETRY,
                          RFB_ERR_PROTOCOL);
            }
            if (actual->encoding == (int32_t)RFB_ENCODING_DESKTOPSIZE &&
                actual->x == 0u && actual->y == 0u &&
                actual->width == scheduler->framebuffer_width &&
                actual->height == scheduler->framebuffer_height &&
                !scheduler->initial_desktop_size_seen &&
                scheduler->initial_zrle_rectangles == 0u) {
                scheduler->initial_desktop_size_seen = true;
                return RFB_OK;
            }
            return reject_structure(scheduler, observation,
                                    RFB_CAPTURE_FAILURE_RECT_ENCODING,
                                    RFB_ERR_PROTOCOL);
        }
        // The schedule is frozen against ServerInit geometry. A resize in the
        // quarantined response invalidates every prevalidated query even
        // though the engine has already decoded the pseudo-rectangle.
        if (actual->encoding == (int32_t)RFB_ENCODING_DESKTOPSIZE) {
            return fail_with(scheduler,
                             RFB_CAPTURE_FAILURE_RECT_GEOMETRY,
                             RFB_ERR_PROTOCOL);
        }
        if (actual->encoding == (int32_t)RFB_ENCODING_APPLE_MVS) {
            return classify_initial_mvs_rect(scheduler, actual, payload,
                                             payload_len, observation);
        }
        return RFB_OK;
    }
    return classify_target_rect(scheduler, actual, payload, payload_len,
                                observation);
}

static void publish_result(rfb_capture_scheduler *scheduler)
{
    scheduler->last_result = scheduler->current_result;
    scheduler->has_last_result = true;
    if (scheduler->on_result != NULL) {
        scheduler->on_result(scheduler->on_result_ctx,
                             &scheduler->last_result);
    }
}

rfb_error rfb_capture_scheduler_fbu_complete(
    rfb_capture_scheduler *scheduler, uint64_t now_ms)
{
    if (scheduler == NULL) {
        return RFB_ERR_INTERNAL;
    }
    if (scheduler->state == RFB_CAPTURE_SCHEDULER_FAILED) {
        return scheduler->error;
    }
    if (scheduler->state == RFB_CAPTURE_SCHEDULER_RECEIVING_ANNOUNCEMENT) {
        if (scheduler->rectangles_seen != 1u) {
            return fail_with_at(scheduler, RFB_CAPTURE_FAILURE_RECT_COUNT,
                                RFB_ERR_PROTOCOL, now_ms);
        }
        // The announcement produces no observation and cannot restart the
        // quiet window; the interrupted phase simply resumes.
        scheduler->state = scheduler->announcement_resume_state;
        return RFB_OK;
    }
    if (scheduler->state != RFB_CAPTURE_SCHEDULER_RECEIVING_INITIAL &&
        scheduler->state != RFB_CAPTURE_SCHEDULER_RECEIVING) {
        return fail_with_at(scheduler, RFB_CAPTURE_FAILURE_SEQUENCE,
                            RFB_ERR_PROTOCOL, now_ms);
    }
    if (scheduler->rectangles_seen !=
        scheduler->current_result.rectangle_count) {
        return fail_with_at(scheduler, RFB_CAPTURE_FAILURE_RECT_COUNT,
                            RFB_ERR_PROTOCOL, now_ms);
    }
    if (scheduler->current_result.initial && scheduler->initial_zrle_only &&
        scheduler->initial_zrle_rectangles != 1u) {
        return fail_with_at(scheduler, RFB_CAPTURE_FAILURE_RECT_ENCODING,
                            RFB_ERR_PROTOCOL, now_ms);
    }
    if (now_ms < scheduler->request_started_ms) {
        return fail_with_at(scheduler, RFB_CAPTURE_FAILURE_SEQUENCE,
                            RFB_ERR_PROTOCOL, now_ms);
    }
    if (now_ms - scheduler->request_started_ms >=
        (uint64_t)scheduler->response_timeout_ms) {
        return fail_with_at(scheduler, RFB_CAPTURE_FAILURE_TIMEOUT,
                            RFB_ERR_TIMEOUT, now_ms);
    }
    scheduler->quiet_started_ms = now_ms;
    scheduler->quiet_phase_started_ms = now_ms;
    scheduler->state = scheduler->current_result.initial
                           ? RFB_CAPTURE_SCHEDULER_QUIET_INITIAL
                           : RFB_CAPTURE_SCHEDULER_QUIET_RESPONSE;
    return RFB_OK;
}

rfb_error rfb_capture_scheduler_note_quiet(
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
        return fail_with_at(scheduler, RFB_CAPTURE_FAILURE_SEQUENCE,
                            RFB_ERR_PROTOCOL, now_ms);
    }
    if (now_ms < scheduler->quiet_started_ms) {
        return fail_with_at(scheduler, RFB_CAPTURE_FAILURE_SEQUENCE,
                            RFB_ERR_PROTOCOL, now_ms);
    }
    if (now_ms - scheduler->quiet_phase_started_ms >=
        (uint64_t)scheduler->response_timeout_ms) {
        return fail_with_at(scheduler, RFB_CAPTURE_FAILURE_TIMEOUT,
                            RFB_ERR_TIMEOUT, now_ms);
    }
    if (now_ms - scheduler->quiet_started_ms < (uint64_t)scheduler->quiet_ms) {
        return RFB_OK;
    }
    // A complete FBU does not close the association until the continuous
    // quiet boundary closes. Do not expose plausible-looking metadata that a
    // delayed competing FBU can subsequently invalidate.
    publish_result(scheduler);
    if (scheduler->state == RFB_CAPTURE_SCHEDULER_QUIET_INITIAL) {
        if (scheduler->initial_only) {
            store_final_observation(scheduler, true,
                                    RFB_CAPTURE_FINAL_CONTROL_CLOSED,
                                    true, true,
                                    RFB_CAPTURE_FAILURE_NONE, now_ms);
            scheduler->state = RFB_CAPTURE_SCHEDULER_DONE;
            return RFB_OK;
        }
        store_final_observation(scheduler, false,
                                RFB_CAPTURE_FINAL_QUARANTINED_INITIAL,
                                true, true,
                                RFB_CAPTURE_FAILURE_NONE, now_ms);
        if (scheduler->require_mutation_ack) {
            memset(&scheduler->current_result, 0,
                   sizeof scheduler->current_result);
            scheduler->rectangles_seen = 0u;
            scheduler->mutation_started_ms = now_ms;
            scheduler->state = RFB_CAPTURE_SCHEDULER_MUTATION_HOLD;
        } else {
            scheduler->state = RFB_CAPTURE_SCHEDULER_READY;
        }
        return RFB_OK;
    }
    store_final_observation(scheduler, true,
                            RFB_CAPTURE_FINAL_ASSOCIATION_CLOSED, true, true,
                            RFB_CAPTURE_FAILURE_NONE, now_ms);
    scheduler->query_index++;
    scheduler->state = scheduler->query_index == scheduler->query_count
                           ? RFB_CAPTURE_SCHEDULER_DONE
                           : RFB_CAPTURE_SCHEDULER_READY;
    return RFB_OK;
}
