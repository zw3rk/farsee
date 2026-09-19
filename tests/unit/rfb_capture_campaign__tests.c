// SPDX-License-Identifier: Apache-2.0

#include "rfb_test.h"

#include "farsee/apple_mvs_bits.h"
#include "farsee/encoding.h"
#include "farsee/rfb_capture_scheduler.h"

#include <stdint.h>
#include <string.h>

#define RECT_CAPACITY 5u
#define INITIAL_MAX 4u
#define FINAL_CAPACITY 2u
#define FBUR_WIRE_LENGTH 10u

typedef struct campaign_fixture {
    rfb_capture_scheduler scheduler;
    rfb_capture_query query;
    rfb_capture_rect_observation_v1 rectangles[RECT_CAPACITY];
    rfb_capture_final_observation_v1 finals[FINAL_CAPACITY];
} campaign_fixture;

static void ignored_result(void *ctx, const rfb_capture_result *result)
{
    (void)ctx;
    (void)result;
}

static rfb_capture_scheduler_config campaign_config(
    campaign_fixture *fixture)
{
    const rfb_capture_scheduler_config config = {
        .queries = &fixture->query,
        .query_count = 1u,
        .framebuffer_width = 1024u,
        .framebuffer_height = 768u,
        .response_timeout_ms = 100u,
        .quiet_ms = 10u,
        .require_mutation_ack = true,
        .mutation_timeout_ms = 200u,
        .initial_rectangle_max = INITIAL_MAX,
        .rect_observations = fixture->rectangles,
        .rect_observation_capacity = RECT_CAPACITY,
        .final_observations = fixture->finals,
        .final_observation_capacity = FINAL_CAPACITY,
    };
    return config;
}

static size_t singleton_type0(uint8_t *body, size_t capacity)
{
    RFB_CHECK(capacity >= 9u);
    uint8_t command[2];
    apple_mvs_bit_writer writer;
    apple_mvs_bit_writer_init(&writer, command, sizeof command);
    RFB_CHECK(apple_mvs_bit_writer_put(&writer, 0u, 1u));
    RFB_CHECK(apple_mvs_bit_writer_put(&writer, 4u, 3u));
    RFB_CHECK(apple_mvs_bit_writer_put(&writer, 0u, 1u));
    RFB_CHECK(apple_mvs_bit_writer_put(&writer, 0x6du, 8u));
    RFB_CHECK(apple_mvs_bit_writer_finish(&writer));
    RFB_CHECK_EQ_UINT(writer.len, 2u);

    body[0] = 0u;
    body[1] = 3u;
    body[2] = 5u;
    body[3] = 0u;
    body[4] = 0u;
    body[5] = 8u;
    memcpy(body + 6u, command, writer.len);
    body[8] = 0x6du;
    return 9u;
}

static void campaign_fixture_init(campaign_fixture *fixture,
                                  rfb_capture_geometry_policy geometry)
{
    memset(fixture, 0, sizeof *fixture);
    fixture->query.id = 310001u;
    fixture->query.incremental = true;
    fixture->query.geometry_policy = geometry;
    fixture->query.x = 0u;
    fixture->query.y = 0u;
    fixture->query.width = 1024u;
    fixture->query.height = 768u;

    const rfb_capture_scheduler_config config = campaign_config(fixture);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_init_config(
                         &fixture->scheduler, &config),
                     RFB_OK);
}

static void target_request_drained(campaign_fixture *fixture,
                                   uint64_t queue_ms, uint64_t drain_ms,
                                   uint64_t tx_before)
{
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_mutation_acknowledged(
                         &fixture->scheduler, 20u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_queue_started(
                         &fixture->scheduler, queue_ms, tx_before, true),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_queued(
                         &fixture->scheduler, queue_ms, FBUR_WIRE_LENGTH,
                         FBUR_WIRE_LENGTH),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_drained(
                         &fixture->scheduler, drain_ms,
                         tx_before + FBUR_WIRE_LENGTH, true),
                     RFB_OK);
}

static void target_singleton_complete(campaign_fixture *fixture,
                                      uint64_t fbu_ms,
                                      uint64_t complete_ms)
{
    uint8_t body[9];
    const size_t body_len = singleton_type0(body, sizeof body);
    const rfb_rect_header actual = {
        .x = 96u, .y = 128u, .width = 8u, .height = 8u,
        .encoding = RFB_ENCODING_APPLE_MVS};

    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_begin_at(
                         &fixture->scheduler, 1u, fbu_ms),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_record_rect(
                         &fixture->scheduler, &actual, body, body_len),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_complete(
                         &fixture->scheduler, complete_ms),
                     RFB_OK);
}

static void check_config_rejected_atomically(
    campaign_fixture *fixture, const rfb_capture_scheduler_config *config)
{
    memset(&fixture->scheduler, 0xa5, sizeof fixture->scheduler);
    memset(fixture->rectangles, 0x5a, sizeof fixture->rectangles);
    memset(fixture->finals, 0x3c, sizeof fixture->finals);
    const rfb_capture_scheduler scheduler_before = fixture->scheduler;
    rfb_capture_rect_observation_v1 rectangles_before[RECT_CAPACITY];
    rfb_capture_final_observation_v1 finals_before[FINAL_CAPACITY];
    memcpy(rectangles_before, fixture->rectangles, sizeof rectangles_before);
    memcpy(finals_before, fixture->finals, sizeof finals_before);

    RFB_CHECK_EQ_INT(rfb_capture_scheduler_init_config(&fixture->scheduler,
                                                       config),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK(memcmp(&fixture->scheduler, &scheduler_before,
                     sizeof scheduler_before) == 0);
    RFB_CHECK(memcmp(fixture->rectangles, rectangles_before,
                     sizeof rectangles_before) == 0);
    RFB_CHECK(memcmp(fixture->finals, finals_before,
                     sizeof finals_before) == 0);
}

static void initial_two_rectangles(campaign_fixture *fixture)
{
    const rfb_rect_header first = {
        .x = 0u, .y = 0u, .width = 512u, .height = 768u,
        .encoding = RFB_ENCODING_RAW};
    const rfb_rect_header second = {
        .x = 512u, .y = 0u, .width = 512u, .height = 768u,
        .encoding = RFB_ENCODING_RAW};
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_initial_request_sent(
                         &fixture->scheduler, 1u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_begin(&fixture->scheduler, 2u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_record_rect(
                         &fixture->scheduler, &first, NULL, 0u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_record_rect(
                         &fixture->scheduler, &second, NULL, 0u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_complete(
                         &fixture->scheduler, 2u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_note_quiet(&fixture->scheduler, 12u),
                     RFB_OK);
}

RFB_TEST(rfb_capture_campaign,
         initial_observations_are_truthful_and_enter_mutation_hold)
{
    campaign_fixture fixture;
    campaign_fixture_init(&fixture, RFB_CAPTURE_GEOMETRY_WITHIN_REQUEST);
    initial_two_rectangles(&fixture);

    RFB_CHECK_EQ_INT(fixture.scheduler.state,
                     RFB_CAPTURE_SCHEDULER_MUTATION_HOLD);
    RFB_CHECK_EQ_UINT(fixture.scheduler.rect_observation_count, 2u);
    for (size_t i = 0u; i < 2u; i++) {
        const rfb_capture_rect_observation_v1 *observation =
            &fixture.rectangles[i];
        RFB_CHECK_EQ_UINT(observation->version,
                          RFB_CAPTURE_OBSERVATION_VERSION_1);
        RFB_CHECK_EQ_UINT(observation->size, sizeof *observation);
        RFB_CHECK_EQ_INT(observation->phase, RFB_CAPTURE_PHASE_INITIAL);
        RFB_CHECK(!observation->has_request);
        RFB_CHECK_EQ_UINT(observation->declared_rectangle_count, 2u);
        RFB_CHECK_EQ_UINT(observation->rectangle_index, i);
    }
    RFB_CHECK(fixture.finals[0].present);
    RFB_CHECK(!fixture.finals[0].terminal);
    RFB_CHECK_EQ_INT(fixture.finals[0].phase, RFB_CAPTURE_PHASE_INITIAL);
    RFB_CHECK(!fixture.finals[0].has_request);
    RFB_CHECK(fixture.finals[0].fbu_complete);
    RFB_CHECK(fixture.finals[0].quiet_complete);
    RFB_CHECK(!fixture.finals[1].present);
}

RFB_TEST(rfb_capture_campaign,
         mutation_ack_then_exact_drain_starts_response_timer)
{
    campaign_fixture fixture;
    campaign_fixture_init(&fixture, RFB_CAPTURE_GEOMETRY_WITHIN_REQUEST);
    initial_two_rectangles(&fixture);

    RFB_CHECK_EQ_INT(rfb_capture_scheduler_mutation_acknowledged(
                         &fixture.scheduler, 20u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(fixture.scheduler.state,
                     RFB_CAPTURE_SCHEDULER_MUTATION_ACKED);
    rfb_capture_query query;
    RFB_CHECK(rfb_capture_scheduler_next_request(&fixture.scheduler, &query));
    RFB_CHECK(query.incremental);
    RFB_CHECK_EQ_UINT(query.x, 0u);
    RFB_CHECK_EQ_UINT(query.y, 0u);
    RFB_CHECK_EQ_UINT(query.width, 1024u);
    RFB_CHECK_EQ_UINT(query.height, 768u);

    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_queue_started(
                         &fixture.scheduler, 21u, 1000u, true),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_queued(
                         &fixture.scheduler, 21u, FBUR_WIRE_LENGTH,
                         FBUR_WIRE_LENGTH),
                     RFB_OK);
    RFB_CHECK_EQ_INT(fixture.scheduler.state,
                     RFB_CAPTURE_SCHEDULER_REQUEST_DRAINING);
    RFB_CHECK_EQ_UINT(fixture.scheduler.request_started_ms, 0u);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_drained(
                         &fixture.scheduler, 22u, 1009u, true),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(fixture.scheduler.failure,
                     RFB_CAPTURE_FAILURE_REQUEST_DRAIN);

    campaign_fixture_init(&fixture, RFB_CAPTURE_GEOMETRY_WITHIN_REQUEST);
    initial_two_rectangles(&fixture);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_mutation_acknowledged(
                         &fixture.scheduler, 20u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_queue_started(
                         &fixture.scheduler, 21u, 1000u, true),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_queued(
                         &fixture.scheduler, 21u, FBUR_WIRE_LENGTH,
                         FBUR_WIRE_LENGTH),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_drained(
                         &fixture.scheduler, 22u, 1010u, true),
                     RFB_OK);
    RFB_CHECK_EQ_INT(fixture.scheduler.state,
                     RFB_CAPTURE_SCHEDULER_OUTSTANDING);
    RFB_CHECK_EQ_UINT(fixture.scheduler.request_started_ms, 22u);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_tick(&fixture.scheduler, 121u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_tick(&fixture.scheduler, 122u),
                     RFB_ERR_TIMEOUT);
}

RFB_TEST(rfb_capture_campaign, early_duplicate_and_late_ack_fail_closed)
{
    campaign_fixture fixture;
    campaign_fixture_init(&fixture, RFB_CAPTURE_GEOMETRY_WITHIN_REQUEST);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_mutation_acknowledged(
                         &fixture.scheduler, 1u),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(fixture.scheduler.failure, RFB_CAPTURE_FAILURE_CONTROL);
    RFB_CHECK(fixture.finals[0].present);
    RFB_CHECK(fixture.finals[0].terminal);

    campaign_fixture_init(&fixture, RFB_CAPTURE_GEOMETRY_WITHIN_REQUEST);
    initial_two_rectangles(&fixture);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_mutation_acknowledged(
                         &fixture.scheduler, 20u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_mutation_acknowledged(
                         &fixture.scheduler, 21u),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(fixture.scheduler.failure, RFB_CAPTURE_FAILURE_CONTROL);
    RFB_CHECK(fixture.finals[1].present);
    RFB_CHECK(fixture.finals[1].terminal);
}

RFB_TEST(rfb_capture_campaign,
         structurally_valid_wrong_geometry_is_retained_before_rejection)
{
    campaign_fixture fixture;
    campaign_fixture_init(&fixture, RFB_CAPTURE_GEOMETRY_WITHIN_REQUEST);
    initial_two_rectangles(&fixture);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_mutation_acknowledged(
                         &fixture.scheduler, 20u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_queue_started(
                         &fixture.scheduler, 21u, 100u, true),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_queued(
                         &fixture.scheduler, 21u, 10u, 10u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_drained(
                         &fixture.scheduler, 22u, 110u, true),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_begin(&fixture.scheduler, 1u),
                     RFB_OK);

    uint8_t body[9];
    const size_t body_len = singleton_type0(body, sizeof body);
    const rfb_rect_header actual = {
        .x = 1024u, .y = 0u, .width = 8u, .height = 8u,
        .encoding = RFB_ENCODING_APPLE_MVS};
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_record_rect(
                         &fixture.scheduler, &actual, body, body_len),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(fixture.scheduler.failure,
                     RFB_CAPTURE_FAILURE_RECT_GEOMETRY);

    const rfb_capture_rect_observation_v1 *observation =
        &fixture.rectangles[INITIAL_MAX];
    RFB_CHECK_EQ_INT(observation->phase, RFB_CAPTURE_PHASE_TARGET);
    RFB_CHECK(observation->has_request);
    RFB_CHECK_EQ_UINT(observation->requested.id, fixture.query.id);
    RFB_CHECK_EQ_INT(observation->geometry,
                     RFB_CAPTURE_GEOMETRY_CLASS_OUTSIDE);
    RFB_CHECK(observation->structure_checked);
    RFB_CHECK(observation->structure_valid);
    RFB_CHECK_EQ_INT(observation->structure_failure,
                     RFB_CAPTURE_FAILURE_NONE);
    RFB_CHECK_EQ_UINT(observation->mvs_command_records, 1u);
    RFB_CHECK_EQ_UINT(observation->mvs_first_run, 1u);
    RFB_CHECK(fixture.finals[1].present);
    RFB_CHECK(fixture.finals[1].terminal);
    RFB_CHECK_EQ_INT(fixture.finals[1].classification,
                     RFB_CAPTURE_FINAL_REJECTED);
    RFB_CHECK_EQ_INT(fixture.finals[1].failure,
                     RFB_CAPTURE_FAILURE_RECT_GEOMETRY);
}

RFB_TEST(rfb_capture_campaign,
         malformed_structure_precedes_wrong_geometry_and_remains_observed)
{
    campaign_fixture fixture;
    campaign_fixture_init(&fixture, RFB_CAPTURE_GEOMETRY_WITHIN_REQUEST);
    initial_two_rectangles(&fixture);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_mutation_acknowledged(
                         &fixture.scheduler, 20u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_queue_started(
                         &fixture.scheduler, 21u, 100u, true),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_queued(
                         &fixture.scheduler, 21u, 10u, 10u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_drained(
                         &fixture.scheduler, 22u, 110u, true),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_begin(&fixture.scheduler, 1u),
                     RFB_OK);

    uint8_t malformed[9];
    const size_t malformed_len = singleton_type0(malformed, sizeof malformed);
    malformed[0] = 1u;
    const rfb_rect_header actual = {
        .x = 1024u, .y = 0u, .width = 8u, .height = 8u,
        .encoding = RFB_ENCODING_APPLE_MVS};
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_record_rect(
                         &fixture.scheduler, &actual, malformed, malformed_len),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(fixture.scheduler.failure,
                     RFB_CAPTURE_FAILURE_MVS_GRAMMAR);
    const rfb_capture_rect_observation_v1 *observation =
        &fixture.rectangles[INITIAL_MAX];
    RFB_CHECK(observation->structure_checked);
    RFB_CHECK(!observation->structure_valid);
    RFB_CHECK_EQ_INT(observation->structure_failure,
                     RFB_CAPTURE_FAILURE_MVS_GRAMMAR);
    RFB_CHECK_EQ_INT(observation->geometry,
                     RFB_CAPTURE_GEOMETRY_CLASS_OUTSIDE);
}

RFB_TEST(rfb_capture_campaign,
         initial_rectangle_limit_preserves_terminal_final_capacity)
{
    campaign_fixture fixture;
    campaign_fixture_init(&fixture, RFB_CAPTURE_GEOMETRY_WITHIN_REQUEST);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_initial_request_sent(
                         &fixture.scheduler, 1u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_begin(
                         &fixture.scheduler, INITIAL_MAX + 1u),
                     RFB_ERR_LIMIT);
    RFB_CHECK_EQ_INT(fixture.scheduler.failure,
                     RFB_CAPTURE_FAILURE_OBSERVATION_LIMIT);
    RFB_CHECK_EQ_UINT(fixture.scheduler.rect_observation_count, 0u);
    RFB_CHECK(fixture.finals[0].present);
    RFB_CHECK(fixture.finals[0].terminal);
    RFB_CHECK(!fixture.finals[1].present);
}

RFB_TEST(rfb_capture_campaign,
         initial_type0_has_structural_facts_without_request_sentinels)
{
    campaign_fixture fixture;
    campaign_fixture_init(&fixture, RFB_CAPTURE_GEOMETRY_WITHIN_REQUEST);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_initial_request_sent(
                         &fixture.scheduler, 1u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_begin(&fixture.scheduler, 1u),
                     RFB_OK);
    uint8_t body[9];
    const size_t body_len = singleton_type0(body, sizeof body);
    const rfb_rect_header actual = {
        .x = 96u, .y = 128u, .width = 8u, .height = 8u,
        .encoding = RFB_ENCODING_APPLE_MVS};
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_record_rect(
                         &fixture.scheduler, &actual, body, body_len),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_complete(
                         &fixture.scheduler, 2u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_note_quiet(&fixture.scheduler, 12u),
                     RFB_OK);
    const rfb_capture_rect_observation_v1 *observation =
        &fixture.rectangles[0];
    RFB_CHECK(!observation->has_request);
    RFB_CHECK(observation->structure_checked);
    RFB_CHECK(observation->structure_valid);
    RFB_CHECK(observation->mvs_type0);
    RFB_CHECK_EQ_UINT(observation->mvs_command_records, 1u);
    RFB_CHECK_EQ_UINT(observation->mvs_first_run, 1u);
}

RFB_TEST(rfb_capture_campaign,
         contained_single_record_closes_target_association)
{
    campaign_fixture fixture;
    campaign_fixture_init(&fixture, RFB_CAPTURE_GEOMETRY_WITHIN_REQUEST);
    initial_two_rectangles(&fixture);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_mutation_acknowledged(
                         &fixture.scheduler, 20u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_queue_started(
                         &fixture.scheduler, 21u, 100u, true),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_queued(
                         &fixture.scheduler, 21u, 10u, 10u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_drained(
                         &fixture.scheduler, 22u, 110u, true),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_begin(&fixture.scheduler, 1u),
                     RFB_OK);
    uint8_t body[9];
    const size_t body_len = singleton_type0(body, sizeof body);
    const rfb_rect_header actual = {
        .x = 96u, .y = 128u, .width = 8u, .height = 8u,
        .encoding = RFB_ENCODING_APPLE_MVS};
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_record_rect(
                         &fixture.scheduler, &actual, body, body_len),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_complete(
                         &fixture.scheduler, 23u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_note_quiet(&fixture.scheduler, 33u),
                     RFB_OK);
    RFB_CHECK(rfb_capture_scheduler_done(&fixture.scheduler));
    const rfb_capture_rect_observation_v1 *observation =
        &fixture.rectangles[INITIAL_MAX];
    RFB_CHECK_EQ_INT(observation->geometry,
                     RFB_CAPTURE_GEOMETRY_CLASS_CONTAINED);
    RFB_CHECK(observation->structural_one_record_run_one);
    RFB_CHECK(fixture.finals[1].present);
    RFB_CHECK(fixture.finals[1].terminal);
    RFB_CHECK_EQ_INT(fixture.finals[1].classification,
                     RFB_CAPTURE_FINAL_ASSOCIATION_CLOSED);
    RFB_CHECK(fixture.finals[1].fbu_complete);
    RFB_CHECK(fixture.finals[1].quiet_complete);
    RFB_CHECK_EQ_INT(fixture.finals[1].failure,
                     RFB_CAPTURE_FAILURE_NONE);
}

RFB_TEST(rfb_capture_campaign,
         predrain_and_delayed_competing_fbus_are_terminal)
{
    campaign_fixture fixture;
    campaign_fixture_init(&fixture, RFB_CAPTURE_GEOMETRY_WITHIN_REQUEST);
    initial_two_rectangles(&fixture);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_mutation_acknowledged(
                         &fixture.scheduler, 20u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_queue_started(
                         &fixture.scheduler, 21u, 100u, true),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_queued(
                         &fixture.scheduler, 21u, 10u, 10u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_begin(&fixture.scheduler, 1u),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(fixture.scheduler.failure,
                     RFB_CAPTURE_FAILURE_UNSOLICITED_FBU);

    campaign_fixture_init(&fixture, RFB_CAPTURE_GEOMETRY_WITHIN_REQUEST);
    initial_two_rectangles(&fixture);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_mutation_acknowledged(
                         &fixture.scheduler, 20u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_queue_started(
                         &fixture.scheduler, 21u, 100u, true),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_queued(
                         &fixture.scheduler, 21u, 10u, 10u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_drained(
                         &fixture.scheduler, 22u, 110u, true),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_begin(&fixture.scheduler, 1u),
                     RFB_OK);
    uint8_t body[9];
    const size_t body_len = singleton_type0(body, sizeof body);
    const rfb_rect_header actual = {
        .x = 96u, .y = 128u, .width = 8u, .height = 8u,
        .encoding = RFB_ENCODING_APPLE_MVS};
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_record_rect(
                         &fixture.scheduler, &actual, body, body_len),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_complete(
                         &fixture.scheduler, 23u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_begin(&fixture.scheduler, 0u),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(fixture.scheduler.failure,
                     RFB_CAPTURE_FAILURE_UNSOLICITED_FBU);
    RFB_CHECK_EQ_UINT(fixture.rectangles[INITIAL_MAX].mvs_command_records, 1u);
    RFB_CHECK(fixture.finals[1].present);
    RFB_CHECK(fixture.finals[1].terminal);
    RFB_CHECK_EQ_INT(fixture.finals[1].classification,
                     RFB_CAPTURE_FINAL_REJECTED);
}

RFB_TEST(rfb_capture_campaign,
         completed_target_rejection_preserves_truthful_terminal_final)
{
    campaign_fixture fixture;
    campaign_fixture_init(&fixture, RFB_CAPTURE_GEOMETRY_WITHIN_REQUEST);
    initial_two_rectangles(&fixture);
    target_request_drained(&fixture, 21u, 25u, 100u);
    target_singleton_complete(&fixture, 27u, 28u);

    RFB_CHECK_EQ_INT(fixture.scheduler.state,
                     RFB_CAPTURE_SCHEDULER_QUIET_RESPONSE);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_begin(&fixture.scheduler, 0u),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_UINT(fixture.scheduler.final_observation_count, 2u);
    const rfb_capture_final_observation_v1 *final = &fixture.finals[1];
    RFB_CHECK(final->present);
    RFB_CHECK(final->terminal);
    RFB_CHECK_EQ_INT(final->phase, RFB_CAPTURE_PHASE_TARGET);
    RFB_CHECK(final->has_request);
    RFB_CHECK_EQ_UINT(final->requested.id, fixture.query.id);
    RFB_CHECK_EQ_UINT(final->declared_rectangle_count, 1u);
    RFB_CHECK_EQ_UINT(final->rectangles_seen, 1u);
    RFB_CHECK(final->fbu_complete);
    RFB_CHECK(!final->quiet_complete);
    RFB_CHECK_EQ_INT(final->classification, RFB_CAPTURE_FINAL_REJECTED);
    RFB_CHECK_EQ_INT(final->failure,
                     RFB_CAPTURE_FAILURE_UNSOLICITED_FBU);
}

RFB_TEST(rfb_capture_campaign,
         rejected_target_fbu_retains_declared_and_seen_counts)
{
    campaign_fixture fixture;
    campaign_fixture_init(&fixture, RFB_CAPTURE_GEOMETRY_WITHIN_REQUEST);
    initial_two_rectangles(&fixture);
    target_request_drained(&fixture, 21u, 25u, 100u);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_begin_at(
                         &fixture.scheduler, 2u, 27u),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_UINT(fixture.finals[1].declared_rectangle_count, 2u);
    RFB_CHECK_EQ_UINT(fixture.finals[1].rectangles_seen, 0u);
    RFB_CHECK(!fixture.finals[1].fbu_complete);
    RFB_CHECK_EQ_UINT(fixture.finals[1].drain_to_fbu_ms, 2u);
    RFB_CHECK_EQ_INT(fixture.finals[1].failure,
                     RFB_CAPTURE_FAILURE_RECT_COUNT);

    campaign_fixture_init(&fixture, RFB_CAPTURE_GEOMETRY_WITHIN_REQUEST);
    initial_two_rectangles(&fixture);
    target_request_drained(&fixture, 21u, 25u, 100u);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_begin_at(
                         &fixture.scheduler, 0u, 27u),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_UINT(fixture.finals[1].declared_rectangle_count, 0u);
    RFB_CHECK_EQ_UINT(fixture.finals[1].rectangles_seen, 0u);
    RFB_CHECK(!fixture.finals[1].fbu_complete);
    RFB_CHECK_EQ_INT(fixture.finals[1].failure,
                     RFB_CAPTURE_FAILURE_RECT_COUNT);
}

RFB_TEST(rfb_capture_campaign,
         target_fbu_timestamp_seals_all_three_final_durations)
{
    campaign_fixture fixture;
    campaign_fixture_init(&fixture, RFB_CAPTURE_GEOMETRY_WITHIN_REQUEST);
    initial_two_rectangles(&fixture);
    target_request_drained(&fixture, 21u, 25u, 100u);
    target_singleton_complete(&fixture, 30u, 31u);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_note_quiet(&fixture.scheduler, 41u),
                     RFB_OK);

    const rfb_capture_final_observation_v1 *final = &fixture.finals[1];
    RFB_CHECK_EQ_INT(final->classification,
                     RFB_CAPTURE_FINAL_ASSOCIATION_CLOSED);
    RFB_CHECK_EQ_UINT(final->queue_to_drain_ms, 4u);
    RFB_CHECK_EQ_UINT(final->drain_to_fbu_ms, 5u);
    RFB_CHECK_EQ_UINT(final->quiet_duration_ms, 10u);
    RFB_CHECK_EQ_UINT(fixture.rectangles[0].sequence, 1u);
    RFB_CHECK_EQ_UINT(fixture.rectangles[1].sequence, 2u);
    RFB_CHECK_EQ_UINT(fixture.finals[0].sequence, 3u);
    RFB_CHECK_EQ_UINT(fixture.rectangles[INITIAL_MAX].sequence, 4u);
    RFB_CHECK_EQ_UINT(fixture.finals[1].sequence, 5u);
    for (size_t i = 0u; i < FINAL_CAPACITY; i++) {
        RFB_CHECK_EQ_UINT(fixture.finals[i].version,
                          RFB_CAPTURE_OBSERVATION_VERSION_1);
        RFB_CHECK_EQ_UINT(fixture.finals[i].size,
                          sizeof fixture.finals[i]);
    }
    RFB_CHECK(!fixture.finals[0].terminal);
    RFB_CHECK(fixture.finals[1].terminal);
}

RFB_TEST(rfb_capture_campaign,
         queued_request_requires_exact_fbur_length_and_monotonic_time)
{
    campaign_fixture fixture;
    campaign_fixture_init(&fixture, RFB_CAPTURE_GEOMETRY_WITHIN_REQUEST);
    initial_two_rectangles(&fixture);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_mutation_acknowledged(
                         &fixture.scheduler, 20u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_queue_started(
                         &fixture.scheduler, 21u, 100u, false),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(fixture.scheduler.failure,
                     RFB_CAPTURE_FAILURE_REQUEST_DRAIN);

    static const uint64_t rejected_lengths[] = {
        FBUR_WIRE_LENGTH - 1u, FBUR_WIRE_LENGTH + 1u};
    for (size_t i = 0u; i < 2u; i++) {
        campaign_fixture_init(&fixture, RFB_CAPTURE_GEOMETRY_WITHIN_REQUEST);
        initial_two_rectangles(&fixture);
        RFB_CHECK_EQ_INT(rfb_capture_scheduler_mutation_acknowledged(
                             &fixture.scheduler, 20u),
                         RFB_OK);
        RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_queue_started(
                             &fixture.scheduler, 21u, 100u, true),
                         RFB_OK);
        RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_queued(
                             &fixture.scheduler, 21u, rejected_lengths[i],
                             FBUR_WIRE_LENGTH),
                         RFB_ERR_PROTOCOL);
        RFB_CHECK_EQ_INT(fixture.scheduler.failure,
                         RFB_CAPTURE_FAILURE_REQUEST_DRAIN);
    }

    campaign_fixture_init(&fixture, RFB_CAPTURE_GEOMETRY_WITHIN_REQUEST);
    initial_two_rectangles(&fixture);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_mutation_acknowledged(
                         &fixture.scheduler, 20u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_queue_started(
                         &fixture.scheduler, 21u, 100u, true),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_queued(
                         &fixture.scheduler, 20u, FBUR_WIRE_LENGTH,
                         FBUR_WIRE_LENGTH),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(fixture.scheduler.failure,
                     RFB_CAPTURE_FAILURE_REQUEST_DRAIN);

    campaign_fixture_init(&fixture, RFB_CAPTURE_GEOMETRY_WITHIN_REQUEST);
    initial_two_rectangles(&fixture);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_mutation_acknowledged(
                         &fixture.scheduler, 20u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_queue_started(
                         &fixture.scheduler, 21u, 100u, true),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_queued(
                         &fixture.scheduler, 21u, FBUR_WIRE_LENGTH,
                         FBUR_WIRE_LENGTH),
                     RFB_OK);
}

RFB_TEST(rfb_capture_campaign,
         drained_request_requires_exact_transport_boundary)
{
    campaign_fixture fixture;
    campaign_fixture_init(&fixture, RFB_CAPTURE_GEOMETRY_WITHIN_REQUEST);
    initial_two_rectangles(&fixture);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_mutation_acknowledged(
                         &fixture.scheduler, 20u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_queue_started(
                         &fixture.scheduler, 21u, 100u, true),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_queued(
                         &fixture.scheduler, 21u, FBUR_WIRE_LENGTH,
                         FBUR_WIRE_LENGTH),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_drained(
                         &fixture.scheduler, 22u, 110u, false),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(fixture.scheduler.failure,
                     RFB_CAPTURE_FAILURE_REQUEST_DRAIN);

    static const uint64_t rejected_after[] = {109u, 111u};
    for (size_t i = 0u; i < 2u; i++) {
        campaign_fixture_init(&fixture, RFB_CAPTURE_GEOMETRY_WITHIN_REQUEST);
        initial_two_rectangles(&fixture);
        RFB_CHECK_EQ_INT(rfb_capture_scheduler_mutation_acknowledged(
                             &fixture.scheduler, 20u),
                         RFB_OK);
        RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_queue_started(
                             &fixture.scheduler, 21u, 100u, true),
                         RFB_OK);
        RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_queued(
                             &fixture.scheduler, 21u, FBUR_WIRE_LENGTH,
                             FBUR_WIRE_LENGTH),
                         RFB_OK);
        RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_drained(
                             &fixture.scheduler, 22u, rejected_after[i], true),
                         RFB_ERR_PROTOCOL);
        RFB_CHECK_EQ_INT(fixture.scheduler.failure,
                         RFB_CAPTURE_FAILURE_REQUEST_DRAIN);
    }

    campaign_fixture_init(&fixture, RFB_CAPTURE_GEOMETRY_WITHIN_REQUEST);
    initial_two_rectangles(&fixture);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_mutation_acknowledged(
                         &fixture.scheduler, 20u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_queue_started(
                         &fixture.scheduler, 21u, 100u, true),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_queued(
                         &fixture.scheduler, 21u, FBUR_WIRE_LENGTH,
                         FBUR_WIRE_LENGTH),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_drained(
                         &fixture.scheduler, 20u, 110u, true),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(fixture.scheduler.failure,
                     RFB_CAPTURE_FAILURE_REQUEST_DRAIN);

    campaign_fixture_init(&fixture, RFB_CAPTURE_GEOMETRY_WITHIN_REQUEST);
    initial_two_rectangles(&fixture);
    target_request_drained(&fixture, 21u, 22u, 100u);
    RFB_CHECK_EQ_INT(fixture.scheduler.state,
                     RFB_CAPTURE_SCHEDULER_OUTSTANDING);
}

RFB_TEST(rfb_capture_campaign,
         mutation_campaign_config_is_strict_and_atomic)
{
    campaign_fixture fixture;
    campaign_fixture_init(&fixture, RFB_CAPTURE_GEOMETRY_WITHIN_REQUEST);
    rfb_capture_scheduler_config config = campaign_config(&fixture);

    rfb_capture_query queries[2] = {fixture.query, fixture.query};
    queries[1].id++;
    config.queries = queries;
    config.query_count = 2u;
    check_config_rejected_atomically(&fixture, &config);

    config = campaign_config(&fixture);
    fixture.query.incremental = false;
    check_config_rejected_atomically(&fixture, &config);
    fixture.query.incremental = true;

    config = campaign_config(&fixture);
    fixture.query.x = 8u;
    fixture.query.width = 1016u;
    check_config_rejected_atomically(&fixture, &config);
    fixture.query.x = 0u;
    fixture.query.width = 1024u;

    config = campaign_config(&fixture);
    fixture.query.geometry_policy = RFB_CAPTURE_GEOMETRY_EXACT;
    check_config_rejected_atomically(&fixture, &config);
    fixture.query.geometry_policy = RFB_CAPTURE_GEOMETRY_WITHIN_REQUEST;

    config = campaign_config(&fixture);
    config.on_result = ignored_result;
    check_config_rejected_atomically(&fixture, &config);
}
