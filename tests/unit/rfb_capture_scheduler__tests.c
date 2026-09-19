// SPDX-License-Identifier: Apache-2.0

#include "rfb_test.h"

#include "farsee/apple_mvs_bits.h"
#include "farsee/encoding.h"
#include "farsee/rfb_capture_scheduler.h"

#include <stdint.h>
#include <string.h>

typedef struct capture_result_sink {
    rfb_capture_result result[4];
    size_t count;
} capture_result_sink;

static void capture_result_store(void *ctx, const rfb_capture_result *result)
{
    capture_result_sink *sink = (capture_result_sink *)ctx;
    RFB_CHECK(sink != NULL);
    RFB_CHECK(result != NULL);
    RFB_CHECK(sink->count < 4u);
    sink->result[sink->count++] = *result;
}

static size_t build_singleton_type0(uint8_t *body, size_t cap)
{
    RFB_CHECK(cap >= 9u);
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

static size_t build_run_two_type0(uint8_t *body, size_t cap)
{
    RFB_CHECK(cap >= 10u);
    // format=0, command=4, extended repeat nibble=0 (repeat one), marker m,
    // then the required seven zero bits to the byte boundary.
    static const uint8_t command[] = {0x48u, 0x36u, 0x80u};

    body[0] = 0u;
    body[1] = 3u;
    body[2] = 5u;
    body[3] = 0u;
    body[4] = 0u;
    body[5] = 9u;
    memcpy(body + 6u, command, sizeof command);
    body[9] = 0x6du;
    return 10u;
}

static rfb_capture_query capture_query(void)
{
    const rfb_capture_query query = {
        .id = 17u, .x = 16u, .y = 24u, .width = 8u, .height = 8u};
    return query;
}

static void finish_initial(rfb_capture_scheduler *scheduler)
{
    const rfb_rect_header initial = {
        .x = 0u, .y = 0u, .width = 1024u, .height = 768u,
        .encoding = RFB_ENCODING_RAW};
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_initial_request_sent(scheduler, 1u), RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_begin(scheduler, 1u), RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_record_rect(
                         scheduler, &initial, NULL, 0u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_complete(scheduler, 2u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(scheduler->state, RFB_CAPTURE_SCHEDULER_QUIET_INITIAL);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_note_quiet(scheduler, 12u), RFB_OK);
    RFB_CHECK_EQ_INT(scheduler->state, RFB_CAPTURE_SCHEDULER_READY);
}

static rfb_capture_query mutation_query(void)
{
    const rfb_capture_query query = {
        .id = 23u,
        .incremental = true,
        .geometry_policy = RFB_CAPTURE_GEOMETRY_WITHIN_REQUEST,
        .x = 0u,
        .y = 0u,
        .width = 1024u,
        .height = 768u,
    };
    return query;
}

static rfb_capture_scheduler_config mutation_config(
    const rfb_capture_query *query,
    rfb_capture_rect_observation_v1 *rectangles,
    rfb_capture_final_observation_v1 *finals)
{
    const rfb_capture_scheduler_config config = {
        .queries = query,
        .query_count = 1u,
        .framebuffer_width = 1024u,
        .framebuffer_height = 768u,
        .response_timeout_ms = 100u,
        .quiet_ms = 10u,
        .require_mutation_ack = true,
        .mutation_timeout_ms = 20u,
        .initial_rectangle_max = 2u,
        .rect_observations = rectangles,
        .rect_observation_capacity = 3u,
        .final_observations = finals,
        .final_observation_capacity = 2u,
    };
    return config;
}

static void enter_mutation_hold(
    rfb_capture_scheduler *scheduler,
    const rfb_capture_scheduler_config *config)
{
    const rfb_rect_header initial = {
        .x = 0u,
        .y = 0u,
        .width = 1024u,
        .height = 768u,
        .encoding = RFB_ENCODING_RAW,
    };
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_init_config(scheduler, config), RFB_OK);
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_initial_request_sent(scheduler, 1u), RFB_OK);
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_fbu_begin_at(scheduler, 1u, 2u), RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_record_rect(
                         scheduler, &initial, NULL, 0u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_complete(scheduler, 3u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_note_quiet(scheduler, 13u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(scheduler->state,
                     RFB_CAPTURE_SCHEDULER_MUTATION_HOLD);
}

static void enter_mutation_acked(
    rfb_capture_scheduler *scheduler,
    const rfb_capture_scheduler_config *config)
{
    enter_mutation_hold(scheduler, config);
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_mutation_acknowledged(scheduler, 14u), RFB_OK);
}

static void enter_request_draining(
    rfb_capture_scheduler *scheduler,
    const rfb_capture_scheduler_config *config)
{
    enter_mutation_acked(scheduler, config);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_queue_started(
                         scheduler, 15u, 100u, true),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_queued(
                         scheduler, 16u, 10u, 12u),
                     RFB_OK);
}

static void check_invalid_config(
    const rfb_capture_scheduler_config *config)
{
    rfb_capture_scheduler scheduler;
    rfb_capture_scheduler before;
    memset(&scheduler, 0x5a, sizeof scheduler);
    before = scheduler;
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_init_config(&scheduler, config),
        RFB_ERR_PROTOCOL);
    RFB_CHECK_MEM_EQ(&scheduler, &before, sizeof scheduler);
}

RFB_TEST(rfb_capture_scheduler, plan_accepts_exact_aligned_queries)
{
    const rfb_capture_query queries[] = {
        {.id = 1u, .x = 0u, .y = 0u, .width = 8u, .height = 8u},
        {.id = 2u, .x = 1000u, .y = 752u, .width = 24u, .height = 16u},
    };
    rfb_capture_scheduler scheduler;
    memset(&scheduler, 0xa5, sizeof scheduler);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_init(
                         &scheduler, queries, 2u, 1024u, 768u, 5000u, 10u,
                         NULL, NULL),
                     RFB_OK);
    RFB_CHECK_EQ_INT(scheduler.state, RFB_CAPTURE_SCHEDULER_WAIT_INITIAL);
    RFB_CHECK_EQ_UINT(scheduler.query_count, 2u);
    RFB_CHECK(rfb_capture_scheduler_active(&scheduler));
}

RFB_TEST(rfb_capture_scheduler, invalid_plan_leaves_destination_unchanged)
{
    const rfb_capture_query invalid[] = {
        {.id = 1u, .x = 3u, .y = 0u, .width = 8u, .height = 8u},
    };
    rfb_capture_scheduler scheduler;
    rfb_capture_scheduler before;
    memset(&scheduler, 0x5a, sizeof scheduler);
    before = scheduler;
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_init(
                         &scheduler, invalid, 1u, 1024u, 768u, 1000u, 10u,
                         NULL, NULL),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK(memcmp(&scheduler, &before, sizeof scheduler) == 0);

    RFB_CHECK_EQ_INT(rfb_capture_scheduler_init(
                         &scheduler, NULL, 0u, 1024u, 768u, 1000u, 10u, NULL,
                         NULL),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK(memcmp(&scheduler, &before, sizeof scheduler) == 0);
}

RFB_TEST(rfb_capture_scheduler, plan_rejects_bounds_zero_and_limits)
{
    rfb_capture_scheduler scheduler;
    const rfb_capture_query zero = capture_query();
    rfb_capture_query bad = zero;
    bad.width = 0u;
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_init(
                         &scheduler, &bad, 1u, 1024u, 768u, 1000u, 10u, NULL,
                         NULL),
                     RFB_ERR_PROTOCOL);
    bad = zero;
    bad.x = 1016u;
    bad.width = 16u;
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_init(
                         &scheduler, &bad, 1u, 1024u, 768u, 1000u, 10u, NULL,
                         NULL),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_init(
                         &scheduler, &zero, RFB_CAPTURE_QUERY_MAX + 1u, 1024u,
                         768u, 1000u, 10u, NULL, NULL),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_init(
                         &scheduler, &zero, 1u, 1024u, 768u, 0u, 10u, NULL,
                         NULL),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_init(
                         &scheduler, &zero, 1u, 1024u, 768u, 1000u, 0u, NULL,
                         NULL),
                     RFB_ERR_PROTOCOL);

    const rfb_capture_query duplicate_ids[] = {
        {.id = 9u, .x = 0u, .y = 0u, .width = 8u, .height = 8u},
        {.id = 9u, .x = 8u, .y = 0u, .width = 8u, .height = 8u},
    };
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_init(
                         &scheduler, duplicate_ids, 2u, 1024u, 768u, 1000u,
                         10u, NULL, NULL),
                     RFB_ERR_PROTOCOL);
}

RFB_TEST(rfb_capture_scheduler, initial_fbu_is_quarantined_until_quiet)
{
    const rfb_capture_query query = capture_query();
    capture_result_sink sink;
    memset(&sink, 0, sizeof sink);
    rfb_capture_scheduler scheduler;
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_init(
                         &scheduler, &query, 1u, 1024u, 768u, 1000u, 10u,
                         capture_result_store, &sink),
                     RFB_OK);
    rfb_capture_query out;
    RFB_CHECK(!rfb_capture_scheduler_next_request(&scheduler, &out));
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_initial_request_sent(&scheduler,
                                                                1u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_begin(&scheduler, 1u), RFB_OK);
    RFB_CHECK_EQ_INT(scheduler.state,
                     RFB_CAPTURE_SCHEDULER_RECEIVING_INITIAL);
    RFB_CHECK(!rfb_capture_scheduler_next_request(&scheduler, &out));
    const rfb_rect_header initial = {
        .x = 0u, .y = 0u, .width = 1024u, .height = 768u,
        .encoding = RFB_ENCODING_RAW};
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_record_rect(
                         &scheduler, &initial, NULL, 0u),
                     RFB_OK);
    RFB_CHECK(!rfb_capture_scheduler_next_request(&scheduler, &out));
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_complete(&scheduler, 2u),
                     RFB_OK);
    RFB_CHECK(!rfb_capture_scheduler_next_request(&scheduler, &out));
    RFB_CHECK_EQ_UINT(sink.count, 0u);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_note_quiet(&scheduler, 11u),
                     RFB_OK);
    RFB_CHECK_EQ_UINT(sink.count, 0u);
    RFB_CHECK(!rfb_capture_scheduler_next_request(&scheduler, &out));
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_note_quiet(&scheduler, 12u),
                     RFB_OK);
    RFB_CHECK_EQ_UINT(sink.count, 1u);
    RFB_CHECK(sink.result[0].initial);
    RFB_CHECK(rfb_capture_scheduler_next_request(&scheduler, &out));
    RFB_CHECK_EQ_UINT(out.id, query.id);
}

RFB_TEST(rfb_capture_scheduler, mandatory_initial_response_is_time_bounded)
{
    const rfb_capture_query query = capture_query();
    rfb_capture_scheduler scheduler;
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_init(
                         &scheduler, &query, 1u, 1024u, 768u, 100u, 10u, NULL,
                         NULL),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_initial_request_sent(&scheduler,
                                                                50u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_tick(&scheduler, 149u), RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_tick(&scheduler, 150u),
                     RFB_ERR_TIMEOUT);
    RFB_CHECK_EQ_INT(scheduler.failure, RFB_CAPTURE_FAILURE_TIMEOUT);
}

RFB_TEST(rfb_capture_scheduler,
         initial_only_zrle_control_closes_after_quiet)
{
    rfb_capture_rect_observation_v1 rectangles[5];
    rfb_capture_final_observation_v1 finals[2];
    rfb_capture_scheduler scheduler;
    const rfb_capture_scheduler_config config = {
        .queries = NULL,
        .query_count = 0u,
        .framebuffer_width = 1024u,
        .framebuffer_height = 768u,
        .response_timeout_ms = 1000u,
        .quiet_ms = 10u,
        .initial_only = true,
        .initial_zrle_only = true,
        .initial_rectangle_max = 4u,
        .rect_observations = rectangles,
        .rect_observation_capacity = 5u,
        .final_observations = finals,
        .final_observation_capacity = 2u,
    };
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_init_config(&scheduler, &config), RFB_OK);
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_initial_request_sent(&scheduler, 1u), RFB_OK);
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_fbu_begin(&scheduler, 2u), RFB_OK);
    const rfb_rect_header zrle = {
        .x = 0u, .y = 0u, .width = 1024u, .height = 768u,
        .encoding = RFB_ENCODING_ZRLE};
    const rfb_rect_header cursor = {
        .x = 0u, .y = 0u, .width = 16u, .height = 16u,
        .encoding = RFB_ENCODING_CURSOR};
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_record_rect(
                         &scheduler, &zrle, NULL, 0u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_record_rect(
                         &scheduler, &cursor, NULL, 0u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_complete(&scheduler, 2u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_note_quiet(&scheduler, 12u),
                     RFB_OK);
    RFB_CHECK(rfb_capture_scheduler_done(&scheduler));
    RFB_CHECK(finals[0].present);
    RFB_CHECK(finals[0].terminal);
    RFB_CHECK_EQ_INT(finals[0].classification,
                     RFB_CAPTURE_FINAL_CONTROL_CLOSED);
}

RFB_TEST(rfb_capture_scheduler,
         initial_only_zrle_rejects_mixed_pixels_and_accepts_noop_resize)
{
    rfb_capture_rect_observation_v1 rectangles[3];
    rfb_capture_final_observation_v1 finals[2];
    rfb_capture_scheduler scheduler;
    const rfb_capture_scheduler_config config = {
        .framebuffer_width = 1024u,
        .framebuffer_height = 768u,
        .response_timeout_ms = 1000u,
        .quiet_ms = 10u,
        .initial_only = true,
        .initial_zrle_only = true,
        .initial_rectangle_max = 2u,
        .rect_observations = rectangles,
        .rect_observation_capacity = 3u,
        .final_observations = finals,
        .final_observation_capacity = 2u,
    };
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_init_config(&scheduler, &config), RFB_OK);
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_initial_request_sent(&scheduler, 1u), RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_begin(&scheduler, 1u), RFB_OK);
    const rfb_rect_header raw = {
        .x = 0u, .y = 0u, .width = 1024u, .height = 768u,
        .encoding = RFB_ENCODING_RAW};
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_record_rect(
                         &scheduler, &raw, NULL, 0u),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(scheduler.failure,
                     RFB_CAPTURE_FAILURE_RECT_ENCODING);

    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_init_config(&scheduler, &config), RFB_OK);
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_initial_request_sent(&scheduler, 1u), RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_begin(&scheduler, 2u), RFB_OK);
    const rfb_rect_header desktop = {
        .x = 0u, .y = 0u, .width = 1024u, .height = 768u,
        .encoding = RFB_ENCODING_DESKTOPSIZE};
    const rfb_rect_header zrle = {
        .x = 0u, .y = 0u, .width = 1024u, .height = 768u,
        .encoding = RFB_ENCODING_ZRLE};
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_record_rect(
                         &scheduler, &desktop, NULL, 0u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_record_rect(
                         &scheduler, &zrle, NULL, 0u),
                     RFB_OK);
}

RFB_TEST(rfb_capture_scheduler,
         initial_only_zrle_rejects_invalid_config_and_coverage)
{
    rfb_capture_rect_observation_v1 rectangles[4];
    rfb_capture_final_observation_v1 finals[2];
    rfb_capture_scheduler scheduler;
    rfb_capture_scheduler before;
    const rfb_capture_query query = capture_query();
    rfb_capture_scheduler_config config = {
        .framebuffer_width = 1024u,
        .framebuffer_height = 768u,
        .response_timeout_ms = 1000u,
        .quiet_ms = 10u,
        .initial_only = true,
        .initial_zrle_only = true,
        .initial_rectangle_max = 3u,
        .rect_observations = rectangles,
        .rect_observation_capacity = 4u,
        .final_observations = finals,
        .final_observation_capacity = 2u,
    };
    memset(&scheduler, 0x5a, sizeof scheduler);
    before = scheduler;
    config.queries = &query;
    config.query_count = 1u;
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_init_config(&scheduler, &config),
        RFB_ERR_PROTOCOL);
    RFB_CHECK_MEM_EQ(&scheduler, &before, sizeof scheduler);
    config.queries = NULL;
    config.query_count = 0u;
    config.initial_zrle_only = false;
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_init_config(&scheduler, &config),
        RFB_ERR_PROTOCOL);
    RFB_CHECK_MEM_EQ(&scheduler, &before, sizeof scheduler);
    config.initial_zrle_only = true;

    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_init_config(&scheduler, &config), RFB_OK);
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_initial_request_sent(&scheduler, 1u), RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_begin(&scheduler, 1u), RFB_OK);
    const rfb_rect_header subrectangle = {
        .x = 0u, .y = 0u, .width = 512u, .height = 768u,
        .encoding = RFB_ENCODING_ZRLE};
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_record_rect(
                         &scheduler, &subrectangle, NULL, 0u),
                     RFB_ERR_PROTOCOL);

    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_init_config(&scheduler, &config), RFB_OK);
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_initial_request_sent(&scheduler, 1u), RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_begin(&scheduler, 2u), RFB_OK);
    const rfb_rect_header zrle = {
        .x = 0u, .y = 0u, .width = 1024u, .height = 768u,
        .encoding = RFB_ENCODING_ZRLE};
    const rfb_rect_header desktop = {
        .x = 0u, .y = 0u, .width = 1024u, .height = 768u,
        .encoding = RFB_ENCODING_DESKTOPSIZE};
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_record_rect(
                         &scheduler, &zrle, NULL, 0u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_record_rect(
                         &scheduler, &desktop, NULL, 0u),
                     RFB_ERR_PROTOCOL);

    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_init_config(&scheduler, &config), RFB_OK);
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_initial_request_sent(&scheduler, 1u), RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_begin(&scheduler, 2u), RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_record_rect(
                         &scheduler, &zrle, NULL, 0u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_record_rect(
                         &scheduler, &zrle, NULL, 0u),
                     RFB_ERR_PROTOCOL);

    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_init_config(&scheduler, &config), RFB_OK);
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_initial_request_sent(&scheduler, 1u), RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_begin(&scheduler, 2u), RFB_OK);
    const rfb_rect_header invalid_cursor = {
        .x = 16u, .y = 0u, .width = 16u, .height = 16u,
        .encoding = RFB_ENCODING_CURSOR};
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_record_rect(
                         &scheduler, &invalid_cursor, NULL, 0u),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(scheduler.failure,
                     RFB_CAPTURE_FAILURE_RECT_GEOMETRY);

    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_init_config(&scheduler, &config), RFB_OK);
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_initial_request_sent(&scheduler, 1u), RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_begin(&scheduler, 2u), RFB_OK);
    const rfb_rect_header zero_cursor = {
        .x = 0u, .y = 0u, .width = 0u, .height = 0u,
        .encoding = RFB_ENCODING_CURSOR};
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_record_rect(
                         &scheduler, &zero_cursor, NULL, 0u),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(scheduler.failure,
                     RFB_CAPTURE_FAILURE_RECT_GEOMETRY);
}

RFB_TEST(rfb_capture_scheduler, exact_type0_response_classifies_direct_sample)
{
    const rfb_capture_query query = capture_query();
    capture_result_sink sink;
    memset(&sink, 0, sizeof sink);
    rfb_capture_scheduler scheduler;
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_init(
                         &scheduler, &query, 1u, 1024u, 768u, 1000u, 10u,
                         capture_result_store, &sink),
                     RFB_OK);
    finish_initial(&scheduler);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_sent(&scheduler, 100u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_begin(&scheduler, 1u), RFB_OK);
    uint8_t body[9];
    const size_t body_len = build_singleton_type0(body, sizeof body);
    const rfb_rect_header actual = {
        .x = query.x, .y = query.y, .width = query.width,
        .height = query.height, .encoding = RFB_ENCODING_APPLE_MVS};
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_record_rect(
                         &scheduler, &actual, body, body_len),
                     RFB_OK);
    RFB_CHECK(!rfb_capture_scheduler_next_request(&scheduler, NULL));
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_complete(&scheduler, 101u),
                     RFB_OK);
    RFB_CHECK_EQ_UINT(sink.count, 1u);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_note_activity(&scheduler, 105u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_note_quiet(&scheduler, 114u),
                     RFB_OK);
    RFB_CHECK_EQ_UINT(sink.count, 1u);
    RFB_CHECK(!rfb_capture_scheduler_done(&scheduler));
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_note_quiet(&scheduler, 115u),
                     RFB_OK);
    RFB_CHECK_EQ_UINT(sink.count, 2u);
    const rfb_capture_result *result = &sink.result[1];
    RFB_CHECK(!result->initial);
    RFB_CHECK(result->mvs_type0);
    RFB_CHECK_EQ_UINT(result->mvs_normal_count, 3u);
    RFB_CHECK_EQ_UINT(result->mvs_large_count, 5u);
    RFB_CHECK_EQ_UINT(result->mvs_payload_len, body_len);
    RFB_CHECK_EQ_UINT(result->mvs_image_offset, 8u);
    RFB_CHECK_EQ_UINT(result->mvs_command_records, 1u);
    RFB_CHECK_EQ_UINT(result->mvs_command_marker_end_bits, 13u);
    RFB_CHECK_EQ_UINT(result->mvs_command_padding_bits, 3u);
    RFB_CHECK_EQ_UINT(result->mvs_image_marker_start_bits, 0u);
    RFB_CHECK_EQ_UINT(result->mvs_image_marker_end_bits, 8u);
    RFB_CHECK_EQ_UINT(result->mvs_image_padding_bits, 0u);
    RFB_CHECK_EQ_UINT(result->mvs_first_command, 4u);
    RFB_CHECK_EQ_UINT(result->mvs_first_run, 1u);
    RFB_CHECK(result->direct_one_record_run_one);
    RFB_CHECK(rfb_capture_scheduler_done(&scheduler));
}

RFB_TEST(rfb_capture_scheduler,
         delayed_competing_fbu_discards_unadmitted_target)
{
    const rfb_capture_query query = capture_query();
    capture_result_sink sink;
    memset(&sink, 0, sizeof sink);
    rfb_capture_scheduler scheduler;
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_init(
                         &scheduler, &query, 1u, 1024u, 768u, 1000u, 10u,
                         capture_result_store, &sink),
                     RFB_OK);
    finish_initial(&scheduler);
    RFB_CHECK_EQ_UINT(sink.count, 1u);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_sent(&scheduler, 100u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_begin(&scheduler, 1u), RFB_OK);
    uint8_t body[9];
    const size_t body_len = build_singleton_type0(body, sizeof body);
    const rfb_rect_header actual = {
        .x = query.x, .y = query.y, .width = query.width,
        .height = query.height, .encoding = RFB_ENCODING_APPLE_MVS};
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_record_rect(
                         &scheduler, &actual, body, body_len),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_complete(&scheduler, 101u),
                     RFB_OK);
    RFB_CHECK_EQ_UINT(sink.count, 1u);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_begin(&scheduler, 0u),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_UINT(sink.count, 1u);
    RFB_CHECK_EQ_INT(scheduler.failure,
                     RFB_CAPTURE_FAILURE_UNSOLICITED_FBU);
}

RFB_TEST(rfb_capture_scheduler, initial_desktop_size_invalidates_frozen_plan)
{
    const rfb_capture_query query = capture_query();
    capture_result_sink sink;
    memset(&sink, 0, sizeof sink);
    rfb_capture_scheduler scheduler;
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_init(
                         &scheduler, &query, 1u, 1024u, 768u, 1000u, 10u,
                         capture_result_store, &sink),
                     RFB_OK);
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_initial_request_sent(&scheduler, 1u), RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_begin(&scheduler, 1u), RFB_OK);
    const rfb_rect_header resize = {
        .x = 0u, .y = 0u, .width = 1000u, .height = 752u,
        .encoding = RFB_ENCODING_DESKTOPSIZE};
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_record_rect(
                         &scheduler, &resize, NULL, 0u),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_UINT(sink.count, 0u);
    RFB_CHECK_EQ_INT(scheduler.failure,
                     RFB_CAPTURE_FAILURE_RECT_GEOMETRY);
}

RFB_TEST(rfb_capture_scheduler, quiet_activity_cannot_extend_bound_forever)
{
    const rfb_capture_query query = capture_query();
    rfb_capture_scheduler scheduler;
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_init(
                         &scheduler, &query, 1u, 1024u, 768u, 100u, 10u, NULL,
                         NULL),
                     RFB_OK);
    finish_initial(&scheduler);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_sent(&scheduler, 100u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_begin(&scheduler, 1u), RFB_OK);
    uint8_t body[9];
    const size_t body_len = build_singleton_type0(body, sizeof body);
    const rfb_rect_header actual = {
        .x = query.x, .y = query.y, .width = query.width,
        .height = query.height, .encoding = RFB_ENCODING_APPLE_MVS};
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_record_rect(
                         &scheduler, &actual, body, body_len),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_complete(&scheduler, 101u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_note_activity(&scheduler, 190u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_note_activity(&scheduler, 200u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_note_activity(&scheduler, 201u),
                     RFB_ERR_TIMEOUT);
    RFB_CHECK_EQ_INT(scheduler.failure, RFB_CAPTURE_FAILURE_TIMEOUT);
}

RFB_TEST(rfb_capture_scheduler, targeted_response_rejects_ambiguous_shape)
{
    const rfb_capture_query query = capture_query();
    rfb_capture_scheduler scheduler;
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_init(
                         &scheduler, &query, 1u, 1024u, 768u, 1000u, 10u,
                         NULL, NULL),
                     RFB_OK);
    finish_initial(&scheduler);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_sent(&scheduler, 1u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_begin(&scheduler, 2u),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(scheduler.state, RFB_CAPTURE_SCHEDULER_FAILED);
    RFB_CHECK_EQ_INT(scheduler.failure, RFB_CAPTURE_FAILURE_RECT_COUNT);
}

RFB_TEST(rfb_capture_scheduler, targeted_response_requires_actual_geometry)
{
    const rfb_capture_query query = capture_query();
    rfb_capture_scheduler scheduler;
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_init(
                         &scheduler, &query, 1u, 1024u, 768u, 1000u, 10u,
                         NULL, NULL),
                     RFB_OK);
    finish_initial(&scheduler);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_sent(&scheduler, 1u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_begin(&scheduler, 1u), RFB_OK);
    // Keep the widened actual rectangle structurally valid so this regression
    // isolates policy geometry rather than failing earlier at MVS grammar.
    uint8_t body[10];
    const size_t body_len = build_run_two_type0(body, sizeof body);
    const rfb_rect_header wrong = {
        .x = query.x, .y = query.y, .width = 16u, .height = query.height,
        .encoding = RFB_ENCODING_APPLE_MVS};
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_record_rect(
                         &scheduler, &wrong, body, body_len),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(scheduler.failure, RFB_CAPTURE_FAILURE_RECT_GEOMETRY);
}

RFB_TEST(rfb_capture_scheduler, targeted_response_requires_type0_mvs)
{
    const rfb_capture_query query = capture_query();
    rfb_capture_scheduler scheduler;
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_init(
                         &scheduler, &query, 1u, 1024u, 768u, 1000u, 10u,
                         NULL, NULL),
                     RFB_OK);
    finish_initial(&scheduler);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_sent(&scheduler, 1u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_begin(&scheduler, 1u), RFB_OK);
    const rfb_rect_header wrong = {
        .x = query.x, .y = query.y, .width = query.width,
        .height = query.height, .encoding = RFB_ENCODING_RAW};
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_record_rect(
                         &scheduler, &wrong, NULL, 0u),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(scheduler.failure, RFB_CAPTURE_FAILURE_RECT_ENCODING);
}

RFB_TEST(rfb_capture_scheduler, targeted_response_rejects_unknown_quality)
{
    const rfb_capture_query query = capture_query();
    rfb_capture_scheduler scheduler;
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_init(
                         &scheduler, &query, 1u, 1024u, 768u, 1000u, 10u,
                         NULL, NULL),
                     RFB_OK);
    finish_initial(&scheduler);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_sent(&scheduler, 1u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_begin(&scheduler, 1u), RFB_OK);
    uint8_t body[9];
    const size_t body_len = build_singleton_type0(body, sizeof body);
    body[1] = 7u;
    const rfb_rect_header actual = {
        .x = query.x, .y = query.y, .width = query.width,
        .height = query.height, .encoding = RFB_ENCODING_APPLE_MVS};
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_record_rect(
                         &scheduler, &actual, body, body_len),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(scheduler.failure, RFB_CAPTURE_FAILURE_MVS_GRAMMAR);
}

RFB_TEST(rfb_capture_scheduler, targeted_response_rejects_type_and_leftover)
{
    const rfb_capture_query query = capture_query();
    rfb_capture_scheduler scheduler;
    uint8_t body[10];
    size_t body_len = build_singleton_type0(body, sizeof body);
    const rfb_rect_header actual = {
        .x = query.x, .y = query.y, .width = query.width,
        .height = query.height, .encoding = RFB_ENCODING_APPLE_MVS};

    RFB_CHECK_EQ_INT(rfb_capture_scheduler_init(
                         &scheduler, &query, 1u, 1024u, 768u, 1000u, 10u,
                         NULL, NULL),
                     RFB_OK);
    finish_initial(&scheduler);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_sent(&scheduler, 1u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_begin(&scheduler, 1u), RFB_OK);
    body[0] = 1u;
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_record_rect(
                         &scheduler, &actual, body, body_len),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(scheduler.failure, RFB_CAPTURE_FAILURE_MVS_GRAMMAR);

    body_len = build_singleton_type0(body, sizeof body);
    body[body_len++] = 0x80u;
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_init(
                         &scheduler, &query, 1u, 1024u, 768u, 1000u, 10u,
                         NULL, NULL),
                     RFB_OK);
    finish_initial(&scheduler);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_sent(&scheduler, 1u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_begin(&scheduler, 1u), RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_record_rect(
                         &scheduler, &actual, body, body_len),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(scheduler.failure, RFB_CAPTURE_FAILURE_MVS_GRAMMAR);
}

RFB_TEST(rfb_capture_scheduler, monotonic_sequence_gap_fails_closed)
{
    const rfb_capture_query query = capture_query();
    rfb_capture_scheduler scheduler;
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_init(
                         &scheduler, &query, 1u, 1024u, 768u, 100u, 10u, NULL,
                         NULL),
                     RFB_OK);
    finish_initial(&scheduler);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_sent(&scheduler, 100u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_tick(&scheduler, 99u),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(scheduler.failure, RFB_CAPTURE_FAILURE_SEQUENCE);
}

RFB_TEST(rfb_capture_scheduler, timeout_and_eof_are_sticky)
{
    const rfb_capture_query query = capture_query();
    rfb_capture_scheduler scheduler;
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_init(
                         &scheduler, &query, 1u, 1024u, 768u, 100u, 10u, NULL,
                         NULL),
                     RFB_OK);
    finish_initial(&scheduler);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_sent(&scheduler, 50u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_tick(&scheduler, 149u), RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_tick(&scheduler, 150u),
                     RFB_ERR_TIMEOUT);
    RFB_CHECK_EQ_INT(scheduler.failure, RFB_CAPTURE_FAILURE_TIMEOUT);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_note_eof(&scheduler),
                     RFB_ERR_TIMEOUT);
    RFB_CHECK_EQ_INT(scheduler.failure, RFB_CAPTURE_FAILURE_TIMEOUT);
}

RFB_TEST(rfb_capture_scheduler, unsolicited_fbu_and_eof_fail_closed)
{
    const rfb_capture_query query = capture_query();
    rfb_capture_scheduler scheduler;
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_init(
                         &scheduler, &query, 1u, 1024u, 768u, 100u, 10u, NULL,
                         NULL),
                     RFB_OK);
    finish_initial(&scheduler);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_begin(&scheduler, 1u),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(scheduler.failure,
                     RFB_CAPTURE_FAILURE_UNSOLICITED_FBU);

    RFB_CHECK_EQ_INT(rfb_capture_scheduler_init(
                         &scheduler, &query, 1u, 1024u, 768u, 100u, 10u, NULL,
                         NULL),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_note_eof(&scheduler), RFB_ERR_EOF);
    RFB_CHECK_EQ_INT(scheduler.failure, RFB_CAPTURE_FAILURE_EOF);
}

// The session can answer one non-incremental full-screen request with
// the paint update, then announces the desktop size in a second update. The
// announcement carries no paint and cannot change the framebuffer, so it must
// not be mistaken for an unsolicited paint.
RFB_TEST(rfb_capture_scheduler, trailing_desktop_size_announcement_is_benign)
{
    const rfb_capture_query query = capture_query();
    capture_result_sink sink;
    memset(&sink, 0, sizeof sink);
    rfb_capture_scheduler scheduler;
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_init(
                         &scheduler, &query, 1u, 1024u, 768u, 1000u, 10u,
                         capture_result_store, &sink),
                     RFB_OK);
    finish_initial(&scheduler);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_sent(&scheduler, 100u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_begin(&scheduler, 1u), RFB_OK);
    uint8_t body[9];
    const size_t body_len = build_singleton_type0(body, sizeof body);
    const rfb_rect_header actual = {
        .x = query.x, .y = query.y, .width = query.width,
        .height = query.height, .encoding = RFB_ENCODING_APPLE_MVS};
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_record_rect(
                         &scheduler, &actual, body, body_len),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_complete(&scheduler, 101u),
                     RFB_OK);

    // The trailing announcement must be accepted and must not fail the run.
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_begin(&scheduler, 1u), RFB_OK);
    const rfb_rect_header announcement = {
        .x = 0u, .y = 0u, .width = 1024u, .height = 768u,
        .encoding = RFB_ENCODING_DESKTOPSIZE};
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_record_rect(
                         &scheduler, &announcement, NULL, 0u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_complete(&scheduler, 102u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(scheduler.failure, RFB_CAPTURE_FAILURE_NONE);

    RFB_CHECK_EQ_INT(rfb_capture_scheduler_note_quiet(&scheduler, 112u),
                     RFB_OK);
    RFB_CHECK_EQ_UINT(sink.count, 2u);
    RFB_CHECK(sink.result[1].mvs_type0);
}

// A desktop-size announcement that reports different geometry is a real
// change, not an echo, and must still fail closed.
RFB_TEST(rfb_capture_scheduler, trailing_desktop_size_resize_fails_closed)
{
    const rfb_capture_query query = capture_query();
    capture_result_sink sink;
    memset(&sink, 0, sizeof sink);
    rfb_capture_scheduler scheduler;
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_init(
                         &scheduler, &query, 1u, 1024u, 768u, 1000u, 10u,
                         capture_result_store, &sink),
                     RFB_OK);
    finish_initial(&scheduler);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_sent(&scheduler, 100u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_begin(&scheduler, 1u), RFB_OK);
    uint8_t body[9];
    const size_t body_len = build_singleton_type0(body, sizeof body);
    const rfb_rect_header actual = {
        .x = query.x, .y = query.y, .width = query.width,
        .height = query.height, .encoding = RFB_ENCODING_APPLE_MVS};
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_record_rect(
                         &scheduler, &actual, body, body_len),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_complete(&scheduler, 101u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_begin(&scheduler, 1u), RFB_OK);
    const rfb_rect_header resized = {
        .x = 0u, .y = 0u, .width = 800u, .height = 600u,
        .encoding = RFB_ENCODING_DESKTOPSIZE};
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_record_rect(
                         &scheduler, &resized, NULL, 0u),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(scheduler.failure, RFB_CAPTURE_FAILURE_RECT_GEOMETRY);
}

// Tolerating announcements must not weaken the unsolicited-paint rule.
RFB_TEST(rfb_capture_scheduler, trailing_paint_without_request_still_fails)
{
    const rfb_capture_query query = capture_query();
    capture_result_sink sink;
    memset(&sink, 0, sizeof sink);
    rfb_capture_scheduler scheduler;
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_init(
                         &scheduler, &query, 1u, 1024u, 768u, 1000u, 10u,
                         capture_result_store, &sink),
                     RFB_OK);
    finish_initial(&scheduler);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_sent(&scheduler, 100u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_begin(&scheduler, 1u), RFB_OK);
    uint8_t body[9];
    const size_t body_len = build_singleton_type0(body, sizeof body);
    const rfb_rect_header actual = {
        .x = query.x, .y = query.y, .width = query.width,
        .height = query.height, .encoding = RFB_ENCODING_APPLE_MVS};
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_record_rect(
                         &scheduler, &actual, body, body_len),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_complete(&scheduler, 101u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_begin(&scheduler, 1u), RFB_OK);
    const rfb_rect_header paint = {
        .x = query.x, .y = query.y, .width = query.width,
        .height = query.height, .encoding = RFB_ENCODING_APPLE_MVS};
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_record_rect(
                         &scheduler, &paint, body, body_len),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(scheduler.failure,
                     RFB_CAPTURE_FAILURE_UNSOLICITED_FBU);
}

// The quiet-initial phase accepts a trailing announcement while settling. A
// competing paint in that phase must still fail closed.
RFB_TEST(rfb_capture_scheduler, quiet_initial_announcement_and_paint)
{
    const rfb_capture_query query = capture_query();
    capture_result_sink sink;
    memset(&sink, 0, sizeof sink);
    rfb_capture_scheduler scheduler;
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_init(
                         &scheduler, &query, 1u, 1024u, 768u, 1000u, 10u,
                         capture_result_store, &sink),
                     RFB_OK);
    const rfb_rect_header initial = {
        .x = 0u, .y = 0u, .width = 1024u, .height = 768u,
        .encoding = RFB_ENCODING_RAW};
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_initial_request_sent(&scheduler, 1u), RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_begin(&scheduler, 1u), RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_record_rect(
                         &scheduler, &initial, NULL, 0u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_complete(&scheduler, 2u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(scheduler.state, RFB_CAPTURE_SCHEDULER_QUIET_INITIAL);

    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_begin(&scheduler, 1u), RFB_OK);
    RFB_CHECK_EQ_INT(scheduler.state,
                     RFB_CAPTURE_SCHEDULER_RECEIVING_ANNOUNCEMENT);
    const rfb_rect_header announcement = {
        .x = 0u, .y = 0u, .width = 1024u, .height = 768u,
        .encoding = RFB_ENCODING_DESKTOPSIZE};
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_record_rect(
                         &scheduler, &announcement, NULL, 0u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_complete(&scheduler, 3u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(scheduler.state, RFB_CAPTURE_SCHEDULER_QUIET_INITIAL);
    RFB_CHECK_EQ_INT(scheduler.failure, RFB_CAPTURE_FAILURE_NONE);

    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_begin(&scheduler, 1u), RFB_OK);
    const rfb_rect_header paint = {
        .x = 0u, .y = 0u, .width = 1024u, .height = 768u,
        .encoding = RFB_ENCODING_ZRLE};
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_record_rect(
                         &scheduler, &paint, NULL, 0u),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(scheduler.failure,
                     RFB_CAPTURE_FAILURE_UNSOLICITED_FBU);
}

// Typed control traffic carries no framebuffer damage, so it must not restart
// or starve the quiet window.
RFB_TEST(rfb_capture_scheduler, control_activity_does_not_restart_quiet)
{
    const rfb_capture_query query = capture_query();
    capture_result_sink sink;
    memset(&sink, 0, sizeof sink);
    rfb_capture_scheduler scheduler;
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_init(
                         &scheduler, &query, 1u, 1024u, 768u, 1000u, 100u,
                         capture_result_store, &sink),
                     RFB_OK);
    const rfb_rect_header initial = {
        .x = 0u, .y = 0u, .width = 1024u, .height = 768u,
        .encoding = RFB_ENCODING_RAW};
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_initial_request_sent(&scheduler, 1u), RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_begin(&scheduler, 1u), RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_record_rect(
                         &scheduler, &initial, NULL, 0u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_complete(&scheduler, 10u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(scheduler.state, RFB_CAPTURE_SCHEDULER_QUIET_INITIAL);

    // Nine control messages inside the 100 ms window, one every 10 ms.
    for (uint64_t i = 1u; i <= 9u; i++) {
        RFB_CHECK_EQ_INT(rfb_capture_scheduler_note_control_activity(
                             &scheduler, 10u + i * 10u),
                         RFB_OK);
    }
    // Damage-free traffic must leave the window intact, so it closes on time.
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_note_quiet(&scheduler, 111u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(scheduler.state, RFB_CAPTURE_SCHEDULER_READY);
    RFB_CHECK_EQ_INT(scheduler.failure, RFB_CAPTURE_FAILURE_NONE);
}

// Ignoring control traffic must not disable the run's outer bound: a session
// that only ever emits control must still fail closed on the response timeout.
RFB_TEST(rfb_capture_scheduler, control_activity_still_honours_the_timeout)
{
    const rfb_capture_query query = capture_query();
    capture_result_sink sink;
    memset(&sink, 0, sizeof sink);
    rfb_capture_scheduler scheduler;
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_init(
                         &scheduler, &query, 1u, 1024u, 768u, 100u, 1000u,
                         capture_result_store, &sink),
                     RFB_OK);
    const rfb_rect_header initial = {
        .x = 0u, .y = 0u, .width = 1024u, .height = 768u,
        .encoding = RFB_ENCODING_RAW};
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_initial_request_sent(&scheduler, 1u), RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_begin(&scheduler, 1u), RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_record_rect(
                         &scheduler, &initial, NULL, 0u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_complete(&scheduler, 10u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_note_control_activity(
                         &scheduler, 50u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_note_control_activity(
                         &scheduler, 111u),
                     RFB_ERR_TIMEOUT);
    RFB_CHECK_EQ_INT(scheduler.failure, RFB_CAPTURE_FAILURE_TIMEOUT);
}

RFB_TEST(rfb_capture_scheduler,
         observations_reject_capacity_arithmetic_overflow)
{
    const rfb_capture_query query = {
        .id = 1u,
        .incremental = true,
        .geometry_policy = RFB_CAPTURE_GEOMETRY_WITHIN_REQUEST,
        .x = 0u,
        .y = 0u,
        .width = 1024u,
        .height = 768u,
    };
    rfb_capture_rect_observation_v1 rectangle;
    rfb_capture_final_observation_v1 finals[2];
    rfb_capture_scheduler scheduler;
    rfb_capture_scheduler before;
    memset(&scheduler, 0x5a, sizeof scheduler);
    before = scheduler;
    const rfb_capture_scheduler_config config = {
        .queries = &query,
        .query_count = 1u,
        .framebuffer_width = 1024u,
        .framebuffer_height = 768u,
        .response_timeout_ms = 1000u,
        .quiet_ms = 10u,
        .require_mutation_ack = true,
        .mutation_timeout_ms = 100u,
        .initial_rectangle_max = SIZE_MAX,
        .rect_observations = &rectangle,
        .rect_observation_capacity = 0u,
        .final_observations = finals,
        .final_observation_capacity = 2u,
    };

    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_init_config(&scheduler, &config),
        RFB_ERR_PROTOCOL);
    RFB_CHECK_MEM_EQ(&scheduler, &before, sizeof scheduler);
}

RFB_TEST(rfb_capture_scheduler,
         mutation_request_drain_records_bounded_observations)
{
    const rfb_capture_query query = mutation_query();
    rfb_capture_rect_observation_v1 rectangles[3];
    rfb_capture_final_observation_v1 finals[2];
    const rfb_capture_scheduler_config config =
        mutation_config(&query, rectangles, finals);
    rfb_capture_scheduler scheduler;
    enter_mutation_hold(&scheduler, &config);

    RFB_CHECK_EQ_UINT(scheduler.rect_observation_count, 1u);
    RFB_CHECK_EQ_UINT(scheduler.final_observation_count, 1u);
    RFB_CHECK_EQ_UINT(rectangles[0].sequence, 1u);
    RFB_CHECK_EQ_INT(rectangles[0].phase, RFB_CAPTURE_PHASE_INITIAL);
    RFB_CHECK_EQ_UINT(finals[0].sequence, 2u);
    RFB_CHECK(!finals[0].terminal);
    RFB_CHECK_EQ_INT(finals[0].classification,
                     RFB_CAPTURE_FINAL_QUARANTINED_INITIAL);

    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_mutation_acknowledged(&scheduler, 14u), RFB_OK);
    rfb_capture_query out;
    RFB_CHECK(rfb_capture_scheduler_next_request(&scheduler, &out));
    RFB_CHECK_EQ_UINT(out.id, query.id);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_queue_started(
                         &scheduler, 15u, 100u, true),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_queued(
                         &scheduler, 16u, 10u, 12u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_drained(
                         &scheduler, 17u, 112u, true),
                     RFB_OK);
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_fbu_begin_at(&scheduler, 1u, 18u), RFB_OK);

    uint8_t body[9];
    const size_t body_len = build_singleton_type0(body, sizeof body);
    const rfb_rect_header actual = {
        .x = 8u,
        .y = 8u,
        .width = 8u,
        .height = 8u,
        .encoding = RFB_ENCODING_APPLE_MVS,
    };
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_record_rect(
                         &scheduler, &actual, body, body_len),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_complete(&scheduler, 19u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_note_quiet(&scheduler, 28u),
                     RFB_OK);
    RFB_CHECK(!rfb_capture_scheduler_done(&scheduler));
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_note_quiet(&scheduler, 29u),
                     RFB_OK);
    RFB_CHECK(rfb_capture_scheduler_done(&scheduler));

    RFB_CHECK_EQ_UINT(scheduler.rect_observation_count, 2u);
    RFB_CHECK_EQ_UINT(scheduler.final_observation_count, 2u);
    RFB_CHECK_EQ_UINT(rectangles[1].version, 0u);
    RFB_CHECK_EQ_UINT(rectangles[2].sequence, 3u);
    RFB_CHECK_EQ_INT(rectangles[2].phase, RFB_CAPTURE_PHASE_TARGET);
    RFB_CHECK(rectangles[2].has_request);
    RFB_CHECK_EQ_INT(rectangles[2].geometry,
                     RFB_CAPTURE_GEOMETRY_CLASS_CONTAINED);
    RFB_CHECK(rectangles[2].structure_checked);
    RFB_CHECK(rectangles[2].structure_valid);
    RFB_CHECK_EQ_UINT(finals[1].sequence, 4u);
    RFB_CHECK(finals[1].terminal);
    RFB_CHECK(finals[1].has_request);
    RFB_CHECK_EQ_UINT(finals[1].requested.id, query.id);
    RFB_CHECK_EQ_UINT(finals[1].queue_to_drain_ms, 2u);
    RFB_CHECK_EQ_UINT(finals[1].drain_to_fbu_ms, 1u);
    RFB_CHECK_EQ_UINT(finals[1].quiet_duration_ms, 10u);
    RFB_CHECK_EQ_INT(finals[1].classification,
                     RFB_CAPTURE_FINAL_ASSOCIATION_CLOSED);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_note_eof(&scheduler), RFB_OK);

    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fail(
                         &scheduler, RFB_CAPTURE_FAILURE_CONTROL,
                         RFB_ERR_PROTOCOL),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_UINT(scheduler.final_observation_count, 2u);
}

RFB_TEST(rfb_capture_scheduler,
         mutation_acknowledgement_is_ordered_and_time_bounded)
{
    const rfb_capture_query query = mutation_query();
    rfb_capture_rect_observation_v1 rectangles[3];
    rfb_capture_final_observation_v1 finals[2];
    const rfb_capture_scheduler_config config =
        mutation_config(&query, rectangles, finals);
    rfb_capture_scheduler scheduler;

    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_mutation_acknowledged(NULL, 0u),
        RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_init_config(&scheduler, &config), RFB_OK);
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_mutation_acknowledged(&scheduler, 1u),
        RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(scheduler.failure, RFB_CAPTURE_FAILURE_CONTROL);

    enter_mutation_hold(&scheduler, &config);
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_mutation_acknowledged(&scheduler, 12u),
        RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(scheduler.failure, RFB_CAPTURE_FAILURE_CONTROL);

    enter_mutation_hold(&scheduler, &config);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_tick(&scheduler, 12u),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(scheduler.failure, RFB_CAPTURE_FAILURE_SEQUENCE);

    enter_mutation_hold(&scheduler, &config);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_tick(&scheduler, 32u), RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_tick(&scheduler, 33u),
                     RFB_ERR_TIMEOUT);
    RFB_CHECK_EQ_INT(scheduler.failure, RFB_CAPTURE_FAILURE_TIMEOUT);

    enter_mutation_hold(&scheduler, &config);
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_mutation_acknowledged(&scheduler, 33u),
        RFB_ERR_TIMEOUT);
    RFB_CHECK_EQ_INT(scheduler.failure, RFB_CAPTURE_FAILURE_TIMEOUT);
}

RFB_TEST(rfb_capture_scheduler,
         request_queue_and_drain_reject_ambiguous_transport_state)
{
    const rfb_capture_query query = mutation_query();
    rfb_capture_rect_observation_v1 rectangles[3];
    rfb_capture_final_observation_v1 finals[2];
    const rfb_capture_scheduler_config config =
        mutation_config(&query, rectangles, finals);
    rfb_capture_scheduler scheduler;

    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_queue_started(
                         NULL, 0u, 0u, true),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_queued(
                         NULL, 0u, 10u, 10u),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_drained(
                         NULL, 0u, 0u, true),
                     RFB_ERR_INTERNAL);

    enter_mutation_hold(&scheduler, &config);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_queue_started(
                         &scheduler, 14u, 100u, true),
                     RFB_ERR_PROTOCOL);

    enter_mutation_acked(&scheduler, &config);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_queue_started(
                         &scheduler, 15u, 100u, false),
                     RFB_ERR_PROTOCOL);

    enter_mutation_acked(&scheduler, &config);
    scheduler.query_index = scheduler.query_count;
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_queue_started(
                         &scheduler, 15u, 100u, true),
                     RFB_ERR_PROTOCOL);

    enter_mutation_acked(&scheduler, &config);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_queue_started(
                         &scheduler, 15u, 100u, true),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_queued(
                         &scheduler, 14u, 10u, 10u),
                     RFB_ERR_PROTOCOL);

    enter_mutation_acked(&scheduler, &config);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_queue_started(
                         &scheduler, 15u, 100u, true),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_queued(
                         &scheduler, 16u, 9u, 10u),
                     RFB_ERR_PROTOCOL);

    enter_mutation_acked(&scheduler, &config);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_queue_started(
                         &scheduler, 15u, 100u, true),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_queued(
                         &scheduler, 16u, 10u, 9u),
                     RFB_ERR_PROTOCOL);

    enter_request_draining(&scheduler, &config);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_drained(
                         &scheduler, 14u, 112u, true),
                     RFB_ERR_PROTOCOL);

    enter_request_draining(&scheduler, &config);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_drained(
                         &scheduler, 17u, 99u, true),
                     RFB_ERR_PROTOCOL);

    enter_request_draining(&scheduler, &config);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_drained(
                         &scheduler, 17u, 112u, false),
                     RFB_ERR_PROTOCOL);

    enter_request_draining(&scheduler, &config);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_drained(
                         &scheduler, 17u, 111u, true),
                     RFB_ERR_PROTOCOL);
}

RFB_TEST(rfb_capture_scheduler,
         config_rejects_incomplete_observation_and_mutation_contracts)
{
    rfb_capture_query query = mutation_query();
    rfb_capture_rect_observation_v1 rectangles[3];
    rfb_capture_final_observation_v1 finals[3];
    rfb_capture_scheduler_config config =
        mutation_config(&query, rectangles, finals);
    rfb_capture_scheduler scheduler;

    RFB_CHECK_EQ_INT(rfb_capture_scheduler_init_config(NULL, &config),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_init_config(&scheduler, NULL),
                     RFB_ERR_PROTOCOL);

    config.response_timeout_ms = 600001u;
    check_invalid_config(&config);
    config = mutation_config(&query, rectangles, finals);
    config.quiet_ms = 600001u;
    check_invalid_config(&config);
    config = mutation_config(&query, rectangles, finals);
    config.mutation_timeout_ms = 0u;
    check_invalid_config(&config);
    config = mutation_config(&query, rectangles, finals);
    config.mutation_timeout_ms = 600001u;
    check_invalid_config(&config);

    config = mutation_config(&query, rectangles, finals);
    config.rect_observations = NULL;
    check_invalid_config(&config);
    config = mutation_config(&query, rectangles, finals);
    config.final_observations = NULL;
    check_invalid_config(&config);
    config = mutation_config(&query, rectangles, finals);
    config.initial_rectangle_max = 0u;
    check_invalid_config(&config);
    config = mutation_config(&query, rectangles, finals);
    config.rect_observation_capacity = config.initial_rectangle_max;
    check_invalid_config(&config);
    config = mutation_config(&query, rectangles, finals);
    config.final_observation_capacity = 1u;
    check_invalid_config(&config);
    if (SIZE_MAX > UINT32_MAX) {
        config = mutation_config(&query, rectangles, finals);
        config.rect_observation_capacity = (size_t)UINT32_MAX + 1u;
        check_invalid_config(&config);
    }

    config = mutation_config(&query, rectangles, finals);
    config.rect_observations = NULL;
    config.rect_observation_capacity = 0u;
    config.final_observations = NULL;
    config.final_observation_capacity = 0u;
    config.initial_rectangle_max = 0u;
    check_invalid_config(&config);

    config = mutation_config(&query, rectangles, finals);
    config.query_count = 2u;
    check_invalid_config(&config);
    config = mutation_config(&query, rectangles, finals);
    query.incremental = false;
    check_invalid_config(&config);
    query = mutation_query();
    config = mutation_config(&query, rectangles, finals);
    query.x = 8u;
    check_invalid_config(&config);
    query = mutation_query();
    config = mutation_config(&query, rectangles, finals);
    query.y = 8u;
    check_invalid_config(&config);
    query = mutation_query();
    config = mutation_config(&query, rectangles, finals);
    query.width = 1016u;
    check_invalid_config(&config);
    query = mutation_query();
    config = mutation_config(&query, rectangles, finals);
    query.height = 760u;
    check_invalid_config(&config);
    query = mutation_query();
    config = mutation_config(&query, rectangles, finals);
    query.geometry_policy = RFB_CAPTURE_GEOMETRY_EXACT;
    check_invalid_config(&config);
    query = mutation_query();
    config = mutation_config(&query, rectangles, finals);
    config.final_observation_capacity = 3u;
    check_invalid_config(&config);
    config = mutation_config(&query, rectangles, finals);
    config.on_result = capture_result_store;
    check_invalid_config(&config);
}

RFB_TEST(rfb_capture_scheduler,
         query_validation_rejects_remaining_invalid_shapes)
{
    rfb_capture_scheduler scheduler;
    const rfb_capture_query good = capture_query();
    rfb_capture_query bad = good;

    RFB_CHECK_EQ_INT(rfb_capture_scheduler_init(
                         &scheduler, &good, 1u, 0u, 768u, 100u, 10u, NULL,
                         NULL),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_init(
                         &scheduler, &good, 1u, 1024u, 0u, 100u, 10u, NULL,
                         NULL),
                     RFB_ERR_PROTOCOL);

    bad.height = 0u;
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_init(
                         &scheduler, &bad, 1u, 1024u, 768u, 100u, 10u, NULL,
                         NULL),
                     RFB_ERR_PROTOCOL);
    bad = good;
    bad.y = 3u;
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_init(
                         &scheduler, &bad, 1u, 1024u, 768u, 100u, 10u, NULL,
                         NULL),
                     RFB_ERR_PROTOCOL);
    bad = good;
    bad.width = 9u;
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_init(
                         &scheduler, &bad, 1u, 1024u, 768u, 100u, 10u, NULL,
                         NULL),
                     RFB_ERR_PROTOCOL);
    bad = good;
    bad.height = 9u;
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_init(
                         &scheduler, &bad, 1u, 1024u, 768u, 100u, 10u, NULL,
                         NULL),
                     RFB_ERR_PROTOCOL);
    bad = good;
    bad.geometry_policy = (rfb_capture_geometry_policy)99;
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_init(
                         &scheduler, &bad, 1u, 1024u, 768u, 100u, 10u, NULL,
                         NULL),
                     RFB_ERR_PROTOCOL);
    bad = good;
    bad.y = 760u;
    bad.height = 16u;
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_init(
                         &scheduler, &bad, 1u, 1024u, 768u, 100u, 10u, NULL,
                         NULL),
                     RFB_ERR_PROTOCOL);
}

RFB_TEST(rfb_capture_scheduler,
         observation_storage_fails_closed_at_each_bound)
{
    const rfb_capture_query query = mutation_query();
    rfb_capture_rect_observation_v1 rectangles[3];
    rfb_capture_final_observation_v1 finals[2];
    const rfb_capture_scheduler_config config =
        mutation_config(&query, rectangles, finals);
    rfb_capture_scheduler scheduler;
    const rfb_rect_header initial = {
        .x = 0u,
        .y = 0u,
        .width = 1024u,
        .height = 768u,
        .encoding = RFB_ENCODING_RAW,
    };

    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_init_config(&scheduler, &config), RFB_OK);
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_initial_request_sent(&scheduler, 1u), RFB_OK);
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_fbu_begin_at(&scheduler, 3u, 2u),
        RFB_ERR_LIMIT);
    RFB_CHECK_EQ_INT(scheduler.failure,
                     RFB_CAPTURE_FAILURE_OBSERVATION_LIMIT);

    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_init_config(&scheduler, &config), RFB_OK);
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_initial_request_sent(&scheduler, 1u), RFB_OK);
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_fbu_begin_at(&scheduler, 1u, 2u), RFB_OK);
    rectangles[0].version = RFB_CAPTURE_OBSERVATION_VERSION_1;
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_record_rect(
                         &scheduler, &initial, NULL, 0u),
                     RFB_ERR_LIMIT);
    RFB_CHECK_EQ_INT(scheduler.failure,
                     RFB_CAPTURE_FAILURE_OBSERVATION_LIMIT);

    enter_request_draining(&scheduler, &config);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_drained(
                         &scheduler, 17u, 112u, true),
                     RFB_OK);
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_fbu_begin_at(&scheduler, 1u, 18u), RFB_OK);
    rectangles[2].version = RFB_CAPTURE_OBSERVATION_VERSION_1;
    uint8_t body[9];
    const size_t body_len = build_singleton_type0(body, sizeof body);
    const rfb_rect_header target = {
        .x = 8u,
        .y = 8u,
        .width = 8u,
        .height = 8u,
        .encoding = RFB_ENCODING_APPLE_MVS,
    };
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_record_rect(
                         &scheduler, &target, body, body_len),
                     RFB_ERR_LIMIT);
    RFB_CHECK_EQ_INT(scheduler.failure,
                     RFB_CAPTURE_FAILURE_OBSERVATION_LIMIT);
}

RFB_TEST(rfb_capture_scheduler,
         failed_state_is_sticky_across_scheduler_events)
{
    const rfb_capture_query query = capture_query();
    const rfb_rect_header rect = {
        .x = query.x,
        .y = query.y,
        .width = query.width,
        .height = query.height,
        .encoding = RFB_ENCODING_RAW,
    };
    rfb_capture_scheduler scheduler;
    memset(&scheduler, 0, sizeof scheduler);

    RFB_CHECK(!rfb_capture_scheduler_active(NULL));
    RFB_CHECK(!rfb_capture_scheduler_done(NULL));
    RFB_CHECK(!rfb_capture_scheduler_active(&scheduler));
    RFB_CHECK(!rfb_capture_scheduler_done(&scheduler));
    RFB_CHECK(!rfb_capture_scheduler_next_request(NULL, NULL));
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_initial_request_sent(NULL, 0u),
        RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_sent(NULL, 0u),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_begin(NULL, 0u),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_begin_at(NULL, 0u, 0u),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_record_rect(
                         NULL, &rect, NULL, 0u),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_record_rect(
                         &scheduler, NULL, NULL, 0u),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_record_rect(
                         &scheduler, &rect, NULL, 1u),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_complete(NULL, 0u),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_note_activity(NULL, 0u),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_note_control_activity(NULL, 0u),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_note_quiet(NULL, 0u),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_tick(NULL, 0u),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_note_eof(NULL),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fail(
                         NULL, RFB_CAPTURE_FAILURE_CONTROL,
                         RFB_ERR_PROTOCOL),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fail(
                         &scheduler, RFB_CAPTURE_FAILURE_NONE,
                         RFB_ERR_PROTOCOL),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fail(
                         &scheduler, RFB_CAPTURE_FAILURE_CONTROL, RFB_OK),
                     RFB_ERR_INTERNAL);

    RFB_CHECK_EQ_INT(rfb_capture_scheduler_init(
                         &scheduler, &query, 1u, 1024u, 768u, 100u, 10u,
                         NULL, NULL),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_sent(&scheduler, 1u),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(scheduler.failure, RFB_CAPTURE_FAILURE_SEQUENCE);
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_initial_request_sent(&scheduler, 1u),
        RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_sent(&scheduler, 1u),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_mutation_acknowledged(&scheduler, 1u),
        RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_queue_started(
                         &scheduler, 1u, 0u, true),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_queued(
                         &scheduler, 1u, 10u, 10u),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_drained(
                         &scheduler, 1u, 10u, true),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_begin(&scheduler, 1u),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_record_rect(
                         &scheduler, &rect, NULL, 0u),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_complete(&scheduler, 1u),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_note_activity(&scheduler, 1u),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_note_control_activity(&scheduler, 1u),
        RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_note_quiet(&scheduler, 1u),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_tick(&scheduler, 1u),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_note_eof(&scheduler),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fail(
                         &scheduler, RFB_CAPTURE_FAILURE_CONTROL,
                         RFB_ERR_EOF),
                     RFB_ERR_PROTOCOL);
}

RFB_TEST(rfb_capture_scheduler,
         queued_and_quiet_ticks_enforce_outer_bounds)
{
    const rfb_capture_query query = mutation_query();
    rfb_capture_rect_observation_v1 rectangles[3];
    rfb_capture_final_observation_v1 finals[2];
    const rfb_capture_scheduler_config config =
        mutation_config(&query, rectangles, finals);
    rfb_capture_scheduler scheduler;

    enter_mutation_acked(&scheduler, &config);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_queue_started(
                         &scheduler, 15u, 100u, true),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_tick(&scheduler, 14u),
                     RFB_ERR_PROTOCOL);

    enter_mutation_acked(&scheduler, &config);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_queue_started(
                         &scheduler, 15u, 100u, true),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_tick(&scheduler, 114u), RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_tick(&scheduler, 115u),
                     RFB_ERR_TIMEOUT);
    RFB_CHECK_EQ_INT(scheduler.failure,
                     RFB_CAPTURE_FAILURE_REQUEST_DRAIN);

    enter_request_draining(&scheduler, &config);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_tick(&scheduler, 114u), RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_tick(&scheduler, 115u),
                     RFB_ERR_TIMEOUT);
    RFB_CHECK_EQ_INT(scheduler.failure,
                     RFB_CAPTURE_FAILURE_REQUEST_DRAIN);

    const rfb_capture_query ordinary = capture_query();
    const rfb_rect_header initial = {
        .x = 0u,
        .y = 0u,
        .width = 1024u,
        .height = 768u,
        .encoding = RFB_ENCODING_RAW,
    };
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_init(
                         &scheduler, &ordinary, 1u, 1024u, 768u, 100u, 10u,
                         NULL, NULL),
                     RFB_OK);
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_initial_request_sent(&scheduler, 1u), RFB_OK);
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_fbu_begin_at(&scheduler, 1u, 2u), RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_record_rect(
                         &scheduler, &initial, NULL, 0u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_complete(&scheduler, 3u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_tick(&scheduler, 2u),
                     RFB_ERR_PROTOCOL);

    RFB_CHECK_EQ_INT(rfb_capture_scheduler_init(
                         &scheduler, &ordinary, 1u, 1024u, 768u, 100u, 10u,
                         NULL, NULL),
                     RFB_OK);
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_initial_request_sent(&scheduler, 1u), RFB_OK);
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_fbu_begin_at(&scheduler, 1u, 2u), RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_record_rect(
                         &scheduler, &initial, NULL, 0u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_complete(&scheduler, 3u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_tick(&scheduler, 102u), RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_tick(&scheduler, 103u),
                     RFB_ERR_TIMEOUT);
}

RFB_TEST(rfb_capture_scheduler,
         initial_mvs_observation_uses_target_structural_classifier)
{
    const rfb_capture_query query = mutation_query();
    rfb_capture_rect_observation_v1 rectangles[3];
    rfb_capture_final_observation_v1 finals[2];
    const rfb_capture_scheduler_config config =
        mutation_config(&query, rectangles, finals);
    rfb_capture_scheduler scheduler;
    uint8_t body[9];
    const size_t body_len = build_singleton_type0(body, sizeof body);
    const rfb_rect_header initial = {
        .x = 0u,
        .y = 0u,
        .width = 8u,
        .height = 8u,
        .encoding = RFB_ENCODING_APPLE_MVS,
    };

    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_init_config(&scheduler, &config), RFB_OK);
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_initial_request_sent(&scheduler, 1u), RFB_OK);
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_fbu_begin_at(&scheduler, 1u, 2u), RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_record_rect(
                         &scheduler, &initial, body, body_len),
                     RFB_OK);
    RFB_CHECK(rectangles[0].structure_checked);
    RFB_CHECK(rectangles[0].structure_valid);
    RFB_CHECK(rectangles[0].mvs_type0);
    RFB_CHECK_EQ_UINT(rectangles[0].mvs_command_records, 1u);
    RFB_CHECK_EQ_UINT(rectangles[0].mvs_first_run, 1u);
    RFB_CHECK(rectangles[0].structural_one_record_run_one);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_complete(&scheduler, 3u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_note_quiet(&scheduler, 13u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(scheduler.state,
                     RFB_CAPTURE_SCHEDULER_MUTATION_HOLD);
}

RFB_TEST(rfb_capture_scheduler,
         sequence_entrypoints_reject_invalid_order_and_time)
{
    const rfb_capture_query query = capture_query();
    const rfb_rect_header initial = {
        .x = 0u,
        .y = 0u,
        .width = 1024u,
        .height = 768u,
        .encoding = RFB_ENCODING_RAW,
    };
    rfb_capture_scheduler scheduler;

    RFB_CHECK_EQ_INT(rfb_capture_scheduler_init(
                         &scheduler, &query, 1u, 1024u, 768u, 100u, 10u,
                         NULL, NULL),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_complete(&scheduler, 1u),
                     RFB_ERR_PROTOCOL);

    RFB_CHECK_EQ_INT(rfb_capture_scheduler_init(
                         &scheduler, &query, 1u, 1024u, 768u, 100u, 10u,
                         NULL, NULL),
                     RFB_OK);
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_initial_request_sent(&scheduler, 10u), RFB_OK);
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_fbu_begin_at(&scheduler, 1u, 9u),
        RFB_ERR_PROTOCOL);

    RFB_CHECK_EQ_INT(rfb_capture_scheduler_init(
                         &scheduler, &query, 1u, 1024u, 768u, 100u, 10u,
                         NULL, NULL),
                     RFB_OK);
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_initial_request_sent(&scheduler, 1u), RFB_OK);
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_fbu_begin_at(&scheduler, 1u, 2u), RFB_OK);
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_initial_request_sent(&scheduler, 3u),
        RFB_ERR_PROTOCOL);

    RFB_CHECK_EQ_INT(rfb_capture_scheduler_init(
                         &scheduler, &query, 1u, 1024u, 768u, 100u, 10u,
                         NULL, NULL),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_record_rect(
                         &scheduler, &initial, NULL, 0u),
                     RFB_ERR_PROTOCOL);

    RFB_CHECK_EQ_INT(rfb_capture_scheduler_init(
                         &scheduler, &query, 1u, 1024u, 768u, 100u, 10u,
                         NULL, NULL),
                     RFB_OK);
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_initial_request_sent(&scheduler, 1u), RFB_OK);
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_fbu_begin_at(&scheduler, 0u, 2u), RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_record_rect(
                         &scheduler, &initial, NULL, 0u),
                     RFB_ERR_PROTOCOL);
}

RFB_TEST(rfb_capture_scheduler,
         completion_rejects_missing_rectangles_and_regressed_time)
{
    const rfb_capture_query query = capture_query();
    const rfb_rect_header initial = {
        .x = 0u,
        .y = 0u,
        .width = 1024u,
        .height = 768u,
        .encoding = RFB_ENCODING_RAW,
    };
    rfb_capture_scheduler scheduler;

    RFB_CHECK_EQ_INT(rfb_capture_scheduler_init(
                         &scheduler, &query, 1u, 1024u, 768u, 100u, 10u,
                         NULL, NULL),
                     RFB_OK);
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_initial_request_sent(&scheduler, 1u), RFB_OK);
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_fbu_begin_at(&scheduler, 1u, 2u), RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_complete(&scheduler, 3u),
                     RFB_ERR_PROTOCOL);

    RFB_CHECK_EQ_INT(rfb_capture_scheduler_init(
                         &scheduler, &query, 1u, 1024u, 768u, 100u, 10u,
                         NULL, NULL),
                     RFB_OK);
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_initial_request_sent(&scheduler, 10u), RFB_OK);
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_fbu_begin_at(&scheduler, 1u, 10u), RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_record_rect(
                         &scheduler, &initial, NULL, 0u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_complete(&scheduler, 9u),
                     RFB_ERR_PROTOCOL);

    RFB_CHECK_EQ_INT(rfb_capture_scheduler_init(
                         &scheduler, &query, 1u, 1024u, 768u, 100u, 10u,
                         NULL, NULL),
                     RFB_OK);
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_initial_request_sent(&scheduler, 1u), RFB_OK);
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_fbu_begin_at(&scheduler, 1u, 2u), RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_record_rect(
                         &scheduler, &initial, NULL, 0u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_complete(&scheduler, 3u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_fbu_begin_at(&scheduler, 1u, 4u), RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_complete(&scheduler, 5u),
                     RFB_ERR_PROTOCOL);
}

RFB_TEST(rfb_capture_scheduler,
         initial_only_requires_zrle_before_completion)
{
    const rfb_capture_scheduler_config config = {
        .framebuffer_width = 1024u,
        .framebuffer_height = 768u,
        .response_timeout_ms = 100u,
        .quiet_ms = 10u,
        .initial_only = true,
        .initial_zrle_only = true,
    };
    const rfb_rect_header cursor = {
        .x = 0u,
        .y = 0u,
        .width = 1u,
        .height = 1u,
        .encoding = RFB_ENCODING_CURSOR,
    };
    rfb_capture_scheduler scheduler;

    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_init_config(&scheduler, &config), RFB_OK);
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_initial_request_sent(&scheduler, 1u), RFB_OK);
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_fbu_begin_at(&scheduler, 1u, 2u), RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_record_rect(
                         &scheduler, &cursor, NULL, 0u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_complete(&scheduler, 3u),
                     RFB_ERR_PROTOCOL);
}

RFB_TEST(rfb_capture_scheduler,
         quiet_entrypoints_enforce_state_and_monotonic_time)
{
    const rfb_capture_query query = capture_query();
    const rfb_rect_header initial = {
        .x = 0u,
        .y = 0u,
        .width = 1024u,
        .height = 768u,
        .encoding = RFB_ENCODING_RAW,
    };
    rfb_capture_scheduler scheduler;

    RFB_CHECK_EQ_INT(rfb_capture_scheduler_init(
                         &scheduler, &query, 1u, 1024u, 768u, 100u, 10u,
                         NULL, NULL),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_note_activity(&scheduler, 1u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_note_control_activity(&scheduler, 1u), RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_note_quiet(&scheduler, 1u),
                     RFB_ERR_PROTOCOL);

    RFB_CHECK_EQ_INT(rfb_capture_scheduler_init(
                         &scheduler, &query, 1u, 1024u, 768u, 100u, 10u,
                         NULL, NULL),
                     RFB_OK);
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_initial_request_sent(&scheduler, 1u), RFB_OK);
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_fbu_begin_at(&scheduler, 1u, 2u), RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_record_rect(
                         &scheduler, &initial, NULL, 0u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_complete(&scheduler, 3u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_note_activity(&scheduler, 2u),
                     RFB_ERR_PROTOCOL);

    RFB_CHECK_EQ_INT(rfb_capture_scheduler_init(
                         &scheduler, &query, 1u, 1024u, 768u, 100u, 10u,
                         NULL, NULL),
                     RFB_OK);
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_initial_request_sent(&scheduler, 1u), RFB_OK);
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_fbu_begin_at(&scheduler, 1u, 2u), RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_record_rect(
                         &scheduler, &initial, NULL, 0u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_complete(&scheduler, 3u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_note_control_activity(
                         &scheduler, 2u),
                     RFB_ERR_PROTOCOL);

    RFB_CHECK_EQ_INT(rfb_capture_scheduler_init(
                         &scheduler, &query, 1u, 1024u, 768u, 100u, 10u,
                         NULL, NULL),
                     RFB_OK);
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_initial_request_sent(&scheduler, 1u), RFB_OK);
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_fbu_begin_at(&scheduler, 1u, 2u), RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_record_rect(
                         &scheduler, &initial, NULL, 0u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_complete(&scheduler, 3u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_note_quiet(&scheduler, 2u),
                     RFB_ERR_PROTOCOL);

    RFB_CHECK_EQ_INT(rfb_capture_scheduler_init(
                         &scheduler, &query, 1u, 1024u, 768u, 100u, 10u,
                         NULL, NULL),
                     RFB_OK);
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_initial_request_sent(&scheduler, 1u), RFB_OK);
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_fbu_begin_at(&scheduler, 1u, 2u), RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_record_rect(
                         &scheduler, &initial, NULL, 0u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_fbu_complete(&scheduler, 3u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_note_quiet(&scheduler, 103u),
                     RFB_ERR_TIMEOUT);
}

RFB_TEST(rfb_capture_scheduler,
         mvs_failures_cover_initial_and_target_geometry)
{
    const rfb_capture_query query = capture_query();
    const uint8_t malformed[] = {0u};
    rfb_capture_scheduler scheduler;
    uint8_t body[9];
    const size_t body_len = build_singleton_type0(body, sizeof body);
    const rfb_rect_header initial_mvs = {
        .x = 0u,
        .y = 0u,
        .width = 8u,
        .height = 8u,
        .encoding = RFB_ENCODING_APPLE_MVS,
    };

    RFB_CHECK_EQ_INT(rfb_capture_scheduler_init(
                         &scheduler, &query, 1u, 1024u, 768u, 100u, 10u,
                         NULL, NULL),
                     RFB_OK);
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_initial_request_sent(&scheduler, 1u), RFB_OK);
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_fbu_begin_at(&scheduler, 1u, 2u), RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_record_rect(
                         &scheduler, &initial_mvs, malformed,
                         sizeof malformed),
                     RFB_ERR_PROTOCOL);

    RFB_CHECK_EQ_INT(rfb_capture_scheduler_init(
                         &scheduler, &query, 1u, 1024u, 768u, 100u, 10u,
                         NULL, NULL),
                     RFB_OK);
    finish_initial(&scheduler);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_sent(&scheduler, 20u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_fbu_begin_at(&scheduler, 1u, 19u),
        RFB_ERR_PROTOCOL);

    const rfb_rect_header zero_width = {
        .x = 16u,
        .y = 24u,
        .width = 0u,
        .height = 8u,
        .encoding = RFB_ENCODING_APPLE_MVS,
    };
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_init(
                         &scheduler, &query, 1u, 1024u, 768u, 100u, 10u,
                         NULL, NULL),
                     RFB_OK);
    finish_initial(&scheduler);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_request_sent(&scheduler, 20u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(
        rfb_capture_scheduler_fbu_begin_at(&scheduler, 1u, 20u), RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_scheduler_record_rect(
                         &scheduler, &zero_width, body, body_len),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(scheduler.failure, RFB_CAPTURE_FAILURE_MVS_GRAMMAR);
}
