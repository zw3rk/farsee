// SPDX-License-Identifier: Apache-2.0
//
// Loopback integration driver for the capture-only rfb_session path.

#include "farsee/error.h"
#include "farsee/farsee_atomic.h"
#include "farsee/rfb_capture_control.h"
#include "farsee/rfb_capture_scheduler.h"
#include "farsee/rfb_session.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct capture_sink {
    unsigned callbacks;
    unsigned initial;
    unsigned targeted;
    bool direct;
    rfb_capture_result target;
} capture_sink;

static void capture_result(void *ctx, const rfb_capture_result *result)
{
    capture_sink *sink = (capture_sink *)ctx;
    if (sink == NULL || result == NULL) {
        return;
    }
    sink->callbacks++;
    if (result->initial) {
        sink->initial++;
        return;
    }
    sink->targeted++;
    sink->direct = result->direct_one_record_run_one;
    sink->target = *result;
}

static bool parse_u16(const char *text, uint16_t *out)
{
    if (text == NULL || out == NULL || text[0] == '\0' || text[0] == '-') {
        return false;
    }
    errno = 0;
    char *end = NULL;
    const unsigned long value = strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value == 0u ||
        value > UINT16_MAX) {
        return false;
    }
    *out = (uint16_t)value;
    return true;
}

static bool parse_u32(const char *text, uint32_t *out)
{
    if (text == NULL || out == NULL || text[0] == '\0' || text[0] == '-') {
        return false;
    }
    errno = 0;
    char *end = NULL;
    const unsigned long value = strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value == 0u ||
        value > UINT32_MAX) {
        return false;
    }
    *out = (uint32_t)value;
    return true;
}

static bool parse_fd(const char *text, int *out)
{
    if (text == NULL || out == NULL || text[0] == '\0' || text[0] == '-') {
        return false;
    }
    errno = 0;
    char *end = NULL;
    const long value = strtol(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value > INT_MAX) {
        return false;
    }
    *out = (int)value;
    return true;
}

int main(int argc, char **argv)
{
    const bool use_connected_fd =
        argc >= 4 && strcmp(argv[1], "--connected-fd") == 0;
    if ((use_connected_fd && argc != 4 && argc != 5) ||
        (!use_connected_fd && argc != 3 && argc != 4)) {
        (void)fprintf(
            stderr,
            "usage: %s <port> <response-timeout-ms> [control-fd]\n"
            "       %s --connected-fd <fd> <response-timeout-ms> "
            "[control-fd|zrle-control]\n",
            argv[0], argv[0]);
        return 2;
    }
    uint16_t port = 0u;
    uint32_t response_timeout_ms = 0u;
    int control_fd = -1;
    int connected_fd = -1;
    bool zrle_control = false;
    if (use_connected_fd) {
        if (!parse_fd(argv[2], &connected_fd) ||
            !parse_u32(argv[3], &response_timeout_ms) ||
            (argc == 5 && strcmp(argv[4], "zrle-control") != 0 &&
             !parse_fd(argv[4], &control_fd))) {
            return 2;
        }
        zrle_control = argc == 5 && strcmp(argv[4], "zrle-control") == 0;
    } else {
        if (!parse_u16(argv[1], &port) ||
            !parse_u32(argv[2], &response_timeout_ms) ||
            (argc == 4 && strcmp(argv[3], "zrle-control") != 0 &&
             !parse_fd(argv[3], &control_fd))) {
            return 2;
        }
        zrle_control =
            argc == 4 && strcmp(argv[3], "zrle-control") == 0;
    }
    const bool mutation_campaign = control_fd >= 0;

    rfb_session *session = (rfb_session *)calloc(1u, rfb_session_size());
    if (session == NULL) {
        return 1;
    }
    rfb_session_clear(session);

    const rfb_capture_query query = {
        .id = 17u,
        .incremental = mutation_campaign,
        .geometry_policy = mutation_campaign
                               ? RFB_CAPTURE_GEOMETRY_WITHIN_REQUEST
                               : RFB_CAPTURE_GEOMETRY_EXACT,
        .x = 0u,
        .y = 0u,
        .width = mutation_campaign ? 16u : 8u,
        .height = mutation_campaign ? 16u : 8u,
    };
    capture_sink sink;
    memset(&sink, 0, sizeof sink);
    rfb_capture_rect_observation_v1 rectangles[5];
    rfb_capture_final_observation_v1 finals[2];
    memset(rectangles, 0, sizeof rectangles);
    memset(finals, 0, sizeof finals);
    uint8_t source_b_binding[RFB_CAPTURE_CONTROL_BINDING_SIZE];
    for (size_t i = 0u; i < sizeof source_b_binding; i++) {
        source_b_binding[i] = (uint8_t)(i + 1u);
    }
    farsee_atomic_int stop = 0;
    rfb_session_config config;
    memset(&config, 0, sizeof config);
    config.host = use_connected_fd ? NULL : "127.0.0.1";
    config.port = use_connected_fd ? 0u : port;
    config.use_connected_fd = use_connected_fd;
    config.connected_fd = connected_fd;
    config.allow_none_auth = true;
    config.shared = true;
    config.auth_mode = FARSEE_AUTH_MODE_VNC;
    config.stop_flag = &stop;
    config.connect_timeout_ms = 2000u;
    config.view_only = true;
    config.capture_queries = zrle_control ? NULL : &query;
    config.capture_query_count = zrle_control ? 0u : 1u;
    config.capture_response_timeout_ms = response_timeout_ms;
    config.capture_quiet_ms = 30u;
    if (mutation_campaign) {
        config.capture_require_mutation_ack = true;
        config.capture_mutation_timeout_ms = response_timeout_ms;
        config.capture_control_fd = control_fd;
        config.capture_slot_nonce = UINT64_C(0x1020304050607080);
        config.capture_transition_id = UINT32_C(0x01020304);
        config.capture_source_b_binding = source_b_binding;
        config.capture_initial_rectangle_max = 4u;
        config.capture_rect_observations = rectangles;
        config.capture_rect_observation_capacity = 5u;
        config.capture_final_observations = finals;
        config.capture_final_observation_capacity = 2u;
    } else if (zrle_control) {
        config.capture_initial_only = true;
        config.capture_initial_zrle_only = true;
        config.capture_initial_rectangle_max = 4u;
        config.capture_rect_observations = rectangles;
        config.capture_rect_observation_capacity = 5u;
        config.capture_final_observations = finals;
        config.capture_final_observation_capacity = 2u;
    } else {
        config.capture_on_result = capture_result;
        config.capture_on_result_ctx = &sink;
    }

    const rfb_error connect_error =
        rfb_session_connect_classic(session, &config);
    if (connect_error == RFB_OK) {
        rfb_session_protocol_loop(session);
    }
    const rfb_error last_error = rfb_session_last_error(session);
    const rfb_capture_scheduler_state state =
        rfb_session_capture_state(session);
    const rfb_capture_failure failure =
        rfb_session_capture_failure(session);
    const rfb_framebuffer *frame = rfb_session_framebuffer(session);
    const bool frame_ready = frame != NULL && frame->rgba != NULL &&
                             frame->width > 0u && frame->height > 0u;
    const size_t frame_bytes = frame_ready
        ? (size_t)frame->stride * (size_t)frame->height
        : 0u;
    bool frame_all_expected = frame_bytes > 0u && frame_bytes % 4u == 0u;
    for (size_t i = 0u; frame_all_expected && i < frame_bytes; i += 4u) {
        frame_all_expected = frame->rgba[i] == 0x11u &&
                             frame->rgba[i + 1u] == 0x22u &&
                             frame->rgba[i + 2u] == 0x33u &&
                             frame->rgba[i + 3u] == 0xffu;
    }
    const unsigned frame_width =
        frame_ready ? (unsigned)frame->width : 0u;
    const unsigned frame_height =
        frame_ready ? (unsigned)frame->height : 0u;
    unsigned frame_first_rgba[4] = {0u, 0u, 0u, 0u};
    if (frame_ready) {
        for (size_t i = 0u; i < 4u; i++) {
            frame_first_rgba[i] = (unsigned)frame->rgba[i];
        }
    }

    const rfb_capture_final_observation_v1 *final = NULL;
    if (finals[1].present) {
        final = &finals[1];
    } else if (finals[0].present) {
        final = &finals[0];
    }

    rfb_session_destroy(session);
    free(session);
    const bool borrowed_fd_open =
        use_connected_fd && fcntl(connected_fd, F_GETFD) >= 0;

    (void)printf(
        "{\"result\":\"ok\",\"connect_error\":%u,\"error\":%u,"
        "\"state\":%u,\"failure\":%u,\"callbacks\":%u,"
        "\"initial\":%u,\"targeted\":%u,\"direct\":%s,"
        "\"requested_id\":%u,\"actual_x\":%u,\"actual_y\":%u,"
        "\"actual_width\":%u,\"actual_height\":%u,"
        "\"actual_encoding\":%d,\"records\":%u,\"first_run\":%u,"
        "\"final_present\":%s,\"final_terminal\":%s,"
        "\"final_classification\":%u,\"final_fbu_complete\":%s,"
        "\"final_quiet_complete\":%s,\"final_declared\":%u,"
        "\"final_seen\":%u,\"frame_width\":%u,\"frame_height\":%u,"
        "\"frame_first_rgba\":[%u,%u,%u,%u],\"frame_bytes\":%zu,"
        "\"frame_all_expected\":%s,\"borrowed_fd_open\":%s}\n",
        (unsigned)connect_error, (unsigned)last_error, (unsigned)state,
        (unsigned)failure, sink.callbacks, sink.initial, sink.targeted,
        sink.direct ? "true" : "false", (unsigned)sink.target.requested.id,
        (unsigned)sink.target.actual.x, (unsigned)sink.target.actual.y,
        (unsigned)sink.target.actual.width,
        (unsigned)sink.target.actual.height,
        (int)sink.target.actual.encoding,
        (unsigned)sink.target.mvs_command_records,
        (unsigned)sink.target.mvs_first_run,
        final != NULL ? "true" : "false",
        final != NULL && final->terminal ? "true" : "false",
        final != NULL ? (unsigned)final->classification : 0u,
        final != NULL && final->fbu_complete ? "true" : "false",
        final != NULL && final->quiet_complete ? "true" : "false",
        final != NULL ? (unsigned)final->declared_rectangle_count : 0u,
        final != NULL ? (unsigned)final->rectangles_seen : 0u,
        frame_width, frame_height,
        frame_first_rgba[0], frame_first_rgba[1], frame_first_rgba[2],
        frame_first_rgba[3], frame_bytes,
        frame_all_expected ? "true" : "false",
        borrowed_fd_open ? "true" : "false");

    return 0;
}
