// SPDX-License-Identifier: Apache-2.0
//
// Test-only post-auth Apple capture fixture. This TU is linked only into the
// test runner; no campaign or product binary can activate deterministic keys.

#include "farsee/apple_record.h"
#include "farsee/buffer.h"
#include "farsee/limits.h"
#include "farsee/rfb_capture_control.h"
#include "farsee/rfb_server_engine.h"
#include "farsee/rfb_session.h"
#include "rfb/rfb_session_internal.h"
#include "rfb_session_capture_fixture.h"

#include <string.h>

static uint64_t fixed_capture_clock(void *opaque)
{
    return opaque != NULL ? *(const uint64_t *)opaque : 0u;
}

typedef struct setup_transport_capture {
    uint8_t *bytes;
    size_t capacity;
    size_t length;
} setup_transport_capture;

static rfb_io_result capture_setup_write(void *ctx, const uint8_t *buffer,
                                         size_t length, size_t *written)
{
    setup_transport_capture *capture = (setup_transport_capture *)ctx;
    if (capture == NULL || buffer == NULL || written == NULL ||
        length > capture->capacity - capture->length) {
        return RFB_IO_ERROR;
    }
    memcpy(capture->bytes + capture->length, buffer, length);
    capture->length += length;
    *written = length;
    return RFB_IO_OK;
}

static rfb_error init_setup_session(rfb_session *session,
                                    const rfb_session_config *config,
                                    setup_transport_capture *capture)
{
    if (session == NULL || config == NULL || capture == NULL) {
        return RFB_ERR_INTERNAL;
    }
    rfb_session_clear(session);
    session->cfg = *config;
    session->alloc = rfb_default_allocator();
    session->io.ctx = capture;
    session->io.write = capture_setup_write;
    rfb_buffer_init(&session->out, session->alloc,
                    RFB_LIMIT_OUTBOUND_BYTES);
    return RFB_OK;
}

rfb_error rfb_session_test_activate_apple_capture(
    rfb_session *session, const rfb_session_config *config,
    const rfb_io_adapter *adapter, int poll_fd,
    farsee_atomic_u64 *transport_tx_bytes, uint16_t framebuffer_width,
    uint16_t framebuffer_height, const uint8_t c2s_key[16],
    const uint8_t c2s_iv[16], const uint8_t s2c_key[16],
    const uint8_t s2c_iv[16], uint64_t now_ms)
{
    if (session == NULL || config == NULL || adapter == NULL ||
        adapter->read == NULL || adapter->write == NULL || poll_fd < 0 ||
        transport_tx_bytes == NULL || framebuffer_width == 0u ||
        framebuffer_height == 0u || c2s_key == NULL || c2s_iv == NULL ||
        s2c_key == NULL || s2c_iv == NULL || now_ms == 0u ||
        (config->capture_query_count == 0u && !config->capture_initial_only) ||
        (config->capture_require_mutation_ack &&
         !rfb_capture_control_endpoint_valid(config->capture_control_fd))) {
        return RFB_ERR_PROTOCOL;
    }

    rfb_session_clear(session);
    session->cfg = *config;
    session->sock.fd = poll_fd;
    session->io = *adapter;
    session->transport_tx_bytes = transport_tx_bytes;
    session->alloc = rfb_default_allocator();
    rfb_buffer_init(&session->in, session->alloc,
                    RFB_LIMIT_FB_BYTES_POLICY);
    rfb_buffer_init(&session->out, session->alloc,
                    RFB_LIMIT_OUTBOUND_BYTES);
    rfb_buffer_init(&session->apple_plain, session->alloc,
                    RFB_LIMIT_FB_BYTES_POLICY);
    rfb_buffer_init(&session->apple_stage, session->alloc,
                    RFB_LIMIT_FB_BYTES_POLICY);
    rfb_framebuffer_init(&session->fb, session->alloc);
    rfb_error error = rfb_framebuffer_resize(
        &session->fb, framebuffer_width, framebuffer_height,
        RFB_LIMIT_FB_BYTES_POLICY);
    if (error != RFB_OK) {
        session->last_error = error;
        return error;
    }
    session->fb_width = framebuffer_width;
    session->fb_height = framebuffer_height;
    session->pf = rfb_pixel_format_canonical_request();
    session->server_pf = session->pf;
    session->zstream = rfb_zlib_create();
    if (session->zstream == NULL) {
        session->last_error = RFB_ERR_NOMEM;
        return RFB_ERR_NOMEM;
    }
    rfb_pacing_init(&session->pacing, config->max_fps);
    rfb_server_engine_init(&session->eng);

    const rfb_capture_scheduler_config scheduler_config = {
        .queries = config->capture_queries,
        .query_count = config->capture_query_count,
        .framebuffer_width = framebuffer_width,
        .framebuffer_height = framebuffer_height,
        .response_timeout_ms = config->capture_response_timeout_ms,
        .quiet_ms = config->capture_quiet_ms,
        .initial_only = config->capture_initial_only,
        .initial_zrle_only = config->capture_initial_zrle_only,
        .require_mutation_ack = config->capture_require_mutation_ack,
        .mutation_timeout_ms = config->capture_mutation_timeout_ms,
        .initial_rectangle_max = config->capture_initial_rectangle_max,
        .rect_observations = config->capture_rect_observations,
        .rect_observation_capacity =
            config->capture_rect_observation_capacity,
        .final_observations = config->capture_final_observations,
        .final_observation_capacity =
            config->capture_final_observation_capacity,
        .on_result = config->capture_on_result,
        .on_result_ctx = config->capture_on_result_ctx,
    };
    error = rfb_capture_scheduler_init_config(&session->capture,
                                               &scheduler_config);
    if (error != RFB_OK) {
        session->last_error = error;
        return error;
    }
    session->capture_enabled = true;
    session->capture_now_ms = now_ms;
    session->dialect = RFB_SESSION_DIALECT_APPLE_CLEARTEXT_MVP;

    uint8_t wrap_key[16];
    memset(wrap_key, 0x5au, sizeof wrap_key);
    apple_record_init(&session->apple_rl, wrap_key);
    memset(wrap_key, 0, sizeof wrap_key);
    session->apple_rl_inited = true;
    if (!apple_record_set_direction(&session->apple_rl, APPLE_DIR_ENCRYPT,
                                    c2s_key, c2s_iv) ||
        !apple_record_set_direction(&session->apple_rl, APPLE_DIR_DECRYPT,
                                    s2c_key, s2c_iv)) {
        session->last_error = RFB_ERR_INTERNAL;
        return RFB_ERR_INTERNAL;
    }
    session->apple_records_active = true;
    session->active = true;
    session->last_error = RFB_OK;

    error = session_send_fbur_rect(session, false, 0u, 0u,
                                   framebuffer_width, framebuffer_height);
    if (error == RFB_OK) {
        error = rfb_session_capture_step_with_clock(
            session, fixed_capture_clock, &now_ms, 0);
        session->capture_clock_now_ms = NULL;
        session->capture_clock_opaque = NULL;
    }
    if (error != RFB_OK) {
        session->last_error = error;
    }
    return error;
}

rfb_error rfb_session_test_apple_capture_step(rfb_session *session,
                                              uint64_t now_ms)
{
    const rfb_error error = rfb_session_capture_step_with_clock(
        session, fixed_capture_clock, &now_ms, 0);
    if (session != NULL) {
        session->capture_clock_now_ms = NULL;
        session->capture_clock_opaque = NULL;
    }
    return error;
}

rfb_error rfb_session_test_apple_capture_step_with_clock(
    rfb_session *session, rfb_session_test_clock_now_ms_fn now_ms,
    void *clock_opaque, int poll_ms)
{
    const rfb_error error = rfb_session_capture_step_with_clock(
        session, now_ms, clock_opaque, poll_ms);
    if (session != NULL) {
        session->capture_clock_now_ms = NULL;
        session->capture_clock_opaque = NULL;
    }
    return error;
}

rfb_error rfb_session_test_capture_modern_setup(
    rfb_session *session, const rfb_session_config *config,
    rfb_session_test_modern_setup_mode mode, uint8_t *transport_bytes,
    size_t transport_capacity, size_t *transport_length)
{
    if (session == NULL || config == NULL || transport_bytes == NULL ||
        transport_length == NULL ||
        (mode != RFB_SESSION_TEST_MODERN_SETUP_CONTROL &&
         mode != RFB_SESSION_TEST_MODERN_SETUP_PRIVATE_ENCODINGS &&
         mode != RFB_SESSION_TEST_MODERN_SETUP_DEFAULT) ||
        (config->capture_initial_only !=
         (mode == RFB_SESSION_TEST_MODERN_SETUP_CONTROL))) {
        return RFB_ERR_INTERNAL;
    }
    *transport_length = 0u;
    setup_transport_capture capture = {
        .bytes = transport_bytes,
        .capacity = transport_capacity,
        .length = 0u,
    };
    rfb_error error = init_setup_session(session, config, &capture);
    if (error != RFB_OK) {
        return error;
    }
    error = session_queue_apple_modern_setup(
        session, mode == RFB_SESSION_TEST_MODERN_SETUP_PRIVATE_ENCODINGS);
    *transport_length = capture.length;
    rfb_buffer_destroy(&session->out);
    return error;
}
