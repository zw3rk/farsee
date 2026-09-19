// SPDX-License-Identifier: Apache-2.0
//
// Deterministic contracts for the FreeRDP facade event pump.

#ifdef FARSEE_WITH_RDP

#include "protocol/rdp/rdp_callbacks.h"
#include "protocol/rdp/rdp_freerdp_facade_internal.h"
#include "tests/test_framework/rfb_test.h"

#include <freerdp/error.h>
#include <freerdp/freerdp.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define FAKE_RUN_STEPS 8u
#define FAKE_RUN_HANDLES 64u

typedef struct fake_facade_run {
    size_t disconnect_after;
    size_t handle_count;
    bool abort_event_present;
    bool check_ok;
    uint32_t last_error;
    rdp_freerdp_wait_result waits[FAKE_RUN_STEPS];
    size_t wait_result_count;
    uint64_t times[FAKE_RUN_STEPS];
    size_t time_count;

    unsigned shall_calls;
    unsigned abort_calls;
    unsigned get_handles_calls;
    unsigned abort_event_calls;
    unsigned wait_calls;
    unsigned check_calls;
    unsigned clock_calls;
    unsigned last_error_calls;
    unsigned tick_calls;
    size_t observed_wait_count;
    uint32_t observed_wait_ms;
    rdp_freerdp_wait_handle observed_last_handle;

    unsigned char handle_tokens[FAKE_RUN_HANDLES];
    unsigned char abort_token;
} fake_facade_run;

typedef struct fake_facade_stats {
    bool active;
    bool available;
    uint64_t in_bytes;
    uint64_t out_bytes;
    unsigned active_calls;
    unsigned get_calls;
} fake_facade_stats;

static bool strings_equal(const char *left, const char *right)
{
    return left != NULL && right != NULL && strcmp(left, right) == 0;
}

static bool fake_stats_active(void *user, void *context)
{
    fake_facade_stats *fake = (fake_facade_stats *)user;
    RFB_CHECK(context == fake);
    fake->active_calls++;
    return fake->active;
}

static bool fake_stats_get(void *user, void *context, uint64_t *out_in_bytes,
                           uint64_t *out_out_bytes)
{
    fake_facade_stats *fake = (fake_facade_stats *)user;
    RFB_CHECK(context == fake);
    RFB_CHECK(out_in_bytes != NULL);
    RFB_CHECK(out_out_bytes != NULL);
    fake->get_calls++;
    if (!fake->available) {
        return false;
    }
    *out_in_bytes = fake->in_bytes;
    *out_out_bytes = fake->out_bytes;
    return true;
}

static void fake_run_reset(fake_facade_run *fake)
{
    memset(fake, 0, sizeof *fake);
    fake->disconnect_after = 1u;
    fake->handle_count = 1u;
    fake->abort_event_present = true;
    fake->check_ok = true;
    fake->last_error = FREERDP_ERROR_SUCCESS;
    fake->waits[0] = RDP_FREERDP_WAIT_TIMEOUT;
    fake->wait_result_count = 1u;
}

static bool fake_shall_disconnect(void *user, void *context)
{
    fake_facade_run *fake = (fake_facade_run *)user;
    RFB_CHECK(context == fake);
    fake->shall_calls++;
    return (size_t)fake->shall_calls > fake->disconnect_after;
}

static void fake_abort_connect(void *user, void *context)
{
    fake_facade_run *fake = (fake_facade_run *)user;
    RFB_CHECK(context == fake);
    fake->abort_calls++;
}

static size_t fake_get_event_handles(void *user, void *context,
                                     rdp_freerdp_wait_handle *handles,
                                     size_t capacity)
{
    fake_facade_run *fake = (fake_facade_run *)user;
    RFB_CHECK(context == fake);
    fake->get_handles_calls++;
    if (fake->handle_count <= capacity) {
        for (size_t i = 0u; i < fake->handle_count; i++) {
            handles[i] = &fake->handle_tokens[i];
        }
    }
    return fake->handle_count;
}

static rdp_freerdp_wait_handle fake_abort_event(void *user, void *context)
{
    fake_facade_run *fake = (fake_facade_run *)user;
    RFB_CHECK(context == fake);
    fake->abort_event_calls++;
    return fake->abort_event_present ? &fake->abort_token : NULL;
}

static rdp_freerdp_wait_result fake_wait(
    void *user, const rdp_freerdp_wait_handle *handles,
    size_t handle_count, uint32_t timeout_ms)
{
    fake_facade_run *fake = (fake_facade_run *)user;
    RFB_CHECK(handles != NULL);
    fake->observed_wait_count = handle_count;
    fake->observed_wait_ms = timeout_ms;
    fake->observed_last_handle = handles[handle_count - 1u];
    const size_t index = fake->wait_calls < fake->wait_result_count
                           ? fake->wait_calls
                           : fake->wait_result_count - 1u;
    fake->wait_calls++;
    return fake->waits[index];
}

static bool fake_check_event_handles(void *user, void *context)
{
    fake_facade_run *fake = (fake_facade_run *)user;
    RFB_CHECK(context == fake);
    fake->check_calls++;
    return fake->check_ok;
}

static uint64_t fake_monotonic_ms(void *user)
{
    fake_facade_run *fake = (fake_facade_run *)user;
    const size_t index = fake->clock_calls < fake->time_count
                           ? fake->clock_calls
                           : fake->time_count - 1u;
    fake->clock_calls++;
    return fake->time_count != 0u ? fake->times[index] : 0u;
}

static uint32_t fake_last_error(void *user, void *context)
{
    fake_facade_run *fake = (fake_facade_run *)user;
    RFB_CHECK(context == fake);
    fake->last_error_calls++;
    return fake->last_error;
}

static void fake_tick(void *user)
{
    fake_facade_run *fake = (fake_facade_run *)user;
    fake->tick_calls++;
}

static rdp_freerdp_run_ops fake_run_ops(fake_facade_run *fake)
{
    const rdp_freerdp_run_ops ops = {
        .user = fake,
        .shall_disconnect = fake_shall_disconnect,
        .abort_connect = fake_abort_connect,
        .get_event_handles = fake_get_event_handles,
        .abort_event = fake_abort_event,
        .wait = fake_wait,
        .check_event_handles = fake_check_event_handles,
        .monotonic_ms = fake_monotonic_ms,
        .last_error = fake_last_error,
    };
    return ops;
}

static void check_error(farsee_error error, farsee_error_code code,
                        farsee_subsystem subsystem)
{
    RFB_CHECK_EQ_INT(error.code, code);
    RFB_CHECK_EQ_INT(error.subsystem, subsystem);
    RFB_CHECK_EQ_INT(error.phase, FARSEE_PHASE_ACTIVE);
}

RFB_TEST(rdp_facade_run, wire_stats__requires_active_available_counters)
{
    fake_facade_stats fake;
    memset(&fake, 0, sizeof fake);
    const rdp_freerdp_stats_ops ops = {
        .user = &fake,
        .is_active = fake_stats_active,
        .get_stats = fake_stats_get,
    };
    uint64_t in_bytes = 11u;
    uint64_t out_bytes = 22u;

    RFB_CHECK(!rdp_freerdp_wire_stats_context(
        &fake, &in_bytes, &out_bytes, &ops));
    RFB_CHECK_EQ_UINT(fake.active_calls, 1u);
    RFB_CHECK_EQ_UINT(fake.get_calls, 0u);
    RFB_CHECK_EQ_UINT(in_bytes, 11u);
    RFB_CHECK_EQ_UINT(out_bytes, 22u);

    fake.active = true;
    RFB_CHECK(!rdp_freerdp_wire_stats_context(
        &fake, &in_bytes, &out_bytes, &ops));
    RFB_CHECK_EQ_UINT(fake.get_calls, 1u);
    RFB_CHECK_EQ_UINT(in_bytes, 11u);
    RFB_CHECK_EQ_UINT(out_bytes, 22u);

    fake.available = true;
    fake.in_bytes = UINT64_C(0x1020304050607080);
    fake.out_bytes = UINT64_C(0x8877665544332211);
    RFB_CHECK(rdp_freerdp_wire_stats_context(
        &fake, &in_bytes, &out_bytes, &ops));
    RFB_CHECK_EQ_UINT(in_bytes, fake.in_bytes);
    RFB_CHECK_EQ_UINT(out_bytes, fake.out_bytes);
    RFB_CHECK(rdp_freerdp_wire_stats_context(
        &fake, NULL, NULL, &ops));
}

RFB_TEST(rdp_facade_run, wire_stats__rejects_incomplete_operation_table)
{
    fake_facade_stats fake;
    memset(&fake, 0, sizeof fake);
    fake.active = true;
    fake.available = true;
    rdp_freerdp_stats_ops ops = {
        .user = &fake,
        .is_active = fake_stats_active,
        .get_stats = fake_stats_get,
    };
    uint64_t in_bytes = 11u;
    uint64_t out_bytes = 22u;

    RFB_CHECK(!rdp_freerdp_wire_stats_context(
        NULL, &in_bytes, &out_bytes, &ops));
    RFB_CHECK(!rdp_freerdp_wire_stats_context(
        &fake, &in_bytes, &out_bytes, NULL));
    ops.is_active = NULL;
    RFB_CHECK(!rdp_freerdp_wire_stats_context(
        &fake, &in_bytes, &out_bytes, &ops));
    ops.is_active = fake_stats_active;
    ops.get_stats = NULL;
    RFB_CHECK(!rdp_freerdp_wire_stats_context(
        &fake, &in_bytes, &out_bytes, &ops));

    RFB_CHECK_EQ_UINT(fake.active_calls, 0u);
    RFB_CHECK_EQ_UINT(fake.get_calls, 0u);
    RFB_CHECK_EQ_UINT(in_bytes, 11u);
    RFB_CHECK_EQ_UINT(out_bytes, 22u);
}

static void check_invalid_run_contract(
    fake_facade_run *fake, const rdp_run_budget *budget,
    const rdp_freerdp_run_ops *ops)
{
    bool got_frame = true;
    check_error(rdp_freerdp_run_context_until(
                    fake, budget, &got_frame, ops),
                FARSEE_ERR_STATE, FARSEE_SUB_RDP);
    RFB_CHECK(!got_frame);
}

RFB_TEST(rdp_facade_run, invalid_contract__fails_closed_and_resets_output)
{
    fake_facade_run fake;
    fake_run_reset(&fake);
    rdp_freerdp_run_ops ops = fake_run_ops(&fake);
    rdp_run_budget budget;
    memset(&budget, 0, sizeof budget);
    bool got_frame = true;

    check_error(rdp_freerdp_run_context_until(
                    NULL, &budget, &got_frame, &ops),
                FARSEE_ERR_STATE, FARSEE_SUB_RDP);
    RFB_CHECK(!got_frame);
    RFB_CHECK_EQ_UINT(fake.shall_calls, 0u);

    got_frame = true;
    ops.wait = NULL;
    check_error(rdp_freerdp_run_context_until(
                    &fake, &budget, &got_frame, &ops),
                FARSEE_ERR_STATE, FARSEE_SUB_RDP);
    RFB_CHECK(!got_frame);
    RFB_CHECK_EQ_UINT(fake.shall_calls, 0u);
}

RFB_TEST(rdp_facade_run, incomplete_run_ops__each_fails_closed)
{
    fake_facade_run fake;
    fake_run_reset(&fake);
    rdp_freerdp_run_ops ops = fake_run_ops(&fake);
    const rdp_freerdp_run_ops complete = ops;
    rdp_run_budget budget;
    memset(&budget, 0, sizeof budget);

    check_invalid_run_contract(&fake, NULL, &ops);
    check_invalid_run_contract(&fake, &budget, NULL);
    ops.shall_disconnect = NULL;
    check_invalid_run_contract(&fake, &budget, &ops);
    ops = complete;
    ops.abort_connect = NULL;
    check_invalid_run_contract(&fake, &budget, &ops);
    ops = complete;
    ops.get_event_handles = NULL;
    check_invalid_run_contract(&fake, &budget, &ops);
    ops = complete;
    ops.abort_event = NULL;
    check_invalid_run_contract(&fake, &budget, &ops);
    ops = complete;
    ops.wait = NULL;
    check_invalid_run_contract(&fake, &budget, &ops);
    ops = complete;
    ops.check_event_handles = NULL;
    check_invalid_run_contract(&fake, &budget, &ops);
    ops = complete;
    ops.monotonic_ms = NULL;
    check_invalid_run_contract(&fake, &budget, &ops);
    ops = complete;
    ops.last_error = NULL;
    check_invalid_run_contract(&fake, &budget, &ops);

    RFB_CHECK_EQ_UINT(fake.shall_calls, 0u);
    RFB_CHECK_EQ_UINT(fake.abort_event_calls, 0u);
}

RFB_TEST(rdp_facade_run, oversized_handle_set__fails_before_waiting)
{
    fake_facade_run fake;
    fake_run_reset(&fake);
    fake.disconnect_after = SIZE_MAX;
    fake.handle_count = FAKE_RUN_HANDLES;
    rdp_freerdp_run_ops ops = fake_run_ops(&fake);
    rdp_run_budget budget;
    memset(&budget, 0, sizeof budget);

    check_error(rdp_freerdp_run_context_until(
                    &fake, &budget, NULL, &ops),
                FARSEE_ERR_STATE, FARSEE_SUB_RDP);
    RFB_CHECK_EQ_UINT(fake.get_handles_calls, 1u);
    RFB_CHECK_EQ_UINT(fake.wait_calls, 0u);
    RFB_CHECK_EQ_UINT(fake.last_error_calls, 0u);
}

RFB_TEST(rdp_facade_run, maximum_handle_set__keeps_abort_event_wakeable)
{
    fake_facade_run fake;
    fake_run_reset(&fake);
    fake.handle_count = FAKE_RUN_HANDLES - 1u;
    rdp_freerdp_run_ops ops = fake_run_ops(&fake);
    rdp_run_budget budget;
    memset(&budget, 0, sizeof budget);

    check_error(rdp_freerdp_run_context_until(
                    &fake, &budget, NULL, &ops),
                FARSEE_E_OK, FARSEE_SUB_NONE);
    RFB_CHECK_EQ_UINT(fake.wait_calls, 1u);
    RFB_CHECK_EQ_UINT(fake.observed_wait_count, FAKE_RUN_HANDLES);
    RFB_CHECK(fake.observed_last_handle == &fake.abort_token);
}

RFB_TEST(rdp_facade_run, requested_stop__aborts_wait_and_returns_cleanly)
{
    fake_facade_run fake;
    fake_run_reset(&fake);
    fake.disconnect_after = SIZE_MAX;
    rdp_freerdp_run_ops ops = fake_run_ops(&fake);
    farsee_atomic_int stop = 1;
    rdp_run_budget budget;
    memset(&budget, 0, sizeof budget);
    budget.stop_flag = &stop;
    bool got_frame = true;

    check_error(rdp_freerdp_run_context_until(
                    &fake, &budget, &got_frame, &ops),
                FARSEE_E_OK, FARSEE_SUB_NONE);
    RFB_CHECK(!got_frame);
    RFB_CHECK_EQ_UINT(fake.abort_calls, 1u);
    RFB_CHECK_EQ_UINT(fake.get_handles_calls, 0u);
    RFB_CHECK_EQ_UINT(fake.wait_calls, 0u);
    RFB_CHECK_EQ_UINT(fake.last_error_calls, 0u);
}

RFB_TEST(rdp_facade_run, wait_timeout__ticks_before_and_after_without_dispatch)
{
    fake_facade_run fake;
    fake_run_reset(&fake);
    rdp_freerdp_run_ops ops = fake_run_ops(&fake);
    rdp_run_budget budget;
    memset(&budget, 0, sizeof budget);
    budget.on_tick = fake_tick;
    budget.on_tick_user = &fake;

    check_error(rdp_freerdp_run_context_until(
                    &fake, &budget, NULL, &ops),
                FARSEE_E_OK, FARSEE_SUB_NONE);
    RFB_CHECK_EQ_UINT(fake.tick_calls, 2u);
    RFB_CHECK_EQ_UINT(fake.check_calls, 0u);
    RFB_CHECK_EQ_UINT(fake.wait_calls, 1u);
    RFB_CHECK_EQ_UINT(fake.observed_wait_count, 2u);
    RFB_CHECK_EQ_UINT(fake.observed_wait_ms, 10u);
    RFB_CHECK(fake.observed_last_handle == &fake.abort_token);
}

RFB_TEST(rdp_facade_run, signaled_wait__dispatches_without_abort_event)
{
    fake_facade_run fake;
    fake_run_reset(&fake);
    fake.abort_event_present = false;
    fake.waits[0] = RDP_FREERDP_WAIT_SIGNALED;
    rdp_freerdp_run_ops ops = fake_run_ops(&fake);
    rdp_run_budget budget;
    memset(&budget, 0, sizeof budget);

    check_error(rdp_freerdp_run_context_until(
                    &fake, &budget, NULL, &ops),
                FARSEE_E_OK, FARSEE_SUB_NONE);
    RFB_CHECK_EQ_UINT(fake.wait_calls, 1u);
    RFB_CHECK_EQ_UINT(fake.check_calls, 1u);
    RFB_CHECK_EQ_UINT(fake.observed_wait_count, 1u);
    RFB_CHECK(fake.observed_last_handle == &fake.handle_tokens[0]);
}

RFB_TEST(rdp_facade_run, failed_wait__preserves_transport_failure)
{
    fake_facade_run fake;
    fake_run_reset(&fake);
    fake.disconnect_after = SIZE_MAX;
    fake.waits[0] = RDP_FREERDP_WAIT_FAILED;
    fake.last_error = FREERDP_ERROR_CONNECT_TRANSPORT_FAILED;
    rdp_freerdp_run_ops ops = fake_run_ops(&fake);
    rdp_run_budget budget;
    memset(&budget, 0, sizeof budget);
    budget.on_tick = fake_tick;
    budget.on_tick_user = &fake;

    check_error(rdp_freerdp_run_context_until(
                    &fake, &budget, NULL, &ops),
                FARSEE_ERR_CONNECT_FAILURE, FARSEE_SUB_RDP);
    RFB_CHECK_EQ_UINT(fake.tick_calls, 1u);
    RFB_CHECK_EQ_UINT(fake.check_calls, 0u);
    RFB_CHECK_EQ_UINT(fake.last_error_calls, 1u);
}

RFB_TEST(rdp_facade_run, failed_dispatch__classifies_clean_peer_disconnect)
{
    fake_facade_run fake;
    fake_run_reset(&fake);
    fake.disconnect_after = SIZE_MAX;
    fake.waits[0] = RDP_FREERDP_WAIT_SIGNALED;
    fake.check_ok = false;
    fake.last_error = FREERDP_ERROR_IDLE_TIMEOUT;
    rdp_freerdp_run_ops ops = fake_run_ops(&fake);
    rdp_run_budget budget;
    memset(&budget, 0, sizeof budget);
    budget.on_tick = fake_tick;
    budget.on_tick_user = &fake;

    check_error(rdp_freerdp_run_context_until(
                    &fake, &budget, NULL, &ops),
                FARSEE_E_OK, FARSEE_SUB_NONE);
    RFB_CHECK_EQ_UINT(fake.tick_calls, 1u);
    RFB_CHECK_EQ_UINT(fake.check_calls, 1u);
    RFB_CHECK_EQ_UINT(fake.last_error_calls, 1u);
}

RFB_TEST(rdp_facade_run, peer_end__accepts_only_documented_clean_error_codes)
{
    static const uint32_t clean[] = {
        FREERDP_ERROR_SUCCESS,
        FREERDP_ERROR_NONE,
        FREERDP_ERROR_LOGOFF_BY_USER,
        FREERDP_ERROR_RPC_INITIATED_LOGOFF,
        FREERDP_ERROR_RPC_INITIATED_DISCONNECT,
        FREERDP_ERROR_RPC_INITIATED_DISCONNECT_BY_USER,
        FREERDP_ERROR_DISCONNECTED_BY_OTHER_CONNECTION,
        FREERDP_ERROR_IDLE_TIMEOUT,
    };
    for (size_t i = 0u; i < sizeof clean / sizeof clean[0]; i++) {
        fake_facade_run fake;
        fake_run_reset(&fake);
        fake.handle_count = 0u;
        fake.last_error = clean[i];
        rdp_freerdp_run_ops ops = fake_run_ops(&fake);
        rdp_run_budget budget;
        memset(&budget, 0, sizeof budget);
        check_error(rdp_freerdp_run_context_until(
                        &fake, &budget, NULL, &ops),
                    FARSEE_E_OK, FARSEE_SUB_NONE);
        RFB_CHECK_EQ_UINT(fake.wait_calls, 0u);
        RFB_CHECK_EQ_UINT(fake.last_error_calls, 1u);
    }

    fake_facade_run fake;
    fake_run_reset(&fake);
    fake.handle_count = 0u;
    fake.last_error = FREERDP_ERROR_CONNECT_TRANSPORT_FAILED;
    rdp_freerdp_run_ops ops = fake_run_ops(&fake);
    rdp_run_budget budget;
    memset(&budget, 0, sizeof budget);
    check_error(rdp_freerdp_run_context_until(
                    &fake, &budget, NULL, &ops),
                FARSEE_ERR_CONNECT_FAILURE, FARSEE_SUB_RDP);
    RFB_CHECK_EQ_UINT(fake.last_error_calls, 1u);
}

RFB_TEST(rdp_facade_run, deadline_without_frame__returns_timeout)
{
    fake_facade_run fake;
    fake_run_reset(&fake);
    fake.disconnect_after = SIZE_MAX;
    fake.times[0] = 500u;
    fake.time_count = 1u;
    rdp_freerdp_run_ops ops = fake_run_ops(&fake);
    rdp_run_budget budget;
    memset(&budget, 0, sizeof budget);
    budget.deadline_monotonic_ms = 500u;
    bool got_frame = true;

    check_error(rdp_freerdp_run_context_until(
                    &fake, &budget, &got_frame, &ops),
                FARSEE_ERR_TIMEOUT, FARSEE_SUB_RDP);
    RFB_CHECK(!got_frame);
    RFB_CHECK_EQ_UINT(fake.wait_calls, 1u);
    RFB_CHECK_EQ_UINT(fake.last_error_calls, 0u);
}

static void set_first_frame(rdp_display_sink *sink)
{
    rdp_display_sink_init(sink);
    farsee_atomic_int_store(&sink->first_frame_delivered, 1);
}

RFB_TEST(rdp_facade_run, first_frame__returns_after_zero_settle)
{
    fake_facade_run fake;
    fake_run_reset(&fake);
    fake.disconnect_after = SIZE_MAX;
    fake.times[0] = 100u;
    fake.time_count = 1u;
    rdp_freerdp_run_ops ops = fake_run_ops(&fake);
    rdp_display_sink sink;
    set_first_frame(&sink);
    rdp_run_budget budget;
    memset(&budget, 0, sizeof budget);
    budget.sink = &sink;
    budget.stop_on_first_frame = true;
    bool got_frame = false;

    check_error(rdp_freerdp_run_context_until(
                    &fake, &budget, &got_frame, &ops),
                FARSEE_E_OK, FARSEE_SUB_NONE);
    RFB_CHECK(got_frame);
    RFB_CHECK_EQ_UINT(fake.wait_calls, 1u);
    RFB_CHECK_EQ_UINT(fake.last_error_calls, 0u);
}

RFB_TEST(rdp_facade_run, peer_end_after_frame__reports_delivered_frame)
{
    fake_facade_run fake;
    fake_run_reset(&fake);
    fake.handle_count = 0u;
    rdp_freerdp_run_ops ops = fake_run_ops(&fake);
    rdp_display_sink sink;
    set_first_frame(&sink);
    rdp_run_budget budget;
    memset(&budget, 0, sizeof budget);
    budget.sink = &sink;
    bool got_frame = false;

    check_error(rdp_freerdp_run_context_until(
                    &fake, &budget, &got_frame, &ops),
                FARSEE_E_OK, FARSEE_SUB_NONE);
    RFB_CHECK(got_frame);
    RFB_CHECK_EQ_UINT(fake.wait_calls, 0u);
    RFB_CHECK_EQ_UINT(fake.last_error_calls, 1u);
}

RFB_TEST(rdp_facade_run, deadline_after_frame__returns_success)
{
    fake_facade_run fake;
    fake_run_reset(&fake);
    fake.disconnect_after = SIZE_MAX;
    fake.times[0] = 100u;
    fake.time_count = 1u;
    rdp_freerdp_run_ops ops = fake_run_ops(&fake);
    rdp_display_sink sink;
    set_first_frame(&sink);
    rdp_run_budget budget;
    memset(&budget, 0, sizeof budget);
    budget.sink = &sink;
    budget.deadline_monotonic_ms = 100u;
    bool got_frame = false;

    check_error(rdp_freerdp_run_context_until(
                    &fake, &budget, &got_frame, &ops),
                FARSEE_E_OK, FARSEE_SUB_NONE);
    RFB_CHECK(got_frame);
    RFB_CHECK_EQ_UINT(fake.last_error_calls, 0u);
}

RFB_TEST(rdp_facade_run, settle_window__tracks_a_first_frame_at_time_zero)
{
    fake_facade_run fake;
    fake_run_reset(&fake);
    fake.disconnect_after = SIZE_MAX;
    fake.times[0] = 0u;
    fake.times[1] = 5u;
    fake.times[2] = 5u;
    fake.time_count = 3u;
    fake.waits[0] = RDP_FREERDP_WAIT_TIMEOUT;
    fake.waits[1] = RDP_FREERDP_WAIT_TIMEOUT;
    fake.waits[2] = RDP_FREERDP_WAIT_FAILED;
    fake.wait_result_count = 3u;
    fake.last_error = FREERDP_ERROR_CONNECT_TRANSPORT_FAILED;
    rdp_freerdp_run_ops ops = fake_run_ops(&fake);
    rdp_display_sink sink;
    set_first_frame(&sink);
    rdp_run_budget budget;
    memset(&budget, 0, sizeof budget);
    budget.sink = &sink;
    budget.stop_on_first_frame = true;
    budget.settle_ms_after_first = 5u;
    bool got_frame = false;

    check_error(rdp_freerdp_run_context_until(
                    &fake, &budget, &got_frame, &ops),
                FARSEE_E_OK, FARSEE_SUB_NONE);
    RFB_CHECK(got_frame);
    RFB_CHECK_EQ_UINT(fake.wait_calls, 2u);
    RFB_CHECK_EQ_UINT(fake.last_error_calls, 0u);
}

RFB_TEST(rdp_facade_run, settle_window__does_not_wrap_near_uint64_max)
{
    fake_facade_run fake;
    fake_run_reset(&fake);
    fake.disconnect_after = SIZE_MAX;
    fake.times[0] = UINT64_MAX - 2u;
    fake.times[1] = UINT64_MAX - 1u;
    fake.time_count = 2u;
    fake.waits[0] = RDP_FREERDP_WAIT_TIMEOUT;
    fake.waits[1] = RDP_FREERDP_WAIT_FAILED;
    fake.wait_result_count = 2u;
    rdp_freerdp_run_ops ops = fake_run_ops(&fake);
    rdp_display_sink sink;
    set_first_frame(&sink);
    rdp_run_budget budget;
    memset(&budget, 0, sizeof budget);
    budget.sink = &sink;
    budget.stop_on_first_frame = true;
    budget.settle_ms_after_first = 10u;
    bool got_frame = false;

    check_error(rdp_freerdp_run_context_until(
                    &fake, &budget, &got_frame, &ops),
                FARSEE_E_OK, FARSEE_SUB_NONE);
    RFB_CHECK(got_frame);
    RFB_CHECK_EQ_UINT(fake.wait_calls, 2u);
    RFB_CHECK_EQ_UINT(fake.last_error_calls, 1u);
}

RFB_TEST(rdp_facade, null_runtime_contracts__fail_closed_without_side_effects)
{
    uint64_t in_bytes = 11u;
    uint64_t out_bytes = 22u;
    RFB_CHECK(rdp_freerdp_cliprdr_state(NULL) == NULL);
    RFB_CHECK(rdp_freerdp_instance_opaque(NULL) == NULL);
    RFB_CHECK(!rdp_freerdp_wire_stats(NULL, &in_bytes, &out_bytes));
    RFB_CHECK_EQ_UINT(in_bytes, 11u);
    RFB_CHECK_EQ_UINT(out_bytes, 22u);
    RFB_CHECK_EQ_INT(rdp_freerdp_wire_fd(NULL), -1);
    RFB_CHECK(!rdp_freerdp_connect(NULL));
    RFB_CHECK(!rdp_freerdp_connect_with_stop(NULL, NULL));
    rdp_freerdp_clear_credentials(NULL);
    rdp_freerdp_request_stop(NULL);
    rdp_freerdp_disconnect(NULL);
    RFB_CHECK_EQ_UINT(rdp_freerdp_last_error(NULL), 0u);
    RFB_CHECK(strcmp(rdp_freerdp_last_error_name(NULL),
                     "FREERDP_ERROR_SUCCESS") == 0);
    RFB_CHECK(!rdp_freerdp_is_clean_peer_disconnect(NULL));
    rdp_freerdp_destroy(NULL);
}

RFB_TEST(rdp_facade, fresh_context__has_no_wire_or_error_state)
{
    rdp_freerdp_ctx *ctx = rdp_freerdp_create();
    RFB_CHECK(ctx != NULL);
    RFB_CHECK(rdp_freerdp_instance_opaque(ctx) != NULL);
    RFB_CHECK(rdp_freerdp_cliprdr_state(ctx) != NULL);
    uint64_t in_bytes = 11u;
    uint64_t out_bytes = 22u;
    RFB_CHECK(!rdp_freerdp_wire_stats(ctx, &in_bytes, &out_bytes));
    RFB_CHECK_EQ_UINT(in_bytes, 11u);
    RFB_CHECK_EQ_UINT(out_bytes, 22u);
    RFB_CHECK_EQ_INT(rdp_freerdp_wire_fd(ctx), -1);
    RFB_CHECK_EQ_UINT(rdp_freerdp_last_error(ctx), 0u);
    RFB_CHECK(strcmp(rdp_freerdp_last_error_name(ctx),
                     "FREERDP_ERROR_SUCCESS") == 0);
    RFB_CHECK(rdp_freerdp_is_clean_peer_disconnect(ctx));

    farsee_atomic_int stop = 1;
    rdp_run_budget budget;
    memset(&budget, 0, sizeof budget);
    budget.stop_flag = &stop;
    bool got_frame = true;
    check_error(rdp_freerdp_run_until(ctx, &budget, &got_frame),
                FARSEE_E_OK, FARSEE_SUB_NONE);
    RFB_CHECK(!got_frame);
    got_frame = true;
    check_error(rdp_freerdp_run_until(ctx, NULL, &got_frame),
                FARSEE_ERR_STATE, FARSEE_SUB_RDP);
    RFB_CHECK(!got_frame);

    rdp_freerdp_request_stop(ctx);
    rdp_freerdp_disconnect(ctx);
    rdp_freerdp_disconnect(ctx);
    rdp_freerdp_destroy(&ctx);
    RFB_CHECK(ctx == NULL);
}

RFB_TEST(rdp_facade, last_error__reports_nonclean_transport_failure)
{
    rdp_freerdp_ctx *ctx = rdp_freerdp_create();
    RFB_CHECK(ctx != NULL);
    freerdp *instance = (freerdp *)rdp_freerdp_instance_opaque(ctx);
    RFB_CHECK(instance != NULL);
    RFB_CHECK(instance->context != NULL);

    freerdp_set_last_error(instance->context,
                           FREERDP_ERROR_CONNECT_TRANSPORT_FAILED);
    RFB_CHECK_EQ_UINT(rdp_freerdp_last_error(ctx),
                      FREERDP_ERROR_CONNECT_TRANSPORT_FAILED);
    const char *name = rdp_freerdp_last_error_name(ctx);
    RFB_CHECK(name != NULL);
    RFB_CHECK(!strings_equal(name, "FREERDP_ERROR_SUCCESS"));
    RFB_CHECK(!rdp_freerdp_is_clean_peer_disconnect(ctx));
    rdp_freerdp_destroy(&ctx);
}

RFB_TEST(rdp_facade, clear_credentials__prevents_callback_reuse)
{
    farsee_rdp_settings settings;
    farsee_rdp_settings_init_for_host(
        &settings, "rdp.test", 3389u, "alice", "EXAMPLE");
    farsee_security_policy policy = farsee_security_policy_default_rdp();
    policy.allow_insecure_cert = true;
    farsee_credential_response credentials;
    farsee_credential_response_init(&credentials);
    credentials.username = "alice";
    credentials.domain = "EXAMPLE";
    uint8_t password_bytes[] = { 's', 'e', 'c', 'r', 'e', 't' };
    credentials.password.data = password_bytes;
    credentials.password.len = sizeof password_bytes;
    credentials.password.cap = sizeof password_bytes;

    RFB_CHECK(!rdp_freerdp_apply_settings(
        NULL, &settings, &policy, &credentials,
        FARSEE_TRUST_DECISION_APPROVE_ONCE, NULL));
    rdp_freerdp_ctx *ctx = rdp_freerdp_create();
    RFB_CHECK(ctx != NULL);
    RFB_CHECK(!rdp_freerdp_apply_settings(
        ctx, NULL, &policy, &credentials,
        FARSEE_TRUST_DECISION_APPROVE_ONCE, NULL));
    RFB_CHECK(!rdp_freerdp_apply_settings(
        ctx, &settings, NULL, &credentials,
        FARSEE_TRUST_DECISION_APPROVE_ONCE, NULL));
    RFB_CHECK(rdp_freerdp_apply_settings(
        ctx, &settings, &policy, &credentials,
        FARSEE_TRUST_DECISION_APPROVE_ONCE, NULL));

    freerdp *instance = (freerdp *)rdp_freerdp_instance_opaque(ctx);
    RFB_CHECK(instance != NULL);
    char *username = NULL;
    char *password = NULL;
    char *domain = NULL;
    RFB_CHECK(instance->Authenticate(
                  instance, &username, &password, &domain) == TRUE);
    RFB_CHECK(strings_equal(username, "alice"));
    RFB_CHECK(strings_equal(password, "secret"));
    RFB_CHECK(strings_equal(domain, "EXAMPLE"));
    free(username);
    free(password);
    free(domain);

    rdp_freerdp_clear_credentials(ctx);
    username = NULL;
    password = NULL;
    domain = NULL;
    RFB_CHECK(instance->Authenticate(
                  instance, &username, &password, &domain) == FALSE);
    RFB_CHECK(username == NULL);
    RFB_CHECK(password == NULL);
    RFB_CHECK(domain == NULL);
    rdp_freerdp_destroy(&ctx);
}

#endif  // FARSEE_WITH_RDP
