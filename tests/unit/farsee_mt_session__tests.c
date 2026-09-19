// SPDX-License-Identifier: Apache-2.0
//
// Shared multi-thread session skeleton tests.
// The stop flag is farsee_atomic_int, not bare volatile sig_atomic_t.

#include "farsee/farsee_atomic.h"
#include "farsee/farsee_cmd_queue.h"
#include "farsee/farsee_error.h"
#include "farsee/farsee_frame_slot.h"
#include "farsee/farsee_mt_session.h"
#include "farsee/farsee_thread.h"
#include "tests/test_framework/rfb_test.h"

#include <string.h>

// --- helpers ---------------------------------------------------------------

typedef struct mt_test_ctx {
    farsee_atomic_int *stop;
    farsee_atomic_int protocol_ran;
    farsee_atomic_int present_ran;
    farsee_atomic_int input_ran;
    farsee_atomic_int frames_seen;
    farsee_atomic_int after_present_count;
    uint8_t pixel[4];
} mt_test_ctx;

static farsee_mt_terminal_kind test_protocol_fn(
    void *user, farsee_frame_slot *slot, farsee_cmd_queue *cmds,
    farsee_atomic_int *stop, farsee_mt_terminal *terminal)
{
    mt_test_ctx *t = (mt_test_ctx *)user;
    (void)cmds;
    farsee_atomic_int_store(&t->protocol_ran, 1);
    // Publish one frame then request stop so the session winds down.
    (void)farsee_frame_slot_publish(slot, t->pixel, 1, 1, 4,
                                    FARSEE_PIXEL_BGRA8888);
    // Brief wait so present can observe the frame.
    {
        const uint64_t dl = farsee_thread_monotonic_ms() + 200u;
        while (!farsee_atomic_int_load_nonzero(stop) &&
               farsee_thread_monotonic_ms() < dl) {
            if (farsee_atomic_int_load_nonzero(&t->frames_seen)) {
                break;
            }
            // Spin lightly via timed cond on the slot kick path.
            farsee_frame_view v;
            if (farsee_frame_slot_acquire_wait(slot, 0,
                                               farsee_thread_monotonic_ms() + 20u,
                                               stop, &v)) {
                farsee_frame_slot_release(slot, &v);
            }
        }
    }
    farsee_atomic_int_store(stop, 1);
    farsee_frame_slot_kick(slot);
    farsee_cmd_queue_kick(cmds);
    (void)terminal;
    return FARSEE_MT_TERMINAL_REQUESTED_STOP;
}

static bool test_on_frame(void *user, const farsee_frame_view *v)
{
    mt_test_ctx *t = (mt_test_ctx *)user;
    if (v != NULL && v->pixels != NULL) {
        (void)atomic_fetch_add_explicit(&t->frames_seen, 1,
                                        memory_order_acq_rel);
        return true;
    }
    return false;
}

static void test_after_present(void *user)
{
    mt_test_ctx *t = (mt_test_ctx *)user;
    (void)atomic_fetch_add_explicit(&t->after_present_count, 1,
                                    memory_order_acq_rel);
}

static farsee_mt_terminal_kind test_present_fn(
    void *user, farsee_frame_slot *slot, farsee_atomic_int *stop,
    farsee_mt_terminal *terminal)
{
    mt_test_ctx *t = (mt_test_ctx *)user;
    farsee_atomic_int_store(&t->present_ran, 1);
    return farsee_mt_present_loop(
        slot, stop, 16u, test_on_frame, t, test_after_present, t,
        /*force_repaint=*/NULL, terminal);
}

static farsee_mt_terminal_kind test_input_fn(
    void *user, farsee_cmd_queue *cmds, farsee_atomic_int *stop,
    farsee_mt_terminal *terminal)
{
    mt_test_ctx *t = (mt_test_ctx *)user;
    (void)cmds;
    farsee_atomic_int_store(&t->input_ran, 1);
    // Wait until stop (set by protocol or farsee_mt_run after protocol joins).
    while (!farsee_atomic_int_load_nonzero(stop)) {
        const uint64_t dl = farsee_thread_monotonic_ms() + 50u;
        farsee_cmd c;
        (void)farsee_cmd_queue_pop(cmds, &c, dl, stop);
    }
    (void)terminal;
    return FARSEE_MT_TERMINAL_REQUESTED_STOP;
}

RFB_TEST(farsee_mt, farsee_mt_run__bad_config_returns_state)
{
    farsee_mt_outcome outcome;
    farsee_error e = farsee_mt_run(NULL, &outcome);
    RFB_CHECK(e.code == FARSEE_ERR_STATE);
    RFB_CHECK(outcome.kind == FARSEE_MT_TERMINAL_INTERNAL_FAILURE);
}

RFB_TEST(farsee_mt, farsee_mt_run__three_threads_stop_clean)
{
    farsee_frame_slot slot;
    farsee_cmd_queue cmds;
    RFB_CHECK(farsee_frame_slot_init(&slot));
    RFB_CHECK(farsee_cmd_queue_init(&cmds));

    farsee_atomic_int stop = 0;
    mt_test_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.stop = &stop;
    ctx.pixel[0] = 0x11;
    ctx.pixel[1] = 0x22;
    ctx.pixel[2] = 0x33;
    ctx.pixel[3] = 0xFF;

    farsee_mt_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.slot = &slot;
    cfg.cmds = &cmds;
    cfg.stop_flag = &stop;
    cfg.protocol_fn = test_protocol_fn;
    cfg.protocol_user = &ctx;
    cfg.present_fn = test_present_fn;
    cfg.present_user = &ctx;
    cfg.input_fn = test_input_fn;
    cfg.input_user = &ctx;

    farsee_mt_outcome outcome;
    farsee_error e = farsee_mt_run(&cfg, &outcome);
    RFB_CHECK(e.code == FARSEE_E_OK);
    RFB_CHECK(outcome.kind == FARSEE_MT_TERMINAL_REQUESTED_STOP);
    RFB_CHECK(farsee_atomic_int_load(&ctx.protocol_ran) == 1);
    RFB_CHECK(farsee_atomic_int_load(&ctx.present_ran) == 1);
    RFB_CHECK(farsee_atomic_int_load(&ctx.input_ran) == 1);
    RFB_CHECK(farsee_atomic_int_load(&ctx.frames_seen) >= 1);
    RFB_CHECK(farsee_atomic_int_load(&ctx.after_present_count) >= 1);
    RFB_CHECK(farsee_atomic_int_load_nonzero(&stop));

    farsee_cmd_queue_destroy(&cmds);
    farsee_frame_slot_destroy(&slot);
}

static size_t delayed_input_create_calls;
static farsee_atomic_int delayed_protocol_done;
static farsee_thread_fn delayed_protocol_entry;
static void *delayed_protocol_arg;
static farsee_thread_fn delayed_input_entry;
static void *delayed_input_arg;

static void *run_protocol_then_signal(void *arg)
{
    (void)arg;
    void *result = delayed_protocol_entry(delayed_protocol_arg);
    farsee_atomic_int_store(&delayed_protocol_done, 1);
    return result;
}

static void *run_input_after_protocol(void *arg)
{
    (void)arg;
    while (!farsee_atomic_int_load_nonzero(&delayed_protocol_done)) {
    }
    return delayed_input_entry(delayed_input_arg);
}

static farsee_thread *delay_third_thread_until_stop(farsee_thread_fn fn,
                                                    void *arg)
{
    delayed_input_create_calls++;
    if (delayed_input_create_calls == 1u) {
        delayed_protocol_entry = fn;
        delayed_protocol_arg = arg;
        return farsee_thread_create(run_protocol_then_signal, NULL);
    }
    if (delayed_input_create_calls == 3u) {
        delayed_input_entry = fn;
        delayed_input_arg = arg;
        return farsee_thread_create(run_input_after_protocol, NULL);
    }
    return farsee_thread_create(fn, arg);
}

// The thread-creation seam delays the input worker until after the protocol
// worker reports its terminal outcome. The input callback must still run when
// all three worker creations succeeded.
RFB_TEST(farsee_mt, farsee_mt_run__late_input_worker_still_runs)
{
    farsee_frame_slot slot;
    farsee_cmd_queue cmds;
    RFB_CHECK(farsee_frame_slot_init(&slot));
    RFB_CHECK(farsee_cmd_queue_init(&cmds));

    farsee_atomic_int stop = 0;
    mt_test_ctx ctx;
    memset(&ctx, 0, sizeof ctx);
    ctx.stop = &stop;
    ctx.pixel[3] = 0xffu;
    delayed_input_create_calls = 0u;
    farsee_atomic_int_store(&delayed_protocol_done, 0);
    delayed_protocol_entry = NULL;
    delayed_protocol_arg = NULL;
    delayed_input_entry = NULL;
    delayed_input_arg = NULL;

    farsee_mt_config cfg = {
        .slot = &slot,
        .cmds = &cmds,
        .stop_flag = &stop,
        .protocol_fn = test_protocol_fn,
        .protocol_user = &ctx,
        .present_fn = test_present_fn,
        .present_user = &ctx,
        .input_fn = test_input_fn,
        .input_user = &ctx,
        .thread_create = delay_third_thread_until_stop,
    };
    farsee_mt_outcome outcome;
    const farsee_error error = farsee_mt_run(&cfg, &outcome);
    RFB_CHECK(error.code == FARSEE_E_OK);
    RFB_CHECK(outcome.kind == FARSEE_MT_TERMINAL_REQUESTED_STOP);
    RFB_CHECK_EQ_UINT(delayed_input_create_calls, 3u);
    RFB_CHECK(farsee_atomic_int_load(&ctx.input_ran) == 1);

    delayed_protocol_entry = NULL;
    delayed_protocol_arg = NULL;
    delayed_input_entry = NULL;
    delayed_input_arg = NULL;
    farsee_cmd_queue_destroy(&cmds);
    farsee_frame_slot_destroy(&slot);
}

// force_repaint type used by farsee_mt_present_loop: exchange clears.
RFB_TEST(farsee_mt, present_loop__force_repaint_exchange_clears)
{
    farsee_atomic_int force_repaint = 0;
    farsee_atomic_int_store(&force_repaint, 1);
    RFB_CHECK_EQ_INT(farsee_atomic_int_exchange(&force_repaint, 0), 1);
    RFB_CHECK_EQ_INT(farsee_atomic_int_load(&force_repaint), 0);
    RFB_CHECK_EQ_INT(farsee_atomic_int_exchange(&force_repaint, 0), 0);
}

// With forced repaint and an empty slot, stop after three cadence callbacks.
typedef struct force_empty_ctx {
    farsee_atomic_int *stop;
    volatile int after_n;
    volatile int on_frame_n;
} force_empty_ctx;

static bool force_empty_on_frame(void *user, const farsee_frame_view *v)
{
    force_empty_ctx *t = (force_empty_ctx *)user;
    (void)v;
    t->on_frame_n++;
    return true;
}

static void force_empty_after(void *user)
{
    force_empty_ctx *t = (force_empty_ctx *)user;
    t->after_n++;
    if (t->after_n >= 3) {
        farsee_atomic_int_store(t->stop, 1);
    }
}

RFB_TEST(farsee_mt, present_loop__force_repaint_empty_slot__bounded)
{
    farsee_frame_slot slot;
    RFB_CHECK(farsee_frame_slot_init(&slot));
    farsee_atomic_int stop = 0;
    farsee_atomic_int force = 0;
    farsee_atomic_int_store(&force, 1);
    force_empty_ctx ctx;
    memset(&ctx, 0, sizeof ctx);
    ctx.stop = &stop;
    const uint64_t t0 = farsee_thread_monotonic_ms();
    farsee_mt_terminal terminal;
    farsee_mt_terminal_init(&terminal);
    (void)farsee_mt_present_loop(&slot, &stop, 16u, force_empty_on_frame, &ctx,
                                 force_empty_after, &ctx, &force, &terminal);
    const uint64_t elapsed = farsee_thread_monotonic_ms() - t0;
    // The callback requests stop after its third invocation; allow at most 2 s.
    RFB_CHECK(elapsed < 2000u);
    RFB_CHECK(ctx.after_n >= 3);
    // force cleared even without a frame
    RFB_CHECK_EQ_INT(farsee_atomic_int_load(&force), 0);
    farsee_frame_slot_destroy(&slot);
}

// With force clear and no frame, idle cadence ticks still call after_present;
// this callback requests stop after its third invocation.
RFB_TEST(farsee_mt, present_loop__idle_empty_after_force_cleared__stops)
{
    farsee_frame_slot slot;
    RFB_CHECK(farsee_frame_slot_init(&slot));
    farsee_atomic_int stop = 0;
    farsee_atomic_int force = 0;
    // Force starts clear; only idle empty cadence ticks invoke after_present.
    force_empty_ctx ctx;
    memset(&ctx, 0, sizeof ctx);
    ctx.stop = &stop;
    const uint64_t t0 = farsee_thread_monotonic_ms();
    farsee_mt_terminal terminal;
    farsee_mt_terminal_init(&terminal);
    (void)farsee_mt_present_loop(&slot, &stop, 5u, force_empty_on_frame, &ctx,
                                 force_empty_after, &ctx, &force, &terminal);
    const uint64_t elapsed = farsee_thread_monotonic_ms() - t0;
    RFB_CHECK(elapsed < 2000u);
    RFB_CHECK(ctx.after_n >= 3);
    RFB_CHECK(farsee_atomic_int_load_nonzero(&stop));
    farsee_frame_slot_destroy(&slot);
}

RFB_TEST(farsee_mt, terminal__first_report_wins)
{
    farsee_mt_terminal terminal;
    farsee_mt_terminal_init(&terminal);
    RFB_CHECK(farsee_mt_terminal_report(
        &terminal, FARSEE_MT_TERMINAL_PROTOCOL_FAILURE));
    RFB_CHECK(!farsee_mt_terminal_report(
        &terminal, FARSEE_MT_TERMINAL_PRESENTER_FAILURE));
    RFB_CHECK(farsee_mt_terminal_load(&terminal) ==
              FARSEE_MT_TERMINAL_PROTOCOL_FAILURE);
}

RFB_TEST(farsee_mt, terminal__kinds_map_to_distinct_errors)
{
    RFB_CHECK(farsee_mt_terminal_error(
        FARSEE_MT_TERMINAL_REQUESTED_STOP).code == FARSEE_E_OK);
    RFB_CHECK(farsee_mt_terminal_error(
        FARSEE_MT_TERMINAL_PROTOCOL_FAILURE).code ==
        FARSEE_ERR_PROTOCOL_VIOLATION);
    RFB_CHECK(farsee_mt_terminal_error(
        FARSEE_MT_TERMINAL_PRESENTER_FAILURE).code ==
        FARSEE_ERR_PRESENTER_FAILURE);
    RFB_CHECK(farsee_mt_terminal_error(
        FARSEE_MT_TERMINAL_INPUT_FAILURE).code ==
        FARSEE_ERR_LOCAL_IO_FAILURE);
    RFB_CHECK(farsee_mt_terminal_error(
        FARSEE_MT_TERMINAL_THREAD_CREATION_FAILURE).code ==
        FARSEE_ERR_INTERNAL);
    RFB_CHECK(farsee_mt_terminal_error(
        FARSEE_MT_TERMINAL_ALLOCATION_FAILURE).code ==
        FARSEE_ERR_OUT_OF_MEMORY);
}

static farsee_thread *always_fail_thread_create(farsee_thread_fn fn, void *arg)
{
    (void)fn;
    (void)arg;
    return NULL;
}

static size_t partial_create_calls;

static farsee_thread *fail_second_thread_create(farsee_thread_fn fn, void *arg)
{
    partial_create_calls++;
    if (partial_create_calls == 2u) {
        return NULL;
    }
    return farsee_thread_create(fn, arg);
}

RFB_TEST(farsee_mt, farsee_mt_run__thread_create_failure_is_structured)
{
    farsee_frame_slot slot;
    farsee_cmd_queue cmds;
    RFB_CHECK(farsee_frame_slot_init(&slot));
    RFB_CHECK(farsee_cmd_queue_init(&cmds));
    farsee_atomic_int stop = 0;
    mt_test_ctx ctx;
    memset(&ctx, 0, sizeof ctx);
    farsee_mt_config cfg = {
        .slot = &slot,
        .cmds = &cmds,
        .stop_flag = &stop,
        .protocol_fn = test_protocol_fn,
        .protocol_user = &ctx,
        .present_fn = test_present_fn,
        .present_user = &ctx,
        .input_fn = test_input_fn,
        .input_user = &ctx,
        .thread_create = always_fail_thread_create,
    };
    farsee_mt_outcome outcome;
    farsee_error error = farsee_mt_run(&cfg, &outcome);
    RFB_CHECK(error.code == FARSEE_ERR_INTERNAL);
    RFB_CHECK(outcome.kind == FARSEE_MT_TERMINAL_THREAD_CREATION_FAILURE);
    RFB_CHECK(farsee_atomic_int_load(&ctx.protocol_ran) == 0);
    RFB_CHECK(farsee_atomic_int_load(&ctx.present_ran) == 0);
    RFB_CHECK(farsee_atomic_int_load(&ctx.input_ran) == 0);
    farsee_cmd_queue_destroy(&cmds);
    farsee_frame_slot_destroy(&slot);
}

RFB_TEST(farsee_mt, farsee_mt_run__partial_thread_create_failure_is_joined)
{
    farsee_frame_slot slot;
    farsee_cmd_queue cmds;
    RFB_CHECK(farsee_frame_slot_init(&slot));
    RFB_CHECK(farsee_cmd_queue_init(&cmds));
    farsee_atomic_int stop = 0;
    mt_test_ctx ctx;
    memset(&ctx, 0, sizeof ctx);
    partial_create_calls = 0u;
    farsee_mt_config cfg = {
        .slot = &slot,
        .cmds = &cmds,
        .stop_flag = &stop,
        .protocol_fn = test_protocol_fn,
        .protocol_user = &ctx,
        .present_fn = test_present_fn,
        .present_user = &ctx,
        .input_fn = test_input_fn,
        .input_user = &ctx,
        .thread_create = fail_second_thread_create,
    };
    farsee_mt_outcome outcome;
    farsee_error error = farsee_mt_run(&cfg, &outcome);
    RFB_CHECK(error.code == FARSEE_ERR_INTERNAL);
    RFB_CHECK(outcome.kind == FARSEE_MT_TERMINAL_THREAD_CREATION_FAILURE);
    RFB_CHECK_EQ_UINT(partial_create_calls, 2u);
    RFB_CHECK(farsee_atomic_int_load(&ctx.protocol_ran) == 0);
    RFB_CHECK(farsee_atomic_int_load(&ctx.present_ran) == 0);
    RFB_CHECK(farsee_atomic_int_load(&ctx.input_ran) == 0);
    farsee_cmd_queue_destroy(&cmds);
    farsee_frame_slot_destroy(&slot);
}

typedef enum terminal_origin {
    TERMINAL_FROM_PROTOCOL,
    TERMINAL_FROM_PRESENT,
    TERMINAL_FROM_INPUT,
} terminal_origin;

typedef struct terminal_run_ctx {
    terminal_origin origin;
    farsee_mt_terminal_kind kind;
} terminal_run_ctx;

static farsee_mt_terminal_kind terminal_protocol_fn(
    void *user, farsee_frame_slot *slot, farsee_cmd_queue *cmds,
    farsee_atomic_int *stop, farsee_mt_terminal *terminal)
{
    terminal_run_ctx *ctx = (terminal_run_ctx *)user;
    (void)slot;
    (void)cmds;
    (void)terminal;
    if (ctx->origin == TERMINAL_FROM_PROTOCOL) {
        return ctx->kind;
    }
    while (!farsee_atomic_int_load_nonzero(stop)) {
    }
    return FARSEE_MT_TERMINAL_REQUESTED_STOP;
}

static farsee_mt_terminal_kind terminal_present_fn(
    void *user, farsee_frame_slot *slot, farsee_atomic_int *stop,
    farsee_mt_terminal *terminal)
{
    terminal_run_ctx *ctx = (terminal_run_ctx *)user;
    (void)slot;
    (void)terminal;
    if (ctx->origin == TERMINAL_FROM_PRESENT) {
        return ctx->kind;
    }
    while (!farsee_atomic_int_load_nonzero(stop)) {
    }
    return FARSEE_MT_TERMINAL_REQUESTED_STOP;
}

static farsee_mt_terminal_kind terminal_input_fn(
    void *user, farsee_cmd_queue *cmds, farsee_atomic_int *stop,
    farsee_mt_terminal *terminal)
{
    terminal_run_ctx *ctx = (terminal_run_ctx *)user;
    (void)cmds;
    (void)terminal;
    if (ctx->origin == TERMINAL_FROM_INPUT) {
        return ctx->kind;
    }
    while (!farsee_atomic_int_load_nonzero(stop)) {
    }
    return FARSEE_MT_TERMINAL_REQUESTED_STOP;
}

static farsee_mt_outcome run_terminal_case(terminal_origin origin,
                                           farsee_mt_terminal_kind kind)
{
    farsee_frame_slot slot;
    farsee_cmd_queue cmds;
    farsee_mt_outcome outcome;
    memset(&outcome, 0, sizeof outcome);
    const bool slot_ready = farsee_frame_slot_init(&slot);
    const bool cmds_ready = slot_ready && farsee_cmd_queue_init(&cmds);
    if (!slot_ready || !cmds_ready) {
        outcome.kind = FARSEE_MT_TERMINAL_INTERNAL_FAILURE;
        outcome.error = farsee_mt_terminal_error(outcome.kind);
        if (cmds_ready) {
            farsee_cmd_queue_destroy(&cmds);
        }
        farsee_frame_slot_destroy(&slot);
        return outcome;
    }
    farsee_atomic_int stop = 0;
    terminal_run_ctx ctx = { .origin = origin, .kind = kind };
    farsee_mt_config cfg = {
        .slot = &slot,
        .cmds = &cmds,
        .stop_flag = &stop,
        .protocol_fn = terminal_protocol_fn,
        .protocol_user = &ctx,
        .present_fn = terminal_present_fn,
        .present_user = &ctx,
        .input_fn = terminal_input_fn,
        .input_user = &ctx,
    };
    (void)farsee_mt_run(&cfg, &outcome);
    farsee_cmd_queue_destroy(&cmds);
    farsee_frame_slot_destroy(&slot);
    return outcome;
}

RFB_TEST(farsee_mt, farsee_mt_run__worker_failures_remain_distinct)
{
    farsee_mt_outcome protocol = run_terminal_case(
        TERMINAL_FROM_PROTOCOL, FARSEE_MT_TERMINAL_PROTOCOL_FAILURE);
    farsee_mt_outcome allocation = run_terminal_case(
        TERMINAL_FROM_PROTOCOL, FARSEE_MT_TERMINAL_ALLOCATION_FAILURE);
    farsee_mt_outcome presenter = run_terminal_case(
        TERMINAL_FROM_PRESENT, FARSEE_MT_TERMINAL_PRESENTER_FAILURE);
    farsee_mt_outcome input = run_terminal_case(
        TERMINAL_FROM_INPUT, FARSEE_MT_TERMINAL_INPUT_FAILURE);
    RFB_CHECK(protocol.kind == FARSEE_MT_TERMINAL_PROTOCOL_FAILURE);
    RFB_CHECK(protocol.error.code == FARSEE_ERR_PROTOCOL_VIOLATION);
    RFB_CHECK(allocation.kind == FARSEE_MT_TERMINAL_ALLOCATION_FAILURE);
    RFB_CHECK(allocation.error.code == FARSEE_ERR_OUT_OF_MEMORY);
    RFB_CHECK(presenter.kind == FARSEE_MT_TERMINAL_PRESENTER_FAILURE);
    RFB_CHECK(presenter.error.code == FARSEE_ERR_PRESENTER_FAILURE);
    RFB_CHECK(input.kind == FARSEE_MT_TERMINAL_INPUT_FAILURE);
    RFB_CHECK(input.error.code == FARSEE_ERR_LOCAL_IO_FAILURE);
}

RFB_TEST(farsee_mt, terminal__rejects_invalid_reports_and_maps_boundaries)
{
    farsee_mt_terminal terminal;
    farsee_mt_terminal_init(NULL);
    farsee_mt_terminal_init(&terminal);
    RFB_CHECK(!farsee_mt_terminal_report(
        NULL, FARSEE_MT_TERMINAL_REQUESTED_STOP));
    RFB_CHECK(!farsee_mt_terminal_report(&terminal, FARSEE_MT_TERMINAL_NONE));
    RFB_CHECK(!farsee_mt_terminal_report(
        &terminal, (farsee_mt_terminal_kind)(FARSEE_MT_TERMINAL_INTERNAL_FAILURE +
                                             1)));
    RFB_CHECK(farsee_mt_terminal_load(NULL) == FARSEE_MT_TERMINAL_NONE);
    RFB_CHECK(farsee_mt_terminal_error(FARSEE_MT_TERMINAL_PEER_CLOSED).code ==
              FARSEE_E_OK);
    RFB_CHECK(farsee_mt_terminal_error(FARSEE_MT_TERMINAL_NONE).code ==
              FARSEE_ERR_INTERNAL);
    RFB_CHECK(farsee_mt_terminal_error(
                  FARSEE_MT_TERMINAL_INTERNAL_FAILURE).code ==
              FARSEE_ERR_INTERNAL);
    RFB_CHECK(farsee_mt_terminal_error((farsee_mt_terminal_kind)99).code ==
              FARSEE_ERR_INTERNAL);
}

static farsee_mt_terminal_kind none_protocol_fn(
    void *user, farsee_frame_slot *slot, farsee_cmd_queue *cmds,
    farsee_atomic_int *stop, farsee_mt_terminal *terminal)
{
    (void)user;
    (void)slot;
    (void)cmds;
    (void)stop;
    (void)terminal;
    return FARSEE_MT_TERMINAL_NONE;
}

static farsee_mt_terminal_kind none_present_fn(
    void *user, farsee_frame_slot *slot, farsee_atomic_int *stop,
    farsee_mt_terminal *terminal)
{
    (void)user;
    (void)slot;
    (void)stop;
    (void)terminal;
    return FARSEE_MT_TERMINAL_NONE;
}

static farsee_mt_terminal_kind none_input_fn(
    void *user, farsee_cmd_queue *cmds, farsee_atomic_int *stop,
    farsee_mt_terminal *terminal)
{
    (void)user;
    (void)cmds;
    (void)stop;
    (void)terminal;
    return FARSEE_MT_TERMINAL_NONE;
}

static farsee_mt_config valid_guard_config(farsee_frame_slot *slot,
                                           farsee_cmd_queue *cmds,
                                           farsee_atomic_int *stop)
{
    return (farsee_mt_config){
        .slot = slot,
        .cmds = cmds,
        .stop_flag = stop,
        .protocol_fn = none_protocol_fn,
        .present_fn = none_present_fn,
        .input_fn = none_input_fn,
    };
}

RFB_TEST(farsee_mt, farsee_mt_run__rejects_each_missing_required_field)
{
    farsee_frame_slot slot;
    farsee_cmd_queue cmds;
    farsee_atomic_int stop = 0;
    farsee_mt_config cfg = valid_guard_config(&slot, &cmds, &stop);

    RFB_CHECK(farsee_mt_run(NULL, NULL).code == FARSEE_ERR_STATE);
    cfg.slot = NULL;
    RFB_CHECK(farsee_mt_run(&cfg, NULL).code == FARSEE_ERR_STATE);
    cfg = valid_guard_config(&slot, &cmds, &stop);
    cfg.cmds = NULL;
    RFB_CHECK(farsee_mt_run(&cfg, NULL).code == FARSEE_ERR_STATE);
    cfg = valid_guard_config(&slot, &cmds, &stop);
    cfg.stop_flag = NULL;
    RFB_CHECK(farsee_mt_run(&cfg, NULL).code == FARSEE_ERR_STATE);
    cfg = valid_guard_config(&slot, &cmds, &stop);
    cfg.protocol_fn = NULL;
    RFB_CHECK(farsee_mt_run(&cfg, NULL).code == FARSEE_ERR_STATE);
    cfg = valid_guard_config(&slot, &cmds, &stop);
    cfg.present_fn = NULL;
    RFB_CHECK(farsee_mt_run(&cfg, NULL).code == FARSEE_ERR_STATE);
    cfg = valid_guard_config(&slot, &cmds, &stop);
    cfg.input_fn = NULL;
    RFB_CHECK(farsee_mt_run(&cfg, NULL).code == FARSEE_ERR_STATE);
}

static size_t third_create_calls;

static farsee_thread *fail_third_thread_create(farsee_thread_fn fn, void *arg)
{
    third_create_calls++;
    if (third_create_calls == 3u) {
        return NULL;
    }
    return farsee_thread_create(fn, arg);
}

RFB_TEST(farsee_mt, farsee_mt_run__third_thread_failure_joins_first_two)
{
    farsee_frame_slot slot;
    farsee_cmd_queue cmds;
    RFB_CHECK(farsee_frame_slot_init(&slot));
    RFB_CHECK(farsee_cmd_queue_init(&cmds));
    farsee_atomic_int stop = 0;
    farsee_mt_config cfg = valid_guard_config(&slot, &cmds, &stop);
    cfg.thread_create = fail_third_thread_create;
    third_create_calls = 0u;

    farsee_mt_outcome outcome;
    const farsee_error error = farsee_mt_run(&cfg, &outcome);
    RFB_CHECK(error.code == FARSEE_ERR_INTERNAL);
    RFB_CHECK(outcome.kind == FARSEE_MT_TERMINAL_THREAD_CREATION_FAILURE);
    RFB_CHECK_EQ_UINT(third_create_calls, 3u);
    RFB_CHECK(farsee_atomic_int_load_nonzero(&stop));

    farsee_cmd_queue_destroy(&cmds);
    farsee_frame_slot_destroy(&slot);
}

RFB_TEST(farsee_mt, farsee_mt_run__no_worker_outcome_becomes_internal)
{
    farsee_frame_slot slot;
    farsee_cmd_queue cmds;
    RFB_CHECK(farsee_frame_slot_init(&slot));
    RFB_CHECK(farsee_cmd_queue_init(&cmds));
    farsee_atomic_int stop = 0;
    const farsee_mt_config cfg = valid_guard_config(&slot, &cmds, &stop);

    const farsee_error error = farsee_mt_run(&cfg, NULL);
    RFB_CHECK(error.code == FARSEE_ERR_INTERNAL);
    RFB_CHECK(farsee_atomic_int_load_nonzero(&stop));

    farsee_cmd_queue_destroy(&cmds);
    farsee_frame_slot_destroy(&slot);
}

static bool reject_frame(void *user, const farsee_frame_view *view)
{
    unsigned *calls = (unsigned *)user;
    (*calls)++;
    RFB_CHECK(view != NULL);
    return false;
}

static bool accept_frame_and_stop(void *user, const farsee_frame_view *view)
{
    farsee_atomic_int *stop = (farsee_atomic_int *)user;
    RFB_CHECK(view != NULL);
    farsee_atomic_int_store(stop, 1);
    return true;
}

RFB_TEST(farsee_mt, present_loop__guards_default_interval_and_outcomes)
{
    farsee_frame_slot slot;
    RFB_CHECK(farsee_frame_slot_init(&slot));
    farsee_atomic_int stop = 1;
    farsee_mt_terminal terminal;
    farsee_mt_terminal_init(&terminal);

    RFB_CHECK(farsee_mt_present_loop(
                  NULL, &stop, 1u, accept_frame_and_stop, &stop,
                  NULL, NULL, NULL, &terminal) ==
              FARSEE_MT_TERMINAL_INTERNAL_FAILURE);
    RFB_CHECK(farsee_mt_present_loop(
                  &slot, NULL, 1u, accept_frame_and_stop, &stop,
                  NULL, NULL, NULL, &terminal) ==
              FARSEE_MT_TERMINAL_INTERNAL_FAILURE);
    RFB_CHECK(farsee_mt_present_loop(
                  &slot, &stop, 1u, NULL, NULL, NULL, NULL, NULL,
                  &terminal) == FARSEE_MT_TERMINAL_INTERNAL_FAILURE);
    RFB_CHECK(farsee_mt_present_loop(
                  &slot, &stop, 0u, accept_frame_and_stop, &stop,
                  NULL, NULL, NULL, &terminal) ==
              FARSEE_MT_TERMINAL_REQUESTED_STOP);

    const uint8_t pixel[4] = { 1u, 2u, 3u, 255u };
    RFB_CHECK(farsee_frame_slot_publish(
        &slot, pixel, 1u, 1u, sizeof pixel, FARSEE_PIXEL_RGBA8888));
    farsee_atomic_int_store(&stop, 0);
    unsigned rejected = 0u;
    RFB_CHECK(farsee_mt_present_loop(
                  &slot, &stop, 1u, reject_frame, &rejected,
                  NULL, NULL, NULL, &terminal) ==
              FARSEE_MT_TERMINAL_PRESENTER_FAILURE);
    RFB_CHECK_EQ_UINT(rejected, 1u);
    RFB_CHECK(farsee_mt_terminal_load(&terminal) ==
              FARSEE_MT_TERMINAL_PRESENTER_FAILURE);

    farsee_atomic_int_store(&stop, 0);
    RFB_CHECK(farsee_mt_present_loop(
                  &slot, &stop, 1u, accept_frame_and_stop, &stop,
                  NULL, NULL, NULL, &terminal) ==
              FARSEE_MT_TERMINAL_REQUESTED_STOP);
    farsee_frame_slot_destroy(&slot);
}
