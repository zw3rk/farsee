// SPDX-License-Identifier: Apache-2.0
//
// Shared multi-thread session skeleton tests.
// P0-N3: stop flag is farsee_atomic_int (not bare volatile sig_atomic_t).

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
    volatile int protocol_ran;
    volatile int present_ran;
    volatile int input_ran;
    volatile int frames_seen;
    volatile int after_present_count;
    uint8_t pixel[4];
} mt_test_ctx;

static void test_protocol_fn(void *user, farsee_frame_slot *slot,
                             farsee_cmd_queue *cmds, farsee_atomic_int *stop)
{
    mt_test_ctx *t = (mt_test_ctx *)user;
    (void)cmds;
    t->protocol_ran = 1;
    // Publish one frame then request stop so the session winds down.
    (void)farsee_frame_slot_publish(slot, t->pixel, 1, 1, 4,
                                    FARSEE_PIXEL_BGRA8888);
    // Brief wait so present can observe the frame.
    {
        const uint64_t dl = farsee_thread_monotonic_ms() + 200u;
        while (!farsee_atomic_int_load_nonzero(stop) &&
               farsee_thread_monotonic_ms() < dl) {
            if (t->frames_seen > 0) {
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
}

static bool test_on_frame(void *user, const farsee_frame_view *v)
{
    mt_test_ctx *t = (mt_test_ctx *)user;
    if (v != NULL && v->pixels != NULL) {
        t->frames_seen++;
        return true;
    }
    return false;
}

static void test_after_present(void *user)
{
    mt_test_ctx *t = (mt_test_ctx *)user;
    t->after_present_count++;
}

static void test_present_fn(void *user, farsee_frame_slot *slot,
                            farsee_atomic_int *stop)
{
    mt_test_ctx *t = (mt_test_ctx *)user;
    t->present_ran = 1;
    farsee_mt_present_loop(slot, stop, 16u, test_on_frame, t, test_after_present,
                           t, /*force_repaint=*/NULL);
}

static void test_input_fn(void *user, farsee_cmd_queue *cmds,
                          farsee_atomic_int *stop)
{
    mt_test_ctx *t = (mt_test_ctx *)user;
    (void)cmds;
    t->input_ran = 1;
    // Wait until stop (set by protocol or farsee_mt_run after protocol joins).
    while (!farsee_atomic_int_load_nonzero(stop)) {
        const uint64_t dl = farsee_thread_monotonic_ms() + 50u;
        farsee_cmd c;
        (void)farsee_cmd_queue_pop(cmds, &c, dl, stop);
    }
}

RFB_TEST(farsee_mt, farsee_mt_run__bad_config_returns_state)
{
    farsee_error e = farsee_mt_run(NULL);
    RFB_CHECK(e.code == FARSEE_ERR_STATE);
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

    farsee_error e = farsee_mt_run(&cfg);
    RFB_CHECK(e.code == FARSEE_E_OK);
    RFB_CHECK(ctx.protocol_ran == 1);
    RFB_CHECK(ctx.present_ran == 1);
    RFB_CHECK(ctx.input_ran == 1);
    RFB_CHECK(ctx.frames_seen >= 1);
    RFB_CHECK(ctx.after_present_count >= 1);
    RFB_CHECK(farsee_atomic_int_load_nonzero(&stop));

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

// loop r1 T4: force_repaint with empty slot must not busy-spin forever.
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
    farsee_mt_present_loop(&slot, &stop, 16u, force_empty_on_frame, &ctx,
                           force_empty_after, &ctx, &force);
    const uint64_t elapsed = farsee_thread_monotonic_ms() - t0;
    // Should exit via after_present stop within a few intervals, not peg CPU
    // for seconds. Allow generous bound for CI load.
    RFB_CHECK(elapsed < 2000u);
    RFB_CHECK(ctx.after_n >= 3);
    // force cleared even without a frame
    RFB_CHECK_EQ_INT(farsee_atomic_int_load(&force), 0);
    farsee_frame_slot_destroy(&slot);
}

// Regression (−): after the first forced empty tick, force is 0 and the idle
// cadence path must still call after_present. Without that, after_n stuck at 1
// and the loop never stopped (Linux Clang CI hang, full suite flaky).
RFB_TEST(farsee_mt, present_loop__idle_empty_after_force_cleared__stops)
{
    farsee_frame_slot slot;
    RFB_CHECK(farsee_frame_slot_init(&slot));
    farsee_atomic_int stop = 0;
    farsee_atomic_int force = 0;
    // force starts clear — only idle empty cadence ticks (the path that used
    // to skip after_present after advancing next_ms).
    force_empty_ctx ctx;
    memset(&ctx, 0, sizeof ctx);
    ctx.stop = &stop;
    const uint64_t t0 = farsee_thread_monotonic_ms();
    farsee_mt_present_loop(&slot, &stop, 5u, force_empty_on_frame, &ctx,
                           force_empty_after, &ctx, &force);
    const uint64_t elapsed = farsee_thread_monotonic_ms() - t0;
    RFB_CHECK(elapsed < 2000u);
    RFB_CHECK(ctx.after_n >= 3);
    RFB_CHECK(farsee_atomic_int_load_nonzero(&stop));
    farsee_frame_slot_destroy(&slot);
}
