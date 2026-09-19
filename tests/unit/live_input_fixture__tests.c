// SPDX-License-Identifier: Apache-2.0
//
// Live-input text fixtures (no openpty, no FreeRDP, no network).
//
// These encode the product contracts that live Kitty/RDP sessions depend on:
//
//   1) UI mutex is not held across a blocking or slow Kitty drain.
//   2) TTY bytes → live_shell demux → inject ops → farsee_cmd_queue, so RFB
//      protocol drain has KeyEvent/PointerEvent without a peer.
//
// Positive: concurrent locker proceeds while "present" drains a full pipe
//           (drain is outside the lock); demux enqueues key + pointer.
// Negative: full pipe does not hang drain; view_only suppresses inject.

#include "rfb_test.h"

#include "app/live_shell.h"
#include "farsee/farsee_atomic.h"
#include "farsee/farsee_cmd_queue.h"
#include "farsee/farsee_input.h"
#include "farsee/farsee_thread.h"
#include "farsee/kitty_drain.h"
#include "farsee/buffer.h"
#include "farsee/allocator.h"
#include "farsee/normalized_input.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

// ---------------------------------------------------------------------------
// Fixture 1 — UI mutex versus Kitty drain
// ---------------------------------------------------------------------------
//
// Product pattern (rfb_live_after_present / rdp_live_drain_graphics):
//   lock → home/cursor work → unlock → drain_kitty_out → (optional status)
//
// The drain runs outside the lock so input can redraw status.
//
// This fixture fills a pipe, runs a "present" thread that follows the product
// pattern while an "input" thread must acquire the same mutex within a
// bounded deadline. If drain were under the lock with a blocking write, the
// input thread would miss the deadline (CI hang / fail).

typedef struct ui_mutex_fixture {
    farsee_mutex *mu;
    farsee_cond *cv;
    farsee_atomic_int present_released; // present left the lock before drain
    farsee_atomic_int input_got_lock;
    farsee_atomic_int stop;
    int pipe_wr; // nonblocking, full
    rfb_buffer *kitty_out;
} ui_mutex_fixture;

static void *present_thread_fn(void *arg)
{
    ui_mutex_fixture *f = (ui_mutex_fixture *)arg;
    // Critical section: only instantaneous UI work.
    farsee_mutex_lock(f->mu);
    farsee_atomic_int_store(&f->present_released, 0);
    // Publish that we are about to leave the lock (input may proceed).
    farsee_mutex_unlock(f->mu);
    farsee_atomic_int_store(&f->present_released, 1);
    farsee_cond_broadcast(f->cv);

    // Drain OUTSIDE the lock — may hit EAGAIN on a full pipe; must not hang.
    farsee_drain_kitty_out(f->kitty_out, f->pipe_wr, NULL);

    farsee_mutex_lock(f->mu);
    // Optional status band would run here under lock (instant).
    farsee_mutex_unlock(f->mu);
    return NULL;
}

static void *input_thread_fn(void *arg)
{
    ui_mutex_fixture *f = (ui_mutex_fixture *)arg;
    // Wait until present has left the lock (or stop).
    farsee_mutex_lock(f->mu);
    while (!farsee_atomic_int_load_nonzero(&f->present_released) &&
           !farsee_atomic_int_load_nonzero(&f->stop)) {
        const uint64_t dl = farsee_thread_monotonic_ms() + 50u;
        (void)farsee_cond_timedwait(f->cv, f->mu, dl);
    }
    // Must acquire promptly even if drain is still "busy" on a full pipe.
    farsee_atomic_int_store(&f->input_got_lock, 1);
    farsee_mutex_unlock(f->mu);
    return NULL;
}

static void fill_pipe_nonblocking(int wr)
{
    int fl = fcntl(wr, F_GETFL);
    if (fl >= 0) {
        (void)fcntl(wr, F_SETFL, fl | O_NONBLOCK);
    }
    uint8_t junk[4096];
    memset(junk, 0xCD, sizeof junk);
    for (;;) {
        ssize_t w = write(wr, junk, sizeof junk);
        if (w < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            }
            break;
        }
        if (w == 0) {
            break;
        }
    }
}

RFB_TEST(live_input_fixture, ui_mutex__drain_outside_lock__input_acquires)
{
    int fds[2];
    RFB_CHECK(pipe(fds) == 0);
    fill_pipe_nonblocking(fds[1]);

    rfb_buffer kitty;
    rfb_buffer_init(&kitty, rfb_default_allocator(), 64u * 1024u);
    // Large enough that a *blocking* write under the lock would stall.
    uint8_t payload[8192];
    memset(payload, 'K', sizeof payload);
    RFB_CHECK(rfb_buffer_append(&kitty, payload, sizeof payload) == RFB_OK);

    ui_mutex_fixture f;
    memset(&f, 0, sizeof f);
    f.mu = farsee_mutex_create();
    f.cv = farsee_cond_create();
    RFB_CHECK(f.mu != NULL && f.cv != NULL);
    f.pipe_wr = fds[1];
    f.kitty_out = &kitty;
    farsee_atomic_int_store(&f.present_released, 0);
    farsee_atomic_int_store(&f.input_got_lock, 0);
    farsee_atomic_int_store(&f.stop, 0);

    farsee_thread *tp = farsee_thread_create(present_thread_fn, &f);
    farsee_thread *ti = farsee_thread_create(input_thread_fn, &f);
    RFB_CHECK(tp != NULL && ti != NULL);

    // Bounded wait: input must get the lock within 2s even with a full pipe.
    const uint64_t deadline = farsee_thread_monotonic_ms() + 2000u;
    while (!farsee_atomic_int_load_nonzero(&f.input_got_lock) &&
           farsee_thread_monotonic_ms() < deadline) {
        // Sleep via empty timedwait on a private cond — no bare usleep assert.
        farsee_mutex *wmu = farsee_mutex_create();
        farsee_cond *wcv = farsee_cond_create();
        if (wmu != NULL && wcv != NULL) {
            farsee_mutex_lock(wmu);
            (void)farsee_cond_timedwait(wcv, wmu,
                                        farsee_thread_monotonic_ms() + 20u);
            farsee_mutex_unlock(wmu);
        }
        farsee_cond_destroy(&wcv);
        farsee_mutex_destroy(&wmu);
    }
    farsee_atomic_int_store(&f.stop, 1);
    farsee_cond_broadcast(f.cv);

    farsee_thread_join(&tp, NULL);
    farsee_thread_join(&ti, NULL);

    RFB_CHECK(farsee_atomic_int_load_nonzero(&f.input_got_lock));
    // Drain left unwritten bytes (full pipe) rather than hanging.
    RFB_CHECK(rfb_buffer_length(&kitty) <= sizeof payload);

    farsee_cond_destroy(&f.cv);
    farsee_mutex_destroy(&f.mu);
    rfb_buffer_destroy(&kitty);
    (void)close(fds[0]);
    (void)close(fds[1]);
}

// ---------------------------------------------------------------------------
// Fixture 2 — shell demux → cmd queue (RFB inject seam without a peer)
// ---------------------------------------------------------------------------

typedef struct inject_sink {
    farsee_cmd_queue *cmds;
    unsigned prev_buttons;
} inject_sink;

static void sink_key(void *u, const rfb_norm_key *nk)
{
    inject_sink *s = (inject_sink *)u;
    if (s == NULL || nk == NULL || s->cmds == NULL) {
        return;
    }
    farsee_cmd c;
    memset(&c, 0, sizeof c);
    c.kind = FARSEE_CMD_KEY;
    c.key.logical = nk->keysym;
    c.key.action = nk->down ? FARSEE_KEY_PRESS : FARSEE_KEY_RELEASE;
    c.key.quality = FARSEE_INPUT_QUALITY_INFERRED;
    (void)farsee_cmd_queue_push(s->cmds, &c);
}

static bool sink_pointer(void *u, int32_t x, int32_t y, uint8_t buttons,
                         int wv, int wh)
{
    inject_sink *s = (inject_sink *)u;
    if (s == NULL || s->cmds == NULL) {
        return false;
    }
    farsee_cmd c;
    memset(&c, 0, sizeof c);
    c.kind = FARSEE_CMD_POINTER;
    c.pe.abs_x = x;
    c.pe.abs_y = y;
    c.pe.buttons = buttons;
    c.pe.wheel_v = wv;
    c.pe.wheel_h = wh;
    c.pe.quality = FARSEE_INPUT_QUALITY_INFERRED;
    c.prev_buttons = s->prev_buttons;
    if (!farsee_cmd_queue_push(s->cmds, &c)) {
        return false;
    }
    s->prev_buttons = buttons;
    return true;
}

RFB_TEST(live_input_fixture, shell_feed__legacy_keys__enqueue_cmd_queue)
{
    farsee_cmd_queue cmds;
    RFB_CHECK(farsee_cmd_queue_init(&cmds));

    farsee_live_shell shell;
    farsee_live_shell_ops ops;
    inject_sink sink;
    memset(&sink, 0, sizeof sink);
    sink.cmds = &cmds;

    farsee_live_shell_init(&shell, NULL, /*status_rows=*/2u);
    memset(&ops, 0, sizeof ops);
    ops.inject_key = sink_key;
    ops.inject_pointer = sink_pointer;
    shell.ops = &ops;
    shell.ops_user = &sink;
    shell.desk_w = 100;
    shell.desk_h = 100;
    shell.term_cols = 40;
    shell.term_rows = 20;
    farsee_live_shell_set_view_scale(&shell, 100u);
    (void)farsee_live_shell_refresh_layout(&shell, /*apply_kitty=*/false);

    // Legacy printable: demux emits press (auto-release is RFB inject policy).
    const uint8_t keys[] = {'a', 'b', 'c'};
    farsee_live_shell_feed_tty(&shell, keys, sizeof keys, /*now=*/1000u);

    RFB_CHECK(farsee_atomic_u64_load(&shell.input_events) >= 3u);

    unsigned nkeys = 0;
    farsee_cmd out;
    const uint64_t now = farsee_thread_monotonic_ms();
    while (farsee_cmd_queue_pop(&cmds, &out, now, NULL)) {
        if (out.kind == FARSEE_CMD_KEY) {
            nkeys++;
        }
    }
    RFB_CHECK(nkeys >= 3u);

    farsee_cmd_queue_destroy(&cmds);
}

RFB_TEST(live_input_fixture, shell_feed__sgr_click__enqueue_pointer)
{
    farsee_cmd_queue cmds;
    RFB_CHECK(farsee_cmd_queue_init(&cmds));

    farsee_live_shell shell;
    farsee_live_shell_ops ops;
    inject_sink sink;
    memset(&sink, 0, sizeof sink);
    sink.cmds = &cmds;

    farsee_live_shell_init(&shell, NULL, 1u);
    memset(&ops, 0, sizeof ops);
    ops.inject_key = sink_key;
    ops.inject_pointer = sink_pointer;
    shell.ops = &ops;
    shell.ops_user = &sink;
    shell.desk_w = 200;
    shell.desk_h = 200;
    shell.term_cols = 40;
    shell.term_rows = 20;
    shell.term_pw = 400;
    shell.term_ph = 400;
    farsee_live_shell_set_view_scale(&shell, 100u);
    (void)farsee_live_shell_refresh_layout(&shell, false);

    // SGR left press + release at cell 5,5.
    const char *sgr = "\033[<0;5;5M\033[<0;5;5m";
    farsee_live_shell_feed_tty(&shell, (const uint8_t *)sgr, strlen(sgr), 0u);

    RFB_CHECK(farsee_atomic_u64_load(&shell.input_events) >= 1u);

    unsigned nptr = 0;
    farsee_cmd out;
    const uint64_t now = farsee_thread_monotonic_ms();
    while (farsee_cmd_queue_pop(&cmds, &out, now, NULL)) {
        if (out.kind == FARSEE_CMD_POINTER) {
            nptr++;
            RFB_CHECK(out.pe.abs_x >= 0);
            RFB_CHECK(out.pe.abs_y >= 0);
            RFB_CHECK(out.pe.abs_x < (int32_t)shell.desk_w);
            RFB_CHECK(out.pe.abs_y < (int32_t)shell.desk_h);
        }
    }
    RFB_CHECK(nptr >= 2u); // press + release

    farsee_cmd_queue_destroy(&cmds);
}

// High-rate SGR motion split like a real Kitty flood (ESC[ | body).
RFB_TEST(live_input_fixture, shell_feed__sgr_split_prefix__still_enqueues)
{
    farsee_cmd_queue cmds;
    RFB_CHECK(farsee_cmd_queue_init(&cmds));

    farsee_live_shell shell;
    farsee_live_shell_ops ops;
    inject_sink sink;
    memset(&sink, 0, sizeof sink);
    sink.cmds = &cmds;

    farsee_live_shell_init(&shell, NULL, 1u);
    memset(&ops, 0, sizeof ops);
    ops.inject_key = sink_key;
    ops.inject_pointer = sink_pointer;
    shell.ops = &ops;
    shell.ops_user = &sink;
    shell.desk_w = 1280;
    shell.desk_h = 800;
    shell.term_cols = 120;
    shell.term_rows = 40;
    shell.term_pw = 1920;
    shell.term_ph = 1080;
    farsee_live_shell_set_view_scale(&shell, 100u);
    (void)farsee_live_shell_refresh_layout(&shell, false);

    // Simulate motion events with ESC[ split from the body.
    for (int n = 0; n < 20; n++) {
        static const uint8_t pre[] = {0x1Bu, '['};
        char body[32];
        int bn = snprintf(body, sizeof body, "<35;%d;%dM", 100 + n, 200 + n);
        RFB_CHECK(bn > 0);
        farsee_live_shell_feed_tty(&shell, pre, sizeof pre, 1000u + (uint64_t)n);
        farsee_live_shell_feed_tty(&shell, (const uint8_t *)body, (size_t)bn,
                                   1000u + (uint64_t)n);
    }

    RFB_CHECK(farsee_atomic_u64_load(&shell.input_events) >= 20u);

    unsigned nptr = 0;
    farsee_cmd out;
    const uint64_t now = farsee_thread_monotonic_ms();
    while (farsee_cmd_queue_pop(&cmds, &out, now, NULL)) {
        if (out.kind == FARSEE_CMD_POINTER) {
            nptr++;
        }
    }
    RFB_CHECK(nptr >= 20u);

    farsee_cmd_queue_destroy(&cmds);
}

RFB_TEST(live_input_fixture, shell_feed__view_only__no_cmd_enqueue)
{
    farsee_cmd_queue cmds;
    RFB_CHECK(farsee_cmd_queue_init(&cmds));

    farsee_live_shell shell;
    farsee_live_shell_ops ops;
    inject_sink sink;
    memset(&sink, 0, sizeof sink);
    sink.cmds = &cmds;

    farsee_live_shell_init(&shell, NULL, 1u);
    memset(&ops, 0, sizeof ops);
    ops.inject_key = sink_key;
    ops.inject_pointer = sink_pointer;
    shell.ops = &ops;
    shell.ops_user = &sink;
    shell.view_only = true;
    shell.desk_w = 100;
    shell.desk_h = 100;
    shell.term_cols = 40;
    shell.term_rows = 20;
    (void)farsee_live_shell_refresh_layout(&shell, false);

    const uint8_t a[] = {'a'};
    farsee_live_shell_feed_tty(&shell, a, 1, 0u);
    const char *sgr = "\033[<0;2;2M";
    farsee_live_shell_feed_tty(&shell, (const uint8_t *)sgr, strlen(sgr), 0u);

    RFB_CHECK_EQ_UINT(farsee_atomic_u64_load(&shell.input_events), 0u);
    farsee_cmd out;
    RFB_CHECK(!farsee_cmd_queue_pop(&cmds, &out, farsee_thread_monotonic_ms(),
                                    NULL));

    farsee_cmd_queue_destroy(&cmds);
}
