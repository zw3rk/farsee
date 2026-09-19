// SPDX-License-Identifier: Apache-2.0
//
// POSIX reactor backend contracts. These tests exercise farsee_reactor_tick
// directly with real pipe descriptors and short-deadline timers. One-shot
// callbacks are snapshotted before removal, and slots are revalidated before
// dispatch.
//
// POLLHUP must surface through a tick as FARSEE_REACTOR_HANGUP (the
// poller-level mapping is covered in poller_error_events__tests.c).

#include "farsee/farsee_reactor.h"
#include "tests/test_framework/rfb_test.h"

#include <time.h>
#include <unistd.h>

// --- helpers ----------------------------------------------------------------

static uint64_t posix_mono_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static bool pipe_write_byte(int fd)
{
    char b = 'x';
    return write(fd, &b, 1) == 1;
}

typedef struct {
    int fired;
    unsigned last_triggered;
    void *last_user;
} tick_ctx;

static void on_timer_fire(farsee_waitable *w, unsigned triggered, void *user)
{
    (void)w;
    tick_ctx *c = (tick_ctx *)user;
    c->fired++;
    c->last_triggered = triggered;
    c->last_user = user;
}

typedef struct {
    int fired;
    unsigned last_triggered;
} fd_ctx;

static void on_fd_event(farsee_waitable *w, unsigned triggered, void *user)
{
    (void)w;
    fd_ctx *c = (fd_ctx *)user;
    c->fired++;
    c->last_triggered = triggered;
}

typedef struct {
    farsee_reactor *r;
    farsee_reactor_token victim;
    bool remove_victim;
    int fired;
} removing_ctx;

static void on_fd_remove_other(farsee_waitable *w, unsigned triggered, void *user)
{
    (void)w; (void)triggered;
    removing_ctx *c = (removing_ctx *)user;
    c->fired++;
    if (c->remove_victim) {
        (void)farsee_reactor_remove(c->r, c->victim);
    }
}

// --- (a): expired one-shot timer must dispatch its own callback ------------

RFB_TEST(reactor_posix, posix_reactor__expired_one_shot_timer__fires_once_with_correct_user)
{
    farsee_reactor *r = farsee_reactor_create();
    RFB_CHECK(r != NULL);

    // A registered-but-idle fd bounds the second tick once the timer is
    // gone (with no waitables at all the tick would block forever).
    int p[2];
    RFB_CHECK(pipe(p) == 0);
    fd_ctx pipe_hits = {0};
    farsee_reactor_token ptok = farsee_reactor_add(r, p[0],
        FARSEE_REACTOR_READ, on_fd_event, &pipe_hits);
    RFB_CHECK(ptok != FARSEE_REACTOR_INVALID_TOKEN);

    tick_ctx timer_hits = {0};
    farsee_reactor_token ttok = farsee_reactor_add_timer(r,
        posix_mono_ms() + 30, on_timer_fire, &timer_hits);
    RFB_CHECK(ttok != FARSEE_REACTOR_INVALID_TOKEN);

    // The one-shot callback remains valid after its timer slot is removed.
    int n = farsee_reactor_tick(r, 16);
    RFB_CHECK_EQ_INT(n, 1);
    RFB_CHECK_EQ_INT(timer_hits.fired, 1);
    RFB_CHECK_MSG(timer_hits.last_user == (void *)&timer_hits,
                  "timer callback received the wrong user pointer");
    RFB_CHECK_EQ_UINT(timer_hits.last_triggered, (unsigned)FARSEE_REACTOR_NONE);

    // One-shot: the timer must not fire again. Make the pipe readable so
    // this tick returns (only the pipe may dispatch).
    RFB_CHECK(pipe_write_byte(p[1]));
    n = farsee_reactor_tick(r, 16);
    RFB_CHECK_EQ_INT(n, 1);
    RFB_CHECK_EQ_INT(pipe_hits.fired, 1);
    RFB_CHECK_EQ_INT(timer_hits.fired, 1);

    farsee_reactor_destroy(&r);
    (void)close(p[0]);
    (void)close(p[1]);
}

// --- (b): callback A removes B; B's stale snapshot must not dispatch -------

RFB_TEST(reactor_posix, posix_reactor__callback_removes_other__victim_not_dispatched)
{
    farsee_reactor *r = farsee_reactor_create();
    RFB_CHECK(r != NULL);

    int pa[2], pb[2];
    RFB_CHECK(pipe(pa) == 0);
    RFB_CHECK(pipe(pb) == 0);
    RFB_CHECK(pipe_write_byte(pa[1]));
    RFB_CHECK(pipe_write_byte(pb[1]));

    // A is registered first (lower slot index => dispatched first).
    removing_ctx a = {0};
    a.r = r;
    fd_ctx b_hits = {0};
    farsee_reactor_token ta = farsee_reactor_add(r, pa[0],
        FARSEE_REACTOR_READ, on_fd_remove_other, &a);
    farsee_reactor_token tb = farsee_reactor_add(r, pb[0],
        FARSEE_REACTOR_READ, on_fd_event, &b_hits);
    RFB_CHECK(ta != FARSEE_REACTOR_INVALID_TOKEN);
    RFB_CHECK(tb != FARSEE_REACTOR_INVALID_TOKEN);
    a.victim = tb;
    a.remove_victim = true;

    // A removes B, so B must not be dispatched from the poll snapshot.
    int n = farsee_reactor_tick(r, 16);
    RFB_CHECK_EQ_INT(n, 1);
    RFB_CHECK_EQ_INT(a.fired, 1);
    RFB_CHECK_EQ_INT(b_hits.fired, 0);  // B was removed: must not dispatch
    RFB_CHECK_EQ_UINT(farsee_reactor_count(r), 1u);  // only A remains

    farsee_reactor_destroy(&r);
    (void)close(pa[0]);
    (void)close(pa[1]);
    (void)close(pb[0]);
    (void)close(pb[1]);
}

// --- (b): removed AND re-added slot must not fire from stale events --------

static void on_new_slot(farsee_waitable *w, unsigned triggered, void *user)
{
    (void)w; (void)triggered;
    fd_ctx *c = (fd_ctx *)user;
    c->fired++;
}

typedef struct {
    farsee_reactor *r;
    farsee_reactor_token victim;
    int victim_fd;
    farsee_reactor_cb reborn_cb;
    void *reborn_user;
    int fired;
} readd_ctx;

static void on_fd_remove_then_readd(farsee_waitable *w, unsigned triggered,
                                    void *user)
{
    (void)w; (void)triggered;
    readd_ctx *c = (readd_ctx *)user;
    c->fired++;
    (void)farsee_reactor_remove(c->r, c->victim);
    (void)farsee_reactor_add(c->r, c->victim_fd, FARSEE_REACTOR_READ,
                             c->reborn_cb, c->reborn_user);
}

RFB_TEST(reactor_posix, posix_reactor__removed_then_readded_waitable__stale_events_dropped)
{
    farsee_reactor *r = farsee_reactor_create();
    RFB_CHECK(r != NULL);

    int pa[2], pb[2];
    RFB_CHECK(pipe(pa) == 0);
    RFB_CHECK(pipe(pb) == 0);
    RFB_CHECK(pipe_write_byte(pa[1]));
    RFB_CHECK(pipe_write_byte(pb[1]));

    readd_ctx a = {0};
    a.r = r;
    fd_ctx reborn = {0};
    a.reborn_cb = on_new_slot;
    a.reborn_user = &reborn;
    farsee_reactor_token ta = farsee_reactor_add(r, pa[0],
        FARSEE_REACTOR_READ, on_fd_remove_then_readd, &a);
    farsee_reactor_token tb = farsee_reactor_add(r, pb[0],
        FARSEE_REACTOR_READ, on_new_slot, &reborn);
    RFB_CHECK(ta != FARSEE_REACTOR_INVALID_TOKEN);
    RFB_CHECK(tb != FARSEE_REACTOR_INVALID_TOKEN);
    a.victim = tb;
    a.victim_fd = pb[0];

    // A re-added slot must not receive events from the prior slot occupant.
    int n = farsee_reactor_tick(r, 16);
    RFB_CHECK_EQ_INT(n, 1);
    RFB_CHECK_EQ_INT(a.fired, 1);
    RFB_CHECK_EQ_INT(reborn.fired, 0);  // stale events must not fire it

    // The re-added waitable stays registered for future ticks.
    RFB_CHECK_EQ_UINT(farsee_reactor_count(r), 2u);

    farsee_reactor_destroy(&r);
    (void)close(pa[0]);
    (void)close(pa[1]);
    (void)close(pb[0]);
    (void)close(pb[1]);
}

// --- Closed peer surfaces HANGUP through a tick -----------------------------

RFB_TEST(reactor_posix, posix_reactor__peer_closed_pipe__delivers_hangup_event)
{
    farsee_reactor *r = farsee_reactor_create();
    RFB_CHECK(r != NULL);

    int p[2];
    RFB_CHECK(pipe(p) == 0);
    fd_ctx hits = {0};
    farsee_reactor_token tok = farsee_reactor_add(r, p[0],
        FARSEE_REACTOR_READ, on_fd_event, &hits);
    RFB_CHECK(tok != FARSEE_REACTOR_INVALID_TOKEN);

    // Peer gone: the read end must report HANGUP, not look like a timeout.
    RFB_CHECK(close(p[1]) == 0);

    // Bound the tick so a backend that drops HUP cannot hang forever:
    // a short-deadline timer fires instead if HUP is lost.
    tick_ctx timer_hits = {0};
    farsee_reactor_token ttok = farsee_reactor_add_timer(r,
        posix_mono_ms() + 80, on_timer_fire, &timer_hits);
    RFB_CHECK(ttok != FARSEE_REACTOR_INVALID_TOKEN);

    int n = farsee_reactor_tick(r, 16);
    RFB_CHECK(n >= 1);
    RFB_CHECK_EQ_INT(hits.fired, 1);
    RFB_CHECK_MSG(hits.last_triggered & FARSEE_REACTOR_HANGUP,
                  "closed peer did not deliver FARSEE_REACTOR_HANGUP");

    farsee_reactor_destroy(&r);
    (void)close(p[0]);
}

// --- An invalid fd surfaces ERROR through a tick -----------------------------

RFB_TEST(reactor_posix, posix_reactor__fd_closed_under_us__delivers_error_event)
{
    farsee_reactor *r = farsee_reactor_create();
    RFB_CHECK(r != NULL);

    int p[2];
    RFB_CHECK(pipe(p) == 0);
    fd_ctx hits = {0};
    farsee_reactor_token tok = farsee_reactor_add(r, p[0],
        FARSEE_REACTOR_READ, on_fd_event, &hits);
    RFB_CHECK(tok != FARSEE_REACTOR_INVALID_TOKEN);

    // Close BOTH ends so the registered fd number is invalid: poll must
    // report POLLNVAL, which the tick delivers as FARSEE_REACTOR_ERROR
    // instead of silently looking like a timeout (bounded by the timer).
    (void)close(p[0]);
    (void)close(p[1]);

    tick_ctx timer_hits = {0};
    farsee_reactor_token ttok = farsee_reactor_add_timer(r,
        posix_mono_ms() + 80, on_timer_fire, &timer_hits);
    RFB_CHECK(ttok != FARSEE_REACTOR_INVALID_TOKEN);

    int n = farsee_reactor_tick(r, 16);
    RFB_CHECK(n >= 1);
    RFB_CHECK_EQ_INT(hits.fired, 1);
    RFB_CHECK_MSG(hits.last_triggered & FARSEE_REACTOR_ERROR,
                  "invalid fd did not deliver FARSEE_REACTOR_ERROR");

    farsee_reactor_destroy(&r);
}

// rfb_poll_wait caps one call at
// 16 fds. The tick batches larger waitable sets so all events are dispatched.
RFB_TEST(reactor_posix, more_than_sixteen_fds__all_dispatch)
{
    enum { N = 17 };  // one past the single-call poller cap
    int pfd[N][2];
    farsee_reactor_token tok[N];
    fd_ctx ctx[N];
    for (int i = 0; i < N; i++) {
        RFB_CHECK(pipe(pfd[i]) == 0);
        ctx[i].fired = 0;
        ctx[i].last_triggered = 0;
    }

    farsee_reactor *r = farsee_reactor_create();
    RFB_CHECK(r != NULL);
    for (int i = 0; i < N; i++) {
        tok[i] = farsee_reactor_add(r, pfd[i][0], FARSEE_REACTOR_READ,
                                    on_fd_event, &ctx[i]);
        RFB_CHECK(tok[i] != FARSEE_REACTOR_INVALID_TOKEN);
        RFB_CHECK(pipe_write_byte(pfd[i][1]));
    }

    const int dispatched = farsee_reactor_tick(r, 0);
    RFB_CHECK_EQ_INT(dispatched, N);
    for (int i = 0; i < N; i++) {
        RFB_CHECK_EQ_INT(ctx[i].fired, 1);
        RFB_CHECK((ctx[i].last_triggered & FARSEE_REACTOR_READ) != 0);
    }

    farsee_reactor_destroy(&r);
    for (int i = 0; i < N; i++) {
        close(pfd[i][0]);
        close(pfd[i][1]);
    }
}

// The write end of a fresh pipe is writable, so POLLOUT surfaces as
// FARSEE_REACTOR_WRITE through a tick.
RFB_TEST(reactor_posix, write_subscribed_writable_pipe__delivers_write_event)
{
    int pfd[2];
    RFB_CHECK(pipe(pfd) == 0);

    farsee_reactor *r = farsee_reactor_create();
    RFB_CHECK(r != NULL);

    fd_ctx ctx;
    ctx.fired = 0;
    ctx.last_triggered = 0;
    farsee_reactor_token tok =
        farsee_reactor_add(r, pfd[1], FARSEE_REACTOR_WRITE, on_fd_event, &ctx);
    RFB_CHECK(tok != FARSEE_REACTOR_INVALID_TOKEN);

    const int dispatched = farsee_reactor_tick(r, 0);
    RFB_CHECK_EQ_INT(dispatched, 1);
    RFB_CHECK_EQ_INT(ctx.fired, 1);
    RFB_CHECK((ctx.last_triggered & FARSEE_REACTOR_WRITE) != 0);
    RFB_CHECK((ctx.last_triggered & FARSEE_REACTOR_READ) == 0);

    farsee_reactor_destroy(&r);
    close(pfd[0]);
    close(pfd[1]);
}
