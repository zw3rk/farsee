// SPDX-License-Identifier: Apache-2.0
//
// Farsee reactor — core registration table + POSIX backend (F2 gate, §8).
//
// Design: the reactor owns a fixed-capacity table of slots. Each slot is
// either free or holds a {fd-or-timer, events, callback, user, token,
// generation}. Tokens embed a generation counter so a removed slot's token
// can never be reused for a different waitable (§8.2 stale-reuse safety).
//
// The POSIX tick wraps poll() (the existing rfb_poll_wait discipline). The
// fake reactor (tests/fakes/fake_reactor.c) reuses the same core table via
// the private reactor_internal.h seam and supplies its own tick/time.
//
// Safe removal during callback dispatch (§8.2): a callback may remove the
// currently-dispatching waitable; one-shot timers are removed before their
// callback fires, and the callback's `user` context is snapshotted first.

#include "farsee/farsee_reactor.h"
#include "farsee/poller.h"  // existing rfb_poll_wait (adapted, not replaced)
#include "reactor_internal.h"  // PRIVATE seam for the fake reactor

#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <time.h>

// Token packing: high 32 bits = generation, low 32 bits = slot index (+1).
// This makes tokens unique per (slot, generation) and immune to stale reuse.
#define TOKEN_INDEX(tok)   ((size_t)((tok) & 0xFFFFFFFFu) - 1u)
#define TOKEN_GEN(tok)     ((uint32_t)((tok) >> 32))
#define MAKE_TOKEN(idx, gen) \
    (((farsee_reactor_token)(gen) << 32) | (farsee_reactor_token)((idx) + 1u))

struct farsee_reactor {
    farsee__slot slots[FARSEE_REACTOR_MAX_WAITABLES];
    uint32_t     next_generation;  // monotonic; never reused within a slot
    uint64_t   (*now_ms_fn)(const farsee_reactor *);
    int        (*tick_fn)(farsee_reactor *, size_t);
};

// --- Construction / destruction -------------------------------------------

farsee_reactor *farsee_reactor_create(void)
{
    farsee_reactor *r = calloc(1, sizeof(*r));
    if (r == NULL) {
        return NULL;
    }
    r->next_generation = 1;  // 0 reserved so MAKE_TOKEN never yields INVALID
    return r;
}

void farsee_reactor_destroy(farsee_reactor **rptr)
{
    if (rptr == NULL || *rptr == NULL) {
        return;
    }
    free(*rptr);
    *rptr = NULL;
}

size_t farsee_reactor_count(const farsee_reactor *r)
{
    if (r == NULL) {
        return 0;
    }
    size_t n = 0;
    for (size_t i = 0; i < FARSEE_REACTOR_MAX_WAITABLES; ++i) {
        if (r->slots[i].kind != FARSEE__SLOT_FREE) {
            ++n;
        }
    }
    return n;
}

// --- Core slot helpers -----------------------------------------------------

static farsee_reactor_token add_slot(farsee_reactor *r, farsee__slot_kind kind)
{
    if (r == NULL) {
        return FARSEE_REACTOR_INVALID_TOKEN;
    }
    for (size_t i = 0; i < FARSEE_REACTOR_MAX_WAITABLES; ++i) {
        if (r->slots[i].kind == FARSEE__SLOT_FREE) {
            farsee__slot *s = &r->slots[i];
            s->kind = kind;
            s->injected = 0;
            s->pending_remove = false;
            s->generation = r->next_generation++;
            return MAKE_TOKEN(i, s->generation);
        }
    }
    return FARSEE_REACTOR_INVALID_TOKEN;  // registration cap (§8.2)
}

static farsee__slot *slot_for_token(farsee_reactor *r, farsee_reactor_token tok)
{
    if (r == NULL || tok == FARSEE_REACTOR_INVALID_TOKEN) {
        return NULL;
    }
    size_t idx = TOKEN_INDEX(tok);
    if (idx >= FARSEE_REACTOR_MAX_WAITABLES) {
        return NULL;
    }
    farsee__slot *s = &r->slots[idx];
    if (s->kind == FARSEE__SLOT_FREE || s->generation != TOKEN_GEN(tok)) {
        return NULL;  // stale token (removed and not reused)
    }
    return s;
}

farsee_reactor_token farsee_reactor_add(farsee_reactor *r, int fd,
                                        unsigned events,
                                        farsee_reactor_cb cb, void *user)
{
    if (cb == NULL || fd < 0) {
        return FARSEE_REACTOR_INVALID_TOKEN;
    }
    farsee_reactor_token tok = add_slot(r, FARSEE__SLOT_FD);
    farsee__slot *s = slot_for_token(r, tok);
    if (s == NULL) {
        return FARSEE_REACTOR_INVALID_TOKEN;
    }
    s->fd = fd;
    s->events = events;
    s->cb = cb;
    s->user = user;
    s->deadline_ms = 0;
    return tok;
}

farsee_reactor_token farsee_reactor_add_timer(farsee_reactor *r,
                                              uint64_t deadline_monotonic_ms,
                                              farsee_reactor_cb cb,
                                              void *user)
{
    if (cb == NULL) {
        return FARSEE_REACTOR_INVALID_TOKEN;
    }
    farsee_reactor_token tok = add_slot(r, FARSEE__SLOT_TIMER);
    farsee__slot *s = slot_for_token(r, tok);
    if (s == NULL) {
        return FARSEE_REACTOR_INVALID_TOKEN;
    }
    s->fd = -1;
    s->events = 0;
    s->cb = cb;
    s->user = user;
    s->deadline_ms = deadline_monotonic_ms;
    return tok;
}

bool farsee_reactor_modify(farsee_reactor *r, farsee_reactor_token tok,
                           unsigned events)
{
    farsee__slot *s = slot_for_token(r, tok);
    if (s == NULL || s->kind != FARSEE__SLOT_FD) {
        return false;
    }
    s->events = events;
    return true;
}

bool farsee_reactor_remove(farsee_reactor *r, farsee_reactor_token tok)
{
    farsee__slot *s = slot_for_token(r, tok);
    if (s == NULL) {
        return false;
    }
    // Bump the generation so any outstanding token for this slot becomes
    // stale (never reused for a different waitable, §8.2).
    s->generation = r->next_generation++;
    s->kind = FARSEE__SLOT_FREE;
    s->cb = NULL;
    s->user = NULL;
    s->fd = -1;
    s->events = 0;
    s->injected = 0;
    return true;
}

// Dispatch a callback with snapshotted user context so the callback may
// safely remove its own slot during dispatch.
static void dispatch_slot(farsee_reactor *r, size_t idx, unsigned triggered)
{
    farsee__slot *s = &r->slots[idx];
    farsee_reactor_cb cb = s->cb;
    void *user = s->user;
    // Populate the handle with the slot's current token; if the callback
    // removes the slot, the token becomes stale (correct) but the handle
    // pointer stays valid for the callback's duration (stack storage).
    farsee_waitable handle_storage;
    handle_storage.token = MAKE_TOKEN(idx, s->generation);
    cb(&handle_storage, triggered, user);
}

// --- POSIX backend ---------------------------------------------------------

static uint64_t posix_now_ms(void)
{
    // poll's timeout is relative; we need a monotonic millisecond clock
    // for timer deadlines. CLOCK_MONOTONIC via clock_gettime is portable.
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static uint64_t default_now_ms(const farsee_reactor *r)
{
    if (r != NULL && r->now_ms_fn != NULL) {
        return r->now_ms_fn(r);
    }
    return posix_now_ms();
}

// Compute the poll timeout from the nearest pending timer (overflow-safe).
static int compute_timeout_ms(const farsee_reactor *r, uint64_t now)
{
    bool have = false;
    uint64_t nearest = 0;
    for (size_t i = 0; i < FARSEE_REACTOR_MAX_WAITABLES; ++i) {
        if (r->slots[i].kind == FARSEE__SLOT_TIMER) {
            if (!have || r->slots[i].deadline_ms < nearest) {
                nearest = r->slots[i].deadline_ms;
                have = true;
            }
        }
    }
    if (!have) {
        return -1;  // block until a fd fires
    }
    if (nearest <= now) {
        return 0;
    }
    uint64_t delta = nearest - now;
    if (delta > 0x7FFFFFFFull) {
        return 0x7FFFFFFF;  // clamp to INT_MAX (poll takes int)
    }
    return (int)delta;
}

int farsee_reactor_tick(farsee_reactor *r, size_t budget_callbacks)
{
    if (r == NULL) {
        return -1;
    }
    if (r->tick_fn != NULL) {
        return r->tick_fn(r, budget_callbacks);  // fake override
    }

    uint64_t now = default_now_ms(r);
    int timeout = compute_timeout_ms(r, now);

    rfb_poll_fd pfds[FARSEE_REACTOR_MAX_WAITABLES];
    size_t map[FARSEE_REACTOR_MAX_WAITABLES];
    size_t nfds = 0;
    for (size_t i = 0; i < FARSEE_REACTOR_MAX_WAITABLES; ++i) {
        if (r->slots[i].kind == FARSEE__SLOT_FD) {
            pfds[nfds].fd = r->slots[i].fd;
            pfds[nfds].events = (rfb_poll_event)0;
            if (r->slots[i].events & FARSEE_REACTOR_READ) {
                pfds[nfds].events = (rfb_poll_event)(pfds[nfds].events | RFB_POLL_READ);
            }
            if (r->slots[i].events & FARSEE_REACTOR_WRITE) {
                pfds[nfds].events = (rfb_poll_event)(pfds[nfds].events | RFB_POLL_WRITE);
            }
            pfds[nfds].revents = (rfb_poll_event)0;
            map[nfds] = i;
            ++nfds;
        }
    }

    (void)rfb_poll_wait(pfds, nfds, timeout);  // EINTR retried inside

    size_t budget = (budget_callbacks == 0) ? FARSEE_REACTOR_MAX_WAITABLES
                                            : budget_callbacks;
    int dispatched = 0;

    for (size_t i = 0; i < nfds && (size_t)dispatched < budget; ++i) {
        unsigned triggered = 0;
        if (pfds[i].revents & RFB_POLL_READ)  triggered |= FARSEE_REACTOR_READ;
        if (pfds[i].revents & RFB_POLL_WRITE) triggered |= FARSEE_REACTOR_WRITE;
        if (triggered == 0) {
            continue;
        }
        dispatch_slot(r, map[i], triggered);
        ++dispatched;
    }

    // Fire expired timers (re-read time after fd callbacks).
    uint64_t now2 = default_now_ms(r);
    for (size_t i = 0; i < FARSEE_REACTOR_MAX_WAITABLES && (size_t)dispatched < budget; ++i) {
        if (r->slots[i].kind == FARSEE__SLOT_TIMER && r->slots[i].deadline_ms <= now2) {
            farsee_reactor_token tok = MAKE_TOKEN(i, r->slots[i].generation);
            farsee_reactor_remove(r, tok);  // one-shot
            dispatch_slot(r, i, FARSEE_REACTOR_NONE);
            ++dispatched;
        }
    }

    return dispatched;
}

// --- Internal seam for the fake reactor (reactor_internal.h) ---------------

void farsee_reactor__set_now_fn(farsee_reactor *r,
                                uint64_t (*fn)(const farsee_reactor *))
{
    if (r != NULL) {
        r->now_ms_fn = fn;
    }
}

void farsee_reactor__set_tick_fn(farsee_reactor *r,
                                 int (*fn)(farsee_reactor *, size_t))
{
    if (r != NULL) {
        r->tick_fn = fn;
    }
}

bool farsee_reactor__inject(farsee_reactor *r, farsee_reactor_token tok,
                            unsigned events)
{
    farsee__slot *s = slot_for_token(r, tok);
    if (s == NULL) {
        return false;
    }
    s->injected = (s->injected | events) & s->events;
    return s->injected != 0;
}

farsee__slot *farsee_reactor__slot_at(farsee_reactor *r, size_t idx)
{
    if (r == NULL || idx >= FARSEE_REACTOR_MAX_WAITABLES) {
        return NULL;
    }
    return &r->slots[idx];
}
