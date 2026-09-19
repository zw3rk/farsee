// SPDX-License-Identifier: Apache-2.0
//
// Bounded input-command queue (see farsee_cmd_queue.h).

#include "farsee/farsee_cmd_queue.h"

#include <string.h>

bool farsee_cmd_queue_init(farsee_cmd_queue *q)
{
    if (q == NULL) {
        return false;
    }
    memset(q, 0, sizeof(*q));
    q->mu = farsee_mutex_create();
    q->cv = farsee_cond_create();
    if (q->mu == NULL || q->cv == NULL) {
        farsee_cmd_queue_destroy(q);
        return false;
    }
    return true;
}

void farsee_cmd_queue_destroy(farsee_cmd_queue *q)
{
    if (q == NULL) {
        return;
    }
    farsee_cond_destroy(&q->cv);
    farsee_mutex_destroy(&q->mu);
    memset(q, 0, sizeof(*q));
}

void farsee_cmd_queue_kick(farsee_cmd_queue *q)
{
    if (q == NULL) {
        return;
    }
    farsee_mutex_lock(q->mu);
    farsee_cond_broadcast(q->cv);
    farsee_mutex_unlock(q->mu);
}

static void drop_at_index(farsee_cmd_queue *q, size_t i);

static bool is_move_only(const farsee_cmd *c)
{
    return c != NULL && c->kind == FARSEE_CMD_POINTER && c->pe.buttons == 0 &&
           c->prev_buttons == 0 && c->pe.wheel_v == 0 && c->pe.wheel_h == 0;
}

// A non-edge pointer sample with buttons held can be reclaimed for a
// privileged release. This classifier excludes falling and rising edges.
static bool is_button_held_move(const farsee_cmd *c)
{
    if (c == NULL || c->kind != FARSEE_CMD_POINTER) {
        return false;
    }
    if (c->pe.wheel_v != 0 || c->pe.wheel_h != 0) {
        return false;
    }
    // Falling edge (release): buttons==0 && prev!=0 — not reclaimable here.
    // Rising edge: buttons!=0 && prev==0 — keep.
    // Held drag: buttons!=0 && prev!=0 (or pure move already handled).
    return c->pe.buttons != 0u && c->prev_buttons != 0u &&
           c->pe.buttons == c->prev_buttons;
}

// Drop one pure-move slot to reclaim space. Returns true if a move was
// dropped. Never drops keys, button edges, wheel, or RELEASE_ALL.
static bool drop_one_pure_move(farsee_cmd_queue *q)
{
    for (size_t i = 0; i < q->count; i++) {
        size_t idx = (q->head + i) % FARSEE_CMD_QUEUE_CAP;
        if (!is_move_only(&q->q[idx])) {
            continue;
        }
        drop_at_index(q, i);
        q->dropped_moves++;
        return true;
    }
    return false;
}

// Drop one non-edge button-held pointer sample.
static bool drop_one_button_held_move(farsee_cmd_queue *q)
{
    for (size_t i = 0; i < q->count; i++) {
        size_t idx = (q->head + i) % FARSEE_CMD_QUEUE_CAP;
        if (!is_button_held_move(&q->q[idx])) {
            continue;
        }
        drop_at_index(q, i);
        q->dropped_moves++;
        return true;
    }
    return false;
}

// True for releases that receive additional reclaim attempts under pressure:
// key-up, RELEASE_ALL, or a pointer transition from held buttons to zero.
static bool is_privileged_release(const farsee_cmd *c)
{
    if (c == NULL) {
        return false;
    }
    if (c->kind == FARSEE_CMD_RELEASE_ALL) {
        return true;
    }
    if (c->kind == FARSEE_CMD_KEY && c->key.action == FARSEE_KEY_RELEASE) {
        return true;
    }
    // A pointer release changes a nonzero button mask to zero.
    if (c->kind == FARSEE_CMD_POINTER && c->pe.buttons == 0u &&
        c->prev_buttons != 0u) {
        return true;
    }
    return false;
}

static void drop_at_index(farsee_cmd_queue *q, size_t i)
{
    if (i == 0u) {
        q->head = (q->head + 1u) % FARSEE_CMD_QUEUE_CAP;
        q->count--;
    } else {
        for (size_t j = i; j + 1u < q->count; j++) {
            size_t a = (q->head + j) % FARSEE_CMD_QUEUE_CAP;
            size_t b = (q->head + j + 1u) % FARSEE_CMD_QUEUE_CAP;
            q->q[a] = q->q[b];
        }
        q->count--;
    }
}

// Drop a key-down to make room for a release. Prefer matching logical keysym
// when the reclaim is for a key-up; else drop oldest press.
static bool drop_one_key_down(farsee_cmd_queue *q, uint32_t prefer_logical)
{
    size_t prefer_i = (size_t)-1;
    size_t oldest_i = (size_t)-1;
    for (size_t i = 0; i < q->count; i++) {
        size_t idx = (q->head + i) % FARSEE_CMD_QUEUE_CAP;
        const farsee_cmd *c = &q->q[idx];
        if (c->kind != FARSEE_CMD_KEY || c->key.action != FARSEE_KEY_PRESS) {
            continue;
        }
        if (oldest_i == (size_t)-1) {
            oldest_i = i;
        }
        if (prefer_logical != 0u && c->key.logical == prefer_logical) {
            prefer_i = i;
            break;
        }
    }
    size_t use = (prefer_i != (size_t)-1) ? prefer_i : oldest_i;
    if (use == (size_t)-1) {
        return false;
    }
    drop_at_index(q, use);
    q->dropped_keys++;
    return true;
}

bool farsee_cmd_queue_push(farsee_cmd_queue *q, const farsee_cmd *cmd)
{
    if (q == NULL || cmd == NULL) {
        return false;
    }
    farsee_mutex_lock(q->mu);
    if (q->count >= FARSEE_CMD_QUEUE_CAP) {
        // Pure moves are reclaimed first. A privileged release can then
        // reclaim one held-button move or key-down before the push is refused.
        (void)drop_one_pure_move(q);
        if (q->count >= FARSEE_CMD_QUEUE_CAP && is_privileged_release(cmd)) {
            (void)drop_one_button_held_move(q);
            if (q->count >= FARSEE_CMD_QUEUE_CAP) {
                uint32_t prefer = 0u;
                if (cmd->kind == FARSEE_CMD_KEY) {
                    prefer = cmd->key.logical;
                }
                (void)drop_one_key_down(q, prefer);
            }
        }
        if (q->count >= FARSEE_CMD_QUEUE_CAP) {
            // Still full: refuse. Count key/release pressure.
            if (cmd->kind == FARSEE_CMD_KEY ||
                cmd->kind == FARSEE_CMD_RELEASE_ALL ||
                is_privileged_release(cmd)) {
                q->dropped_keys++;
            }
            farsee_mutex_unlock(q->mu);
            return false;
        }
    }
    size_t tail = (q->head + q->count) % FARSEE_CMD_QUEUE_CAP;
    q->q[tail] = *cmd;
    q->count++;
    farsee_cond_signal(q->cv);
    farsee_mutex_unlock(q->mu);
    return true;
}

bool farsee_cmd_queue_pop(farsee_cmd_queue *q, farsee_cmd *out,
                          uint64_t deadline_monotonic_ms,
                          farsee_atomic_int *stop)
{
    if (q == NULL || out == NULL) {
        return false;
    }
    farsee_mutex_lock(q->mu);
    while (q->count == 0) {
        if (farsee_atomic_int_load_nonzero(stop)) {
            farsee_mutex_unlock(q->mu);
            return false;
        }
        if (!farsee_cond_timedwait(q->cv, q->mu, deadline_monotonic_ms)) {
            farsee_mutex_unlock(q->mu);
            return false;
        }
    }
    *out = q->q[q->head];
    q->head = (q->head + 1u) % FARSEE_CMD_QUEUE_CAP;
    q->count--;
    farsee_mutex_unlock(q->mu);
    return true;
}
