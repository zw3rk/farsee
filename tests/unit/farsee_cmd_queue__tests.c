// SPDX-License-Identifier: Apache-2.0
//
// Shared input-command queue tests (input → protocol thread).

#include "farsee/farsee_cmd_queue.h"
#include "farsee/farsee_input.h"
#include "farsee/farsee_thread.h"
#include "tests/test_framework/rfb_test.h"

#include <string.h>

static farsee_cmd queue_key(uint32_t logical, farsee_key_action action)
{
    farsee_cmd cmd;
    memset(&cmd, 0, sizeof cmd);
    cmd.kind = FARSEE_CMD_KEY;
    cmd.key.logical = logical;
    cmd.key.action = action;
    return cmd;
}

static farsee_cmd queue_pointer(unsigned buttons, unsigned prev_buttons,
                                int32_t wheel_v, int32_t wheel_h,
                                int32_t x)
{
    farsee_cmd cmd;
    memset(&cmd, 0, sizeof cmd);
    cmd.kind = FARSEE_CMD_POINTER;
    cmd.pe.abs_x = x;
    cmd.pe.buttons = buttons;
    cmd.prev_buttons = prev_buttons;
    cmd.pe.wheel_v = wheel_v;
    cmd.pe.wheel_h = wheel_h;
    return cmd;
}

static farsee_cmd queue_release_all(void)
{
    farsee_cmd cmd;
    memset(&cmd, 0, sizeof cmd);
    cmd.kind = FARSEE_CMD_RELEASE_ALL;
    return cmd;
}

static bool queue_fill_repeated(farsee_cmd_queue *q, const farsee_cmd *cmd)
{
    for (size_t i = 0u; i < FARSEE_CMD_QUEUE_CAP; i++) {
        if (!farsee_cmd_queue_push(q, cmd)) {
            return false;
        }
    }
    return true;
}

RFB_TEST(farsee_cmds, farsee_cmds_init_destroy__ok)
{
    farsee_cmd_queue q;
    RFB_CHECK(farsee_cmd_queue_init(&q));
    farsee_cmd c;
    RFB_CHECK(!farsee_cmd_queue_pop(&q, &c, farsee_thread_monotonic_ms(), NULL));
    farsee_cmd_queue_destroy(&q);
}

RFB_TEST(farsee_cmds, farsee_cmds_push_pop__fifo)
{
    farsee_cmd_queue q;
    RFB_CHECK(farsee_cmd_queue_init(&q));
    farsee_cmd a;
    memset(&a, 0, sizeof(a));
    a.kind = FARSEE_CMD_KEY;
    a.key.logical = 0x61u;
    a.key.action = FARSEE_KEY_PRESS;
    RFB_CHECK(farsee_cmd_queue_push(&q, &a));
    farsee_cmd b;
    memset(&b, 0, sizeof(b));
    b.kind = FARSEE_CMD_POINTER;
    b.pe.abs_x = 10;
    b.pe.abs_y = 20;
    RFB_CHECK(farsee_cmd_queue_push(&q, &b));

    farsee_cmd out;
    const uint64_t dl = farsee_thread_monotonic_ms() + 1000u;
    RFB_CHECK(farsee_cmd_queue_pop(&q, &out, dl, NULL));
    RFB_CHECK(out.kind == FARSEE_CMD_KEY);
    RFB_CHECK_EQ_UINT(out.key.logical, 0x61u);
    RFB_CHECK(farsee_cmd_queue_pop(&q, &out, dl, NULL));
    RFB_CHECK(out.kind == FARSEE_CMD_POINTER);
    RFB_CHECK_EQ_INT(out.pe.abs_x, 10);
    farsee_cmd_queue_destroy(&q);
}

RFB_TEST(farsee_cmds, farsee_cmds_full__drops_moves_keeps_keys)
{
    farsee_cmd_queue q;
    RFB_CHECK(farsee_cmd_queue_init(&q));
    // Fill with pure moves.
    for (unsigned i = 0; i < FARSEE_CMD_QUEUE_CAP; i++) {
        farsee_cmd m;
        memset(&m, 0, sizeof(m));
        m.kind = FARSEE_CMD_POINTER;
        m.pe.abs_x = (int32_t)i;
        RFB_CHECK(farsee_cmd_queue_push(&q, &m));
    }
    // Key must still land (evicts a move).
    farsee_cmd k;
    memset(&k, 0, sizeof(k));
    k.kind = FARSEE_CMD_KEY;
    k.key.logical = 0x42u;
    k.key.action = FARSEE_KEY_PRESS;
    RFB_CHECK(farsee_cmd_queue_push(&q, &k));
    RFB_CHECK(q.dropped_moves >= 1);

    bool found_key = false;
    farsee_cmd out;
    while (farsee_cmd_queue_pop(&q, &out, farsee_thread_monotonic_ms(), NULL)) {
        if (out.kind == FARSEE_CMD_KEY && out.key.logical == 0x42u) {
            found_key = true;
        }
    }
    RFB_CHECK(found_key);
    farsee_cmd_queue_destroy(&q);
}

RFB_TEST(farsee_cmds, farsee_cmds_release_all__round_trip)
{
    farsee_cmd_queue q;
    RFB_CHECK(farsee_cmd_queue_init(&q));
    farsee_cmd c;
    memset(&c, 0, sizeof(c));
    c.kind = FARSEE_CMD_RELEASE_ALL;
    RFB_CHECK(farsee_cmd_queue_push(&q, &c));
    farsee_cmd out;
    const uint64_t dl = farsee_thread_monotonic_ms() + 1000u;
    RFB_CHECK(farsee_cmd_queue_pop(&q, &out, dl, NULL));
    RFB_CHECK(out.kind == FARSEE_CMD_RELEASE_ALL);
    farsee_cmd_queue_destroy(&q);
}

// A key flood with no pure moves must not silently drop the head key.
RFB_TEST(farsee_cmds, farsee_cmds_full_keys__push_fails_no_key_drop)
{
    farsee_cmd_queue q;
    RFB_CHECK(farsee_cmd_queue_init(&q));
    for (unsigned i = 0; i < FARSEE_CMD_QUEUE_CAP; i++) {
        farsee_cmd k;
        memset(&k, 0, sizeof(k));
        k.kind = FARSEE_CMD_KEY;
        k.key.logical = 0x100u + i;
        k.key.action = FARSEE_KEY_PRESS;
        RFB_CHECK(farsee_cmd_queue_push(&q, &k));
    }
    farsee_cmd extra;
    memset(&extra, 0, sizeof(extra));
    extra.kind = FARSEE_CMD_KEY;
    extra.key.logical = 0xDEAD;
    extra.key.action = FARSEE_KEY_PRESS;
    RFB_CHECK(!farsee_cmd_queue_push(&q, &extra));
    RFB_CHECK(q.dropped_keys >= 1u);
    RFB_CHECK_EQ_UINT(q.count, FARSEE_CMD_QUEUE_CAP);

    // Head key (first pushed) still present — not evicted for the refuse.
    farsee_cmd out;
    RFB_CHECK(farsee_cmd_queue_pop(&q, &out, farsee_thread_monotonic_ms(), NULL));
    RFB_CHECK(out.kind == FARSEE_CMD_KEY);
    RFB_CHECK_EQ_UINT(out.key.logical, 0x100u);
    farsee_cmd_queue_destroy(&q);
}

// When full of key-down events, a key-up still enters by dropping a down.
RFB_TEST(farsee_cmds, farsee_cmds_full_downs__key_up_accepted)
{
    farsee_cmd_queue q;
    RFB_CHECK(farsee_cmd_queue_init(&q));
    for (unsigned i = 0; i < FARSEE_CMD_QUEUE_CAP; i++) {
        farsee_cmd k;
        memset(&k, 0, sizeof(k));
        k.kind = FARSEE_CMD_KEY;
        k.key.logical = 0x200u + i;
        k.key.action = FARSEE_KEY_PRESS;
        RFB_CHECK(farsee_cmd_queue_push(&q, &k));
    }
    farsee_cmd up;
    memset(&up, 0, sizeof(up));
    up.kind = FARSEE_CMD_KEY;
    up.key.logical = 0xBEEF;
    up.key.action = FARSEE_KEY_RELEASE;
    RFB_CHECK(farsee_cmd_queue_push(&q, &up));
    RFB_CHECK_EQ_UINT(q.count, FARSEE_CMD_QUEUE_CAP);
    // Tail is the release we just pushed.
    farsee_cmd last = q.q[(q.head + q.count - 1u) % FARSEE_CMD_QUEUE_CAP];
    RFB_CHECK(last.kind == FARSEE_CMD_KEY);
    RFB_CHECK(last.key.action == FARSEE_KEY_RELEASE);
    RFB_CHECK_EQ_UINT(last.key.logical, 0xBEEFu);
    farsee_cmd_queue_destroy(&q);
}

// A pure-move flood still drops the oldest moves (latest wins).
RFB_TEST(farsee_cmds, farsee_cmds_move_flood__drops_moves_only)
{
    farsee_cmd_queue q;
    RFB_CHECK(farsee_cmd_queue_init(&q));
    for (unsigned i = 0; i < FARSEE_CMD_QUEUE_CAP; i++) {
        farsee_cmd m;
        memset(&m, 0, sizeof(m));
        m.kind = FARSEE_CMD_POINTER;
        m.pe.abs_x = (int32_t)i;
        RFB_CHECK(farsee_cmd_queue_push(&q, &m));
    }
    const uint64_t before = q.dropped_moves;
    farsee_cmd m;
    memset(&m, 0, sizeof(m));
    m.kind = FARSEE_CMD_POINTER;
    m.pe.abs_x = 9999;
    RFB_CHECK(farsee_cmd_queue_push(&q, &m));
    RFB_CHECK(q.dropped_moves > before);
    RFB_CHECK_EQ_UINT(q.dropped_keys, 0u);

    bool saw_latest = false;
    farsee_cmd out;
    while (farsee_cmd_queue_pop(&q, &out, farsee_thread_monotonic_ms(), NULL)) {
        if (out.kind == FARSEE_CMD_POINTER && out.pe.abs_x == 9999) {
            saw_latest = true;
        }
    }
    RFB_CHECK(saw_latest);
    farsee_cmd_queue_destroy(&q);
}

// A pointer falling edge is accepted when the queue is full of key-downs.
RFB_TEST(farsee_cmds, farsee_cmds_full_downs__pointer_release_accepted)
{
    farsee_cmd_queue q;
    RFB_CHECK(farsee_cmd_queue_init(&q));
    for (unsigned i = 0; i < FARSEE_CMD_QUEUE_CAP; i++) {
        farsee_cmd k;
        memset(&k, 0, sizeof(k));
        k.kind = FARSEE_CMD_KEY;
        k.key.logical = 0x100u + i;
        k.key.action = FARSEE_KEY_PRESS;
        RFB_CHECK(farsee_cmd_queue_push(&q, &k));
    }
    farsee_cmd up;
    memset(&up, 0, sizeof(up));
    up.kind = FARSEE_CMD_POINTER;
    up.pe.buttons = 0u;
    up.prev_buttons = 1u; // falling edge
    up.pe.abs_x = 10;
    up.pe.abs_y = 20;
    RFB_CHECK(farsee_cmd_queue_push(&q, &up));
    RFB_CHECK_EQ_UINT(q.count, FARSEE_CMD_QUEUE_CAP);
    farsee_cmd last = q.q[(q.head + q.count - 1u) % FARSEE_CMD_QUEUE_CAP];
    RFB_CHECK(last.kind == FARSEE_CMD_POINTER);
    RFB_CHECK_EQ_UINT(last.pe.buttons, 0u);
    RFB_CHECK_EQ_UINT(last.prev_buttons, 1u);
    farsee_cmd_queue_destroy(&q);
}

// A button-held drag flood must still accept the release.
RFB_TEST(farsee_cmds, farsee_cmds_button_held_flood__pointer_release_accepted)
{
    farsee_cmd_queue q;
    RFB_CHECK(farsee_cmd_queue_init(&q));
    for (unsigned i = 0; i < FARSEE_CMD_QUEUE_CAP; i++) {
        farsee_cmd m;
        memset(&m, 0, sizeof(m));
        m.kind = FARSEE_CMD_POINTER;
        m.pe.abs_x = (int32_t)i;
        m.pe.abs_y = 1;
        m.pe.buttons = 1u; // left held
        m.prev_buttons = 1u; // not an edge
        RFB_CHECK(farsee_cmd_queue_push(&q, &m));
    }
    farsee_cmd up;
    memset(&up, 0, sizeof(up));
    up.kind = FARSEE_CMD_POINTER;
    up.pe.buttons = 0u;
    up.prev_buttons = 1u; // falling edge
    up.pe.abs_x = 99;
    up.pe.abs_y = 99;
    RFB_CHECK(farsee_cmd_queue_push(&q, &up));
    farsee_cmd last = q.q[(q.head + q.count - 1u) % FARSEE_CMD_QUEUE_CAP];
    RFB_CHECK(last.kind == FARSEE_CMD_POINTER);
    RFB_CHECK_EQ_UINT(last.pe.buttons, 0u);
    RFB_CHECK_EQ_UINT(last.prev_buttons, 1u);
    farsee_cmd_queue_destroy(&q);
}

// A key-up prefers the matching logical key when reclaiming space.
RFB_TEST(farsee_cmds, farsee_cmds_full_downs__key_up_prefers_same_logical)
{
    farsee_cmd_queue q;
    RFB_CHECK(farsee_cmd_queue_init(&q));
    for (unsigned i = 0; i < FARSEE_CMD_QUEUE_CAP; i++) {
        farsee_cmd k;
        memset(&k, 0, sizeof(k));
        k.kind = FARSEE_CMD_KEY;
        k.key.logical = (i == 0u) ? 0xABCDu : (0x200u + i);
        k.key.action = FARSEE_KEY_PRESS;
        RFB_CHECK(farsee_cmd_queue_push(&q, &k));
    }
    farsee_cmd up;
    memset(&up, 0, sizeof(up));
    up.kind = FARSEE_CMD_KEY;
    up.key.logical = 0xABCDu;
    up.key.action = FARSEE_KEY_RELEASE;
    RFB_CHECK(farsee_cmd_queue_push(&q, &up));
    // Matching press should be gone; release at tail.
    farsee_cmd last = q.q[(q.head + q.count - 1u) % FARSEE_CMD_QUEUE_CAP];
    RFB_CHECK(last.kind == FARSEE_CMD_KEY);
    RFB_CHECK(last.key.action == FARSEE_KEY_RELEASE);
    RFB_CHECK_EQ_UINT(last.key.logical, 0xABCDu);
    // Oldest non-matching press should still exist if head was not the match.
    // When prefer match is index 0, head advances — remaining should not include press 0xABCD.
    for (size_t i = 0; i < q.count; i++) {
        farsee_cmd c = q.q[(q.head + i) % FARSEE_CMD_QUEUE_CAP];
        if (c.kind == FARSEE_CMD_KEY && c.key.action == FARSEE_KEY_PRESS) {
            RFB_CHECK(c.key.logical != 0xABCDu);
        }
    }
    farsee_cmd_queue_destroy(&q);
}

RFB_TEST(farsee_cmds, public_guards__reject_null_and_stop_only_empty_wait)
{
    farsee_cmd cmd = queue_key(0x61u, FARSEE_KEY_PRESS);
    farsee_cmd out;
    memset(&out, 0, sizeof out);

    RFB_CHECK(!farsee_cmd_queue_init(NULL));
    farsee_cmd_queue_destroy(NULL);
    farsee_cmd_queue_kick(NULL);
    RFB_CHECK(!farsee_cmd_queue_push(NULL, &cmd));
    RFB_CHECK(!farsee_cmd_queue_pop(NULL, &out, 0u, NULL));

    farsee_cmd_queue q;
    RFB_CHECK(farsee_cmd_queue_init(&q));
    farsee_cmd_queue_kick(&q);
    RFB_CHECK_EQ_UINT(q.count, 0u);
    RFB_CHECK(!farsee_cmd_queue_push(&q, NULL));
    RFB_CHECK(!farsee_cmd_queue_pop(&q, NULL, 0u, NULL));

    farsee_atomic_int stop = 0;
    farsee_atomic_int_store(&stop, 1);
    RFB_CHECK(!farsee_cmd_queue_pop(
        &q, &out, farsee_thread_monotonic_ms() + 1000u, &stop));
    RFB_CHECK(farsee_cmd_queue_push(&q, &cmd));
    RFB_CHECK(farsee_cmd_queue_pop(&q, &out, 0u, &stop));
    RFB_CHECK_EQ_UINT(out.key.logical, 0x61u);
    RFB_CHECK_EQ_UINT(q.count, 0u);

    farsee_cmd_queue_destroy(&q);
    RFB_CHECK(q.mu == NULL);
    RFB_CHECK(q.cv == NULL);
    RFB_CHECK_EQ_UINT(q.count, 0u);
}

RFB_TEST(farsee_cmds,
         protected_pointer_mix__classifies_and_refuses_without_reclaim)
{
    farsee_cmd_queue q;
    RFB_CHECK(farsee_cmd_queue_init(&q));

    for (size_t i = 0u; i < FARSEE_CMD_QUEUE_CAP; i++) {
        farsee_cmd sample;
        switch (i % 5u) {
        case 0u:
            sample = queue_pointer(0u, 0u, 1, 0, (int32_t)i);
            break;
        case 1u:
            sample = queue_pointer(0u, 0u, 0, -1, (int32_t)i);
            break;
        case 2u:
            sample = queue_pointer(FARSEE_BUTTON_LEFT, 0u, 0, 0,
                                   (int32_t)i);
            break;
        case 3u:
            sample = queue_pointer(0u, FARSEE_BUTTON_LEFT, 0, 0,
                                   (int32_t)i);
            break;
        default:
            sample = queue_pointer(FARSEE_BUTTON_LEFT, FARSEE_BUTTON_RIGHT,
                                   0, 0, (int32_t)i);
            break;
        }
        RFB_CHECK(farsee_cmd_queue_push(&q, &sample));
    }

    farsee_cmd plain = queue_pointer(FARSEE_BUTTON_RIGHT, 0u, 0, 0, 999);
    RFB_CHECK(!farsee_cmd_queue_push(&q, &plain));
    RFB_CHECK_EQ_UINT(q.dropped_moves, 0u);
    RFB_CHECK_EQ_UINT(q.dropped_keys, 0u);

    farsee_cmd press = queue_key(0x70u, FARSEE_KEY_PRESS);
    RFB_CHECK(!farsee_cmd_queue_push(&q, &press));
    RFB_CHECK_EQ_UINT(q.dropped_keys, 1u);

    farsee_cmd release = queue_key(0x70u, FARSEE_KEY_RELEASE);
    RFB_CHECK(!farsee_cmd_queue_push(&q, &release));
    RFB_CHECK_EQ_UINT(q.dropped_keys, 2u);

    farsee_cmd all = queue_release_all();
    RFB_CHECK(!farsee_cmd_queue_push(&q, &all));
    RFB_CHECK_EQ_UINT(q.dropped_keys, 3u);

    farsee_cmd pointer_release =
        queue_pointer(0u, FARSEE_BUTTON_LEFT, 0, 0, 1000);
    RFB_CHECK(!farsee_cmd_queue_push(&q, &pointer_release));
    RFB_CHECK_EQ_UINT(q.dropped_keys, 4u);
    RFB_CHECK_EQ_UINT(q.dropped_moves, 0u);
    RFB_CHECK_EQ_UINT(q.count, FARSEE_CMD_QUEUE_CAP);
    RFB_CHECK_EQ_UINT(q.head, 0u);

    farsee_cmd_queue_destroy(&q);
}

RFB_TEST(farsee_cmds,
         release_all__reclaims_held_move_then_oldest_key_fallback)
{
    farsee_cmd held = queue_pointer(FARSEE_BUTTON_LEFT, FARSEE_BUTTON_LEFT,
                                    0, 0, 5);
    farsee_cmd all = queue_release_all();

    farsee_cmd_queue held_q;
    RFB_CHECK(farsee_cmd_queue_init(&held_q));
    RFB_CHECK(queue_fill_repeated(&held_q, &held));
    RFB_CHECK(farsee_cmd_queue_push(&held_q, &all));
    RFB_CHECK_EQ_UINT(held_q.dropped_moves, 1u);
    RFB_CHECK_EQ_UINT(held_q.dropped_keys, 0u);
    RFB_CHECK_EQ_INT(
        held_q.q[(held_q.head + held_q.count - 1u) % FARSEE_CMD_QUEUE_CAP].kind,
        FARSEE_CMD_RELEASE_ALL);
    farsee_cmd_queue_destroy(&held_q);

    farsee_cmd_queue key_q;
    RFB_CHECK(farsee_cmd_queue_init(&key_q));
    for (size_t i = 0u; i < FARSEE_CMD_QUEUE_CAP; i++) {
        farsee_cmd key = queue_key(0x1000u + (uint32_t)i,
                                   FARSEE_KEY_PRESS);
        RFB_CHECK(farsee_cmd_queue_push(&key_q, &key));
    }
    RFB_CHECK(farsee_cmd_queue_push(&key_q, &all));
    RFB_CHECK_EQ_UINT(key_q.head, 1u);
    RFB_CHECK_EQ_UINT(key_q.dropped_moves, 0u);
    RFB_CHECK_EQ_UINT(key_q.dropped_keys, 1u);
    RFB_CHECK_EQ_INT(
        key_q.q[(key_q.head + key_q.count - 1u) % FARSEE_CMD_QUEUE_CAP].kind,
        FARSEE_CMD_RELEASE_ALL);
    farsee_cmd_queue_destroy(&key_q);
}

RFB_TEST(farsee_cmds, wrapped_head_interior_move__drops_without_reordering)
{
    farsee_cmd_queue q;
    RFB_CHECK(farsee_cmd_queue_init(&q));
    for (size_t i = 0u; i < FARSEE_CMD_QUEUE_CAP; i++) {
        farsee_cmd key = queue_key(0x2000u + (uint32_t)i,
                                   FARSEE_KEY_PRESS);
        RFB_CHECK(farsee_cmd_queue_push(&q, &key));
    }

    farsee_cmd out;
    for (size_t i = 0u; i < FARSEE_CMD_QUEUE_CAP - 6u; i++) {
        RFB_CHECK(farsee_cmd_queue_pop(&q, &out, 0u, NULL));
    }
    RFB_CHECK_EQ_UINT(q.head, FARSEE_CMD_QUEUE_CAP - 6u);
    RFB_CHECK_EQ_UINT(q.count, 6u);

    for (size_t i = 0u; i < FARSEE_CMD_QUEUE_CAP - 6u; i++) {
        farsee_cmd cmd = (i == 5u)
            ? queue_pointer(0u, 0u, 0, 0, 777)
            : queue_key(0x3000u + (uint32_t)i, FARSEE_KEY_PRESS);
        RFB_CHECK(farsee_cmd_queue_push(&q, &cmd));
    }
    RFB_CHECK_EQ_UINT(q.count, FARSEE_CMD_QUEUE_CAP);

    const size_t head_before = q.head;
    farsee_cmd extra = queue_key(0xFFFFu, FARSEE_KEY_PRESS);
    RFB_CHECK(farsee_cmd_queue_push(&q, &extra));
    RFB_CHECK_EQ_UINT(q.head, head_before);
    RFB_CHECK_EQ_UINT(q.count, FARSEE_CMD_QUEUE_CAP);
    RFB_CHECK_EQ_UINT(q.dropped_moves, 1u);
    for (size_t i = 0u; i < q.count; i++) {
        const farsee_cmd *cmd =
            &q.q[(q.head + i) % FARSEE_CMD_QUEUE_CAP];
        RFB_CHECK(cmd->kind == FARSEE_CMD_KEY);
    }
    const farsee_cmd *last =
        &q.q[(q.head + q.count - 1u) % FARSEE_CMD_QUEUE_CAP];
    RFB_CHECK_EQ_UINT(last->key.logical, 0xFFFFu);

    farsee_cmd_queue_destroy(&q);
}

RFB_TEST(farsee_cmds,
         key_release_reclaim__prefers_interior_match_or_oldest_fallback)
{
    farsee_cmd_queue matching;
    RFB_CHECK(farsee_cmd_queue_init(&matching));
    for (size_t i = 0u; i < FARSEE_CMD_QUEUE_CAP; i++) {
        const uint32_t logical = (i == 37u) ? 0xAA55u
                                            : 0x4000u + (uint32_t)i;
        farsee_cmd key = queue_key(logical, FARSEE_KEY_PRESS);
        RFB_CHECK(farsee_cmd_queue_push(&matching, &key));
    }
    farsee_cmd matching_release = queue_key(0xAA55u, FARSEE_KEY_RELEASE);
    RFB_CHECK(farsee_cmd_queue_push(&matching, &matching_release));
    RFB_CHECK_EQ_UINT(matching.head, 0u);
    RFB_CHECK_EQ_UINT(matching.dropped_keys, 1u);
    for (size_t i = 0u; i + 1u < matching.count; i++) {
        const farsee_cmd *cmd =
            &matching.q[(matching.head + i) % FARSEE_CMD_QUEUE_CAP];
        RFB_CHECK(cmd->key.logical != 0xAA55u);
    }
    const farsee_cmd *matching_last =
        &matching.q[(matching.head + matching.count - 1u) %
                    FARSEE_CMD_QUEUE_CAP];
    RFB_CHECK_EQ_UINT(matching_last->key.logical, 0xAA55u);
    RFB_CHECK_EQ_INT(matching_last->key.action, FARSEE_KEY_RELEASE);
    farsee_cmd_queue_destroy(&matching);

    farsee_cmd_queue fallback;
    RFB_CHECK(farsee_cmd_queue_init(&fallback));
    for (size_t i = 0u; i < FARSEE_CMD_QUEUE_CAP; i++) {
        farsee_cmd key = queue_key(0x5000u + (uint32_t)i,
                                   FARSEE_KEY_PRESS);
        RFB_CHECK(farsee_cmd_queue_push(&fallback, &key));
    }
    farsee_cmd unmatched = queue_key(0xDEADu, FARSEE_KEY_RELEASE);
    RFB_CHECK(farsee_cmd_queue_push(&fallback, &unmatched));
    RFB_CHECK_EQ_UINT(fallback.head, 1u);
    RFB_CHECK_EQ_UINT(fallback.dropped_keys, 1u);
    const farsee_cmd *fallback_first = &fallback.q[fallback.head];
    RFB_CHECK_EQ_UINT(fallback_first->key.logical, 0x5001u);
    const farsee_cmd *fallback_last =
        &fallback.q[(fallback.head + fallback.count - 1u) %
                    FARSEE_CMD_QUEUE_CAP];
    RFB_CHECK_EQ_UINT(fallback_last->key.logical, 0xDEADu);
    RFB_CHECK_EQ_INT(fallback_last->key.action, FARSEE_KEY_RELEASE);
    farsee_cmd_queue_destroy(&fallback);
}
