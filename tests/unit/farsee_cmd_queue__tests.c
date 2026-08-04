// SPDX-License-Identifier: Apache-2.0
//
// Shared input-command queue tests (input → protocol thread).

#include "farsee/farsee_cmd_queue.h"
#include "farsee/farsee_input.h"
#include "farsee/farsee_thread.h"
#include "tests/test_framework/rfb_test.h"

#include <string.h>

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

// T10: flood of keys with no pure moves must not silently drop a head key.
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

// Residual T11: when full of downs, a key-up still gets in by dropping a down.
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

// T10: pure-move flood still drops oldest moves (latest-wins).
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

// full2 T2: pointer falling edge accepted under full key downs.
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

// multi-review 2026-07-31 T6: button-held drag flood still accepts release.
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

// full2 T11: key-up prefers matching logical when reclaiming.
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
