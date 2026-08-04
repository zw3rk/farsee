// SPDX-License-Identifier: Apache-2.0
//
// F3 — bounded queue contract tests (§8.5).
//
// Verifies the bounded FIFO: count/byte caps, terminal-bypass-under-
// saturation, priority ordering, high-water metrics, and destructor
// invocation on both pop and queue-destroy (no leak on any path).

#include "farsee/farsee_queue.h"
#include "tests/test_framework/rfb_test.h"
#include <string.h>

// --- basic push/pop round-trip ---------------------------------------------

RFB_TEST(farsee_queue, push_pop__round_trip)
{
    farsee_queue *q = farsee_queue_create((farsee_queue_config){
        .max_items = 4, .max_bytes = 1024});
    RFB_CHECK(q != NULL);
    RFB_CHECK_EQ_UINT(farsee_queue_count(q), 0u);

    const char *msg = "hello";
    RFB_CHECK(farsee_queue_push(q, FARSEE_QUEUE_TAG_NORMAL, msg, 6, NULL, NULL));
    RFB_CHECK_EQ_UINT(farsee_queue_count(q), 1u);

    const void *out = NULL;
    size_t out_bytes = 0;
    farsee_queue_tag out_tag = FARSEE_QUEUE_TAG_NORMAL;
    void *out_user = NULL;
    RFB_CHECK(farsee_queue_pop(q, &out, &out_bytes, &out_tag, &out_user));
    RFB_CHECK(out != NULL);
    RFB_CHECK_EQ_UINT(out_bytes, 6u);
    RFB_CHECK(out_tag == FARSEE_QUEUE_TAG_NORMAL);
    RFB_CHECK(memcmp(out, "hello", 6) == 0);
    RFB_CHECK_EQ_UINT(farsee_queue_count(q), 0u);

    // Empty queue pop returns false.
    RFB_CHECK(farsee_queue_pop(q, &out, &out_bytes, &out_tag, &out_user) == false);
    farsee_queue_destroy(&q);
    RFB_CHECK(q == NULL);
}

// --- FIFO order -------------------------------------------------------------

RFB_TEST(farsee_queue, fifo_order__preserved)
{
    farsee_queue *q = farsee_queue_create((farsee_queue_config){
        .max_items = 8, .max_bytes = 1024});
    const char *vals[] = {"A", "B", "C"};
    for (int i = 0; i < 3; ++i) {
        RFB_CHECK(farsee_queue_push(q, FARSEE_QUEUE_TAG_NORMAL, vals[i], 2, NULL, NULL));
    }
    const void *out = NULL; size_t n = 0; farsee_queue_tag t; void *u;
    for (int i = 0; i < 3; ++i) {
        RFB_CHECK(farsee_queue_pop(q, &out, &n, &t, &u));
        RFB_CHECK_EQ_INT((char)((const char *)out)[0], 'A' + i);
    }
    farsee_queue_destroy(&q);
}

// --- item cap enforced ------------------------------------------------------

RFB_TEST(farsee_queue, item_cap__enforced)
{
    farsee_queue *q = farsee_queue_create((farsee_queue_config){
        .max_items = 2, .max_bytes = 1024});
    RFB_CHECK(farsee_queue_push(q, FARSEE_QUEUE_TAG_NORMAL, "1", 2, NULL, NULL));
    RFB_CHECK(farsee_queue_push(q, FARSEE_QUEUE_TAG_NORMAL, "2", 2, NULL, NULL));
    // Third normal push rejected by item cap.
    RFB_CHECK(farsee_queue_push(q, FARSEE_QUEUE_TAG_NORMAL, "3", 2, NULL, NULL) == false);
    RFB_CHECK_EQ_UINT(farsee_queue_count(q), 2u);
    farsee_queue_destroy(&q);
}

// --- byte cap enforced ------------------------------------------------------

RFB_TEST(farsee_queue, byte_cap__enforced)
{
    farsee_queue *q = farsee_queue_create((farsee_queue_config){
        .max_items = 16, .max_bytes = 10});
    // Two 6-byte payloads exceed the 10-byte cap on the second push.
    RFB_CHECK(farsee_queue_push(q, FARSEE_QUEUE_TAG_NORMAL, "AAAAAA", 6, NULL, NULL));
    RFB_CHECK(farsee_queue_push(q, FARSEE_QUEUE_TAG_NORMAL, "BBBBBB", 6, NULL, NULL) == false);
    RFB_CHECK_EQ_UINT(farsee_queue_bytes(q), 6u);
    farsee_queue_destroy(&q);
}

// --- TERMINAL bypasses caps and locks the queue ----------------------------

RFB_TEST(farsee_queue, terminal__bypasses_caps_and_locks)
{
    farsee_queue *q = farsee_queue_create((farsee_queue_config){
        .max_items = 1, .max_bytes = 4});
    RFB_CHECK(farsee_queue_push(q, FARSEE_QUEUE_TAG_NORMAL, "X", 2, NULL, NULL));
    // Queue full; a TERMINAL push MUST still succeed (§8.5).
    RFB_CHECK(farsee_queue_push(q, FARSEE_QUEUE_TAG_TERMINAL, "BYE", 4, NULL, NULL));
    RFB_CHECK(farsee_queue_is_terminal(q));
    // After a terminal push, all further pushes are rejected.
    RFB_CHECK(farsee_queue_push(q, FARSEE_QUEUE_TAG_NORMAL, "Y", 2, NULL, NULL) == false);
    RFB_CHECK(farsee_queue_push(q, FARSEE_QUEUE_TAG_TERMINAL, "BYE2", 5, NULL, NULL) == false);
    farsee_queue_destroy(&q);
}

// --- TERMINAL delivered after queued entries (§8.5 ordering) ----------------

RFB_TEST(farsee_queue, terminal__delivered_after_queued)
{
    farsee_queue *q = farsee_queue_create((farsee_queue_config){
        .max_items = 8, .max_bytes = 1024});
    RFB_CHECK(farsee_queue_push(q, FARSEE_QUEUE_TAG_NORMAL, "1", 2, NULL, NULL));
    RFB_CHECK(farsee_queue_push(q, FARSEE_QUEUE_TAG_NORMAL, "2", 2, NULL, NULL));
    RFB_CHECK(farsee_queue_push(q, FARSEE_QUEUE_TAG_TERMINAL, "T", 2, NULL, NULL));
    // Pop order: 1, 2, then T (terminal last so prior work is observed).
    const void *out = NULL; size_t n; farsee_queue_tag t; void *u;
    RFB_CHECK(farsee_queue_pop(q, &out, &n, &t, &u)); RFB_CHECK(t == FARSEE_QUEUE_TAG_NORMAL);
    RFB_CHECK(farsee_queue_pop(q, &out, &n, &t, &u)); RFB_CHECK(t == FARSEE_QUEUE_TAG_NORMAL);
    RFB_CHECK(farsee_queue_pop(q, &out, &n, &t, &u)); RFB_CHECK(t == FARSEE_QUEUE_TAG_TERMINAL);
    RFB_CHECK(farsee_queue_pop(q, &out, &n, &t, &u) == false);
    farsee_queue_destroy(&q);
}

// --- PRIORITY jumps the queue ----------------------------------------------

RFB_TEST(farsee_queue, priority__jumps_normal_entries)
{
    farsee_queue *q = farsee_queue_create((farsee_queue_config){
        .max_items = 8, .max_bytes = 1024});
    RFB_CHECK(farsee_queue_push(q, FARSEE_QUEUE_TAG_NORMAL, "N1", 3, NULL, NULL));
    RFB_CHECK(farsee_queue_push(q, FARSEE_QUEUE_TAG_NORMAL, "N2", 3, NULL, NULL));
    RFB_CHECK(farsee_queue_push(q, FARSEE_QUEUE_TAG_PRIORITY, "P1", 3, NULL, NULL));
    // Priority entries (control commands, §8.5) are admitted ahead of normal.
    const void *out = NULL; size_t n; farsee_queue_tag t; void *u;
    RFB_CHECK(farsee_queue_pop(q, &out, &n, &t, &u)); RFB_CHECK(t == FARSEE_QUEUE_TAG_PRIORITY);
    RFB_CHECK(farsee_queue_pop(q, &out, &n, &t, &u)); RFB_CHECK(t == FARSEE_QUEUE_TAG_NORMAL);
    RFB_CHECK(farsee_queue_pop(q, &out, &n, &t, &u)); RFB_CHECK(t == FARSEE_QUEUE_TAG_NORMAL);
    farsee_queue_destroy(&q);
}

// --- high-water metrics -----------------------------------------------------

RFB_TEST(farsee_queue, high_water__tracked)
{
    farsee_queue *q = farsee_queue_create((farsee_queue_config){
        .max_items = 8, .max_bytes = 1024});
    RFB_CHECK(farsee_queue_push(q, FARSEE_QUEUE_TAG_NORMAL, "1", 2, NULL, NULL));
    RFB_CHECK(farsee_queue_push(q, FARSEE_QUEUE_TAG_NORMAL, "2", 2, NULL, NULL));
    RFB_CHECK(farsee_queue_push(q, FARSEE_QUEUE_TAG_NORMAL, "3", 2, NULL, NULL));
    RFB_CHECK_EQ_UINT(farsee_queue_high_water_items(q), 3u);
    const void *out; size_t n; farsee_queue_tag t; void *u;
    RFB_CHECK(farsee_queue_pop(q, &out, &n, &t, &u));
    // High-water mark does not decrease on pop.
    RFB_CHECK_EQ_UINT(farsee_queue_high_water_items(q), 3u);
    farsee_queue_destroy(&q);
}

// --- destructor invoked on pop and on destroy ------------------------------

static int g_destruct_count;
static void counting_dtor(void *user)
{
    (void)user;
    ++g_destruct_count;
}

RFB_TEST(farsee_queue, destructor__invoked_on_pop_and_destroy)
{
    g_destruct_count = 0;
    farsee_queue *q = farsee_queue_create((farsee_queue_config){
        .max_items = 8, .max_bytes = 1024});
    RFB_CHECK(farsee_queue_push(q, FARSEE_QUEUE_TAG_NORMAL, "a", 2, counting_dtor, (void *)1));
    RFB_CHECK(farsee_queue_push(q, FARSEE_QUEUE_TAG_NORMAL, "b", 2, counting_dtor, (void *)2));
    const void *out; size_t n; farsee_queue_tag t; void *u;
    RFB_CHECK(farsee_queue_pop(q, &out, &n, &t, &u));
    RFB_CHECK_EQ_INT(g_destruct_count, 1);
    // Destroy the queue with one entry still inside: its destructor runs.
    farsee_queue_destroy(&q);
    RFB_CHECK_EQ_INT(g_destruct_count, 2);
}

// --- bad config rejected ----------------------------------------------------

RFB_TEST(farsee_queue, bad_config__create_returns_null)
{
    RFB_CHECK(farsee_queue_create((farsee_queue_config){.max_items = 0, .max_bytes = 8}) == NULL);
    RFB_CHECK(farsee_queue_create((farsee_queue_config){.max_items = 8, .max_bytes = 0}) == NULL);
}
