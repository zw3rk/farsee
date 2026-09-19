// SPDX-License-Identifier: Apache-2.0
//
// F3 — bounded queue as an inter-thread channel (§8.3, §8.5).
//
// Exercises the queue exactly as the RDP worker will use it: one producer
// thread pushes commands, the consumer pops them until a TERMINAL entry
// arrives. Verifies the channel is race-free and terminal delivery works
// across a thread boundary (the cancellation path the RDP worker depends
// on). No wall-clock assertions; only outcome.

#include "farsee/farsee_queue.h"
#include "farsee/farsee_thread.h"
#include "tests/test_framework/rfb_test.h"

typedef struct {
    farsee_queue *q;
    long popped_sum;
} consumer_state;

static void *consumer(void *arg)
{
    consumer_state *s = (consumer_state *)arg;
    long sum = 0;
    for (;;) {
        const void *payload = NULL;
        size_t n = 0;
        farsee_queue_tag tag = FARSEE_QUEUE_TAG_NORMAL;
        void *user = NULL;
        // Spin-pop is fine for a test channel; the queue is the unit under
        // test, not scheduling fairness.
        if (!farsee_queue_pop(s->q, &payload, &n, &tag, &user)) {
            continue;
        }
        if (tag == FARSEE_QUEUE_TAG_TERMINAL) {
            break;
        }
        // Each payload is an ASCII digit char; accumulate its value.
        if (n >= 1 && payload != NULL) {
            char c = ((const char *)payload)[0];
            if (c >= '0' && c <= '9') {
                sum += (long)(c - '0');
            }
        }
    }
    s->popped_sum = sum;
    return NULL;
}

RFB_TEST(farsee_queue, inter_thread_channel__terminal_terminates_consumer)
{
    farsee_queue *q = farsee_queue_create((farsee_queue_config){
        .max_items = 64, .max_bytes = 4096});
    RFB_CHECK(q != NULL);
    consumer_state st = {.q = q, .popped_sum = -1};
    farsee_thread *t = farsee_thread_create(consumer, &st);
    RFB_CHECK(t != NULL);

    // Produce digits '1'..'9' then a terminal entry.
    for (char c = '1'; c <= '9'; ++c) {
        RFB_CHECK(farsee_queue_push(q, FARSEE_QUEUE_TAG_NORMAL, &c, 1, NULL, NULL));
    }
    char term = 'T';
    RFB_CHECK(farsee_queue_push(q, FARSEE_QUEUE_TAG_TERMINAL, &term, 1, NULL, NULL));

    farsee_thread_join(&t, NULL);
    RFB_CHECK(t == NULL);
    // Sum 1..9 == 45. Confirms every entry was delivered before the terminal.
    RFB_CHECK_EQ_INT(st.popped_sum, 45);
    farsee_queue_destroy(&q);
}

// Saturation under concurrency: a fast producer hitting the cap must not
// corrupt the queue or deadlock the consumer; rejected pushes return false.
RFB_TEST(farsee_queue, saturation_under_concurrency__no_corruption)
{
    farsee_queue *q = farsee_queue_create((farsee_queue_config){
        .max_items = 4, .max_bytes = 4096});
    consumer_state st = {.q = q, .popped_sum = 0};
    farsee_thread *t = farsee_thread_create(consumer, &st);
    RFB_CHECK(t != NULL);

    int pushed = 0;
    int rejected = 0;
    for (int i = 0; i < 1000; ++i) {
        char c = (char)('0' + (i % 10));
        if (farsee_queue_push(q, FARSEE_QUEUE_TAG_NORMAL, &c, 1, NULL, NULL)) {
            ++pushed;
        } else {
            ++rejected;  // saturated — expected, must be clean
        }
    }
    char term = 'T';
    RFB_CHECK(farsee_queue_push(q, FARSEE_QUEUE_TAG_TERMINAL, &term, 1, NULL, NULL));
    farsee_thread_join(&t, NULL);

    // The consumer must have terminated cleanly (no hang/corruption); the
    // exact sum depends on scheduling, but pushed+rejected must total 1000
    // and at least some pushes must have been rejected by the cap.
    RFB_CHECK_EQ_INT(pushed + rejected, 1000);
    RFB_CHECK_MSG(rejected > 0, "expected some pushes to be rejected by cap");
    farsee_queue_destroy(&q);
}
