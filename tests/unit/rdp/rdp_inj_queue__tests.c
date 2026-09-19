// SPDX-License-Identifier: Apache-2.0
//
// Inject queue tests (input → protocol thread).

#include "protocol/rdp/rdp_inj_queue.h"
#include "tests/test_framework/rfb_test.h"

#include <string.h>

RFB_TEST(rdp_inj, queue_init_destroy__ok)
{
    rdp_inj_queue q;
    RFB_CHECK(rdp_inj_queue_init(&q));
    rdp_inj_cmd c;
    RFB_CHECK(!rdp_inj_queue_pop(&q, &c, farsee_thread_monotonic_ms(), NULL));
    rdp_inj_queue_destroy(&q);
}

RFB_TEST(rdp_inj, queue_push_pop__fifo)
{
    rdp_inj_queue q;
    RFB_CHECK(rdp_inj_queue_init(&q));
    rdp_inj_cmd a;
    memset(&a, 0, sizeof(a));
    a.kind = RDP_INJ_KEY;
    a.keysym = 0x61u;
    a.down = true;
    RFB_CHECK(rdp_inj_queue_push(&q, &a));
    rdp_inj_cmd b;
    memset(&b, 0, sizeof(b));
    b.kind = RDP_INJ_POINTER;
    b.pe.abs_x = 10;
    b.pe.abs_y = 20;
    RFB_CHECK(rdp_inj_queue_push(&q, &b));

    rdp_inj_cmd out;
    const uint64_t dl = farsee_thread_monotonic_ms() + 1000u;
    RFB_CHECK(rdp_inj_queue_pop(&q, &out, dl, NULL));
    RFB_CHECK(out.kind == RDP_INJ_KEY);
    RFB_CHECK_EQ_UINT(out.keysym, 0x61u);
    RFB_CHECK(rdp_inj_queue_pop(&q, &out, dl, NULL));
    RFB_CHECK(out.kind == RDP_INJ_POINTER);
    RFB_CHECK_EQ_INT(out.pe.abs_x, 10);
    rdp_inj_queue_destroy(&q);
}

RFB_TEST(rdp_inj, queue_full__drops_moves_keeps_keys)
{
    rdp_inj_queue q;
    RFB_CHECK(rdp_inj_queue_init(&q));
    // Fill with pure moves.
    for (unsigned i = 0; i < RDP_INJ_QUEUE_CAP; i++) {
        rdp_inj_cmd m;
        memset(&m, 0, sizeof(m));
        m.kind = RDP_INJ_POINTER;
        m.pe.abs_x = (int32_t)i;
        RFB_CHECK(rdp_inj_queue_push(&q, &m));
    }
    // Key must still land (evicts a move).
    rdp_inj_cmd k;
    memset(&k, 0, sizeof(k));
    k.kind = RDP_INJ_KEY;
    k.keysym = 0x42u;
    k.down = true;
    RFB_CHECK(rdp_inj_queue_push(&q, &k));
    RFB_CHECK(q.dropped_moves >= 1);

    bool found_key = false;
    rdp_inj_cmd out;
    const uint64_t dl = farsee_thread_monotonic_ms() + 1000u;
    while (rdp_inj_queue_pop(&q, &out, farsee_thread_monotonic_ms(), NULL)) {
        if (out.kind == RDP_INJ_KEY && out.keysym == 0x42u) {
            found_key = true;
        }
        (void)dl;
    }
    RFB_CHECK(found_key);
    rdp_inj_queue_destroy(&q);
}
