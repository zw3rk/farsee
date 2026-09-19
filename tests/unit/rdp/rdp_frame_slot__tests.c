// SPDX-License-Identifier: Apache-2.0
//
// Latest-wins triple buffer tests.

#include "protocol/rdp/rdp_frame_slot.h"
#include "farsee/memory_budget.h"
#include "tests/test_framework/rfb_test.h"

#include <string.h>

RFB_TEST(rdp_slot, init_destroy__ok)
{
    rdp_frame_slot s;
    RFB_CHECK(rdp_frame_slot_init(&s));
    rdp_frame_view v;
    RFB_CHECK(!rdp_frame_slot_acquire(&s, &v));
    rdp_frame_slot_destroy(&s);
}

RFB_TEST(rdp_slot, budget_allocator_rejects_and_releases_frame_storage)
{
    farsee_memory_budget too_small;
    RFB_CHECK(farsee_memory_budget_init(&too_small, rfb_default_allocator(),
                                        3u));
    rdp_frame_slot slot;
    RFB_CHECK(rdp_frame_slot_init_with_allocator(
        &slot, farsee_memory_budget_allocator(&too_small)));
    uint8_t px[4] = {0u};
    RFB_CHECK_EQ_INT(rdp_frame_slot_publish_ex(&slot, px, 1u, 1u, 4u),
                     FARSEE_FRAME_PUBLISH_OUT_OF_MEMORY);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&too_small), 0u);
    rdp_frame_slot_destroy(&slot);

    farsee_memory_budget exact;
    RFB_CHECK(farsee_memory_budget_init(&exact, rfb_default_allocator(), 4u));
    RFB_CHECK(rdp_frame_slot_init_with_allocator(
        &slot, farsee_memory_budget_allocator(&exact)));
    RFB_CHECK_EQ_INT(rdp_frame_slot_publish_ex(&slot, px, 1u, 1u, 4u),
                     FARSEE_FRAME_PUBLISH_OK);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&exact), 4u);
    rdp_frame_slot_destroy(&slot);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&exact), 0u);
}

RFB_TEST(rdp_slot, publish_acquire__round_trip)
{
    rdp_frame_slot s;
    RFB_CHECK(rdp_frame_slot_init(&s));
    uint8_t px[8] = {1, 2, 3, 4, 5, 6, 7, 8};  // 2x1 BGRA
    RFB_CHECK(rdp_frame_slot_publish(&s, px, 2, 1, 8));
    rdp_frame_view v;
    RFB_CHECK(rdp_frame_slot_acquire(&s, &v));
    RFB_CHECK_EQ_UINT(v.w, 2u);
    RFB_CHECK_EQ_UINT(v.h, 1u);
    RFB_CHECK(v.pixels[0] == 1 && v.pixels[7] == 8);
    RFB_CHECK(v.gen == 1);
    rdp_frame_slot_release(&s, &v);
    rdp_frame_slot_destroy(&s);
}

RFB_TEST(rdp_slot, publish_ex__invalid_frame_is_reported)
{
    rdp_frame_slot s;
    RFB_CHECK(rdp_frame_slot_init(&s));
    uint8_t px[4] = { 1u, 2u, 3u, 4u };
    RFB_CHECK(rdp_frame_slot_publish_ex(&s, px, 1u, 1u, 2u) ==
              FARSEE_FRAME_PUBLISH_INVALID);
    rdp_frame_slot_destroy(&s);
}

RFB_TEST(rdp_slot, publish_twice__latest_wins)
{
    rdp_frame_slot s;
    RFB_CHECK(rdp_frame_slot_init(&s));
    uint8_t a[4] = {0xAA, 0, 0, 0xFF};
    uint8_t b[4] = {0xBB, 0, 0, 0xFF};
    RFB_CHECK(rdp_frame_slot_publish(&s, a, 1, 1, 4));
    RFB_CHECK(rdp_frame_slot_publish(&s, b, 1, 1, 4));
    rdp_frame_view v;
    RFB_CHECK(rdp_frame_slot_acquire(&s, &v));
    RFB_CHECK(v.pixels[0] == 0xBB);
    RFB_CHECK(v.gen == 2);
    // Intermediate was never acquired → counted as dropped.
    RFB_CHECK(s.dropped >= 1);
    rdp_frame_slot_release(&s, &v);
    rdp_frame_slot_destroy(&s);
}

RFB_TEST(rdp_slot, acquire_while_held__still_latest)
{
    rdp_frame_slot s;
    RFB_CHECK(rdp_frame_slot_init(&s));
    uint8_t a[4] = {1, 0, 0, 0xFF};
    uint8_t b[4] = {2, 0, 0, 0xFF};
    RFB_CHECK(rdp_frame_slot_publish(&s, a, 1, 1, 4));
    rdp_frame_view v1;
    RFB_CHECK(rdp_frame_slot_acquire(&s, &v1));
    RFB_CHECK(v1.pixels[0] == 1);
    // Publish while present holds v1 — must use another slot.
    RFB_CHECK(rdp_frame_slot_publish(&s, b, 1, 1, 4));
    rdp_frame_view v2;
    RFB_CHECK(rdp_frame_slot_acquire(&s, &v2));
    RFB_CHECK(v2.pixels[0] == 2);
    RFB_CHECK(v2.gen > v1.gen);
    rdp_frame_slot_release(&s, &v1);
    rdp_frame_slot_release(&s, &v2);
    rdp_frame_slot_destroy(&s);
}
