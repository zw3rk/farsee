// SPDX-License-Identifier: Apache-2.0
//
// Damage-accumulator tests.

#include "rfb_test.h"
#include "farsee/damage.h"

// --- basic add + produce ------------------------------------------------

RFB_TEST(damage, damage__add_one_rect__produced_exact) {
    rfb_damage_accumulator da;
    rfb_damage_init(&da, 100, 100, 1);
    rfb_rect r = { 10, 20, 5, 5 };
    rfb_damage_add(&da, &r);
    RFB_CHECK(rfb_damage_has_pending(&da));
    rfb_damage_batch b = rfb_damage_produce(&da);
    RFB_CHECK_EQ_UINT(b.count, 1u);
    RFB_CHECK(!b.full_frame);
    RFB_CHECK_EQ_UINT(b.rects[0].x, 10u);
    RFB_CHECK_EQ_UINT(b.rects[0].width, 5u);
    // After produce, accumulator is reset.
    RFB_CHECK(!rfb_damage_has_pending(&da));
}

// --- add multiple rects -------------------------------------------------

RFB_TEST(damage, damage__add_three_rects__count_is_three) {
    rfb_damage_accumulator da;
    rfb_damage_init(&da, 100, 100, 1);
    rfb_rect r1 = { 0, 0, 10, 10 };
    rfb_rect r2 = { 20, 20, 5, 5 };
    rfb_rect r3 = { 50, 50, 1, 1 };
    rfb_damage_add(&da, &r1);
    rfb_damage_add(&da, &r2);
    rfb_damage_add(&da, &r3);
    rfb_damage_batch b = rfb_damage_produce(&da);
    RFB_CHECK_EQ_UINT(b.count, 3u);
}

// --- cap converts to full-frame damage ----------------------------------

RFB_TEST(damage, damage__exceeds_cap__converts_to_full_frame) {
    rfb_damage_accumulator da;
    rfb_damage_init(&da, 100, 100, 1);
    da.max_rects = 4;  // small cap for testing
    for (int i = 0; i < 5; i++) {
        rfb_rect r = { (uint32_t)i, 0, 1, 1 };
        rfb_damage_add(&da, &r);
    }
    rfb_damage_batch b = rfb_damage_produce(&da);
    RFB_CHECK(b.full_frame);
    RFB_CHECK_EQ_UINT(b.count, 0u);
}

// --- add_full ------------------------------------------------------------

RFB_TEST(damage, damage__add_full__produces_full_frame) {
    rfb_damage_accumulator da;
    rfb_damage_init(&da, 100, 100, 1);
    rfb_damage_add_full(&da);
    rfb_damage_batch b = rfb_damage_produce(&da);
    RFB_CHECK(b.full_frame);
}

// --- resize clears pending damage ---------------------------------------

RFB_TEST(damage, damage__resize__clears_pending) {
    rfb_damage_accumulator da;
    rfb_damage_init(&da, 100, 100, 1);
    rfb_rect r = { 0, 0, 10, 10 };
    rfb_damage_add(&da, &r);
    RFB_CHECK(rfb_damage_has_pending(&da));
    rfb_damage_resize(&da, 200, 200, 2);
    RFB_CHECK(!rfb_damage_has_pending(&da));
    RFB_CHECK_EQ_UINT(da.fb_width, 200u);
    RFB_CHECK_EQ_UINT(da.framebuffer_generation, 2u);
}

// --- produce resets full_frame flag -------------------------------------

RFB_TEST(damage, damage__produce_after_full__resets) {
    rfb_damage_accumulator da;
    rfb_damage_init(&da, 100, 100, 1);
    rfb_damage_add_full(&da);
    rfb_damage_batch b1 = rfb_damage_produce(&da);
    RFB_CHECK(b1.full_frame);
    // Second produce without new damage → empty.
    rfb_damage_batch b2 = rfb_damage_produce(&da);
    RFB_CHECK(!b2.full_frame);
    RFB_CHECK_EQ_UINT(b2.count, 0u);
}

// --- generation in produced batch ---------------------------------------

RFB_TEST(damage, damage__generation_in_batch) {
    rfb_damage_accumulator da;
    rfb_damage_init(&da, 100, 100, 42);
    rfb_rect r = { 0, 0, 1, 1 };
    rfb_damage_add(&da, &r);
    rfb_damage_batch b = rfb_damage_produce(&da);
    RFB_CHECK_EQ_UINT(b.framebuffer_generation, 42u);
}
