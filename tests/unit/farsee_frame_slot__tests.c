// SPDX-License-Identifier: Apache-2.0
//
// Shared latest-wins triple buffer tests.

#include "farsee/farsee_display.h"
#include "farsee/farsee_frame_slot.h"
#include "tests/test_framework/rfb_test.h"

#include <stdint.h>
#include <string.h>

RFB_TEST(farsee_slot, farsee_slot_init_destroy__ok)
{
    farsee_frame_slot s;
    RFB_CHECK(farsee_frame_slot_init(&s));
    farsee_frame_view v;
    RFB_CHECK(!farsee_frame_slot_acquire(&s, &v));
    farsee_frame_slot_destroy(&s);
}

RFB_TEST(farsee_slot, farsee_slot_publish_acquire__ok)
{
    farsee_frame_slot s;
    RFB_CHECK(farsee_frame_slot_init(&s));
    uint8_t px[8] = {1, 2, 3, 4, 5, 6, 7, 8};  // 2x1 BGRA
    RFB_CHECK(farsee_frame_slot_publish(&s, px, 2, 1, 8, FARSEE_PIXEL_BGRA8888));
    farsee_frame_view v;
    RFB_CHECK(farsee_frame_slot_acquire(&s, &v));
    RFB_CHECK_EQ_UINT(v.w, 2u);
    RFB_CHECK_EQ_UINT(v.h, 1u);
    RFB_CHECK(v.format == FARSEE_PIXEL_BGRA8888);
    RFB_CHECK(v.pixels[0] == 1 && v.pixels[7] == 8);
    RFB_CHECK(v.gen == 1);
    farsee_frame_slot_release(&s, &v);
    farsee_frame_slot_destroy(&s);
}

RFB_TEST(farsee_slot, farsee_slot_publish_twice__latest_wins)
{
    farsee_frame_slot s;
    RFB_CHECK(farsee_frame_slot_init(&s));
    uint8_t a[4] = {0xAA, 0, 0, 0xFF};
    uint8_t b[4] = {0xBB, 0, 0, 0xFF};
    RFB_CHECK(farsee_frame_slot_publish(&s, a, 1, 1, 4, FARSEE_PIXEL_RGBA8888));
    RFB_CHECK(farsee_frame_slot_publish(&s, b, 1, 1, 4, FARSEE_PIXEL_RGBA8888));
    farsee_frame_view v;
    RFB_CHECK(farsee_frame_slot_acquire(&s, &v));
    RFB_CHECK(v.pixels[0] == 0xBB);
    RFB_CHECK(v.format == FARSEE_PIXEL_RGBA8888);
    RFB_CHECK(v.gen == 2);
    RFB_CHECK(s.dropped >= 1);
    farsee_frame_slot_release(&s, &v);
    farsee_frame_slot_destroy(&s);
}

RFB_TEST(farsee_slot, farsee_slot_acquire_while_held__still_latest)
{
    farsee_frame_slot s;
    RFB_CHECK(farsee_frame_slot_init(&s));
    uint8_t a[4] = {1, 0, 0, 0xFF};
    uint8_t b[4] = {2, 0, 0, 0xFF};
    RFB_CHECK(farsee_frame_slot_publish(&s, a, 1, 1, 4, FARSEE_PIXEL_BGRA8888));
    farsee_frame_view v1;
    RFB_CHECK(farsee_frame_slot_acquire(&s, &v1));
    RFB_CHECK(v1.pixels[0] == 1);
    // Publish while present holds v1 — must use another slot.
    RFB_CHECK(farsee_frame_slot_publish(&s, b, 1, 1, 4, FARSEE_PIXEL_BGRA8888));
    farsee_frame_view v2;
    RFB_CHECK(farsee_frame_slot_acquire(&s, &v2));
    RFB_CHECK(v2.pixels[0] == 2);
    RFB_CHECK(v2.gen > v1.gen);
    farsee_frame_slot_release(&s, &v1);
    farsee_frame_slot_release(&s, &v2);
    farsee_frame_slot_destroy(&s);
}

RFB_TEST(farsee_slot, farsee_slot_publish__rejects_bad_stride)
{
    farsee_frame_slot s;
    RFB_CHECK(farsee_frame_slot_init(&s));
    uint8_t px[4] = {1, 2, 3, 4};
    // stride 2 < 1*4 bpp
    RFB_CHECK(!farsee_frame_slot_publish(&s, px, 1, 1, 2, FARSEE_PIXEL_BGRA8888));
    farsee_frame_slot_destroy(&s);
}

// T16: stride*h must use checked mul — absurd dims must not wrap/allocate.
RFB_TEST(farsee_slot, farsee_slot_publish__rejects_stride_h_overflow)
{
    farsee_frame_slot s;
    RFB_CHECK(farsee_frame_slot_init(&s));
    uint8_t px[4] = {1, 2, 3, 4};
    // UINT32_MAX * UINT32_MAX overflows size_t on 32- and 64-bit hosts.
    RFB_CHECK(!farsee_frame_slot_publish(&s, px, 1u, UINT32_MAX, UINT32_MAX,
                                        FARSEE_PIXEL_BGRA8888));
    farsee_frame_slot_destroy(&s);
}
