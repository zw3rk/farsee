// SPDX-License-Identifier: Apache-2.0
//
// Shared latest-wins triple buffer tests.

#include "farsee/farsee_display.h"
#include "farsee/farsee_frame_slot.h"
#include "tests/test_framework/rfb_test.h"

#include <limits.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

typedef struct slot_fault_allocator {
    size_t calls;
    size_t fail_at;
} slot_fault_allocator;

static void *slot_fault_alloc(farsee_allocator *allocator, size_t size)
{
    slot_fault_allocator *fault =
        (slot_fault_allocator *)allocator->user;
    fault->calls++;
    if (fault->calls == fault->fail_at) {
        return NULL;
    }
    return malloc(size);
}

static void slot_fault_free(farsee_allocator *allocator, void *pointer)
{
    (void)allocator;
    free(pointer);
}

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

RFB_TEST(farsee_slot, farsee_slot_cursor__clips_hotspot_at_frame_edges)
{
    farsee_frame_slot slot;
    RFB_CHECK(farsee_frame_slot_init(&slot));
    static const uint8_t frame[] = {
        10u, 20u, 30u, 255u, 10u, 20u, 30u, 255u,
        10u, 20u, 30u, 255u, 10u, 20u, 30u, 255u,
    };
    static const uint8_t cursor_pixels[] = {
        1u, 2u, 3u, 255u,  4u, 5u, 6u, 255u,
        7u, 8u, 9u, 255u,  200u, 100u, 50u, 128u,
    };
    const farsee_cursor cursor = {
        .hotspot_x = 1u,
        .hotspot_y = 1u,
        .width = 2u,
        .height = 2u,
        .format = FARSEE_PIXEL_RGBA8888,
        .data = cursor_pixels,
        .visible = true,
        .pos_x = 0,
        .pos_y = 0,
    };
    RFB_CHECK_EQ_INT(
        farsee_frame_slot_publish_composited_ex(
            &slot, frame, 2u, 2u, 8u, FARSEE_PIXEL_RGBA8888, &cursor),
        FARSEE_FRAME_PUBLISH_OK);
    farsee_frame_view view;
    RFB_CHECK(farsee_frame_slot_acquire(&slot, &view));
    static const uint8_t blended = 105u;
    RFB_CHECK_EQ_UINT(view.pixels[0], blended);
    RFB_CHECK_EQ_UINT(view.pixels[1], 60u);
    RFB_CHECK_EQ_UINT(view.pixels[2], 40u);
    RFB_CHECK_MEM_EQ(view.pixels + 4u, frame + 4u, sizeof frame - 4u);
    static const uint8_t original[] = {
        10u, 20u, 30u, 255u, 10u, 20u, 30u, 255u,
        10u, 20u, 30u, 255u, 10u, 20u, 30u, 255u,
    };
    RFB_CHECK_MEM_EQ(frame, original, sizeof frame);
    farsee_frame_slot_release(&slot, &view);
    farsee_frame_slot_destroy(&slot);
}

RFB_TEST(farsee_slot, farsee_slot_cursor__rejects_malformed_visible_plane)
{
    farsee_frame_slot slot;
    RFB_CHECK(farsee_frame_slot_init(&slot));
    static const uint8_t frame[4] = {0u, 0u, 0u, 255u};
    static const uint8_t cursor_pixel[4] = {0u, 0u, 0u, 255u};
    farsee_cursor cursor;
    memset(&cursor, 0, sizeof cursor);
    cursor.visible = true;
    cursor.width = 1u;
    cursor.height = 1u;
    cursor.format = FARSEE_PIXEL_RGBA8888;

    cursor.data = cursor_pixel;
    RFB_CHECK_EQ_INT(
        farsee_frame_slot_publish_composited_ex(
            &slot, frame, 1u, 1u, 4u, FARSEE_PIXEL_BGRA8888, &cursor),
        FARSEE_FRAME_PUBLISH_INVALID);

    cursor.format = FARSEE_PIXEL_BGRA8888;
    RFB_CHECK_EQ_INT(
        farsee_frame_slot_publish_composited_ex(
            &slot, frame, 1u, 1u, 4u, FARSEE_PIXEL_RGBA8888, &cursor),
        FARSEE_FRAME_PUBLISH_INVALID);

    cursor.format = FARSEE_PIXEL_RGBA8888;
    cursor.width = 0u;
    RFB_CHECK_EQ_INT(
        farsee_frame_slot_publish_composited_ex(
            &slot, frame, 1u, 1u, 4u, FARSEE_PIXEL_RGBA8888, &cursor),
        FARSEE_FRAME_PUBLISH_INVALID);

    cursor.width = 1u;
    cursor.height = 0u;
    RFB_CHECK_EQ_INT(
        farsee_frame_slot_publish_composited_ex(
            &slot, frame, 1u, 1u, 4u, FARSEE_PIXEL_RGBA8888, &cursor),
        FARSEE_FRAME_PUBLISH_INVALID);

    cursor.height = 1u;
    cursor.data = NULL;
    RFB_CHECK_EQ_INT(
        farsee_frame_slot_publish_composited_ex(
            &slot, frame, 1u, 1u, 4u, FARSEE_PIXEL_RGBA8888, &cursor),
        FARSEE_FRAME_PUBLISH_INVALID);
    RFB_CHECK_EQ_UINT(slot.gen, 0u);
    RFB_CHECK(!slot.has_frame);
    farsee_frame_slot_destroy(&slot);
}

RFB_TEST(farsee_slot, farsee_slot_publish__allocation_failure_is_transactional)
{
    slot_fault_allocator fault = { .calls = 0u, .fail_at = 1u };
    farsee_allocator allocator = {
        .alloc = slot_fault_alloc,
        .free = slot_fault_free,
        .user = &fault,
    };
    farsee_frame_slot s;
    RFB_CHECK(farsee_frame_slot_init_with_allocator(&s, &allocator));
    uint8_t pixel[4] = { 1u, 2u, 3u, 0xFFu };
    RFB_CHECK(farsee_frame_slot_publish_ex(
                  &s, pixel, 1u, 1u, 4u, FARSEE_PIXEL_RGBA8888) ==
              FARSEE_FRAME_PUBLISH_OUT_OF_MEMORY);
    RFB_CHECK_EQ_UINT(s.gen, 0u);
    RFB_CHECK(!s.has_frame);
    farsee_frame_view view;
    RFB_CHECK(!farsee_frame_slot_acquire(&s, &view));

    // Positive retry: the failed allocation did not reserve or corrupt a slot.
    RFB_CHECK(farsee_frame_slot_publish(&s, pixel, 1u, 1u, 4u,
                                        FARSEE_PIXEL_RGBA8888));
    RFB_CHECK(farsee_frame_slot_acquire(&s, &view));
    RFB_CHECK_MEM_EQ(view.pixels, pixel, sizeof pixel);
    farsee_frame_slot_release(&s, &view);
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

RFB_TEST(farsee_slot, farsee_slot_acquired_then_released__is_not_dropped)
{
    farsee_frame_slot s;
    RFB_CHECK(farsee_frame_slot_init(&s));
    uint8_t a[4] = { 0xAAu, 0u, 0u, 0xFFu };
    uint8_t b[4] = { 0xBBu, 0u, 0u, 0xFFu };
    RFB_CHECK(farsee_frame_slot_publish(&s, a, 1u, 1u, 4u,
                                        FARSEE_PIXEL_RGBA8888));
    farsee_frame_view view;
    RFB_CHECK(farsee_frame_slot_acquire(&s, &view));
    farsee_frame_slot_release(&s, &view);
    RFB_CHECK(farsee_frame_slot_publish(&s, b, 1u, 1u, 4u,
                                        FARSEE_PIXEL_RGBA8888));
    RFB_CHECK_EQ_UINT(s.dropped, 0u);
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

RFB_TEST(farsee_slot, farsee_slot_two_held_views__third_publish_preserves_both)
{
    farsee_frame_slot s;
    RFB_CHECK(farsee_frame_slot_init(&s));
    uint8_t a[4] = { 0xA1u, 0u, 0u, 0xFFu };
    uint8_t b[4] = { 0xB2u, 0u, 0u, 0xFFu };
    uint8_t c[4] = { 0xC3u, 0u, 0u, 0xFFu };

    RFB_CHECK(farsee_frame_slot_publish(&s, a, 1, 1, 4,
                                        FARSEE_PIXEL_RGBA8888));
    farsee_frame_view va;
    RFB_CHECK(farsee_frame_slot_acquire(&s, &va));
    RFB_CHECK_EQ_UINT(va.pixels[0], 0xA1u);

    RFB_CHECK(farsee_frame_slot_publish(&s, b, 1, 1, 4,
                                        FARSEE_PIXEL_RGBA8888));
    farsee_frame_view vb;
    RFB_CHECK(farsee_frame_slot_acquire(&s, &vb));
    RFB_CHECK_EQ_UINT(vb.pixels[0], 0xB2u);

    RFB_CHECK(farsee_frame_slot_publish(&s, c, 1, 1, 4,
                                        FARSEE_PIXEL_RGBA8888));
    RFB_CHECK_EQ_UINT(va.pixels[0], 0xA1u);
    RFB_CHECK_EQ_UINT(vb.pixels[0], 0xB2u);
    farsee_frame_view vc;
    RFB_CHECK(farsee_frame_slot_acquire(&s, &vc));
    RFB_CHECK_EQ_UINT(vc.pixels[0], 0xC3u);

    // With all three slots held, another publish must fail rather than
    // invalidate any outstanding view.
    RFB_CHECK(farsee_frame_slot_publish_ex(
                  &s, a, 1, 1, 4, FARSEE_PIXEL_RGBA8888) ==
              FARSEE_FRAME_PUBLISH_RESOURCE_BUSY);
    RFB_CHECK_EQ_UINT(va.pixels[0], 0xA1u);
    RFB_CHECK_EQ_UINT(vb.pixels[0], 0xB2u);
    RFB_CHECK_EQ_UINT(vc.pixels[0], 0xC3u);

    farsee_frame_slot_release(&s, &va);
    farsee_frame_slot_release(&s, &vb);
    farsee_frame_slot_release(&s, &vc);
    RFB_CHECK(farsee_frame_slot_publish(&s, a, 1, 1, 4,
                                        FARSEE_PIXEL_RGBA8888));
    farsee_frame_slot_destroy(&s);
}

typedef struct slot_publish_arg {
    farsee_frame_slot *slot;
    const uint8_t *pixels;
    uint32_t w;
    uint32_t h;
    uint32_t stride;
    farsee_atomic_int *ready;
    farsee_atomic_int *go;
    bool result;
} slot_publish_arg;

static void *slot_publish_after_barrier(void *opaque)
{
    slot_publish_arg *arg = (slot_publish_arg *)opaque;
    farsee_atomic_int_store(arg->ready, 1);
    while (!farsee_atomic_int_load_nonzero(arg->go)) {
        // The test releases both publishers only after both are at the gate.
    }
    arg->result = farsee_frame_slot_publish(
        arg->slot, arg->pixels, arg->w, arg->h, arg->stride,
        FARSEE_PIXEL_RGBA8888);
    return NULL;
}

RFB_TEST(farsee_slot, farsee_slot_two_publishers__reserve_distinct_storage)
{
    enum { WIDTH = 2048, HEIGHT = 1024, STRIDE = WIDTH * 4 };
    const size_t frame_size = (size_t)STRIDE * (size_t)HEIGHT;
    uint8_t *a = (uint8_t *)malloc(frame_size);
    uint8_t *b = (uint8_t *)malloc(frame_size);
    RFB_CHECK(a != NULL && b != NULL);
    if (a == NULL || b == NULL) {
        free(a);
        free(b);
        return;
    }
    memset(a, 0x3c, frame_size);
    memset(b, 0xc3, frame_size);

    farsee_frame_slot s;
    RFB_CHECK(farsee_frame_slot_init(&s));
    uint8_t initial[4] = { 0 };
    RFB_CHECK(farsee_frame_slot_publish(&s, initial, 1u, 1u, 4u,
                                        FARSEE_PIXEL_RGBA8888));

    farsee_atomic_int ready_a = 0;
    farsee_atomic_int ready_b = 0;
    farsee_atomic_int go = 0;
    slot_publish_arg aa = {
        .slot = &s, .pixels = a, .w = WIDTH, .h = HEIGHT,
        .stride = STRIDE, .ready = &ready_a, .go = &go, .result = false
    };
    slot_publish_arg bb = {
        .slot = &s, .pixels = b, .w = WIDTH, .h = HEIGHT,
        .stride = STRIDE, .ready = &ready_b, .go = &go, .result = false
    };
    farsee_thread *ta = farsee_thread_create(slot_publish_after_barrier, &aa);
    farsee_thread *tb = farsee_thread_create(slot_publish_after_barrier, &bb);
    RFB_CHECK(ta != NULL && tb != NULL);
    if (ta == NULL || tb == NULL) {
        farsee_atomic_int_store(&go, 1);
        farsee_thread_join(&ta, NULL);
        farsee_thread_join(&tb, NULL);
        farsee_frame_slot_destroy(&s);
        free(a);
        free(b);
        return;
    }
    while (!farsee_atomic_int_load_nonzero(&ready_a) ||
           !farsee_atomic_int_load_nonzero(&ready_b)) {
        // Wait for the deterministic start gate.
    }
    farsee_atomic_int_store(&go, 1);
    farsee_thread_join(&ta, NULL);
    farsee_thread_join(&tb, NULL);
    RFB_CHECK(aa.result && bb.result);

    farsee_frame_view view;
    RFB_CHECK(farsee_frame_slot_acquire(&s, &view));
    RFB_CHECK_EQ_UINT(view.w, WIDTH);
    RFB_CHECK_EQ_UINT(view.h, HEIGHT);
    RFB_CHECK_EQ_UINT(view.stride, STRIDE);
    const uint8_t expected = view.pixels[0];
    RFB_CHECK(expected == 0x3c || expected == 0xc3);
    bool uniform = true;
    for (size_t i = 1u; i < frame_size; i++) {
        if (view.pixels[i] != expected) {
            uniform = false;
            break;
        }
    }
    RFB_CHECK(uniform);
    farsee_frame_slot_release(&s, &view);
    farsee_frame_slot_destroy(&s);
    free(a);
    free(b);
}

RFB_TEST(farsee_slot, farsee_slot_publish__rejects_bad_stride)
{
    farsee_frame_slot s;
    RFB_CHECK(farsee_frame_slot_init(&s));
    uint8_t px[4] = {1, 2, 3, 4};
    // stride 2 < 1*4 bpp
    RFB_CHECK(farsee_frame_slot_publish_ex(
                  &s, px, 1, 1, 2, FARSEE_PIXEL_BGRA8888) ==
              FARSEE_FRAME_PUBLISH_INVALID);
    farsee_frame_slot_destroy(&s);
}

// Extreme dimensions return false. The product either overflows size_t or
// exceeds the fixed allocation cap, depending on size_t width.
RFB_TEST(farsee_slot, farsee_slot_publish__rejects_extreme_allocation_size)
{
    farsee_frame_slot s;
    RFB_CHECK(farsee_frame_slot_init(&s));
    uint8_t px[4] = {1, 2, 3, 4};
    // On 64-bit size_t the product fits, but exceeds the allocation cap.
    RFB_CHECK(!farsee_frame_slot_publish(&s, px, 1u, UINT32_MAX, UINT32_MAX,
                                        FARSEE_PIXEL_BGRA8888));
    farsee_frame_slot_destroy(&s);
}

RFB_TEST(farsee_slot, farsee_slot_init_and_lifecycle__reject_invalid_inputs)
{
    farsee_allocator invalid = { 0 };
    farsee_frame_slot slot;

    RFB_CHECK(!farsee_frame_slot_init_with_allocator(NULL,
                                                      farsee_default_allocator()));
    RFB_CHECK(!farsee_frame_slot_init_with_allocator(&slot, NULL));
    RFB_CHECK(!farsee_frame_slot_init_with_allocator(&slot, &invalid));
    invalid.alloc = slot_fault_alloc;
    RFB_CHECK(!farsee_frame_slot_init_with_allocator(&slot, &invalid));

    farsee_frame_slot_destroy(NULL);
    farsee_frame_slot_kick(NULL);
    memset(&slot, 0, sizeof slot);
    farsee_frame_slot_kick(&slot);
    farsee_frame_slot_destroy(&slot);
    RFB_CHECK_EQ_INT(slot.publish_idx, -1);
}

RFB_TEST(farsee_slot, farsee_slot_publish__rejects_all_invalid_contracts)
{
    farsee_frame_slot slot;
    RFB_CHECK(farsee_frame_slot_init(&slot));
    static const uint8_t pixel[4] = { 1u, 2u, 3u, 4u };

    RFB_CHECK_EQ_INT(
        farsee_frame_slot_publish_ex(NULL, pixel, 1u, 1u, 4u,
                                     FARSEE_PIXEL_RGBA8888),
        FARSEE_FRAME_PUBLISH_INVALID);
    RFB_CHECK_EQ_INT(
        farsee_frame_slot_publish_ex(&slot, NULL, 1u, 1u, 4u,
                                     FARSEE_PIXEL_RGBA8888),
        FARSEE_FRAME_PUBLISH_INVALID);
    RFB_CHECK_EQ_INT(
        farsee_frame_slot_publish_ex(&slot, pixel, 0u, 1u, 4u,
                                     FARSEE_PIXEL_RGBA8888),
        FARSEE_FRAME_PUBLISH_INVALID);
    RFB_CHECK_EQ_INT(
        farsee_frame_slot_publish_ex(&slot, pixel, 1u, 0u, 4u,
                                     FARSEE_PIXEL_RGBA8888),
        FARSEE_FRAME_PUBLISH_INVALID);
    RFB_CHECK_EQ_INT(
        farsee_frame_slot_publish_ex(
            &slot, pixel, 1u, 1u, 4u, (farsee_pixel_format_kind)999),
        FARSEE_FRAME_PUBLISH_INVALID);

    farsee_allocator *const saved_allocator = slot.alloc;
    farsee_allocator invalid = {
        .alloc = NULL,
        .free = slot_fault_free,
        .user = NULL,
    };
    slot.alloc = NULL;
    RFB_CHECK_EQ_INT(
        farsee_frame_slot_publish_ex(&slot, pixel, 1u, 1u, 4u,
                                     FARSEE_PIXEL_RGBA8888),
        FARSEE_FRAME_PUBLISH_OUT_OF_MEMORY);
    slot.alloc = &invalid;
    RFB_CHECK_EQ_INT(
        farsee_frame_slot_publish_ex(&slot, pixel, 1u, 1u, 4u,
                                     FARSEE_PIXEL_RGBA8888),
        FARSEE_FRAME_PUBLISH_OUT_OF_MEMORY);
    invalid.alloc = slot_fault_alloc;
    invalid.free = NULL;
    RFB_CHECK_EQ_INT(
        farsee_frame_slot_publish_ex(&slot, pixel, 1u, 1u, 4u,
                                     FARSEE_PIXEL_RGBA8888),
        FARSEE_FRAME_PUBLISH_OUT_OF_MEMORY);
    slot.alloc = saved_allocator;

    RFB_CHECK(farsee_frame_slot_publish(
        &slot, pixel, 1u, 1u, 4u, FARSEE_PIXEL_RGBA8888));
    RFB_CHECK(farsee_frame_slot_publish(
        &slot, pixel, 1u, 1u, 4u, FARSEE_PIXEL_RGBA8888));
    RFB_CHECK(farsee_frame_slot_publish(
        &slot, pixel, 1u, 1u, 4u, FARSEE_PIXEL_RGBA8888));
    farsee_frame_slot_destroy(&slot);
}

RFB_TEST(farsee_slot, farsee_slot_acquire__guards_reader_saturation)
{
    farsee_frame_slot slot;
    farsee_frame_view view;
    static const uint8_t pixel[4] = { 9u, 8u, 7u, 6u };

    RFB_CHECK(!farsee_frame_slot_acquire(NULL, &view));
    RFB_CHECK(farsee_frame_slot_init(&slot));
    RFB_CHECK(!farsee_frame_slot_acquire(&slot, NULL));
    RFB_CHECK(farsee_frame_slot_publish(
        &slot, pixel, 1u, 1u, 4u, FARSEE_PIXEL_RGBA8888));
    const unsigned index = (unsigned)slot.publish_idx;
    slot.readers[index] = UINT_MAX;
    RFB_CHECK(!farsee_frame_slot_acquire(&slot, &view));
    RFB_CHECK(view.pixels == NULL);
    slot.readers[index] = 0u;
    RFB_CHECK(farsee_frame_slot_acquire(&slot, &view));
    farsee_frame_slot_release(&slot, &view);
    farsee_frame_slot_destroy(&slot);
}

RFB_TEST(farsee_slot, farsee_slot_acquire_wait__covers_stop_frame_and_timeout)
{
    farsee_frame_slot slot;
    farsee_frame_view view;
    farsee_atomic_int stop = 0;
    static const uint8_t pixel[4] = { 4u, 3u, 2u, 1u };

    RFB_CHECK(!farsee_frame_slot_acquire_wait(
        NULL, 0u, 0u, &stop, &view));
    RFB_CHECK(farsee_frame_slot_init(&slot));
    RFB_CHECK(!farsee_frame_slot_acquire_wait(
        &slot, 0u, 0u, &stop, NULL));

    farsee_atomic_int_store(&stop, 1);
    RFB_CHECK(!farsee_frame_slot_acquire_wait(
        &slot, 0u, 0u, &stop, &view));
    farsee_atomic_int_store(&stop, 0);
    RFB_CHECK(farsee_frame_slot_publish(
        &slot, pixel, 1u, 1u, 4u, FARSEE_PIXEL_RGBA8888));
    RFB_CHECK(farsee_frame_slot_acquire_wait(
        &slot, 0u, 0u, NULL, &view));
    const uint64_t generation = view.gen;
    farsee_frame_slot_release(&slot, &view);

    const unsigned index = (unsigned)slot.publish_idx;
    slot.readers[index] = UINT_MAX;
    RFB_CHECK(!farsee_frame_slot_acquire_wait(
        &slot, 0u, 0u, &stop, &view));
    slot.readers[index] = 0u;
    RFB_CHECK(!farsee_frame_slot_acquire_wait(
        &slot, generation, 0u, &stop, &view));
    farsee_frame_slot_destroy(&slot);
}

RFB_TEST(farsee_slot, farsee_slot_release__ignores_stale_and_invalid_views)
{
    farsee_frame_slot slot;
    farsee_frame_view view = {0};
    static const uint8_t pixel[4] = { 0u, 1u, 2u, 3u };

    farsee_frame_slot_release(NULL, &view);
    RFB_CHECK(farsee_frame_slot_init(&slot));
    farsee_frame_slot_release(&slot, NULL);
    RFB_CHECK(farsee_frame_slot_publish(
        &slot, pixel, 1u, 1u, 4u, FARSEE_PIXEL_RGBA8888));
    RFB_CHECK(farsee_frame_slot_acquire(&slot, &view));
    const unsigned index = (unsigned)view.slot_idx;

    farsee_frame_view invalid = view;
    invalid.slot_idx = -1;
    farsee_frame_slot_release(&slot, &invalid);
    invalid.slot_idx = (int)FARSEE_FRAME_SLOT_N;
    farsee_frame_slot_release(&slot, &invalid);
    invalid = view;
    invalid.gen++;
    farsee_frame_slot_release(&slot, &invalid);
    RFB_CHECK_EQ_UINT(slot.readers[index], 1u);

    farsee_frame_slot_release(&slot, &view);
    RFB_CHECK_EQ_UINT(slot.readers[index], 0u);
    farsee_frame_slot_release(&slot, &view);
    RFB_CHECK_EQ_UINT(slot.readers[index], 0u);
    farsee_frame_slot_kick(&slot);
    farsee_frame_slot_destroy(&slot);
}
