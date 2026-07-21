// SPDX-License-Identifier: Apache-2.0
//
// G3 — transactional RGBA8 framebuffer tests (plan.md §G3, §10.3, ADR-0003).
// RED step.

#include "rfb_test.h"
#include "farsee/framebuffer.h"
#include "farsee/allocator.h"
#include "farsee/error.h"

// --- init / resize -------------------------------------------------------

RFB_TEST(fb, fb__resize_1x1__succeeds_and_initializes_black_opaque) {
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    RFB_CHECK_EQ_INT(rfb_framebuffer_resize(&fb, 1, 1, 1u << 20), RFB_OK);
    RFB_CHECK_EQ_UINT(fb.width, 1u);
    RFB_CHECK_EQ_UINT(fb.height, 1u);
    RFB_CHECK_EQ_UINT(fb.stride, 4u);
    const uint8_t *p = rfb_framebuffer_pixel_c(&fb, 0, 0);
    RFB_CHECK_EQ_UINT(p[0], 0u);   // R
    RFB_CHECK_EQ_UINT(p[1], 0u);   // G
    RFB_CHECK_EQ_UINT(p[2], 0u);   // B
    RFB_CHECK_EQ_UINT(p[3], 255u); // A (plan.md §G3: alpha=255)
    rfb_framebuffer_destroy(&fb);
}

RFB_TEST(fb, fb__resize_4x2__stride_is_width_times_4) {
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    RFB_CHECK_EQ_INT(rfb_framebuffer_resize(&fb, 4, 2, 1u << 20), RFB_OK);
    RFB_CHECK_EQ_UINT(fb.stride, 16u);  // 4 pixels * 4 bytes
    RFB_CHECK_EQ_UINT(fb.width, 4u);
    RFB_CHECK_EQ_UINT(fb.height, 2u);
    rfb_framebuffer_destroy(&fb);
}

RFB_TEST(fb, fb__resize_generation_bumps_on_success) {
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    RFB_CHECK_EQ_UINT(fb.generation, 0u);
    rfb_framebuffer_resize(&fb, 2, 2, 1u << 20);
    uint64_t g1 = fb.generation;
    RFB_CHECK(g1 > 0);
    rfb_framebuffer_resize(&fb, 4, 4, 1u << 20);
    RFB_CHECK(fb.generation > g1);
    rfb_framebuffer_destroy(&fb);
}

// --- transactional failure preserves old contents -----------------------

RFB_TEST(fb, fb__resize_over_limit__fails_and_preserves_old_contents) {
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    RFB_CHECK_EQ_INT(rfb_framebuffer_resize(&fb, 2, 2, 1u << 20), RFB_OK);
    uint32_t old_w = fb.width, old_h = fb.height;
    uint64_t old_gen = fb.generation;
    uint8_t *old_rgba = fb.rgba;
    // Now request a resize whose byte count exceeds the tiny limit.
    RFB_CHECK_EQ_INT(rfb_framebuffer_resize(&fb, 1000, 1000, 100), RFB_ERR_LIMIT);
    // Old contents intact.
    RFB_CHECK_EQ_UINT(fb.width, old_w);
    RFB_CHECK_EQ_UINT(fb.height, old_h);
    RFB_CHECK_EQ_UINT(fb.generation, old_gen);
    RFB_CHECK(fb.rgba == old_rgba);  // same pointer
    rfb_framebuffer_destroy(&fb);
}

RFB_TEST(fb, fb__resize_zero_width__fails) {
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    RFB_CHECK_EQ_INT(rfb_framebuffer_resize(&fb, 0, 10, 1u << 20), RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_UINT(fb.width, 0u);
    RFB_CHECK(fb.rgba == NULL);
    rfb_framebuffer_destroy(&fb);
}

RFB_TEST(fb, fb__resize_zero_height__fails) {
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    RFB_CHECK_EQ_INT(rfb_framebuffer_resize(&fb, 10, 0, 1u << 20), RFB_ERR_PROTOCOL);
    rfb_framebuffer_destroy(&fb);
}

// --- bounds checks -------------------------------------------------------

RFB_TEST(fb, fb__in_bounds__edges) {
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_resize(&fb, 4, 4, 1u << 20);
    RFB_CHECK(rfb_framebuffer_in_bounds(&fb, 0, 0));
    RFB_CHECK(rfb_framebuffer_in_bounds(&fb, 3, 3));
    RFB_CHECK(!rfb_framebuffer_in_bounds(&fb, 4, 0));
    RFB_CHECK(!rfb_framebuffer_in_bounds(&fb, 0, 4));
    rfb_framebuffer_destroy(&fb);
}

// --- fill ----------------------------------------------------------------

RFB_TEST(fb, fb__fill__sets_every_pixel) {
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_resize(&fb, 3, 2, 1u << 20);
    rfb_framebuffer_fill(&fb, 0xFF, 0x00, 0x80, 0xFF);
    for (uint32_t y = 0; y < 2; y++) {
        for (uint32_t x = 0; x < 3; x++) {
            const uint8_t *p = rfb_framebuffer_pixel_c(&fb, x, y);
            RFB_CHECK_EQ_UINT(p[0], 0xFFu);
            RFB_CHECK_EQ_UINT(p[1], 0x00u);
            RFB_CHECK_EQ_UINT(p[2], 0x80u);
            RFB_CHECK_EQ_UINT(p[3], 0xFFu);
        }
    }
    rfb_framebuffer_destroy(&fb);
}

// --- destroy is idempotent and safe on zero-init -------------------------

RFB_TEST(fb, fb__destroy_on_zero_init__safe) {
    rfb_framebuffer fb;
    memset(&fb, 0, sizeof fb);
    rfb_framebuffer_destroy(&fb);  // must not crash
    RFB_CHECK(true);
}

// --- policy cap boundary -------------------------------------------------

RFB_TEST(fb, fb__resize_at_policy_limit__succeeds) {
    // 256 * 256 * 4 = 256 KiB. Limit exactly that.
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    RFB_CHECK_EQ_INT(rfb_framebuffer_resize(&fb, 256, 256, 256u * 1024u), RFB_OK);
    rfb_framebuffer_destroy(&fb);
}

RFB_TEST(fb, fb__resize_one_byte_over_policy_limit__fails) {
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    RFB_CHECK_EQ_INT(rfb_framebuffer_resize(&fb, 256, 256, 256u * 1024u - 1), RFB_ERR_LIMIT);
    rfb_framebuffer_destroy(&fb);
}

// --- mutable pixel accessor (rfb_framebuffer_pixel) ---------------------

RFB_TEST(fb, fb__mutable_pixel_accessor__writes_and_reads) {
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_resize(&fb, 3, 3, 1u << 20);
    // Write via the mutable accessor.
    uint8_t *p = rfb_framebuffer_pixel(&fb, 1, 2);
    p[0] = 0x12; p[1] = 0x34; p[2] = 0x56; p[3] = 0xFF;
    // Read back via the const accessor.
    const uint8_t *c = rfb_framebuffer_pixel_c(&fb, 1, 2);
    RFB_CHECK_EQ_UINT(c[0], 0x12u);
    RFB_CHECK_EQ_UINT(c[1], 0x34u);
    RFB_CHECK_EQ_UINT(c[2], 0x56u);
    RFB_CHECK_EQ_UINT(c[3], 0xFFu);
    rfb_framebuffer_destroy(&fb);
}

// --- NULL-safety on init, in_bounds, resize, fill ------------------------

RFB_TEST(fb, fb__init_null__safe_noop) {
    rfb_framebuffer_init(NULL, rfb_default_allocator());
    RFB_CHECK(true);
}

RFB_TEST(fb, fb__in_bounds_null__returns_false) {
    RFB_CHECK(!rfb_framebuffer_in_bounds(NULL, 0, 0));
}

RFB_TEST(fb, fb__resize_null_fb__returns_internal) {
    RFB_CHECK_EQ_INT(rfb_framebuffer_resize(NULL, 10, 10, 1u << 20),
                     RFB_ERR_INTERNAL);
}

RFB_TEST(fb, fb__resize_null_alloc__returns_internal) {
    rfb_framebuffer fb;
    memset(&fb, 0, sizeof fb);
    // alloc is NULL (from memset), so the resize should detect it.
    RFB_CHECK_EQ_INT(rfb_framebuffer_resize(&fb, 10, 10, 1u << 20),
                     RFB_ERR_INTERNAL);
}

RFB_TEST(fb, fb__fill_null_or_unallocated__safe) {
    rfb_framebuffer_fill(NULL, 1, 2, 3, 4);  // NULL → noop
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_fill(&fb, 0xFF, 0xFF, 0xFF, 0xFF);  // no storage allocated
    RFB_CHECK(true);
    rfb_framebuffer_destroy(&fb);
}

// --- fill bumps generation (consistent with resize) ----------------------

RFB_TEST(fb, fb__fill_after_resize__generation_bumps) {
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_resize(&fb, 2, 2, 1u << 20);
    uint64_t gen_before = fb.generation;
    rfb_framebuffer_fill(&fb, 10, 20, 30, 255);
    RFB_CHECK(fb.generation > gen_before);
    rfb_framebuffer_destroy(&fb);
}
