// SPDX-License-Identifier: Apache-2.0
//
// G1 — checked arithmetic tests (plan.md §G1: "exhaustive small-range
// arithmetic cases; exact overflow boundaries for SIZE_MAX").
//
// RED step: written before checked.c exists. Verifies:
//   - add/mul succeed on in-range values;
//   - add/mul fail at the exact SIZE_MAX boundary (off-by-one matters);
//   - rect_bytes is the single chokepoint for width*height*bpp and
//     rejects zero-area and overflow;
//   - *out is untouched on failure (transactional contract).

#include "rfb_test.h"
#include "farsee/checked.h"
#include <stdint.h>
#include <limits.h>

// ---- add ----------------------------------------------------------------

RFB_TEST(checked, checked_add__small_values__succeeds) {
    size_t out = 999;
    RFB_CHECK(rfb_checked_add_size(2, 3, &out));
    RFB_CHECK_EQ_UINT(out, 5);
}

RFB_TEST(checked, checked_add__zero_identity__succeeds) {
    size_t out = 999;
    RFB_CHECK(rfb_checked_add_size(0, 0, &out));
    RFB_CHECK_EQ_UINT(out, 0);
    RFB_CHECK(rfb_checked_add_size(0, 7, &out));
    RFB_CHECK_EQ_UINT(out, 7);
}

RFB_TEST(checked, checked_add__boundary_at_sizemax_minus_one_plus_one__succeeds) {
    size_t out = 0;
    RFB_CHECK(rfb_checked_add_size(SIZE_MAX - 1, 1, &out));
    RFB_CHECK_EQ_UINT(out, SIZE_MAX);
}

RFB_TEST(checked, checked_add__exact_sizemax_plus_one__fails_and_leaves_out_untouched) {
    size_t out = 0xDEAD;
    RFB_CHECK(!rfb_checked_add_size(SIZE_MAX, 1, &out));
    RFB_CHECK_EQ_UINT(out, 0xDEAD);  // untouched on failure
}

RFB_TEST(checked, checked_add__one_plus_sizemax__also_fails) {
    size_t out = 0;
    RFB_CHECK(!rfb_checked_add_size(1, SIZE_MAX, &out));
}

RFB_TEST(checked, checked_add__exhaustive_small_range__matches_native) {
    for (size_t a = 0; a < 64; a++) {
        for (size_t b = 0; b < 64; b++) {
            size_t out = 0;
            RFB_CHECK(rfb_checked_add_size(a, b, &out));
            RFB_CHECK_EQ_UINT(out, a + b);
        }
    }
}

// ---- multiply -----------------------------------------------------------

RFB_TEST(checked, checked_mul__small_values__succeeds) {
    size_t out = 999;
    RFB_CHECK(rfb_checked_mul_size(3, 4, &out));
    RFB_CHECK_EQ_UINT(out, 12);
}

RFB_TEST(checked, checked_mul__zero_operand__succeeds_with_zero) {
    size_t out = 999;
    RFB_CHECK(rfb_checked_mul_size(0, 12345, &out));
    RFB_CHECK_EQ_UINT(out, 0);
    RFB_CHECK(rfb_checked_mul_size(12345, 0, &out));
    RFB_CHECK_EQ_UINT(out, 0);
}

RFB_TEST(checked, checked_mul__sizemax_times_one__succeeds) {
    size_t out = 0;
    RFB_CHECK(rfb_checked_mul_size(SIZE_MAX, 1, &out));
    RFB_CHECK_EQ_UINT(out, SIZE_MAX);
}

RFB_TEST(checked, checked_mul__sizemax_times_two__fails) {
    size_t out = 0xDEAD;
    RFB_CHECK(!rfb_checked_mul_size(SIZE_MAX, 2, &out));
    RFB_CHECK_EQ_UINT(out, 0xDEAD);
}

RFB_TEST(checked, checked_mul__two_times_sizemax__also_fails) {
    size_t out = 0;
    RFB_CHECK(!rfb_checked_mul_size(2, SIZE_MAX, &out));
}

RFB_TEST(checked, checked_mul__power_of_two_boundary__succeeds_then_fails) {
    // Find the largest n such that n * 2 fits; (n+1)*2 must overflow.
    size_t half = SIZE_MAX / 2;
    size_t out1 = 0, out2 = 0xDEAD;
    RFB_CHECK(rfb_checked_mul_size(half, 2, &out1));
    RFB_CHECK_EQ_UINT(out1, half * 2);
    // half+1 times 2 overflows unless half was exact (which depends on parity).
    if ((SIZE_MAX & 1u) == 1) {
        // SIZE_MAX is odd => half*2 == SIZE_MAX-1, so (half+1)*2 == SIZE_MAX+1
        RFB_CHECK(!rfb_checked_mul_size(half + 1, 2, &out2));
        RFB_CHECK_EQ_UINT(out2, 0xDEAD);
    }
}

RFB_TEST(checked, checked_mul__exhaustive_small_range__matches_native) {
    for (size_t a = 0; a < 32; a++) {
        for (size_t b = 0; b < 32; b++) {
            size_t out = 0;
            RFB_CHECK(rfb_checked_mul_size(a, b, &out));
            RFB_CHECK_EQ_UINT(out, a * b);
        }
    }
}

// ---- rect bytes (the chokepoint for width*height*bpp) ------------------

RFB_TEST(checked, checked_rect_bytes__one_by_one_4bpp__is_four) {
    size_t out = 0;
    RFB_CHECK(rfb_checked_rect_bytes(1, 1, 4, &out));
    RFB_CHECK_EQ_UINT(out, 4);
}

RFB_TEST(checked, checked_rect_bytes__small_rectangle__matches) {
    size_t out = 0;
    RFB_CHECK(rfb_checked_rect_bytes(10, 20, 4, &out));
    RFB_CHECK_EQ_UINT(out, 800);
}

RFB_TEST(checked, checked_rect_bytes__zero_width__fails) {
    size_t out = 0xDEAD;
    RFB_CHECK(!rfb_checked_rect_bytes(0, 10, 4, &out));
    RFB_CHECK_EQ_UINT(out, 0xDEAD);
}

RFB_TEST(checked, checked_rect_bytes__zero_height__fails) {
    size_t out = 0xDEAD;
    RFB_CHECK(!rfb_checked_rect_bytes(10, 0, 4, &out));
    RFB_CHECK_EQ_UINT(out, 0xDEAD);
}

RFB_TEST(checked, checked_rect_bytes__huge_width_times_height__fails_on_overflow) {
    size_t out = 0xDEAD;
    // 0xFFFFFFFF * 0xFFFFFFFF * 4 overflows in any width.
    RFB_CHECK(!rfb_checked_rect_bytes(0xFFFFFFFFu, 0xFFFFFFFFu, 4, &out));
    RFB_CHECK_EQ_UINT(out, 0xDEAD);
}

RFB_TEST(checked, checked_rect_bytes__max_policy_framebuffer__fits_in_policy_bytes) {
    // 16384 * 16384 * 4 = 1 GiB; must succeed (within the absolute cap).
    size_t out = 0;
    RFB_CHECK(rfb_checked_rect_bytes(16384, 16384, 4, &out));
    RFB_CHECK_EQ_UINT(out, (size_t)1073741824u);
}

// ---- add_u32 (coordinate bounds, used in G4) ----------------------------

RFB_TEST(checked, checked_add_u32__boundary__succeeds_then_fails) {
    uint32_t out = 0;
    RFB_CHECK(rfb_checked_add_u32(0xFFFFFFFEu, 1, &out));
    RFB_CHECK_EQ_UINT(out, 0xFFFFFFFFu);
    RFB_CHECK(!rfb_checked_add_u32(0xFFFFFFFFu, 1, &out));
}
