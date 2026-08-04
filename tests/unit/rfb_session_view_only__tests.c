// SPDX-License-Identifier: Apache-2.0
//
// P0-N1 — view-only must suppress type-33 wake PointerEvent/KeyEvent.
// Pure helper path: no TCP peer required.

#include "rfb_test.h"
#include "farsee/rfb_session.h"
#include "farsee/error.h"

#include <string.h>

// KeyEvent=4 (8 bytes), PointerEvent=5 (6 bytes). Walk contiguous wake
// messages and count type-4 / type-5 starts.
static void count_key_pointer(const uint8_t *buf, size_t len,
                              unsigned *out_key, unsigned *out_ptr)
{
    unsigned keys = 0u;
    unsigned ptrs = 0u;
    size_t i = 0u;
    while (i < len) {
        const uint8_t t = buf[i];
        if (t == 4u) {
            keys++;
            if (len - i < 8u) {
                break;
            }
            i += 8u;
        } else if (t == 5u) {
            ptrs++;
            if (len - i < 6u) {
                break;
            }
            i += 6u;
        } else {
            // Unexpected type — stop so tests fail clearly.
            break;
        }
    }
    if (out_key != NULL) {
        *out_key = keys;
    }
    if (out_ptr != NULL) {
        *out_ptr = ptrs;
    }
}

// --- Negative: view_only suppresses all wake input ----------------------

RFB_TEST(rfb_session_view_only,
         apple_wake_input__view_only_true__zero_key_and_pointer)
{
    uint8_t buf[64];
    size_t n = 99u;
    memset(buf, 0xAAu, sizeof buf);

    RFB_CHECK_EQ_INT(
        rfb_format_apple_wake_input(buf, sizeof buf, &n,
                                    /*view_only=*/true,
                                    /*with_key=*/true,
                                    /*wake_attempt=*/3u,
                                    /*fb_w=*/1920u, /*fb_h=*/1080u),
        RFB_OK);
    RFB_CHECK_EQ_UINT(n, 0u);

    // Even with with_key and an attempt that would soft-click, no type 4/5.
    unsigned keys = 0u;
    unsigned ptrs = 0u;
    count_key_pointer(buf, n, &keys, &ptrs);
    RFB_CHECK_EQ_UINT(keys, 0u);
    RFB_CHECK_EQ_UINT(ptrs, 0u);
}

RFB_TEST(rfb_session_view_only,
         apple_wake_input__view_only_true_no_key__still_empty)
{
    uint8_t buf[64];
    size_t n = 1u;
    RFB_CHECK_EQ_INT(
        rfb_format_apple_wake_input(buf, sizeof buf, &n,
                                    /*view_only=*/true,
                                    /*with_key=*/false,
                                    /*wake_attempt=*/1u,
                                    /*fb_w=*/100u, /*fb_h=*/100u),
        RFB_OK);
    RFB_CHECK_EQ_UINT(n, 0u);
}

// --- Positive: view_only false still emits pointer (and key when asked)

RFB_TEST(rfb_session_view_only,
         apple_wake_input__view_only_false__emits_pointer)
{
    uint8_t buf[64];
    size_t n = 0u;
    RFB_CHECK_EQ_INT(
        rfb_format_apple_wake_input(buf, sizeof buf, &n,
                                    /*view_only=*/false,
                                    /*with_key=*/false,
                                    /*wake_attempt=*/1u,
                                    /*fb_w=*/200u, /*fb_h=*/100u),
        RFB_OK);
    RFB_CHECK(n >= 6u);

    unsigned keys = 0u;
    unsigned ptrs = 0u;
    count_key_pointer(buf, n, &keys, &ptrs);
    RFB_CHECK_EQ_UINT(keys, 0u);
    RFB_CHECK(ptrs >= 1u);
    RFB_CHECK_EQ_UINT(buf[0], 5u);  // PointerEvent
    // Center of 200x100 is (100, 50).
    RFB_CHECK_EQ_UINT(buf[1], 0u);   // button mask
    RFB_CHECK_EQ_UINT(buf[2], 0u);
    RFB_CHECK_EQ_UINT(buf[3], 100u); // x BE
    RFB_CHECK_EQ_UINT(buf[4], 0u);
    RFB_CHECK_EQ_UINT(buf[5], 50u);  // y BE
}

RFB_TEST(rfb_session_view_only,
         apple_wake_input__view_only_false_with_key__emits_type4)
{
    uint8_t buf[64];
    size_t n = 0u;
    RFB_CHECK_EQ_INT(
        rfb_format_apple_wake_input(buf, sizeof buf, &n,
                                    /*view_only=*/false,
                                    /*with_key=*/true,
                                    /*wake_attempt=*/1u,
                                    /*fb_w=*/800u, /*fb_h=*/600u),
        RFB_OK);
    RFB_CHECK(n > 6u);

    unsigned keys = 0u;
    unsigned ptrs = 0u;
    count_key_pointer(buf, n, &keys, &ptrs);
    RFB_CHECK(ptrs >= 1u);
    RFB_CHECK(keys >= 2u);  // at least down + up
}

// T13: default wake is motion-only (mask 0); no soft click without with_key.
RFB_TEST(rfb_session_view_only,
         apple_wake_input__default_attempt_3__motion_only)
{
    uint8_t buf[64];
    size_t n = 0u;
    RFB_CHECK_EQ_INT(
        rfb_format_apple_wake_input(buf, sizeof buf, &n,
                                    /*view_only=*/false,
                                    /*with_key=*/false,
                                    /*wake_attempt=*/3u,
                                    /*fb_w=*/100u, /*fb_h=*/100u),
        RFB_OK);

    unsigned keys = 0u;
    unsigned ptrs = 0u;
    count_key_pointer(buf, n, &keys, &ptrs);
    RFB_CHECK_EQ_UINT(keys, 0u);
    RFB_CHECK_EQ_UINT(ptrs, 1u); // center motion only
    RFB_CHECK_EQ_UINT(buf[1], 0u); // button mask 0
}

// T13: with_key enables soft click + keys (FARSEE_APPLE_WAKE=input path).
RFB_TEST(rfb_session_view_only,
         apple_wake_input__with_key_attempt_3__click_and_keys)
{
    uint8_t buf[64];
    size_t n = 0u;
    RFB_CHECK_EQ_INT(
        rfb_format_apple_wake_input(buf, sizeof buf, &n,
                                    /*view_only=*/false,
                                    /*with_key=*/true,
                                    /*wake_attempt=*/3u,
                                    /*fb_w=*/100u, /*fb_h=*/100u),
        RFB_OK);

    unsigned keys = 0u;
    unsigned ptrs = 0u;
    count_key_pointer(buf, n, &keys, &ptrs);
    RFB_CHECK(keys >= 2u);
    // motion + soft click down/up
    RFB_CHECK(ptrs >= 3u);
}

RFB_TEST(rfb_session_view_only,
         apple_wake_input__view_only_true_attempt_3_with_key__still_empty)
{
    // Highest-pressure case: would soft-click and emit keys if not gated.
    uint8_t buf[64];
    size_t n = 42u;
    RFB_CHECK_EQ_INT(
        rfb_format_apple_wake_input(buf, sizeof buf, &n,
                                    /*view_only=*/true,
                                    /*with_key=*/true,
                                    /*wake_attempt=*/3u,
                                    /*fb_w=*/1920u, /*fb_h=*/1080u),
        RFB_OK);
    RFB_CHECK_EQ_UINT(n, 0u);
}

// --- Config: view_only field exists and defaults to false via zero-init

RFB_TEST(rfb_session_view_only,
         session_config__view_only_zero_init__false)
{
    rfb_session_config cfg;
    memset(&cfg, 0, sizeof cfg);
    RFB_CHECK(!cfg.view_only);
    cfg.view_only = true;
    RFB_CHECK(cfg.view_only);
}

// --- Null / limit edges -------------------------------------------------

RFB_TEST(rfb_session_view_only,
         apple_wake_input__null_out_len__internal)
{
    uint8_t buf[64];
    RFB_CHECK_EQ_INT(
        rfb_format_apple_wake_input(buf, sizeof buf, NULL,
                                    false, false, 1u, 10u, 10u),
        RFB_ERR_INTERNAL);
}

RFB_TEST(rfb_session_view_only,
         apple_wake_input__null_buf_nonzero_need__internal)
{
    size_t n = 0u;
    // view_only true needs no buffer (writes nothing).
    RFB_CHECK_EQ_INT(
        rfb_format_apple_wake_input(NULL, 0u, &n, true, false, 1u, 10u, 10u),
        RFB_OK);
    RFB_CHECK_EQ_UINT(n, 0u);

    // view_only false with NULL out → internal.
    RFB_CHECK_EQ_INT(
        rfb_format_apple_wake_input(NULL, 0u, &n, false, false, 1u, 10u, 10u),
        RFB_ERR_INTERNAL);
}
