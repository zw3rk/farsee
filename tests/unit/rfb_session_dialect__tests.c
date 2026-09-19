// SPDX-License-Identifier: Apache-2.0
//
// Explicit session dialect (not has_wrap_key as demux/policy flag).
// Pure helpers: classic vs Apple cleartext demux; wake remains view_only-gated.

#include "rfb_test.h"
#include "farsee/rfb_session.h"
#include "farsee/error.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

// Supported Apple control body lengths: 0x4a and 0x50.
static const uint8_t k_apple_ctl_4a_prefix[2] = { 0x00u, 0x4au };
static const uint8_t k_apple_ctl_50_prefix[2] = { 0x00u, 0x50u };
// Classic FBU header: type=0, pad=0, nrects=1.
static const uint8_t k_classic_fbu[4] = { 0x00u, 0x00u, 0x00u, 0x01u };
// type=0 pad≠0 that looks like Apple control but on classic must not skip.
static const uint8_t k_type0_pad_nonzero[4] = { 0x00u, 0x4au, 0x00u, 0x00u };

// --- Dialect enum / zero-init --------------------------------------------

RFB_TEST(rfb_session_dialect, dialect_enum__classic_is_zero)
{
    // Zero-init session/config → CLASSIC (no Apple demux by default).
    RFB_CHECK_EQ_INT((int)RFB_SESSION_DIALECT_CLASSIC, 0);
    rfb_session_dialect d = (rfb_session_dialect)0;
    RFB_CHECK_EQ_INT((int)d, (int)RFB_SESSION_DIALECT_CLASSIC);
}

RFB_TEST(rfb_session_dialect, session_get_dialect__null_and_clear__classic)
{
    RFB_CHECK_EQ_INT((int)rfb_session_get_dialect(NULL),
                     (int)RFB_SESSION_DIALECT_CLASSIC);

    unsigned char storage[4096];
    RFB_CHECK(rfb_session_size() <= sizeof storage);
    rfb_session *s = (rfb_session *)(void *)storage;
    rfb_session_clear(s);
    RFB_CHECK_EQ_INT((int)rfb_session_get_dialect(s),
                     (int)RFB_SESSION_DIALECT_CLASSIC);
    RFB_CHECK(!rfb_session_has_wrap_key(s));
    rfb_session_destroy(s);
}

// --- Pure demux: classic never takes Apple u16be control skip ------------

RFB_TEST(rfb_session_dialect,
         demux__classic_type0_pad_nonzero__not_apple_skip)
{
    size_t total = 999u;
    // Classic dialect: even with Apple-looking 00 4a …, do not skip.
    RFB_CHECK(!rfb_session_apple_u16be_control_eligible(
        RFB_SESSION_DIALECT_CLASSIC, k_type0_pad_nonzero,
        sizeof k_type0_pad_nonzero, &total));
    RFB_CHECK(!rfb_session_apple_u16be_control_eligible(
        RFB_SESSION_DIALECT_CLASSIC, k_apple_ctl_4a_prefix, 2u, &total));
    RFB_CHECK(!rfb_session_apple_u16be_control_eligible(
        RFB_SESSION_DIALECT_CLASSIC, k_apple_ctl_50_prefix, 2u, &total));
}

RFB_TEST(rfb_session_dialect, demux__classic_fbu_header__not_apple_skip)
{
    size_t total = 0u;
    RFB_CHECK(!rfb_session_apple_u16be_control_eligible(
        RFB_SESSION_DIALECT_CLASSIC, k_classic_fbu, sizeof k_classic_fbu,
        &total));
}

// --- Pure demux: Apple cleartext MVP takes control skip ------------------

RFB_TEST(rfb_session_dialect,
         demux__apple_cleartext_type0_pad_4a__eligible)
{
    size_t total = 0u;
    RFB_CHECK(rfb_session_apple_u16be_control_eligible(
        RFB_SESSION_DIALECT_APPLE_CLEARTEXT_MVP, k_apple_ctl_4a_prefix, 2u,
        &total));
    // body_len=0x4a → total = 2 + 0x4a
    RFB_CHECK_EQ_UINT(total, 2u + 0x4au);
}

RFB_TEST(rfb_session_dialect,
         demux__apple_cleartext_type0_pad_50__eligible)
{
    size_t total = 0u;
    RFB_CHECK(rfb_session_apple_u16be_control_eligible(
        RFB_SESSION_DIALECT_APPLE_CLEARTEXT_MVP, k_apple_ctl_50_prefix, 2u,
        &total));
    RFB_CHECK_EQ_UINT(total, 2u + 0x50u);
}

RFB_TEST(rfb_session_dialect,
         demux__apple_cleartext_classic_fbu_pad0__not_eligible)
{
    // Real FBU (pad=0) must never be swallowed as a control record.
    size_t total = 42u;
    RFB_CHECK(!rfb_session_apple_u16be_control_eligible(
        RFB_SESSION_DIALECT_APPLE_CLEARTEXT_MVP, k_classic_fbu,
        sizeof k_classic_fbu, &total));
}

RFB_TEST(rfb_session_dialect,
         demux__apple_body_len_too_small__not_eligible)
{
    // body_len=7 < min 8
    const uint8_t p[2] = { 0x00u, 0x07u };
    size_t total = 0u;
    RFB_CHECK(!rfb_session_apple_u16be_control_eligible(
        RFB_SESSION_DIALECT_APPLE_CLEARTEXT_MVP, p, 2u, &total));
}

RFB_TEST(rfb_session_dialect,
         demux__apple_body_len_too_large__not_eligible)
{
    // body_len=257 > max 256 (u16be 0x0101, but our records have high byte 0)
    // High byte non-zero → not type=0 path; still not eligible.
    const uint8_t p_hi[2] = { 0x01u, 0x00u };
    size_t total = 0u;
    RFB_CHECK(!rfb_session_apple_u16be_control_eligible(
        RFB_SESSION_DIALECT_APPLE_CLEARTEXT_MVP, p_hi, 2u, &total));
}

RFB_TEST(rfb_session_dialect, demux__null_or_short__not_eligible)
{
    size_t total = 0u;
    RFB_CHECK(!rfb_session_apple_u16be_control_eligible(
        RFB_SESSION_DIALECT_APPLE_CLEARTEXT_MVP, NULL, 2u, &total));
    const uint8_t one = 0x00u;
    RFB_CHECK(!rfb_session_apple_u16be_control_eligible(
        RFB_SESSION_DIALECT_APPLE_CLEARTEXT_MVP, &one, 1u, &total));
    RFB_CHECK(!rfb_session_apple_u16be_control_eligible(
        RFB_SESSION_DIALECT_APPLE_CLEARTEXT_MVP, k_apple_ctl_4a_prefix, 2u,
        NULL));
}

// --- Wake: non-view-only still emits for Apple path (policy gate is VO)

RFB_TEST(rfb_session_dialect,
         wake__non_view_only__still_emits_pointer_for_apple_path)
{
    // Dialect does not change the pure wake wire helper; view_only is the
    // only input gate. Apple dialect sessions keep wake under
    // non-view-only.
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
    RFB_CHECK_EQ_UINT(buf[0], 5u);  // PointerEvent
}

RFB_TEST(rfb_session_dialect,
         wake__view_only_true__still_empty_independent_of_dialect)
{
    uint8_t buf[64];
    size_t n = 99u;
    RFB_CHECK_EQ_INT(
        rfb_format_apple_wake_input(buf, sizeof buf, &n,
                                    /*view_only=*/true,
                                    /*with_key=*/true,
                                    /*wake_attempt=*/3u,
                                    /*fb_w=*/1920u, /*fb_h=*/1080u),
        RFB_OK);
    RFB_CHECK_EQ_UINT(n, 0u);
}

// --- has_wrap_key remains secret presence API (not demux policy) ---------

RFB_TEST(rfb_session_dialect,
         has_wrap_key__cleared_session__false_even_if_classic)
{
    // Document contract: has_wrap_key is secret presence only. Cleared
    // session has no wrap key; dialect is classic.
    unsigned char storage[4096];
    RFB_CHECK(rfb_session_size() <= sizeof storage);
    rfb_session *s = (rfb_session *)(void *)storage;
    rfb_session_clear(s);
    RFB_CHECK(!rfb_session_has_wrap_key(s));
    RFB_CHECK_EQ_INT((int)rfb_session_get_dialect(s),
                     (int)RFB_SESSION_DIALECT_CLASSIC);
    // Demux policy uses dialect, not has_wrap_key: classic → no skip.
    size_t total = 0u;
    RFB_CHECK(!rfb_session_apple_u16be_control_eligible(
        rfb_session_get_dialect(s), k_apple_ctl_4a_prefix, 2u, &total));
    rfb_session_destroy(s);
}

// The post-ServerInit setup pointer path uses mask 0 only (no LEFT).
RFB_TEST(rfb_session_dialect, setup_pointer__mask0_only_no_button_edges)
{
    uint8_t buf[32];
    size_t n = 0u;
    RFB_CHECK_EQ_INT(
        rfb_format_apple_setup_pointer(buf, sizeof buf, &n, 1920u, 1080u),
        RFB_OK);
    RFB_CHECK_EQ_UINT(n, 18u); // 3 × PointerEvent(6)
    for (size_t off = 0; off + 6u <= n; off += 6u) {
        RFB_CHECK_EQ_UINT(buf[off], 5u);      // PointerEvent type
        RFB_CHECK_EQ_UINT(buf[off + 1u], 0u); // button mask 0 only
    }
}

RFB_TEST(rfb_session_dialect, setup_pointer__null_out_len__fails)
{
    uint8_t buf[32];
    RFB_CHECK_EQ_INT(
        rfb_format_apple_setup_pointer(buf, sizeof buf, NULL, 10u, 10u),
        RFB_ERR_INTERNAL);
}
