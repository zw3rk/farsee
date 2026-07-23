// SPDX-License-Identifier: Apache-2.0
//
// G25 — authentication downgrade / rollback security regression tests
// (goals.md G25, threat-model T13).
//
// Proves the selection policy NEVER silently downgrades:
//   - prefers type 33 over everything;
//   - never auto-selects legacy type 30 (requires allow_legacy);
//   - never returns a type that was not offered;
//   - prefers 33 > 36 > 35; 30 only with allow_legacy;
//   - None (1) is never auto-selected by the Apple path (it is a classic
//     RFB concern handled separately by the handshake policy).
//
// The invariant under test (goals.md G15): "no silent downgrade from an
// attempted Apple branch to VNC/None after proof failure". The selection
// function is stateless per call, so we assert it cannot even *begin* a
// weaker branch when a stronger offered one exists, and that it never
// invents a type. A separate test covers that within a single connection
// the caller never re-invokes selection after a proof failure (that is a
// caller-side invariant documented here and enforced by the session glue).

#include "rfb_test.h"
#include "farsee/apple_auth.h"

#include <string.h>

// --- Preference ordering -------------------------------------------------

RFB_TEST(g25_downgrade, select__prefers_33_over_36_35_30) {
    static const uint8_t offered[] = { 30, 33, 35, 36 };
    RFB_CHECK_EQ_INT(apple_select_security_type(offered, 4, false), APPLE_SEC_TYPE_33);
    // Even with legacy allowed, 33 wins.
    RFB_CHECK_EQ_INT(apple_select_security_type(offered, 4, true), APPLE_SEC_TYPE_33);
}

RFB_TEST(g25_downgrade, select__prefers_36_over_35_30_when_no_33) {
    static const uint8_t offered[] = { 30, 35, 36 };
    RFB_CHECK_EQ_INT(apple_select_security_type(offered, 3, false), APPLE_SEC_TYPE_36);
}

RFB_TEST(g25_downgrade, select__prefers_35_over_30_when_no_33_36) {
    static const uint8_t offered[] = { 30, 35 };
    RFB_CHECK_EQ_INT(apple_select_security_type(offered, 2, false), APPLE_SEC_TYPE_35);
}

// --- Legacy type 30 is never automatic ----------------------------------

RFB_TEST(g25_downgrade, select__type30_only_alone_is_not_auto_selected) {
    // Type 30 alone must NOT be selected without allow_legacy, even if it
    // is the only offered type. This is the core downgrade defense.
    static const uint8_t offered[] = { 30 };
    RFB_CHECK_EQ_INT(apple_select_security_type(offered, 1, false), 0);
}

RFB_TEST(g25_downgrade, select__type30_selected_only_with_allow_legacy) {
    static const uint8_t offered[] = { 30 };
    RFB_CHECK_EQ_INT(apple_select_security_type(offered, 1, true), APPLE_SEC_TYPE_30);
}

RFB_TEST(g25_downgrade, select__type30_not_chosen_over_33_even_with_legacy) {
    // Legacy flag enables 30 as a fallback, never as a preference over 33.
    static const uint8_t offered[] = { 30, 33 };
    RFB_CHECK_EQ_INT(apple_select_security_type(offered, 2, true), APPLE_SEC_TYPE_33);
}

// --- Never invent a type -------------------------------------------------

RFB_TEST(g25_downgrade, select__unknown_types_only_returns_zero) {
    // Only unknown/unimplemented types → 0 (none acceptable). Must not
    // return a type that was not offered.
    static const uint8_t offered[] = { 99, 100, 200 };
    RFB_CHECK_EQ_INT(apple_select_security_type(offered, 3, false), 0);
    RFB_CHECK_EQ_INT(apple_select_security_type(offered, 3, true), 0);
}

RFB_TEST(g25_downgrade, select__empty_list_returns_zero) {
    RFB_CHECK_EQ_INT(apple_select_security_type(NULL, 0, false), 0);
    RFB_CHECK_EQ_INT(apple_select_security_type(NULL, 0, true), 0);
}

// --- Result is always a member of the offered set ------------------------
// This is the fuzzer's core invariant, restated as explicit cases. A
// downgrade attack would require returning a type the server did not offer.

RFB_TEST(g25_downgrade, select__result_always_in_offered_set) {
    // A mixed list where 33 is present must pick 33 (which is in the set).
    static const uint8_t offered[] = { 2, 30, 33, 99 };
    int sel = apple_select_security_type(offered, 4, false);
    bool in_set = false;
    for (size_t i = 0; i < 4; i++) {
        if (offered[i] == (uint8_t)sel) { in_set = true; break; }
    }
    RFB_CHECK(in_set);
    RFB_CHECK_EQ_INT(sel, APPLE_SEC_TYPE_33);
}

// --- VNC (2) and None (1) are never selected by the Apple path -----------
// The Apple selection policy concerns itself only with Apple types. VNC/None
// are classic-RFB concerns; the Apple path must not silently fall back to
// them (that would be a downgrade from an Apple-capable server to a weaker
// classic auth).

RFB_TEST(g25_downgrade, select__vnc_and_none_not_chosen_by_apple_path) {
    static const uint8_t offered[] = { 1, 2 };  // None, VNC
    // No Apple type offered → 0, never a silent VNC/None downgrade.
    RFB_CHECK_EQ_INT(apple_select_security_type(offered, 2, false), 0);
    RFB_CHECK_EQ_INT(apple_select_security_type(offered, 2, true), 0);
}

RFB_TEST(g25_downgrade, select__apple_type_preferred_over_vnc_none) {
    // When an Apple type AND VNC/None are offered, the Apple type wins.
    static const uint8_t offered[] = { 1, 2, 33 };
    RFB_CHECK_EQ_INT(apple_select_security_type(offered, 3, false), APPLE_SEC_TYPE_33);
}

// --- Dialect detection does not accept hostile banners -------------------

RFB_TEST(g25_downgrade, dialect__apple_banner_recognized) {
    static const uint8_t apple[] = "RFB 003.889\n";
    RFB_CHECK(apple_is_dialect_003_889(apple, 12));
}

RFB_TEST(g25_downgrade, dialect__rfb_38_not_apple) {
    static const uint8_t rfb38[] = "RFB 003.008\n";
    RFB_CHECK(!apple_is_dialect_003_889(rfb38, 12));
}

RFB_TEST(g25_downgrade, dialect__malformed_banner_rejected) {
    static const uint8_t junk[] = "RFB 999.999\n";
    RFB_CHECK(!apple_is_dialect_003_889(junk, 12));
    RFB_CHECK(!apple_is_dialect_003_889((const uint8_t *)"short", 5));
    RFB_CHECK(!apple_is_dialect_003_889(NULL, 0));
}
