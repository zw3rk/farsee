// SPDX-License-Identifier: Apache-2.0
//
// Apple security-type selection and dialect-recognition cases.
//
// Covers ranking among types 33, 36, 35, and 30; legacy-type gating; classic
// type exclusion; offered-list results; and three dialect inputs.

#include "rfb_test.h"
#include "farsee/apple_auth.h"

#include <string.h>

// --- Preference ordering -------------------------------------------------

RFB_TEST(security_downgrade, select__prefers_33_over_36_35_30) {
    static const uint8_t offered[] = { 30, 33, 35, 36 };
    RFB_CHECK_EQ_INT(apple_select_security_type(offered, 4, false), APPLE_SEC_TYPE_33);
    // Even with legacy allowed, 33 wins.
    RFB_CHECK_EQ_INT(apple_select_security_type(offered, 4, true), APPLE_SEC_TYPE_33);
}

RFB_TEST(security_downgrade, select__prefers_36_over_35_30_when_no_33) {
    static const uint8_t offered[] = { 30, 35, 36 };
    RFB_CHECK_EQ_INT(apple_select_security_type(offered, 3, false), APPLE_SEC_TYPE_36);
}

RFB_TEST(security_downgrade, select__prefers_35_over_30_when_no_33_36) {
    static const uint8_t offered[] = { 30, 35 };
    RFB_CHECK_EQ_INT(apple_select_security_type(offered, 2, false), APPLE_SEC_TYPE_35);
}

// --- Legacy type-30 gating ----------------------------------------------

RFB_TEST(security_downgrade, select__type30_only_alone_is_not_auto_selected) {
    // Type 30 alone returns zero unless allow_legacy is true.
    static const uint8_t offered[] = { 30 };
    RFB_CHECK_EQ_INT(apple_select_security_type(offered, 1, false), 0);
}

RFB_TEST(security_downgrade, select__type30_selected_only_with_allow_legacy) {
    static const uint8_t offered[] = { 30 };
    RFB_CHECK_EQ_INT(apple_select_security_type(offered, 1, true), APPLE_SEC_TYPE_30);
}

RFB_TEST(security_downgrade, select__type30_not_chosen_over_33_even_with_legacy) {
    // With legacy enabled, offered type 33 still ranks above type 30.
    static const uint8_t offered[] = { 30, 33 };
    RFB_CHECK_EQ_INT(apple_select_security_type(offered, 2, true), APPLE_SEC_TYPE_33);
}

// --- Unsupported and empty offered lists --------------------------------

RFB_TEST(security_downgrade, select__unknown_types_only_returns_zero) {
    // A list containing only unsupported types returns zero.
    static const uint8_t offered[] = { 99, 100, 200 };
    RFB_CHECK_EQ_INT(apple_select_security_type(offered, 3, false), 0);
    RFB_CHECK_EQ_INT(apple_select_security_type(offered, 3, true), 0);
}

RFB_TEST(security_downgrade, select__empty_list_returns_zero) {
    RFB_CHECK_EQ_INT(apple_select_security_type(NULL, 0, false), 0);
    RFB_CHECK_EQ_INT(apple_select_security_type(NULL, 0, true), 0);
}

// --- One mixed offered-list result --------------------------------------

RFB_TEST(security_downgrade, select__mixed_list_returns_offered_type_33) {
    // This mixed list returns its offered type 33.
    static const uint8_t offered[] = { 2, 30, 33, 99 };
    int sel = apple_select_security_type(offered, 4, false);
    bool in_set = false;
    for (size_t i = 0; i < 4; i++) {
        if (offered[i] == (uint8_t)sel) { in_set = true; break; }
    }
    RFB_CHECK(in_set);
    RFB_CHECK_EQ_INT(sel, APPLE_SEC_TYPE_33);
}

// --- Classic types in Apple-only selection ------------------------------

RFB_TEST(security_downgrade, select__vnc_and_none_not_chosen_by_apple_path) {
    static const uint8_t offered[] = { 1, 2 };  // None, VNC
    // No Apple type is offered, so the selector returns zero.
    RFB_CHECK_EQ_INT(apple_select_security_type(offered, 2, false), 0);
    RFB_CHECK_EQ_INT(apple_select_security_type(offered, 2, true), 0);
}

RFB_TEST(security_downgrade, select__apple_type_preferred_over_vnc_none) {
    // Offered type 33 ranks above the classic types.
    static const uint8_t offered[] = { 1, 2, 33 };
    RFB_CHECK_EQ_INT(apple_select_security_type(offered, 3, false), APPLE_SEC_TYPE_33);
}

// --- Dialect detection does not accept hostile banners -------------------

RFB_TEST(security_downgrade, dialect__apple_banner_recognized) {
    static const uint8_t apple[] = "RFB 003.889\n";
    RFB_CHECK(apple_is_dialect_003_889(apple, 12));
}

RFB_TEST(security_downgrade, dialect__rfb_38_not_apple) {
    static const uint8_t rfb38[] = "RFB 003.008\n";
    RFB_CHECK(!apple_is_dialect_003_889(rfb38, 12));
}

RFB_TEST(security_downgrade, dialect__malformed_banner_rejected) {
    static const uint8_t junk[] = "RFB 999.999\n";
    RFB_CHECK(!apple_is_dialect_003_889(junk, 12));
    RFB_CHECK(!apple_is_dialect_003_889((const uint8_t *)"short", 5));
    RFB_CHECK(!apple_is_dialect_003_889(NULL, 0));
}
