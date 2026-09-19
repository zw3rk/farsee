// SPDX-License-Identifier: Apache-2.0
//
// Pure RFB security-type selection matrix for --auth auto|vnc|apple against
// classic and Apple offered lists.

#include "rfb_test.h"
#include "farsee/handshake.h"

// Helper: run selection with a full policy and assert result + type.
static void expect_select(const uint8_t *offered, size_t count,
                          const farsee_rfb_security_policy *pol,
                          rfb_error want_err, uint8_t want_type)
{
    uint8_t got = 0xFFu;
    rfb_error e = farsee_rfb_select_security(offered, count, pol, &got);
    RFB_CHECK_EQ_INT(e, want_err);
    RFB_CHECK_EQ_INT((int)got, (int)want_type);
}

// ---- defaults ------------------------------------------------------------

RFB_TEST(security_select, default_policy__auto_vnc_on_type33_on_rest_off) {
    farsee_rfb_security_policy p = farsee_rfb_security_policy_default();
    RFB_CHECK_EQ_INT(p.auth_mode, FARSEE_AUTH_MODE_AUTO);
    RFB_CHECK(!p.allow_none);
    RFB_CHECK(!p.allow_legacy_apple);
    RFB_CHECK(p.allow_type_33);
    RFB_CHECK(!p.allow_type_36);
    RFB_CHECK(!p.allow_type_35);
    RFB_CHECK(p.allow_vnc);
}

// ---- empty / null / bad args --------------------------------------------

RFB_TEST(security_select, empty_offered__unsupported) {
    farsee_rfb_security_policy p = farsee_rfb_security_policy_default();
    uint8_t dummy = 1;
    expect_select(&dummy, 0, &p, RFB_ERR_UNSUPPORTED, 0);
    expect_select(NULL, 0, &p, RFB_ERR_UNSUPPORTED, 0);
}

RFB_TEST(security_select, null_offered_nonzero_count__unsupported) {
    farsee_rfb_security_policy p = farsee_rfb_security_policy_default();
    expect_select(NULL, 3, &p, RFB_ERR_UNSUPPORTED, 0);
}

RFB_TEST(security_select, null_out_type__internal) {
    farsee_rfb_security_policy p = farsee_rfb_security_policy_default();
    static const uint8_t offered[] = { 2 };
    rfb_error e = farsee_rfb_select_security(offered, 1, &p, NULL);
    RFB_CHECK_EQ_INT(e, RFB_ERR_INTERNAL);
}

RFB_TEST(security_select, null_policy__uses_defaults) {
    static const uint8_t offered[] = { 2 };
    uint8_t got = 0;
    rfb_error e = farsee_rfb_select_security(offered, 1, NULL, &got);
    RFB_CHECK_EQ_INT(e, RFB_OK);
    RFB_CHECK_EQ_INT((int)got, 2);
}

// ---- classic matrix ------------------------------------------------------

RFB_TEST(security_select, classic_only_type2__auto__selects_2) {
    farsee_rfb_security_policy p = farsee_rfb_security_policy_default();
    p.auth_mode = FARSEE_AUTH_MODE_AUTO;
    static const uint8_t offered[] = { 2 };
    expect_select(offered, 1, &p, RFB_OK, 2);
}

RFB_TEST(security_select, classic_type1_and_2__allow_none_false__selects_2) {
    farsee_rfb_security_policy p = farsee_rfb_security_policy_default();
    p.auth_mode = FARSEE_AUTH_MODE_AUTO;
    p.allow_none = false;
    static const uint8_t offered[] = { 1, 2 };
    expect_select(offered, 2, &p, RFB_OK, 2);
}

RFB_TEST(security_select, classic_only_type1__allow_none_false__fails) {
    farsee_rfb_security_policy p = farsee_rfb_security_policy_default();
    p.auth_mode = FARSEE_AUTH_MODE_AUTO;
    p.allow_none = false;
    static const uint8_t offered[] = { 1 };
    expect_select(offered, 1, &p, RFB_ERR_UNSUPPORTED, 0);
}

RFB_TEST(security_select, classic_only_type1__allow_none_true__selects_1) {
    farsee_rfb_security_policy p = farsee_rfb_security_policy_default();
    p.auth_mode = FARSEE_AUTH_MODE_AUTO;
    p.allow_none = true;
    static const uint8_t offered[] = { 1 };
    expect_select(offered, 1, &p, RFB_OK, 1);
}

// ---- auto vs vnc vs apple on mixed classic+Apple -------------------------

RFB_TEST(security_select, type2_and_33__auto__prefers_33) {
    farsee_rfb_security_policy p = farsee_rfb_security_policy_default();
    p.auth_mode = FARSEE_AUTH_MODE_AUTO;
    static const uint8_t offered[] = { 2, 33 };
    expect_select(offered, 2, &p, RFB_OK, 33);
}

RFB_TEST(security_select, type2_and_33__vnc_mode__selects_2) {
    farsee_rfb_security_policy p = farsee_rfb_security_policy_default();
    p.auth_mode = FARSEE_AUTH_MODE_VNC;
    static const uint8_t offered[] = { 2, 33 };
    expect_select(offered, 2, &p, RFB_OK, 2);
}

RFB_TEST(security_select, type2_and_33__apple_mode__selects_33) {
    farsee_rfb_security_policy p = farsee_rfb_security_policy_default();
    p.auth_mode = FARSEE_AUTH_MODE_APPLE;
    static const uint8_t offered[] = { 2, 33 };
    expect_select(offered, 2, &p, RFB_OK, 33);
}

RFB_TEST(security_select, only_type2__apple_mode__fails) {
    farsee_rfb_security_policy p = farsee_rfb_security_policy_default();
    p.auth_mode = FARSEE_AUTH_MODE_APPLE;
    static const uint8_t offered[] = { 2 };
    expect_select(offered, 1, &p, RFB_ERR_UNSUPPORTED, 0);
}

RFB_TEST(security_select, only_type33__vnc_mode__fails) {
    farsee_rfb_security_policy p = farsee_rfb_security_policy_default();
    p.auth_mode = FARSEE_AUTH_MODE_VNC;
    static const uint8_t offered[] = { 33 };
    expect_select(offered, 1, &p, RFB_ERR_UNSUPPORTED, 0);
}

// ---- legacy type 30 ------------------------------------------------------

RFB_TEST(security_select, only_type30__legacy_off__fails) {
    farsee_rfb_security_policy p = farsee_rfb_security_policy_default();
    p.auth_mode = FARSEE_AUTH_MODE_AUTO;
    p.allow_legacy_apple = false;
    static const uint8_t offered[] = { 30 };
    expect_select(offered, 1, &p, RFB_ERR_UNSUPPORTED, 0);
}

RFB_TEST(security_select, only_type30__legacy_on__selects_30) {
    farsee_rfb_security_policy p = farsee_rfb_security_policy_default();
    p.auth_mode = FARSEE_AUTH_MODE_AUTO;
    p.allow_legacy_apple = true;
    static const uint8_t offered[] = { 30 };
    expect_select(offered, 1, &p, RFB_OK, 30);
}

RFB_TEST(security_select, type30_and_33__legacy_on__prefers_33) {
    farsee_rfb_security_policy p = farsee_rfb_security_policy_default();
    p.auth_mode = FARSEE_AUTH_MODE_AUTO;
    p.allow_legacy_apple = true;
    static const uint8_t offered[] = { 30, 33 };
    expect_select(offered, 2, &p, RFB_OK, 33);
}

// ---- product flags 36 / 35 / allow_vnc / allow_type_33 -------------------

RFB_TEST(security_select, type36_default_off__fails_even_when_offered) {
    farsee_rfb_security_policy p = farsee_rfb_security_policy_default();
    p.auth_mode = FARSEE_AUTH_MODE_AUTO;
    static const uint8_t offered[] = { 36 };
    expect_select(offered, 1, &p, RFB_ERR_UNSUPPORTED, 0);
}

RFB_TEST(security_select, type36_allow_on__auto__selects_36) {
    farsee_rfb_security_policy p = farsee_rfb_security_policy_default();
    p.auth_mode = FARSEE_AUTH_MODE_AUTO;
    p.allow_type_36 = true;
    static const uint8_t offered[] = { 2, 36 };
    expect_select(offered, 2, &p, RFB_OK, 36);
}

RFB_TEST(security_select, type35_allow_on__auto__selects_35) {
    farsee_rfb_security_policy p = farsee_rfb_security_policy_default();
    p.auth_mode = FARSEE_AUTH_MODE_AUTO;
    p.allow_type_35 = true;
    static const uint8_t offered[] = { 2, 35 };
    expect_select(offered, 2, &p, RFB_OK, 35);
}

RFB_TEST(security_select, rank__33_over_36_over_35_over_30_over_2_over_1) {
    farsee_rfb_security_policy p = farsee_rfb_security_policy_default();
    p.auth_mode = FARSEE_AUTH_MODE_AUTO;
    p.allow_none = true;
    p.allow_legacy_apple = true;
    p.allow_type_33 = true;
    p.allow_type_36 = true;
    p.allow_type_35 = true;
    p.allow_vnc = true;
    static const uint8_t all[] = { 1, 2, 30, 33, 35, 36 };
    expect_select(all, 6, &p, RFB_OK, 33);

    static const uint8_t no33[] = { 1, 2, 30, 35, 36 };
    expect_select(no33, 5, &p, RFB_OK, 36);

    static const uint8_t no33_36[] = { 1, 2, 30, 35 };
    expect_select(no33_36, 4, &p, RFB_OK, 35);

    static const uint8_t only_low[] = { 1, 2, 30 };
    expect_select(only_low, 3, &p, RFB_OK, 30);

    static const uint8_t classic[] = { 1, 2 };
    expect_select(classic, 2, &p, RFB_OK, 2);

    static const uint8_t none_only[] = { 1 };
    expect_select(none_only, 1, &p, RFB_OK, 1);
}

RFB_TEST(security_select, allow_vnc_false__skips_type2) {
    farsee_rfb_security_policy p = farsee_rfb_security_policy_default();
    p.auth_mode = FARSEE_AUTH_MODE_AUTO;
    p.allow_vnc = false;
    p.allow_none = true;
    static const uint8_t offered[] = { 1, 2 };
    expect_select(offered, 2, &p, RFB_OK, 1);
}

RFB_TEST(security_select, allow_type33_false__falls_to_classic) {
    farsee_rfb_security_policy p = farsee_rfb_security_policy_default();
    p.auth_mode = FARSEE_AUTH_MODE_AUTO;
    p.allow_type_33 = false;
    static const uint8_t offered[] = { 2, 33 };
    expect_select(offered, 2, &p, RFB_OK, 2);
}

RFB_TEST(security_select, unknown_offered_types_only__fails) {
    farsee_rfb_security_policy p = farsee_rfb_security_policy_default();
    static const uint8_t offered[] = { 16, 19, 99 };
    expect_select(offered, 3, &p, RFB_ERR_UNSUPPORTED, 0);
}
