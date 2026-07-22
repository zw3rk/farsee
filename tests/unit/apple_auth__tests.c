// SPDX-License-Identifier: Apache-2.0
//
// G15 — Apple dialect and auth state-machine framework tests.
// Uses fake deterministic providers — no real Apple crypto.

#include "rfb_test.h"
#include "farsee/apple_auth.h"
#include <string.h>

// --- Dialect detection ---------------------------------------------------

RFB_TEST(g15, dialect__apple_003_889__recognized) {
    static const uint8_t banner[12] = {
        'R','F','B',' ','0','0','3','.','8','8','9','\n'
    };
    RFB_CHECK(apple_is_dialect_003_889(banner, 12));
}

RFB_TEST(g15, dialect__standard_003_008__not_apple) {
    static const uint8_t banner[12] = {
        'R','F','B',' ','0','0','3','.','0','0','8','\n'
    };
    RFB_CHECK(!apple_is_dialect_003_889(banner, 12));
}

RFB_TEST(g15, dialect__null_or_short__false) {
    RFB_CHECK(!apple_is_dialect_003_889(NULL, 12));
    RFB_CHECK(!apple_is_dialect_003_889((const uint8_t *)"short", 5));
}

// --- Security type selection policy --------------------------------------

RFB_TEST(g15, select__type33_preferred) {
    static const uint8_t types[] = { 30, 33, 36 };
    RFB_CHECK_EQ_INT(apple_select_security_type(types, 3, false), 33);
}

RFB_TEST(g15, select__type36_when_no_33) {
    static const uint8_t types[] = { 30, 36 };
    RFB_CHECK_EQ_INT(apple_select_security_type(types, 2, false), 36);
}

RFB_TEST(g15, select__type35_when_no_33_36) {
    static const uint8_t types[] = { 30, 35 };
    RFB_CHECK_EQ_INT(apple_select_security_type(types, 2, false), 35);
}

RFB_TEST(g15, select__type30_only_with_allow_legacy) {
    static const uint8_t types[] = { 30 };
    RFB_CHECK_EQ_INT(apple_select_security_type(types, 1, false), 0);
    RFB_CHECK_EQ_INT(apple_select_security_type(types, 1, true), 30);
}

RFB_TEST(g15, select__no_apple_types__zero) {
    static const uint8_t types[] = { 2, 1 };  // VNC, None
    RFB_CHECK_EQ_INT(apple_select_security_type(types, 2, true), 0);
}

RFB_TEST(g15, select__empty__zero) {
    RFB_CHECK_EQ_INT(apple_select_security_type(NULL, 0, true), 0);
}

// --- Fake auth provider --------------------------------------------------

RFB_TEST(g15, fake_provider__two_messages_then_authenticated) {
    static const uint8_t key[16] = { 0xAA, 0xBB, 0xCC, 0xDD };
    apple_auth_fake fake;
    apple_auth_fake_init(&fake, 2, key);
    apple_auth_ctx ctx = apple_auth_fake_ctx(&fake);

    uint8_t out[64]; size_t out_len = 0;
    uint8_t wrap_key[16] = { 0 };

    // First message: NEED_MORE.
    apple_auth_result_t r1 = ctx.ops->process(&ctx, NULL, 0,
        out, sizeof out, &out_len, wrap_key);
    RFB_CHECK_EQ_INT(r1, APPLE_AUTH_NEED_MORE);

    // Second message: AUTHENTICATED.
    apple_auth_result_t r2 = ctx.ops->process(&ctx, NULL, 0,
        out, sizeof out, &out_len, wrap_key);
    RFB_CHECK_EQ_INT(r2, APPLE_AUTH_AUTHENTICATED);
    RFB_CHECK_MEM_EQ(wrap_key, key, 16);

    ctx.ops->destroy(&ctx);
    // Wrap key should be zeroized after destroy.
    bool all_zero = true;
    for (int i = 0; i < 16; i++) if (fake.wrap_key[i] != 0) { all_zero = false; break; }
    RFB_CHECK(all_zero);
}

RFB_TEST(g15, fake_provider__single_message_authenticated) {
    static const uint8_t key[16] = { 0x01 };
    apple_auth_fake fake;
    apple_auth_fake_init(&fake, 1, key);
    apple_auth_ctx ctx = apple_auth_fake_ctx(&fake);

    uint8_t out[64]; size_t out_len = 0;
    uint8_t wrap_key[16] = { 0 };

    apple_auth_result_t r = ctx.ops->process(&ctx, NULL, 0,
        out, sizeof out, &out_len, wrap_key);
    RFB_CHECK_EQ_INT(r, APPLE_AUTH_AUTHENTICATED);
    RFB_CHECK_MEM_EQ(wrap_key, key, 16);

    ctx.ops->destroy(&ctx);
}
