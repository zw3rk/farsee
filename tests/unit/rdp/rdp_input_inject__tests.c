// SPDX-License-Identifier: Apache-2.0
//
// WP-A / R6 — RDP FreeRDP input inject null-safety + create-without-connect
// smoke tests. Live input delivery is interop (NEEDS_HARDWARE).

#ifdef FARSEE_WITH_RDP

#include "protocol/rdp/rdp_freerdp_facade.h"
#include "protocol/rdp/rdp_input_inject.h"
#include "farsee/farsee_input.h"
#include "tests/test_framework/rfb_test.h"

RFB_TEST(rdp_inject, null_ctx__all_apis_safe)
{
    farsee_key_event ke = {.physical = 0x1E, .action = FARSEE_KEY_PRESS};
    farsee_pointer_event pe = {.abs_x = 10, .abs_y = 20, .buttons = 0};
    farsee_key_ledger ledger;
    farsee_key_ledger_init(&ledger);

    RFB_CHECK(!rdp_input_inject_key(NULL, &ke));
    RFB_CHECK(!rdp_input_inject_key_from_keysym(NULL, 0x61u, 0, true, false));
    RFB_CHECK(!rdp_input_inject_pointer(NULL, &pe, 0, NULL));
    RFB_CHECK(!rdp_input_inject_focus_in(NULL));
    rdp_input_inject_release_all(NULL, &ledger);  // no crash
    rdp_input_inject_release_all(NULL, NULL);
}

RFB_TEST(rdp_inject, null_event__safe)
{
    rdp_freerdp_ctx *ctx = rdp_freerdp_create();
    RFB_CHECK(ctx != NULL);

    RFB_CHECK(!rdp_input_inject_key(ctx, NULL));
    RFB_CHECK(!rdp_input_inject_pointer(ctx, NULL, 0, NULL));
    rdp_input_inject_release_all(ctx, NULL);  // no crash

    rdp_freerdp_destroy(&ctx);
    RFB_CHECK(ctx == NULL);
}

RFB_TEST(rdp_inject, create_without_connect__inject_no_crash)
{
    // After freerdp_context_new the input object exists, but no transport is
    // up. Inject must not crash: may return false (no peer) or true (queued
    // into an idle FreeRDP input path). Either is acceptable for this gate.
    rdp_freerdp_ctx *ctx = rdp_freerdp_create();
    RFB_CHECK(ctx != NULL);

    farsee_key_event press = {
        .physical = 0x1E,
        .logical = 0x61u,
        .action = FARSEE_KEY_PRESS,
        .quality = FARSEE_INPUT_QUALITY_INFERRED,
    };
    (void)rdp_input_inject_key(ctx, &press);

    farsee_key_event rel = press;
    rel.action = FARSEE_KEY_RELEASE;
    (void)rdp_input_inject_key(ctx, &rel);

    (void)rdp_input_inject_key_from_keysym(ctx, 0x61u /* a */, 0, true, false);
    (void)rdp_input_inject_key_from_keysym(ctx, 0x61u, 0, false, false);
    // Unicode-only path (no scancode identity).
    (void)rdp_input_inject_key_from_keysym(ctx, 0xDEADBEEFu, (uint32_t)'x', true, false);
    (void)rdp_input_inject_key_from_keysym(ctx, 0xDEADBEEFu, (uint32_t)'x', false, false);

    farsee_pointer_event pe = {
        .abs_x = 100,
        .abs_y = 200,
        .buttons = FARSEE_BUTTON_LEFT,
        .wheel_v = 120,
        .wheel_h = -120,  // HWHEEL path (T25)
        .quality = FARSEE_INPUT_QUALITY_EXACT,
    };
    unsigned reached = 0;
    (void)rdp_input_inject_pointer(ctx, &pe, 0, &reached);
    pe.buttons = 0;
    pe.wheel_v = 0;
    pe.wheel_h = 240;  // two notches horizontal
    (void)rdp_input_inject_pointer(ctx, &pe, FARSEE_BUTTON_LEFT, &reached);

    farsee_key_ledger ledger;
    farsee_key_ledger_init(&ledger);
    RFB_CHECK(farsee_key_ledger_apply(&ledger, &press));
    rdp_input_inject_release_all(ctx, &ledger);
    RFB_CHECK_EQ_UINT((unsigned)ledger.count, 0u);

    rdp_freerdp_destroy(&ctx);
}

RFB_TEST(rdp_inject, key_without_identity__returns_false)
{
    rdp_freerdp_ctx *ctx = rdp_freerdp_create();
    RFB_CHECK(ctx != NULL);

    farsee_key_event empty = {0};
    empty.action = FARSEE_KEY_PRESS;
    RFB_CHECK(!rdp_input_inject_key(ctx, &empty));
    RFB_CHECK(!rdp_input_inject_key_from_keysym(ctx, 0xDEADBEEFu, 0, true, false));

    rdp_freerdp_destroy(&ctx);
}

#endif  // FARSEE_WITH_RDP
