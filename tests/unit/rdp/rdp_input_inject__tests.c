// SPDX-License-Identifier: Apache-2.0
//
// R6 — RDP FreeRDP input inject null-safety + create-without-connect
// smoke tests. Live input delivery is interop (NEEDS_HARDWARE).

#ifdef FARSEE_WITH_RDP

#include "protocol/rdp/rdp_freerdp_facade.h"
#include "protocol/rdp/rdp_input_inject.h"
#include "farsee/farsee_input.h"
#include "tests/test_framework/rfb_test.h"

#include <freerdp/freerdp.h>
#include <freerdp/input.h>

#include <string.h>

typedef struct rdp_inject_capture {
    unsigned keyboard_calls;
    unsigned unicode_calls;
    unsigned mouse_calls;
    unsigned extended_calls;
    unsigned focus_calls;
    unsigned keyboard_fail_at;
    unsigned unicode_fail_at;
    unsigned mouse_fail_at;
    unsigned extended_fail_at;
    bool focus_result;
    UINT16 keyboard_flags;
    UINT8 keyboard_code;
    UINT16 unicode_flags;
    UINT16 unicode_code;
    UINT16 mouse_flags[16];
    UINT16 mouse_x[16];
    UINT16 mouse_y[16];
    UINT16 extended_flags[16];
} rdp_inject_capture;

typedef struct rdp_inject_fixture {
    rdp_freerdp_ctx *ctx;
    freerdp *instance;
    rdpInput *input;
    void *saved_param1;
    pKeyboardEvent saved_keyboard;
    pUnicodeKeyboardEvent saved_unicode;
    pMouseEvent saved_mouse;
    pExtendedMouseEvent saved_extended;
    pFocusInEvent saved_focus;
    rdp_inject_capture capture;
} rdp_inject_fixture;

static rdp_inject_capture *rdp_inject_capture_from(rdpInput *input)
{
    return input != NULL ? (rdp_inject_capture *)input->param1 : NULL;
}

static BOOL rdp_inject_test_keyboard(rdpInput *input, UINT16 flags, UINT8 code)
{
    rdp_inject_capture *capture = rdp_inject_capture_from(input);
    if (capture == NULL) {
        return FALSE;
    }
    capture->keyboard_calls++;
    capture->keyboard_flags = flags;
    capture->keyboard_code = code;
    return capture->keyboard_fail_at != capture->keyboard_calls;
}

static BOOL rdp_inject_test_unicode(rdpInput *input, UINT16 flags, UINT16 code)
{
    rdp_inject_capture *capture = rdp_inject_capture_from(input);
    if (capture == NULL) {
        return FALSE;
    }
    capture->unicode_calls++;
    capture->unicode_flags = flags;
    capture->unicode_code = code;
    return capture->unicode_fail_at != capture->unicode_calls;
}

static BOOL rdp_inject_test_mouse(rdpInput *input, UINT16 flags,
                                  UINT16 x, UINT16 y)
{
    rdp_inject_capture *capture = rdp_inject_capture_from(input);
    if (capture == NULL) {
        return FALSE;
    }
    capture->mouse_calls++;
    const size_t index = (size_t)(capture->mouse_calls - 1u);
    if (index < sizeof capture->mouse_flags / sizeof capture->mouse_flags[0]) {
        capture->mouse_flags[index] = flags;
        capture->mouse_x[index] = x;
        capture->mouse_y[index] = y;
    }
    return capture->mouse_fail_at != capture->mouse_calls;
}

static BOOL rdp_inject_test_extended(rdpInput *input, UINT16 flags,
                                     UINT16 x, UINT16 y)
{
    (void)x;
    (void)y;
    rdp_inject_capture *capture = rdp_inject_capture_from(input);
    if (capture == NULL) {
        return FALSE;
    }
    capture->extended_calls++;
    const size_t index = (size_t)(capture->extended_calls - 1u);
    if (index < sizeof capture->extended_flags /
                    sizeof capture->extended_flags[0]) {
        capture->extended_flags[index] = flags;
    }
    return capture->extended_fail_at != capture->extended_calls;
}

static BOOL rdp_inject_test_focus(rdpInput *input, UINT16 toggle_states)
{
    (void)toggle_states;
    rdp_inject_capture *capture = rdp_inject_capture_from(input);
    if (capture == NULL) {
        return FALSE;
    }
    capture->focus_calls++;
    return capture->focus_result ? TRUE : FALSE;
}

static bool rdp_inject_fixture_start(rdp_inject_fixture *fixture)
{
    if (fixture == NULL) {
        return false;
    }
    memset(fixture, 0, sizeof *fixture);
    fixture->ctx = rdp_freerdp_create();
    if (fixture->ctx == NULL) {
        return false;
    }
    fixture->instance =
        (freerdp *)rdp_freerdp_instance_opaque(fixture->ctx);
    if (fixture->instance == NULL || fixture->instance->context == NULL ||
        fixture->instance->context->input == NULL) {
        rdp_freerdp_destroy(&fixture->ctx);
        return false;
    }
    fixture->input = fixture->instance->context->input;
    fixture->saved_param1 = fixture->input->param1;
    fixture->saved_keyboard = fixture->input->KeyboardEvent;
    fixture->saved_unicode = fixture->input->UnicodeKeyboardEvent;
    fixture->saved_mouse = fixture->input->MouseEvent;
    fixture->saved_extended = fixture->input->ExtendedMouseEvent;
    fixture->saved_focus = fixture->input->FocusInEvent;
    fixture->capture.focus_result = true;
    fixture->input->param1 = &fixture->capture;
    fixture->input->KeyboardEvent = rdp_inject_test_keyboard;
    fixture->input->UnicodeKeyboardEvent = rdp_inject_test_unicode;
    fixture->input->MouseEvent = rdp_inject_test_mouse;
    fixture->input->ExtendedMouseEvent = rdp_inject_test_extended;
    fixture->input->FocusInEvent = rdp_inject_test_focus;
    return true;
}

static void rdp_inject_fixture_stop(rdp_inject_fixture *fixture)
{
    if (fixture == NULL || fixture->ctx == NULL) {
        return;
    }
    fixture->input->param1 = fixture->saved_param1;
    fixture->input->KeyboardEvent = fixture->saved_keyboard;
    fixture->input->UnicodeKeyboardEvent = fixture->saved_unicode;
    fixture->input->MouseEvent = fixture->saved_mouse;
    fixture->input->ExtendedMouseEvent = fixture->saved_extended;
    fixture->input->FocusInEvent = fixture->saved_focus;
    rdp_freerdp_destroy(&fixture->ctx);
}

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
        .wheel_h = -120,  // Horizontal-wheel path.
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

RFB_TEST(rdp_inject, callback_fixture__covers_focus_and_key_results)
{
    rdp_inject_fixture fixture;
    RFB_CHECK(rdp_inject_fixture_start(&fixture));
    if (fixture.ctx == NULL) {
        return;
    }

    RFB_CHECK(rdp_input_inject_focus_in(fixture.ctx));
    RFB_CHECK_EQ_UINT(fixture.capture.focus_calls, 1u);
    fixture.capture.focus_result = false;
    RFB_CHECK(!rdp_input_inject_focus_in(fixture.ctx));

    farsee_key_event key;
    memset(&key, 0, sizeof key);
    key.physical = 0x1eu;
    key.action = FARSEE_KEY_PRESS;
    RFB_CHECK(rdp_input_inject_key(fixture.ctx, &key));
    key.action = FARSEE_KEY_REPEAT;
    RFB_CHECK(rdp_input_inject_key(fixture.ctx, &key));
    key.action = FARSEE_KEY_RELEASE;
    RFB_CHECK(rdp_input_inject_key(fixture.ctx, &key));
    RFB_CHECK_EQ_UINT(fixture.capture.keyboard_calls, 3u);
    fixture.capture.keyboard_fail_at = 4u;
    RFB_CHECK(!rdp_input_inject_key(fixture.ctx, &key));

    memset(&key, 0, sizeof key);
    key.unicode = (uint32_t)'A';
    key.action = FARSEE_KEY_PRESS;
    RFB_CHECK(rdp_input_inject_key(fixture.ctx, &key));
    RFB_CHECK_EQ_UINT(fixture.capture.unicode_code, (UINT16)'A');
    key.action = FARSEE_KEY_RELEASE;
    RFB_CHECK(rdp_input_inject_key(fixture.ctx, &key));
    RFB_CHECK((fixture.capture.unicode_flags & KBD_FLAGS_RELEASE) != 0u);
    fixture.capture.unicode_fail_at = fixture.capture.unicode_calls + 1u;
    RFB_CHECK(!rdp_input_inject_key(fixture.ctx, &key));
    key.unicode = 0x10000u;
    RFB_CHECK(!rdp_input_inject_key(fixture.ctx, &key));

    fixture.capture.keyboard_fail_at = 0u;
    RFB_CHECK(rdp_input_inject_key_from_keysym(
        fixture.ctx, (uint32_t)'a', 0u, true, true));
    RFB_CHECK(rdp_input_inject_key_from_keysym(
        fixture.ctx, UINT32_C(0xdeadbeef), (uint32_t)'x', true, false));
    RFB_CHECK(!rdp_input_inject_key_from_keysym(
        fixture.ctx, UINT32_C(0xdeadbeef), 0x10000u, true, false));

    rdpInput *saved_input = fixture.instance->context->input;
    fixture.instance->context->input = NULL;
    RFB_CHECK(!rdp_input_inject_focus_in(fixture.ctx));
    RFB_CHECK(!rdp_input_inject_key(fixture.ctx, &key));
    RFB_CHECK(!rdp_input_inject_key_from_keysym(
        fixture.ctx, (uint32_t)'a', 0u, true, false));
    fixture.instance->context->input = saved_input;
    rdpContext *saved_context = fixture.instance->context;
    fixture.instance->context = NULL;
    RFB_CHECK(!rdp_input_inject_focus_in(fixture.ctx));
    fixture.instance->context = saved_context;

    rdp_inject_fixture_stop(&fixture);
}

RFB_TEST(rdp_inject, callback_fixture__covers_pointer_edges_and_wheels)
{
    rdp_inject_fixture fixture;
    RFB_CHECK(rdp_inject_fixture_start(&fixture));
    if (fixture.ctx == NULL) {
        return;
    }

    farsee_pointer_event pointer;
    memset(&pointer, 0, sizeof pointer);
    pointer.abs_x = 100;
    pointer.abs_y = 200;
    RFB_CHECK(rdp_input_inject_pointer(fixture.ctx, &pointer, 0u, NULL));
    RFB_CHECK_EQ_UINT(fixture.capture.mouse_calls, 1u);
    RFB_CHECK_EQ_UINT(fixture.capture.mouse_x[0], 100u);
    RFB_CHECK_EQ_UINT(fixture.capture.mouse_y[0], 200u);
    fixture.capture.mouse_fail_at = 2u;
    RFB_CHECK(!rdp_input_inject_pointer(fixture.ctx, &pointer, 0u, NULL));
    fixture.capture.mouse_fail_at = 0u;

    static const unsigned buttons[] = {
        FARSEE_BUTTON_LEFT,
        FARSEE_BUTTON_MIDDLE,
        FARSEE_BUTTON_RIGHT,
        FARSEE_BUTTON_X1,
        FARSEE_BUTTON_X2,
    };
    pointer.abs_x = -1;
    pointer.abs_y = 0x10000;
    pointer.wheel_v = 0;
    pointer.wheel_h = 0;
    for (size_t i = 0u; i < sizeof buttons / sizeof buttons[0]; i++) {
        unsigned reached = 0u;
        pointer.buttons = buttons[i];
        RFB_CHECK(rdp_input_inject_pointer(
            fixture.ctx, &pointer, 0u, &reached));
        RFB_CHECK_EQ_UINT(reached, buttons[i]);
        pointer.buttons = 0u;
        RFB_CHECK(rdp_input_inject_pointer(
            fixture.ctx, &pointer, buttons[i], &reached));
        RFB_CHECK_EQ_UINT(reached, 0u);
    }
    RFB_CHECK(fixture.capture.extended_calls >= 4u);

    pointer.buttons = 0u;
    pointer.wheel_v = 120;
    pointer.wheel_h = -120;
    RFB_CHECK(rdp_input_inject_pointer(fixture.ctx, &pointer, 0u, NULL));
    pointer.wheel_v = -120;
    pointer.wheel_h = 120;
    RFB_CHECK(rdp_input_inject_pointer(fixture.ctx, &pointer, 0u, NULL));

    memset(&pointer, 0, sizeof pointer);
    pointer.abs_x = -1;
    pointer.abs_y = -1;
    pointer.buttons = FARSEE_BUTTON_LEFT | FARSEE_BUTTON_MIDDLE;
    unsigned reached = 99u;
    fixture.capture.mouse_fail_at = fixture.capture.mouse_calls + 2u;
    RFB_CHECK(!rdp_input_inject_pointer(
        fixture.ctx, &pointer, 0u, &reached));
    RFB_CHECK_EQ_UINT(reached, FARSEE_BUTTON_LEFT);
    fixture.capture.mouse_fail_at = 0u;
    pointer.buttons = 1u << 12;
    reached = 0u;
    RFB_CHECK(!rdp_input_inject_pointer(
        fixture.ctx, &pointer, 0u, &reached));
    RFB_CHECK_EQ_UINT(reached, 0u);

    rdpInput *saved_input = fixture.instance->context->input;
    fixture.instance->context->input = NULL;
    RFB_CHECK(!rdp_input_inject_pointer(
        fixture.ctx, &pointer, 0u, &reached));
    fixture.instance->context->input = saved_input;
    rdp_inject_fixture_stop(&fixture);
}

RFB_TEST(rdp_inject, callback_fixture__covers_release_cleanup_results)
{
    rdp_inject_fixture fixture;
    RFB_CHECK(rdp_inject_fixture_start(&fixture));
    if (fixture.ctx == NULL) {
        return;
    }

    farsee_key_ledger ledger;
    farsee_key_ledger_init(&ledger);
    ledger.count = FARSEE_KEY_LEDGER_MAX + 1u;
    for (size_t i = 0u; i < FARSEE_KEY_LEDGER_MAX; i++) {
        ledger.down[i] = (farsee_physical_key)(i + 1u);
    }
    rdp_input_inject_release_all(fixture.ctx, &ledger);
    RFB_CHECK_EQ_UINT(ledger.count, 0u);

    farsee_key_ledger_init(&ledger);
    ledger.count = 1u;
    ledger.down[0] = 0u;
    rdp_input_inject_release_all(fixture.ctx, &ledger);
    RFB_CHECK_EQ_UINT(ledger.count, 1u);

    farsee_key_ledger_init(&ledger);
    ledger.count = 1u;
    ledger.down[0] = 0x1eu;
    fixture.capture.keyboard_fail_at = fixture.capture.keyboard_calls + 1u;
    rdp_input_inject_release_all(fixture.ctx, &ledger);
    RFB_CHECK_EQ_UINT(ledger.count, 1u);
    fixture.capture.keyboard_fail_at = 0u;

    unsigned buttons = FARSEE_BUTTON_LEFT;
    RFB_CHECK(rdp_input_inject_release_buttons(
        fixture.ctx, NULL, -1, -1));
    unsigned none = 0u;
    RFB_CHECK(rdp_input_inject_release_buttons(
        fixture.ctx, &none, -1, -1));
    RFB_CHECK(!rdp_input_inject_release_buttons(NULL, &buttons, -1, -1));
    RFB_CHECK(rdp_input_inject_release_buttons(
        fixture.ctx, &buttons, -1, -1));
    RFB_CHECK_EQ_UINT(buttons, 0u);
    buttons = FARSEE_BUTTON_LEFT;
    fixture.capture.mouse_fail_at = fixture.capture.mouse_calls + 1u;
    RFB_CHECK(!rdp_input_inject_release_buttons(
        fixture.ctx, &buttons, -1, -1));
    RFB_CHECK_EQ_UINT(buttons, FARSEE_BUTTON_LEFT);

    rdp_inject_fixture_stop(&fixture);
}

#endif  // FARSEE_WITH_RDP
