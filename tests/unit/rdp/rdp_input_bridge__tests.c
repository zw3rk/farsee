// SPDX-License-Identifier: Apache-2.0
//
// R4 — RDP input bridge tests (§15.11).

#ifdef FARSEE_WITH_RDP

#include "protocol/rdp/rdp_input_bridge.h"
#include "tests/test_framework/rfb_test.h"

RFB_TEST(rdp_input, key_dispatch__physical_uses_scancode)
{
    farsee_key_event e = {.physical = 0x1E, .unicode = 0, .quality = FARSEE_INPUT_QUALITY_EXACT};
    RFB_CHECK(rdp_input_key_dispatch(&e) == RDP_KEY_SCANCODE);
}

RFB_TEST(rdp_input, key_dispatch__text_only_uses_unicode)
{
    farsee_key_event e = {.physical = 0, .unicode = 'A', .quality = FARSEE_INPUT_QUALITY_INFERRED};
    RFB_CHECK(rdp_input_key_dispatch(&e) == RDP_KEY_UNICODE);
}

RFB_TEST(rdp_input, key_dispatch__no_identity_drops)
{
    farsee_key_event e = {.physical = 0, .unicode = 0, .quality = FARSEE_INPUT_QUALITY_UNAVAILABLE};
    RFB_CHECK(rdp_input_key_dispatch(&e) == RDP_KEY_DROP);
    RFB_CHECK(rdp_input_key_dispatch(NULL) == RDP_KEY_DROP);
}

RFB_TEST(rdp_input, button_transition__maps_to_rdp_button)
{
    // Left press: prev=0, curr=LEFT -> button 1.
    RFB_CHECK_EQ_UINT(rdp_input_button_for_transition(0, FARSEE_BUTTON_LEFT), 1u);
    // Right press.
    RFB_CHECK_EQ_UINT(rdp_input_button_for_transition(0, FARSEE_BUTTON_RIGHT), 3u);
    // No transition.
    RFB_CHECK_EQ_UINT(rdp_input_button_for_transition(FARSEE_BUTTON_LEFT, FARSEE_BUTTON_LEFT), 0u);
    // Release (curr clears a bit): prev=LEFT, curr=0 -> still button 1.
    RFB_CHECK_EQ_UINT(rdp_input_button_for_transition(FARSEE_BUTTON_LEFT, 0), 1u);
}

// D3: protocol sticky button sync without FreeRDP.
RFB_TEST(rdp_input, button_wire__down_ok_clears_pending)
{
    rdp_button_wire_state s;
    rdp_button_wire_init(&s);
    rdp_button_wire_note_cmd(&s, FARSEE_BUTTON_LEFT, 10, 20);
    RFB_CHECK(rdp_button_wire_needs_sync(&s));
    rdp_button_wire_note_inject(&s, FARSEE_BUTTON_LEFT);
    RFB_CHECK(!rdp_button_wire_needs_sync(&s));
    RFB_CHECK_EQ_UINT(s.wire, FARSEE_BUTTON_LEFT);
}

RFB_TEST(rdp_input, button_wire__release_partial_stays_pending)
{
    rdp_button_wire_state s;
    rdp_button_wire_init(&s);
    rdp_button_wire_note_cmd(&s, FARSEE_BUTTON_LEFT, 1, 1);
    rdp_button_wire_note_inject(&s, FARSEE_BUTTON_LEFT);
    RFB_CHECK(!rdp_button_wire_needs_sync(&s));
    // User release: desired 0, inject only progresses partially (stays LEFT).
    rdp_button_wire_note_cmd(&s, 0u, 1, 1);
    RFB_CHECK(rdp_button_wire_needs_sync(&s));
    rdp_button_wire_note_inject(&s, FARSEE_BUTTON_LEFT); // fail: still held
    RFB_CHECK(rdp_button_wire_needs_sync(&s));
    RFB_CHECK_EQ_UINT(s.wire, FARSEE_BUTTON_LEFT);
    RFB_CHECK_EQ_UINT(s.desired, 0u);
    // Mid-session retry succeeds without new user event.
    rdp_button_wire_note_inject(&s, 0u);
    RFB_CHECK(!rdp_button_wire_needs_sync(&s));
    RFB_CHECK_EQ_UINT(s.wire, 0u);
}

RFB_TEST(rdp_input, button_wire__null_safe)
{
    rdp_button_wire_init(NULL);
    rdp_button_wire_note_cmd(NULL, 1u, 0, 0);
    rdp_button_wire_note_inject(NULL, 0u);
    RFB_CHECK(!rdp_button_wire_needs_sync(NULL));
}

// D3 regression: motion/drag with unchanged mask must not require pending.
// (Protocol always injects original pe; sticky is only for incomplete edges.)
RFB_TEST(rdp_input, button_wire__same_mask_no_pending_after_inject)
{
    rdp_button_wire_state s;
    rdp_button_wire_init(&s);
    rdp_button_wire_note_cmd(&s, FARSEE_BUTTON_LEFT, 5, 5);
    rdp_button_wire_note_inject(&s, FARSEE_BUTTON_LEFT);
    RFB_CHECK(!rdp_button_wire_needs_sync(&s));
    // Drag: same buttons, new coords — note_cmd alone would clear pending;
    // inject path injects full pe independently (codex 68264760 r1 P1).
    rdp_button_wire_note_cmd(&s, FARSEE_BUTTON_LEFT, 6, 6);
    RFB_CHECK(!rdp_button_wire_needs_sync(&s));
    rdp_button_wire_note_inject(&s, FARSEE_BUTTON_LEFT);
    RFB_CHECK(!rdp_button_wire_needs_sync(&s));
    RFB_CHECK_EQ_INT(s.abs_x, 6);
}

RFB_TEST(rdp_input, wheel_notches__multiples_of_120)
{
    RFB_CHECK_EQ_INT(rdp_input_wheel_notches(120), 1);
    RFB_CHECK_EQ_INT(rdp_input_wheel_notches(240), 2);
    RFB_CHECK_EQ_INT(rdp_input_wheel_notches(119), 0);   // sub-notch truncated
    RFB_CHECK_EQ_INT(rdp_input_wheel_notches(-120), -1); // symmetric
    RFB_CHECK_EQ_INT(rdp_input_wheel_notches(-119), 0);
}

// --- keysym → set-1 scancode (WP-A / R6 input inject) ---------------------
// Clean-room: X11 keysym registry + IBM AT/PS2 set-1 / MS-RDPBCGR codes.

static void check_scancode(uint32_t keysym, uint32_t expect_sc, bool expect_ext)
{
    uint32_t sc = 0xFFFFFFFFu;
    bool ext = !expect_ext;
    RFB_CHECK(rdp_input_keysym_to_scancode(keysym, &sc, &ext));
    RFB_CHECK_EQ_UINT(sc, expect_sc);
    RFB_CHECK(ext == expect_ext);
}

RFB_TEST(rdp_input, keysym_to_scancode__letters_a_z)
{
    // a-z → standard set-1 QWERTY row scancodes.
    check_scancode(0x61u /* a */, 0x1Eu, false);
    check_scancode(0x62u /* b */, 0x30u, false);
    check_scancode(0x63u /* c */, 0x2Eu, false);
    check_scancode(0x64u /* d */, 0x20u, false);
    check_scancode(0x65u /* e */, 0x12u, false);
    check_scancode(0x7Au /* z */, 0x2Cu, false);
    // Uppercase uses the same physical keys.
    check_scancode(0x41u /* A */, 0x1Eu, false);
    check_scancode(0x5Au /* Z */, 0x2Cu, false);
}

RFB_TEST(rdp_input, keysym_to_scancode__digits_and_controls)
{
    check_scancode(0x30u /* 0 */, 0x0Bu, false);
    check_scancode(0x31u /* 1 */, 0x02u, false);
    check_scancode(0x39u /* 9 */, 0x0Au, false);
    check_scancode(0x20u /* space */, 0x39u, false);
    check_scancode(0xFF0Du /* Return */, 0x1Cu, false);
    check_scancode(0xFF09u /* Tab */, 0x0Fu, false);
    check_scancode(0xFF1Bu /* Escape */, 0x01u, false);
    check_scancode(0xFF08u /* BackSpace */, 0x0Eu, false);
}

RFB_TEST(rdp_input, keysym_to_scancode__arrows_are_extended)
{
    check_scancode(0xFF51u /* Left */, 0x4Bu, true);
    check_scancode(0xFF52u /* Up */, 0x48u, true);
    check_scancode(0xFF53u /* Right */, 0x4Du, true);
    check_scancode(0xFF54u /* Down */, 0x50u, true);
}

RFB_TEST(rdp_input, keysym_to_scancode__nav_fkeys_modifiers)
{
    check_scancode(0xFF50u /* Home */, 0x47u, true);
    check_scancode(0xFF57u /* End */, 0x4Fu, true);
    check_scancode(0xFF55u /* Page_Up */, 0x49u, true);
    check_scancode(0xFF56u /* Page_Down */, 0x51u, true);
    check_scancode(0xFF63u /* Insert */, 0x52u, true);
    check_scancode(0xFFFFu /* Delete */, 0x53u, true);
    check_scancode(0xFFBEu /* F1 */, 0x3Bu, false);
    check_scancode(0xFFC7u /* F10 */, 0x44u, false);
    check_scancode(0xFFC8u /* F11 */, 0x57u, false);
    check_scancode(0xFFC9u /* F12 */, 0x58u, false);
    check_scancode(0xFFE1u /* Shift_L */, 0x2Au, false);
    check_scancode(0xFFE3u /* Control_L */, 0x1Du, false);
    check_scancode(0xFFE9u /* Alt_L */, 0x38u, false);
    check_scancode(0xFFEBu /* Super_L */, 0x5Bu, true);
    check_scancode(0xFFE7u /* Meta_L */, 0x5Bu, true);
}

RFB_TEST(rdp_input, keysym_to_scancode__unknown_returns_false)
{
    uint32_t sc = 99u;
    bool ext = true;
    RFB_CHECK(!rdp_input_keysym_to_scancode(0xDEADBEEFu, &sc, &ext));
    RFB_CHECK(!rdp_input_keysym_to_scancode(0x61u, NULL, &ext));
    RFB_CHECK(!rdp_input_keysym_to_scancode(0x61u, &sc, NULL));
    RFB_CHECK(!rdp_input_keysym_to_scancode(0x61u, NULL, NULL));
}

RFB_TEST(rdp_input, key_event_from_keysym__fills_physical_and_action)
{
    farsee_key_event e;
    RFB_CHECK(rdp_input_key_event_from_keysym(&e, 0x61u /* a */, 0, true, false));
    RFB_CHECK_EQ_UINT(e.physical, 0x1Eu);  // non-extended packed scancode
    RFB_CHECK_EQ_UINT(e.logical, 0x61u);
    RFB_CHECK(e.action == FARSEE_KEY_PRESS);
    RFB_CHECK(rdp_input_key_event_from_keysym(&e, 0xFF51u /* Left */, 0, false, false));
    RFB_CHECK_EQ_UINT(e.physical, 0x4Bu | 0x100u);  // extended bit set
    RFB_CHECK(e.action == FARSEE_KEY_RELEASE);
    RFB_CHECK(!rdp_input_key_event_from_keysym(NULL, 0x61u, 0, true, false));
}

#endif  // FARSEE_WITH_RDP
