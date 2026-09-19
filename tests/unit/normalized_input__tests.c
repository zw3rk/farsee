// SPDX-License-Identifier: Apache-2.0
//
// Normalized input layer tests.

#include "rfb_test.h"
#include "farsee/normalized_input.h"

#include <string.h>

// ===========================================================================
// Modifier keysym classification
// ===========================================================================

RFB_TEST(norm_mod, modkey_from_sym__shift_left_right__shift) {
    RFB_CHECK_EQ_INT(rfb_norm_modkey_from_sym(XK_Shift_L), RFB_MODKEY_SHIFT);
    RFB_CHECK_EQ_INT(rfb_norm_modkey_from_sym(XK_Shift_R), RFB_MODKEY_SHIFT);
}

RFB_TEST(norm_mod, modkey_from_sym__control__control) {
    RFB_CHECK_EQ_INT(rfb_norm_modkey_from_sym(XK_Control_L), RFB_MODKEY_CONTROL);
    RFB_CHECK_EQ_INT(rfb_norm_modkey_from_sym(XK_Control_R), RFB_MODKEY_CONTROL);
}

RFB_TEST(norm_mod, modkey_from_sym__alt__alt) {
    RFB_CHECK_EQ_INT(rfb_norm_modkey_from_sym(XK_Alt_L), RFB_MODKEY_ALT);
    RFB_CHECK_EQ_INT(rfb_norm_modkey_from_sym(XK_Alt_R), RFB_MODKEY_ALT);
}

RFB_TEST(norm_mod, modkey_from_sym__super__meta_command) {
    // Super is used for Command on macOS.
    RFB_CHECK_EQ_INT(rfb_norm_modkey_from_sym(XK_Super_L), RFB_MODKEY_META);
    RFB_CHECK_EQ_INT(rfb_norm_modkey_from_sym(XK_Super_R), RFB_MODKEY_META);
    RFB_CHECK_EQ_INT(rfb_norm_modkey_from_sym(XK_Meta_L), RFB_MODKEY_META);
    RFB_CHECK_EQ_INT(rfb_norm_modkey_from_sym(XK_Meta_R), RFB_MODKEY_META);
}

RFB_TEST(norm_mod, modkey_from_sym__capslock__capslock) {
    RFB_CHECK_EQ_INT(rfb_norm_modkey_from_sym(XK_Caps_Lock), RFB_MODKEY_CAPSLOCK);
}

RFB_TEST(norm_mod, modkey_from_sym__non_modifier__none) {
    RFB_CHECK_EQ_INT(rfb_norm_modkey_from_sym(0x0061u), RFB_MODKEY_NONE); // 'a'
    RFB_CHECK_EQ_INT(rfb_norm_modkey_from_sym(XK_Return), RFB_MODKEY_NONE);
    RFB_CHECK_EQ_INT(rfb_norm_modkey_from_sym(0u), RFB_MODKEY_NONE);
}

// ===========================================================================
// Modifier tracker — press/release, left/right collapse
// ===========================================================================

RFB_TEST(norm_mod, apply__shift_left_press_sets_shift_bit) {
    rfb_norm_mods m;
    rfb_norm_mods_init(&m);
    RFB_CHECK_EQ_UINT(rfb_norm_mods_bits(&m), RFB_MOD_NONE);
    uint16_t bits = rfb_norm_mods_apply(&m, XK_Shift_L, true);
    RFB_CHECK_EQ_UINT(bits, RFB_MOD_SHIFT);
    RFB_CHECK_EQ_UINT(rfb_norm_mods_bits(&m), RFB_MOD_SHIFT);
}

RFB_TEST(norm_mod, apply__shift_release_clears_bit) {
    rfb_norm_mods m;
    rfb_norm_mods_init(&m);
    rfb_norm_mods_apply(&m, XK_Shift_L, true);
    uint16_t bits = rfb_norm_mods_apply(&m, XK_Shift_L, false);
    RFB_CHECK_EQ_UINT(bits, RFB_MOD_NONE);
}

RFB_TEST(norm_mod, apply__left_and_right_both_held__bit_set_until_both_released) {
    rfb_norm_mods m;
    rfb_norm_mods_init(&m);
    rfb_norm_mods_apply(&m, XK_Control_L, true);
    RFB_CHECK_EQ_UINT(rfb_norm_mods_bits(&m), RFB_MOD_CONTROL);
    // Hold right too
    rfb_norm_mods_apply(&m, XK_Control_R, true);
    RFB_CHECK_EQ_UINT(rfb_norm_mods_bits(&m), RFB_MOD_CONTROL);
    // Release left — still held by right
    rfb_norm_mods_apply(&m, XK_Control_L, false);
    RFB_CHECK_EQ_UINT(rfb_norm_mods_bits(&m), RFB_MOD_CONTROL);
    // Release right — now clear
    rfb_norm_mods_apply(&m, XK_Control_R, false);
    RFB_CHECK_EQ_UINT(rfb_norm_mods_bits(&m), RFB_MOD_NONE);
}

RFB_TEST(norm_mod, apply__multiple_modifiers__all_bits) {
    rfb_norm_mods m;
    rfb_norm_mods_init(&m);
    rfb_norm_mods_apply(&m, XK_Shift_L, true);
    rfb_norm_mods_apply(&m, XK_Super_L, true);  // Command
    rfb_norm_mods_apply(&m, XK_Alt_L, true);    // Option
    RFB_CHECK_EQ_UINT(rfb_norm_mods_bits(&m),
                      (uint16_t)(RFB_MOD_SHIFT | RFB_MOD_META | RFB_MOD_ALT));
}

RFB_TEST(norm_mod, reset__clears_all_modifiers) {
    rfb_norm_mods m;
    rfb_norm_mods_init(&m);
    rfb_norm_mods_apply(&m, XK_Shift_L, true);
    rfb_norm_mods_apply(&m, XK_Control_L, true);
    rfb_norm_mods_apply(&m, XK_Super_L, true);
    uint16_t bits = rfb_norm_mods_reset(&m);
    RFB_CHECK_EQ_UINT(bits, RFB_MOD_NONE);
    RFB_CHECK_EQ_UINT(rfb_norm_mods_bits(&m), RFB_MOD_NONE);
    // A subsequent release of an already-released modifier stays at none.
    RFB_CHECK_EQ_UINT(rfb_norm_mods_apply(&m, XK_Shift_L, false), RFB_MOD_NONE);
}

// ===========================================================================
// Ctrl-C (remote interrupt) vs Ctrl+] (local session quit)
// ===========================================================================

RFB_TEST(norm_quit, key_is_ctrl_c__press_ctrl_c__true) {
    rfb_norm_key k;
    memset(&k, 0, sizeof(k));
    k.keysym = (uint32_t)'c';
    k.modifiers = RFB_MOD_CONTROL;
    k.down = true;
    RFB_CHECK(rfb_norm_key_is_ctrl_c(&k));
    k.keysym = (uint32_t)'C';
    RFB_CHECK(rfb_norm_key_is_ctrl_c(&k));
}

RFB_TEST(norm_quit, key_is_ctrl_c__etx_text__true) {
    rfb_norm_key k;
    memset(&k, 0, sizeof(k));
    k.text = 0x03u;
    k.down = true;
    RFB_CHECK(rfb_norm_key_is_ctrl_c(&k));
}

RFB_TEST(norm_quit, key_is_ctrl_c__release_or_bare_c__false) {
    rfb_norm_key k;
    memset(&k, 0, sizeof(k));
    k.keysym = (uint32_t)'c';
    k.modifiers = RFB_MOD_CONTROL;
    k.down = false;  // key-up is not the interrupt edge
    RFB_CHECK(!rfb_norm_key_is_ctrl_c(&k));
    k.down = true;
    k.modifiers = RFB_MOD_NONE;  // bare 'c'
    RFB_CHECK(!rfb_norm_key_is_ctrl_c(&k));
    k.modifiers = RFB_MOD_CONTROL;
    k.keysym = (uint32_t)'x';  // Ctrl+X is not Ctrl-C
    RFB_CHECK(!rfb_norm_key_is_ctrl_c(&k));
    RFB_CHECK(!rfb_norm_key_is_ctrl_c(NULL));
}

RFB_TEST(norm_quit, byte_is_intr__etx_only) {
    RFB_CHECK(rfb_byte_is_intr(0x03u));
    RFB_CHECK(!rfb_byte_is_intr(0x00u));
    RFB_CHECK(!rfb_byte_is_intr((uint8_t)'c'));
    RFB_CHECK(!rfb_byte_is_intr(0x1Bu));
    RFB_CHECK(!rfb_byte_is_intr(0x1Du));  // Ctrl+] is quit, not intr
}

RFB_TEST(norm_mod, need_synth__control_chord_without_physical) {
    // Kitty C-a: event has CONTROL, tracker has none → need CONTROL.
    uint16_t need = rfb_norm_mods_need_synth(RFB_MOD_CONTROL, RFB_MOD_NONE);
    RFB_CHECK_EQ_UINT(need, RFB_MOD_CONTROL);
    // Physical Control already held → no synth.
    need = rfb_norm_mods_need_synth(RFB_MOD_CONTROL, RFB_MOD_CONTROL);
    RFB_CHECK_EQ_UINT(need, 0u);
    // C-S-a without physical → both.
    need = rfb_norm_mods_need_synth(
        (uint16_t)(RFB_MOD_CONTROL | RFB_MOD_SHIFT), RFB_MOD_NONE);
    RFB_CHECK_EQ_UINT(need, (uint16_t)(RFB_MOD_CONTROL | RFB_MOD_SHIFT));
    // Plain 'a' → nothing.
    need = rfb_norm_mods_need_synth(RFB_MOD_NONE, RFB_MOD_NONE);
    RFB_CHECK_EQ_UINT(need, 0u);
}

RFB_TEST(norm_quit, leader_chord__matches_release) {
    rfb_norm_key k;
    memset(&k, 0, sizeof(k));
    k.keysym = (uint32_t)']';
    k.modifiers = RFB_MOD_CONTROL;
    k.down = false;
    RFB_CHECK(!rfb_norm_key_matches_leader(&k, (uint32_t)']', RFB_MOD_CONTROL));
    RFB_CHECK(rfb_norm_key_is_leader_chord(&k, (uint32_t)']', RFB_MOD_CONTROL));
}

RFB_TEST(norm_quit, key_is_leader__ctrl_bracket__true) {
    rfb_norm_key k;
    memset(&k, 0, sizeof(k));
    k.keysym = (uint32_t)']';
    k.modifiers = RFB_MOD_CONTROL;
    k.down = true;
    RFB_CHECK(rfb_norm_key_is_leader(&k));
    RFB_CHECK(rfb_norm_key_is_session_quit(&k));  // alias
}

RFB_TEST(norm_quit, key_is_leader__negatives) {
    rfb_norm_key k;
    memset(&k, 0, sizeof(k));
    k.keysym = (uint32_t)']';
    k.modifiers = RFB_MOD_CONTROL;
    k.down = false;
    RFB_CHECK(!rfb_norm_key_is_leader(&k));
    k.down = true;
    k.modifiers = RFB_MOD_NONE;
    RFB_CHECK(!rfb_norm_key_is_leader(&k));
    // Ctrl-C is remote interrupt, not the leader.
    k.keysym = (uint32_t)'c';
    k.modifiers = RFB_MOD_CONTROL;
    RFB_CHECK(!rfb_norm_key_is_leader(&k));
    // Ctrl+Alt+] stays free for the remote.
    k.keysym = (uint32_t)']';
    k.modifiers = (uint16_t)(RFB_MOD_CONTROL | RFB_MOD_ALT);
    RFB_CHECK(!rfb_norm_key_is_leader(&k));
    RFB_CHECK(!rfb_norm_key_is_leader(NULL));
}

RFB_TEST(norm_quit, byte_is_leader__gs_only) {
    RFB_CHECK(rfb_byte_is_leader(0x1Du));
    RFB_CHECK(rfb_byte_is_session_quit(0x1Du));
    RFB_CHECK(!rfb_byte_is_leader(0x03u));
    RFB_CHECK(!rfb_byte_is_leader((uint8_t)']'));
}

RFB_TEST(norm_quit, leader_cmd__quit_suspend_pass_cancel) {
    rfb_norm_key k;
    memset(&k, 0, sizeof(k));
    k.down = true;
    k.keysym = (uint32_t)'q';
    RFB_CHECK_EQ_INT(rfb_leader_cmd_from_key(&k, (uint32_t)']', RFB_MOD_CONTROL),
                     RFB_LEADER_CMD_QUIT);
    k.keysym = (uint32_t)'c';
    k.modifiers = RFB_MOD_CONTROL;
    RFB_CHECK_EQ_INT(rfb_leader_cmd_from_key(&k, (uint32_t)']', RFB_MOD_CONTROL),
                     RFB_LEADER_CMD_QUIT);
    k.keysym = (uint32_t)'z';
    k.modifiers = RFB_MOD_NONE;
    RFB_CHECK_EQ_INT(rfb_leader_cmd_from_key(&k, (uint32_t)']', RFB_MOD_CONTROL),
                     RFB_LEADER_CMD_SUSPEND);
    k.keysym = (uint32_t)']';
    k.modifiers = RFB_MOD_CONTROL;
    RFB_CHECK_EQ_INT(rfb_leader_cmd_from_key(&k, (uint32_t)']', RFB_MOD_CONTROL),
                     RFB_LEADER_CMD_PASS);
    k.keysym = XK_Escape;
    k.modifiers = RFB_MOD_NONE;
    RFB_CHECK_EQ_INT(rfb_leader_cmd_from_key(&k, (uint32_t)']', RFB_MOD_CONTROL),
                     RFB_LEADER_CMD_CANCEL);
    RFB_CHECK_EQ_INT(rfb_leader_cmd_from_byte(0x03u, 0x1Du, true),
                     RFB_LEADER_CMD_QUIT);
    RFB_CHECK_EQ_INT(rfb_leader_cmd_from_byte(0x1Au, 0x1Du, true),
                     RFB_LEADER_CMD_SUSPEND);
    RFB_CHECK_EQ_INT(rfb_leader_cmd_from_byte(0x1Du, 0x1Du, true),
                     RFB_LEADER_CMD_PASS);
    k.keysym = (uint32_t)'+';
    k.modifiers = RFB_MOD_NONE;
    RFB_CHECK_EQ_INT(rfb_leader_cmd_from_key(&k, (uint32_t)']', RFB_MOD_CONTROL),
                     RFB_LEADER_CMD_ZOOM_IN);
    k.keysym = (uint32_t)'=';
    RFB_CHECK_EQ_INT(rfb_leader_cmd_from_key(&k, (uint32_t)']', RFB_MOD_CONTROL),
                     RFB_LEADER_CMD_ZOOM_IN);
    k.keysym = (uint32_t)'-';
    RFB_CHECK_EQ_INT(rfb_leader_cmd_from_key(&k, (uint32_t)']', RFB_MOD_CONTROL),
                     RFB_LEADER_CMD_ZOOM_OUT);
    RFB_CHECK_EQ_INT(rfb_leader_cmd_from_byte((uint8_t)'+', 0x1Du, true),
                     RFB_LEADER_CMD_ZOOM_IN);
    RFB_CHECK_EQ_INT(rfb_leader_cmd_from_byte((uint8_t)'-', 0x1Du, true),
                     RFB_LEADER_CMD_ZOOM_OUT);
}

// ===========================================================================
// Pointer buttons
// ===========================================================================

RFB_TEST(norm_ptr, button__left_press__mask_left) {
    rfb_norm_pointer p;
    rfb_norm_pointer_init(&p);
    RFB_CHECK_EQ_UINT(rfb_norm_pointer_button(&p, RFB_PTR_BUTTON_LEFT, true),
                      RFB_PTR_BUTTON_LEFT);
}

RFB_TEST(norm_ptr, button__chord_all_three__combined_mask) {
    rfb_norm_pointer p;
    rfb_norm_pointer_init(&p);
    rfb_norm_pointer_button(&p, RFB_PTR_BUTTON_LEFT, true);
    rfb_norm_pointer_button(&p, RFB_PTR_BUTTON_RIGHT, true);
    rfb_norm_pointer_button(&p, RFB_PTR_BUTTON_MIDDLE, true);
    RFB_CHECK_EQ_UINT(p.button_mask,
                      (uint8_t)(RFB_PTR_BUTTON_LEFT | RFB_PTR_BUTTON_RIGHT |
                                RFB_PTR_BUTTON_MIDDLE));
}

RFB_TEST(norm_ptr, button__release_one_of_chord__others_remain) {
    rfb_norm_pointer p;
    rfb_norm_pointer_init(&p);
    rfb_norm_pointer_button(&p, RFB_PTR_BUTTON_LEFT, true);
    rfb_norm_pointer_button(&p, RFB_PTR_BUTTON_RIGHT, true);
    rfb_norm_pointer_button(&p, RFB_PTR_BUTTON_LEFT, false);
    RFB_CHECK_EQ_UINT(p.button_mask, RFB_PTR_BUTTON_RIGHT);
}

// ===========================================================================
// High-resolution wheel accumulation
// ===========================================================================

RFB_TEST(norm_ptr, wheel__sub_unit_no_emit__zero_notches) {
    rfb_norm_pointer p;
    rfb_norm_pointer_init(&p);
    int32_t v = 999, h = 999;
    rfb_norm_pointer_wheel(&p, 30, 0, &v, &h);  // 30 < 120
    RFB_CHECK_EQ_INT(v, 0);
    RFB_CHECK_EQ_INT(h, 0);
}

RFB_TEST(norm_ptr, wheel__exactly_one_unit__one_notch_down) {
    rfb_norm_pointer p;
    rfb_norm_pointer_init(&p);
    int32_t v = 0, h = 0;
    rfb_norm_pointer_wheel(&p, RFB_PTR_WHEEL_UNIT, 0, &v, &h);
    RFB_CHECK_EQ_INT(v, 1);
}

RFB_TEST(norm_ptr, wheel__negative_is_up) {
    rfb_norm_pointer p;
    rfb_norm_pointer_init(&p);
    int32_t v = 0, h = 0;
    rfb_norm_pointer_wheel(&p, -RFB_PTR_WHEEL_UNIT, 0, &v, &h);
    RFB_CHECK_EQ_INT(v, -1);
}

RFB_TEST(norm_ptr, wheel__accumulates_across_calls) {
    rfb_norm_pointer p;
    rfb_norm_pointer_init(&p);
    int32_t v = 0, h = 0;
    rfb_norm_pointer_wheel(&p, 80, 0, &v, &h);   // 80 < 120 → 0
    RFB_CHECK_EQ_INT(v, 0);
    rfb_norm_pointer_wheel(&p, 80, 0, &v, &h);   // 160 → 1, rem 40
    RFB_CHECK_EQ_INT(v, 1);
    rfb_norm_pointer_wheel(&p, 80, 0, &v, &h);   // 120 → 1, rem 0
    RFB_CHECK_EQ_INT(v, 1);
    rfb_norm_pointer_wheel(&p, 80, 0, &v, &h);   // 80 → 0
    RFB_CHECK_EQ_INT(v, 0);
}

RFB_TEST(norm_ptr, wheel__horizontal) {
    rfb_norm_pointer p;
    rfb_norm_pointer_init(&p);
    int32_t v = 0, h = 0;
    rfb_norm_pointer_wheel(&p, 0, RFB_PTR_WHEEL_UNIT, &v, &h);
    RFB_CHECK_EQ_INT(h, 1);
    rfb_norm_pointer_wheel(&p, 0, -2 * RFB_PTR_WHEEL_UNIT, &v, &h);
    RFB_CHECK_EQ_INT(h, -2);
}

RFB_TEST(norm_ptr, wheel__burst_three_units_at_once) {
    rfb_norm_pointer p;
    rfb_norm_pointer_init(&p);
    int32_t v = 0, h = 0;
    rfb_norm_pointer_wheel(&p, 3 * RFB_PTR_WHEEL_UNIT, 0, &v, &h);
    RFB_CHECK_EQ_INT(v, 3);
}

// ===========================================================================
// Pixel coordinate mapping under scaling/letterboxing
// ===========================================================================

RFB_TEST(norm_geom, map__1to1_identity) {
    rfb_norm_geom g;
    rfb_norm_geom_init(&g);
    RFB_CHECK(rfb_norm_geom_set(&g, 100, 100, 100, 100, 1.0f));
    int32_t x = -1, y = -1;
    RFB_CHECK(rfb_norm_geom_map(&g, 50, 50, &x, &y));
    RFB_CHECK_EQ_INT(x, 50);
    RFB_CHECK_EQ_INT(y, 50);
}

RFB_TEST(norm_geom, map__scale_2x_centered) {
    // fb 200x200 shown in 100x100 viewport at scale 0.5 → fills exactly.
    rfb_norm_geom g;
    rfb_norm_geom_init(&g);
    RFB_CHECK(rfb_norm_geom_set(&g, 200, 200, 100, 100, 0.5f));
    int32_t x = -1, y = -1;
    RFB_CHECK(rfb_norm_geom_map(&g, 50, 50, &x, &y));
    // center of viewport → center of fb
    RFB_CHECK_EQ_INT(x, 100);
    RFB_CHECK_EQ_INT(y, 100);
}

RFB_TEST(norm_geom, map__letterbox_clamps_to_fb) {
    // fb 100x100, viewport 200x200, scale 1.0 → letterboxed, image centered.
    rfb_norm_geom g;
    rfb_norm_geom_init(&g);
    RFB_CHECK(rfb_norm_geom_set(&g, 100, 100, 200, 200, 1.0f));
    int32_t x = -1, y = -1;
    // top-left corner of viewport → clamped to fb 0
    RFB_CHECK(rfb_norm_geom_map(&g, 0, 0, &x, &y));
    RFB_CHECK_EQ_INT(x, 0);
    RFB_CHECK_EQ_INT(y, 0);
    // bottom-right → clamped to 99
    RFB_CHECK(rfb_norm_geom_map(&g, 199, 199, &x, &y));
    RFB_CHECK_EQ_INT(x, 99);
    RFB_CHECK_EQ_INT(y, 99);
}

RFB_TEST(norm_geom, map__invalid_geometry_returns_false) {
    rfb_norm_geom g;
    rfb_norm_geom_init(&g);
    int32_t x = -1, y = -1;
    RFB_CHECK(!rfb_norm_geom_map(&g, 50, 50, &x, &y));
}

RFB_TEST(norm_geom, set__rejects_zero_dimensions) {
    rfb_norm_geom g;
    rfb_norm_geom_init(&g);
    RFB_CHECK(!rfb_norm_geom_set(&g, 0, 100, 100, 100, 1.0f));
    RFB_CHECK(!rfb_norm_geom_set(&g, 100, 0, 100, 100, 1.0f));
    RFB_CHECK(!rfb_norm_geom_set(&g, 100, 100, 0, 100, 1.0f));
    RFB_CHECK(!rfb_norm_geom_set(&g, 100, 100, 100, 0, 1.0f));
    RFB_CHECK(!rfb_norm_geom_set(&g, 100, 100, 100, 100, 0.0f));
}
