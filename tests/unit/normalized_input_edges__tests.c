// SPDX-License-Identifier: Apache-2.0
//
// Boundary contracts for normalized keyboard, pointer, and geometry input.

#include "rfb_test.h"

#include "farsee/normalized_input.h"

#include <math.h>
#include <string.h>

RFB_TEST(norm_edges, geometry__nonfinite_scale__is_rejected_without_mutation)
{
    rfb_norm_geom geometry;
    memset(&geometry, 0xa5, sizeof geometry);
    const rfb_norm_geom before = geometry;

    RFB_CHECK(!rfb_norm_geom_set(&geometry, 10u, 20u, 30u, 40u, NAN));
    RFB_CHECK_MEM_EQ(&geometry, &before, sizeof geometry);
    RFB_CHECK(!rfb_norm_geom_set(
        &geometry, 10u, 20u, 30u, 40u, INFINITY));
    RFB_CHECK_MEM_EQ(&geometry, &before, sizeof geometry);

    RFB_CHECK(rfb_norm_geom_set(&geometry, 10u, 20u, 30u, 40u, 0.5f));
    RFB_CHECK(geometry.valid);
    RFB_CHECK(geometry.scale == 0.5f);
}

RFB_TEST(norm_edges, leader_and_interrupt__all_guard_and_command_variants)
{
    rfb_norm_key key;
    memset(&key, 0, sizeof key);
    RFB_CHECK(!rfb_norm_key_is_ctrl_c(NULL));
    key.text = 0x03u;
    RFB_CHECK(!rfb_norm_key_is_ctrl_c(&key));
    key.down = true;
    RFB_CHECK(rfb_norm_key_is_ctrl_c(&key));
    key.text = (uint32_t)'C';
    key.keysym = (uint32_t)'x';
    key.modifiers = RFB_MOD_CONTROL;
    RFB_CHECK(rfb_norm_key_is_ctrl_c(&key));
    key.text = (uint32_t)'c';
    RFB_CHECK(rfb_norm_key_is_ctrl_c(&key));
    key.text = 0u;
    key.keysym = (uint32_t)'C';
    RFB_CHECK(rfb_norm_key_is_ctrl_c(&key));
    key.keysym = (uint32_t)'x';
    RFB_CHECK(!rfb_norm_key_is_ctrl_c(&key));
    RFB_CHECK(rfb_byte_is_intr(0x03u));
    RFB_CHECK(!rfb_byte_is_intr((uint8_t)'c'));

    RFB_CHECK_EQ_UINT(
        rfb_norm_mods_need_synth(
            (uint16_t)(RFB_MOD_SHIFT | RFB_MOD_CONTROL | RFB_MOD_CAPSLOCK),
            RFB_MOD_SHIFT),
        RFB_MOD_CONTROL);
    RFB_CHECK(!rfb_norm_key_is_leader_chord(NULL, (uint32_t)'b',
                                             RFB_MOD_CONTROL));
    RFB_CHECK(!rfb_norm_key_is_leader_chord(&key, 0u, RFB_MOD_CONTROL));
    key.modifiers = RFB_MOD_NONE;
    RFB_CHECK(!rfb_norm_key_is_leader_chord(
        &key, (uint32_t)'x', RFB_MOD_CONTROL));
    key.modifiers = (uint16_t)(RFB_MOD_CONTROL | RFB_MOD_ALT);
    RFB_CHECK(!rfb_norm_key_is_leader_chord(
        &key, (uint32_t)'x', RFB_MOD_CONTROL));
    key.modifiers = RFB_MOD_CONTROL;
    key.keysym = (uint32_t)'B';
    RFB_CHECK(rfb_norm_key_is_leader_chord(
        &key, (uint32_t)'b', RFB_MOD_CONTROL));
    key.keysym = (uint32_t)'b';
    RFB_CHECK(rfb_norm_key_is_leader_chord(
        &key, (uint32_t)'B', RFB_MOD_CONTROL));
    key.down = false;
    RFB_CHECK(!rfb_norm_key_matches_leader(
        &key, (uint32_t)'b', RFB_MOD_CONTROL));
    RFB_CHECK(!rfb_norm_key_matches_leader(
        NULL, (uint32_t)'b', RFB_MOD_CONTROL));
    RFB_CHECK(!rfb_byte_matches_leader(0x1du, 0x1du, false));
    RFB_CHECK(!rfb_byte_matches_leader(0x1cu, 0x1du, true));
    RFB_CHECK(rfb_byte_matches_leader(0x1du, 0x1du, true));

    RFB_CHECK_EQ_INT(
        rfb_leader_cmd_from_key(NULL, (uint32_t)']', RFB_MOD_CONTROL),
        RFB_LEADER_CMD_NONE);
    RFB_CHECK_EQ_INT(
        rfb_leader_cmd_from_key(&key, (uint32_t)']', RFB_MOD_CONTROL),
        RFB_LEADER_CMD_NONE);
    key.down = true;
    key.keysym = (uint32_t)']';
    RFB_CHECK_EQ_INT(
        rfb_leader_cmd_from_key(&key, (uint32_t)']', RFB_MOD_CONTROL),
        RFB_LEADER_CMD_PASS);
    RFB_CHECK(rfb_norm_key_is_leader(&key));
    RFB_CHECK(rfb_norm_key_is_session_quit(&key));
    RFB_CHECK(rfb_byte_is_leader(0x1du));
    RFB_CHECK(rfb_byte_is_session_quit(0x1du));

    typedef struct key_command_case {
        uint32_t keysym;
        uint32_t text;
        uint16_t modifiers;
        rfb_leader_cmd expected;
    } key_command_case;
    static const key_command_case key_cases[] = {
        {XK_Escape, 0u, 0u, RFB_LEADER_CMD_CANCEL},
        {(uint32_t)'x', 0x1bu, 0u, RFB_LEADER_CMD_CANCEL},
        {(uint32_t)'q', 0u, 0u, RFB_LEADER_CMD_QUIT},
        {(uint32_t)'Q', 0u, 0u, RFB_LEADER_CMD_QUIT},
        {(uint32_t)'c', 0u, 0u, RFB_LEADER_CMD_QUIT},
        {(uint32_t)'C', 0u, 0u, RFB_LEADER_CMD_QUIT},
        {(uint32_t)'x', 0x03u, 0u, RFB_LEADER_CMD_QUIT},
        {(uint32_t)'z', 0u, 0u, RFB_LEADER_CMD_SUSPEND},
        {(uint32_t)'Z', 0u, 0u, RFB_LEADER_CMD_SUSPEND},
        {(uint32_t)'x', 0x1au, RFB_MOD_CONTROL, RFB_LEADER_CMD_SUSPEND},
        {(uint32_t)'+', 0u, 0u, RFB_LEADER_CMD_ZOOM_IN},
        {(uint32_t)'=', 0u, 0u, RFB_LEADER_CMD_ZOOM_IN},
        {(uint32_t)'-', 0u, 0u, RFB_LEADER_CMD_ZOOM_OUT},
        {(uint32_t)'_', 0u, 0u, RFB_LEADER_CMD_ZOOM_OUT},
        {(uint32_t)'x', 0u, 0u, RFB_LEADER_CMD_NONE},
    };
    for (size_t index = 0u;
         index < sizeof key_cases / sizeof key_cases[0]; index++) {
        memset(&key, 0, sizeof key);
        key.down = true;
        key.keysym = key_cases[index].keysym;
        key.text = key_cases[index].text;
        key.modifiers = key_cases[index].modifiers;
        RFB_CHECK_EQ_INT(
            rfb_leader_cmd_from_key(&key, (uint32_t)']', RFB_MOD_CONTROL),
            key_cases[index].expected);
    }

    typedef struct byte_command_case {
        uint8_t byte;
        rfb_leader_cmd expected;
    } byte_command_case;
    static const byte_command_case byte_cases[] = {
        {0x1du, RFB_LEADER_CMD_PASS},
        {0x1bu, RFB_LEADER_CMD_CANCEL},
        {0x03u, RFB_LEADER_CMD_QUIT},
        {(uint8_t)'q', RFB_LEADER_CMD_QUIT},
        {(uint8_t)'Q', RFB_LEADER_CMD_QUIT},
        {(uint8_t)'c', RFB_LEADER_CMD_QUIT},
        {(uint8_t)'C', RFB_LEADER_CMD_QUIT},
        {0x1au, RFB_LEADER_CMD_SUSPEND},
        {(uint8_t)'z', RFB_LEADER_CMD_SUSPEND},
        {(uint8_t)'Z', RFB_LEADER_CMD_SUSPEND},
        {(uint8_t)'+', RFB_LEADER_CMD_ZOOM_IN},
        {(uint8_t)'=', RFB_LEADER_CMD_ZOOM_IN},
        {(uint8_t)'-', RFB_LEADER_CMD_ZOOM_OUT},
        {(uint8_t)'_', RFB_LEADER_CMD_ZOOM_OUT},
        {(uint8_t)'x', RFB_LEADER_CMD_NONE},
    };
    for (size_t index = 0u;
         index < sizeof byte_cases / sizeof byte_cases[0]; index++) {
        RFB_CHECK_EQ_INT(
            rfb_leader_cmd_from_byte(byte_cases[index].byte, 0x1du, true),
            byte_cases[index].expected);
    }
}

RFB_TEST(norm_edges, modifiers__left_right_latches_and_saturation_are_exact)
{
    typedef struct mod_case {
        uint32_t left;
        uint32_t right;
        rfb_modkey kind;
        uint16_t bit;
    } mod_case;
    static const mod_case cases[] = {
        {XK_Shift_L, XK_Shift_R, RFB_MODKEY_SHIFT, RFB_MOD_SHIFT},
        {XK_Control_L, XK_Control_R, RFB_MODKEY_CONTROL, RFB_MOD_CONTROL},
        {XK_Alt_L, XK_Alt_R, RFB_MODKEY_ALT, RFB_MOD_ALT},
        {XK_Meta_L, XK_Meta_R, RFB_MODKEY_META, RFB_MOD_META},
        {XK_Super_L, XK_Super_R, RFB_MODKEY_META, RFB_MOD_META},
    };
    rfb_norm_mods_init(NULL);
    RFB_CHECK_EQ_UINT(rfb_norm_mods_apply(NULL, XK_Shift_L, true),
                      RFB_MOD_NONE);
    RFB_CHECK_EQ_UINT(rfb_norm_mods_reset(NULL), RFB_MOD_NONE);
    RFB_CHECK_EQ_INT(rfb_norm_modkey_from_sym(XK_Shift_Lock),
                     RFB_MODKEY_SHIFT);
    RFB_CHECK_EQ_INT(rfb_norm_modkey_from_sym(XK_Caps_Lock),
                     RFB_MODKEY_CAPSLOCK);
    RFB_CHECK_EQ_INT(rfb_norm_modkey_from_sym((uint32_t)'x'),
                     RFB_MODKEY_NONE);

    rfb_norm_mods mods;
    rfb_norm_mods_init(&mods);
    for (size_t index = 0u; index < sizeof cases / sizeof cases[0]; index++) {
        RFB_CHECK_EQ_INT(rfb_norm_modkey_from_sym(cases[index].left),
                         cases[index].kind);
        RFB_CHECK_EQ_INT(rfb_norm_modkey_from_sym(cases[index].right),
                         cases[index].kind);
        RFB_CHECK_EQ_UINT(rfb_norm_mods_apply(
                              &mods, cases[index].right, false),
                          RFB_MOD_NONE);
        RFB_CHECK_EQ_UINT(rfb_norm_mods_apply(
                              &mods, cases[index].left, false),
                          RFB_MOD_NONE);
        RFB_CHECK((rfb_norm_mods_apply(
                       &mods, cases[index].left, true) & cases[index].bit) != 0u);
        RFB_CHECK((rfb_norm_mods_apply(
                       &mods, cases[index].right, true) & cases[index].bit) != 0u);
        RFB_CHECK((rfb_norm_mods_apply(
                       &mods, cases[index].left, false) & cases[index].bit) != 0u);
        RFB_CHECK((rfb_norm_mods_apply(
                       &mods, cases[index].right, false) & cases[index].bit) == 0u);
    }
    RFB_CHECK_EQ_UINT(rfb_norm_mods_apply(&mods, XK_Caps_Lock, true),
                      RFB_MOD_CAPSLOCK);
    RFB_CHECK_EQ_UINT(rfb_norm_mods_apply(&mods, XK_Caps_Lock, false),
                      RFB_MOD_CAPSLOCK);
    RFB_CHECK_EQ_UINT(rfb_norm_mods_apply(&mods, XK_Caps_Lock, true),
                      RFB_MOD_NONE);
    RFB_CHECK_EQ_UINT(rfb_norm_mods_apply(&mods, (uint32_t)'x', true),
                      RFB_MOD_NONE);
    RFB_CHECK_EQ_UINT(rfb_norm_mods_reset(&mods), RFB_MOD_NONE);
    RFB_CHECK_EQ_UINT(rfb_norm_mods_bits(&mods), RFB_MOD_NONE);
}

RFB_TEST(norm_edges, pointer__null_buttons_and_signed_wheel_notches_are_exact)
{
    rfb_norm_pointer_init(NULL);
    RFB_CHECK_EQ_UINT(
        rfb_norm_pointer_button(NULL, RFB_PTR_BUTTON_LEFT, true),
        RFB_PTR_BUTTON_NONE);
    int32_t vertical = 9;
    int32_t horizontal = 9;
    rfb_norm_pointer_wheel(NULL, 100, -100, &vertical, &horizontal);
    RFB_CHECK_EQ_INT(vertical, 0);
    RFB_CHECK_EQ_INT(horizontal, 0);

    rfb_norm_pointer pointer;
    rfb_norm_pointer_init(&pointer);
    RFB_CHECK_EQ_UINT(
        rfb_norm_pointer_button(&pointer, RFB_PTR_BUTTON_LEFT, true),
        RFB_PTR_BUTTON_LEFT);
    RFB_CHECK_EQ_UINT(
        rfb_norm_pointer_button(&pointer, RFB_PTR_BUTTON_RIGHT, true),
        (uint8_t)(RFB_PTR_BUTTON_LEFT | RFB_PTR_BUTTON_RIGHT));
    RFB_CHECK_EQ_UINT(
        rfb_norm_pointer_button(&pointer, RFB_PTR_BUTTON_LEFT, false),
        RFB_PTR_BUTTON_RIGHT);

    rfb_norm_pointer_wheel(&pointer, 250, -250, &vertical, &horizontal);
    RFB_CHECK_EQ_INT(vertical, 2);
    RFB_CHECK_EQ_INT(horizontal, -2);
    RFB_CHECK_EQ_INT(pointer.wheel_v, 10);
    RFB_CHECK_EQ_INT(pointer.wheel_h, -10);
    rfb_norm_pointer_wheel(&pointer, -130, 130, &vertical, &horizontal);
    RFB_CHECK_EQ_INT(vertical, -1);
    RFB_CHECK_EQ_INT(horizontal, 1);
    RFB_CHECK_EQ_INT(pointer.wheel_v, 0);
    RFB_CHECK_EQ_INT(pointer.wheel_h, 0);
    rfb_norm_pointer_wheel(&pointer, 1, 1, NULL, NULL);
}

RFB_TEST(norm_edges, geometry__guards_clamps_rounding_and_optional_outputs)
{
    rfb_norm_geom_init(NULL);
    rfb_norm_geom geometry;
    rfb_norm_geom_init(&geometry);
    RFB_CHECK(!geometry.valid);
    RFB_CHECK(!rfb_norm_geom_set(NULL, 1u, 1u, 1u, 1u, 1.0f));
    RFB_CHECK(!rfb_norm_geom_set(&geometry, 0u, 1u, 1u, 1u, 1.0f));
    RFB_CHECK(!rfb_norm_geom_set(&geometry, 1u, 0u, 1u, 1u, 1.0f));
    RFB_CHECK(!rfb_norm_geom_set(&geometry, 1u, 1u, 0u, 1u, 1.0f));
    RFB_CHECK(!rfb_norm_geom_set(&geometry, 1u, 1u, 1u, 0u, 1.0f));
    RFB_CHECK(!rfb_norm_geom_set(&geometry, 1u, 1u, 1u, 1u, 0.0f));
    RFB_CHECK(!rfb_norm_geom_set(&geometry, 1u, 1u, 1u, 1u, -1.0f));
    float float_x = -1.0f;
    float float_y = -1.0f;
    RFB_CHECK(!rfb_norm_geom_mapf(
        NULL, 0.0f, 0.0f, &float_x, &float_y));
    RFB_CHECK(!rfb_norm_geom_mapf(
        &geometry, 0.0f, 0.0f, &float_x, &float_y));
    geometry.valid = true;
    geometry.scale = 0.0f;
    RFB_CHECK(!rfb_norm_geom_mapf(
        &geometry, 0.0f, 0.0f, &float_x, &float_y));

    RFB_CHECK(rfb_norm_geom_set(&geometry, 100u, 50u, 200u, 200u, 1.0f));
    RFB_CHECK(rfb_norm_geom_mapf(
        &geometry, -100.0f, -100.0f, &float_x, &float_y));
    RFB_CHECK(float_x == 0.0f);
    RFB_CHECK(float_y == 0.0f);
    RFB_CHECK(rfb_norm_geom_mapf(
        &geometry, 500.0f, 500.0f, &float_x, &float_y));
    RFB_CHECK(float_x == 99.0f);
    RFB_CHECK(float_y == 49.0f);
    RFB_CHECK(rfb_norm_geom_mapf(
        &geometry, 60.25f, 80.75f, NULL, NULL));
    int32_t int_x = -1;
    int32_t int_y = -1;
    RFB_CHECK(rfb_norm_geom_map(&geometry, 61, 81, &int_x, &int_y));
    RFB_CHECK_EQ_INT(int_x, 11);
    RFB_CHECK_EQ_INT(int_y, 6);
    RFB_CHECK(rfb_norm_geom_map(&geometry, 61, 81, NULL, NULL));
}

RFB_TEST(norm_edges, key_mapping__named_codes_and_unicode_boundaries)
{
    typedef struct code_case {
        uint32_t code;
        uint32_t keysym;
    } code_case;
    static const code_case cases[] = {
        {KITTY_CODE_ENTER, XK_Return},
        {KITTY_CODE_TAB, XK_Tab},
        {KITTY_CODE_ESCAPE, XK_Escape},
        {KITTY_CODE_BACKSPACE, XK_BackSpace},
        {KITTY_CODE_SPACE, 0x20u},
        {KITTY_CODE_INSERT, XK_Insert},
        {KITTY_CODE_DELETE, XK_Delete},
        {KITTY_CODE_LEFT, XK_Left},
        {KITTY_CODE_RIGHT, XK_Right},
        {KITTY_CODE_UP, XK_Up},
        {KITTY_CODE_DOWN, XK_Down},
        {KITTY_CODE_HOME, XK_Home},
        {KITTY_CODE_END, XK_End},
        {KITTY_CODE_PAGEUP, XK_Page_Up},
        {KITTY_CODE_PAGEDOWN, XK_Page_Down},
        {KITTY_CODE_F1, XK_F1},
        {KITTY_CODE_F2, XK_F2},
        {KITTY_CODE_F3, XK_F3},
        {KITTY_CODE_F4, XK_F4},
        {KITTY_CODE_F5, XK_F5},
        {KITTY_CODE_F6, XK_F6},
        {KITTY_CODE_F7, XK_F7},
        {KITTY_CODE_F8, XK_F8},
        {KITTY_CODE_F9, XK_F9},
        {KITTY_CODE_F10, XK_F10},
        {KITTY_CODE_F11, XK_F11},
        {KITTY_CODE_F12, XK_F12},
        {KITTY_CODE_SHIFT_L, XK_Shift_L},
        {KITTY_CODE_CTRL_L, XK_Control_L},
        {KITTY_CODE_ALT_L, XK_Alt_L},
        {KITTY_CODE_SUPER_L, XK_Super_L},
        {0x21u, 0x21u},
        {0x10ffffu, 0x10ffffu},
        {0x1fu, 0u},
        {0x110000u, 0u},
    };
    for (size_t index = 0u; index < sizeof cases / sizeof cases[0]; index++) {
        RFB_CHECK_EQ_UINT(rfb_kb_code_to_keysym(cases[index].code),
                          cases[index].keysym);
    }

    RFB_CHECK_EQ_UINT(rfb_kb_keysym_to_text(XK_Shift_L, false), 0u);
    RFB_CHECK_EQ_UINT(rfb_kb_keysym_to_text((uint32_t)'a', false),
                      (uint32_t)'a');
    RFB_CHECK_EQ_UINT(rfb_kb_keysym_to_text((uint32_t)'a', true),
                      (uint32_t)'A');
    RFB_CHECK_EQ_UINT(rfb_kb_keysym_to_text((uint32_t)'A', false),
                      (uint32_t)'A');
    RFB_CHECK_EQ_UINT(rfb_kb_keysym_to_text((uint32_t)'1', false),
                      (uint32_t)'1');
    RFB_CHECK_EQ_UINT(rfb_kb_keysym_to_text((uint32_t)'1', true),
                      (uint32_t)'!');
    RFB_CHECK_EQ_UINT(rfb_kb_keysym_to_text((uint32_t)'?', true),
                      (uint32_t)'?');
    RFB_CHECK_EQ_UINT(rfb_kb_keysym_to_text(0xa0u, false), 0xa0u);
    RFB_CHECK_EQ_UINT(rfb_kb_keysym_to_text(0x100u, false), 0x100u);
    RFB_CHECK_EQ_UINT(rfb_kb_keysym_to_text(0x10ffffu, false), 0x10ffffu);
    RFB_CHECK_EQ_UINT(rfb_kb_keysym_to_text(0x1fu, false), 0u);
    RFB_CHECK_EQ_UINT(rfb_kb_keysym_to_text(0x110000u, false), 0u);
}

RFB_TEST(norm_edges, parser__public_guards_and_escape_fallbacks_reset_state)
{
    rfb_kb_init(NULL);
    rfb_kb keyboard;
    rfb_kb_init(&keyboard);
    rfb_norm_key event;
    memset(&event, 0, sizeof event);
    RFB_CHECK_EQ_INT(rfb_kb_feed(NULL, (uint8_t)'a', NULL, &event),
                     RFB_NORM_SOURCE_NONE);
    RFB_CHECK_EQ_INT(rfb_kb_feed(&keyboard, (uint8_t)'a', NULL, NULL),
                     RFB_NORM_SOURCE_NONE);
    RFB_CHECK_EQ_INT(rfb_kb_flush(NULL, NULL, &event), RFB_NORM_SOURCE_NONE);
    RFB_CHECK_EQ_INT(rfb_kb_flush(&keyboard, NULL, NULL),
                     RFB_NORM_SOURCE_NONE);
    RFB_CHECK_EQ_UINT(rfb_kb_parse(NULL, 1u, NULL, &event, 1u), 0u);
    static const uint8_t byte = (uint8_t)'a';
    RFB_CHECK_EQ_UINT(rfb_kb_parse(&byte, 1u, NULL, NULL, 1u), 0u);
    RFB_CHECK_EQ_UINT(rfb_kb_parse(&byte, 1u, NULL, &event, 0u), 0u);

    RFB_CHECK_EQ_INT(rfb_kb_feed(&keyboard, 0x1bu, NULL, &event),
                     RFB_NORM_SOURCE_NONE);
    RFB_CHECK_EQ_INT(rfb_kb_feed(&keyboard, (uint8_t)'x', NULL, &event),
                     RFB_NORM_SOURCE_LEGACY);
    RFB_CHECK_EQ_UINT(event.keysym, XK_Escape);
    RFB_CHECK_EQ_INT(keyboard.state, RFB_KB_IDLE);

    keyboard.state = (rfb_kb_state)99;
    RFB_CHECK_EQ_INT(rfb_kb_feed(&keyboard, 0u, NULL, &event),
                     RFB_NORM_SOURCE_NONE);
    RFB_CHECK_EQ_INT(keyboard.state, RFB_KB_IDLE);
    RFB_CHECK_EQ_INT(rfb_kb_flush(&keyboard, NULL, &event),
                     RFB_NORM_SOURCE_NONE);
}

RFB_TEST(norm_edges, parser__c0_invalid_utf8_and_malformed_sequences_drop)
{
    static const uint8_t c0_cases[] = {0x00u, 0x01u, 0x08u, 0x09u,
                                       0x0au, 0x0du, 0x7fu};
    static const uint32_t expected[] = {0u, 0u, XK_BackSpace, XK_Tab,
                                        XK_Return, XK_Return, XK_BackSpace};
    for (size_t index = 0u; index < sizeof c0_cases; index++) {
        rfb_norm_key event;
        memset(&event, 0, sizeof event);
        const size_t count = rfb_kb_parse(
            &c0_cases[index], 1u, NULL, &event, 1u);
        RFB_CHECK_EQ_UINT(count, expected[index] == 0u ? 0u : 1u);
        if (expected[index] != 0u) {
            RFB_CHECK_EQ_UINT(event.keysym, expected[index]);
        }
    }

    static const uint8_t invalid_leads[] = {0x80u, 0xc0u, 0xf5u, 0xffu};
    for (size_t index = 0u; index < sizeof invalid_leads; index++) {
        rfb_norm_key event;
        RFB_CHECK_EQ_UINT(rfb_kb_parse(
                              &invalid_leads[index], 1u, NULL, &event, 1u),
                          0u);
    }

    static const uint8_t malformed[][4] = {
        {0xe2u, 0x20u, 0x80u, 0u},
        {0xe2u, 0xc0u, 0x80u, 0u},
        {0xedu, 0xa0u, 0x80u, 0u},
        {0xf4u, 0x90u, 0x80u, 0x80u},
        {0xf0u, 0x80u, 0x80u, 0x80u},
    };
    static const size_t malformed_lengths[] = {3u, 3u, 3u, 4u, 4u};
    for (size_t index = 0u;
         index < sizeof malformed / sizeof malformed[0]; index++) {
        rfb_norm_key event;
        RFB_CHECK_EQ_UINT(rfb_kb_parse(
                              malformed[index], malformed_lengths[index],
                              NULL, &event, 1u),
                          0u);
    }

    static const uint8_t empty_kitty[] = {0x1bu, '[', 'u'};
    static const uint8_t unmapped_kitty[] = {0x1bu, '[', '1', 'u'};
    static const uint8_t unsupported_ss3[] = {0x1bu, 'O', 'M'};
    rfb_norm_key event;
    RFB_CHECK_EQ_UINT(rfb_kb_parse(
                          empty_kitty, sizeof empty_kitty, NULL, &event, 1u),
                      0u);
    RFB_CHECK_EQ_UINT(rfb_kb_parse(
                          unmapped_kitty, sizeof unmapped_kitty, NULL,
                          &event, 1u),
                      0u);
    RFB_CHECK_EQ_UINT(rfb_kb_parse(
                          unsupported_ss3, sizeof unsupported_ss3, NULL,
                          &event, 1u),
                      0u);

    static const uint8_t alternate_code[] = {
        0x1bu, '[', '9', '7', ':', '1', 'u'};
    RFB_CHECK_EQ_UINT(rfb_kb_parse(
                          alternate_code, sizeof alternate_code, NULL,
                          &event, 1u),
                      1u);
    RFB_CHECK_EQ_UINT(event.keysym, (uint32_t)'a');
    static const uint8_t empty_modifier[] = {
        0x1bu, '[', '9', '7', ';', ':', '2', 'u'};
    RFB_CHECK_EQ_UINT(rfb_kb_parse(
                          empty_modifier, sizeof empty_modifier, NULL,
                          &event, 1u),
                      1u);
    RFB_CHECK(event.repeat);
    static const uint8_t empty_event[] = {
        0x1bu, '[', '9', '7', ';', '2', ':', 'u'};
    RFB_CHECK_EQ_UINT(rfb_kb_parse(
                          empty_event, sizeof empty_event, NULL, &event, 1u),
                      1u);
    RFB_CHECK(event.down);
}

RFB_TEST(norm_edges, parser__ss3_and_legacy_tilde_matrix_maps_exact_keys)
{
    typedef struct sequence_case {
        const char *params;
        uint32_t expected;
    } sequence_case;
    static const sequence_case cases[] = {
        {"1", XK_Home}, {"7", XK_Home}, {"2", XK_Insert},
        {"3", XK_Delete}, {"4", XK_End}, {"8", XK_End},
        {"5", XK_Page_Up}, {"6", XK_Page_Down},
        {"11", XK_F1}, {"12", XK_F2}, {"13", XK_F3},
        {"14", XK_F4}, {"15", XK_F5}, {"17", XK_F6},
        {"18", XK_F7}, {"19", XK_F8}, {"20", XK_F9},
        {"21", XK_F10}, {"23", XK_F11}, {"24", XK_F12},
        {"99", 0u},
    };
    for (size_t index = 0u; index < sizeof cases / sizeof cases[0]; index++) {
        uint8_t sequence[16];
        size_t length = 0u;
        sequence[length++] = 0x1bu;
        sequence[length++] = '[';
        const size_t params_length = strlen(cases[index].params);
        memcpy(sequence + length, cases[index].params, params_length);
        length += params_length;
        sequence[length++] = '~';
        rfb_norm_key event;
        memset(&event, 0, sizeof event);
        const size_t count = rfb_kb_parse(
            sequence, length, NULL, &event, 1u);
        RFB_CHECK_EQ_UINT(count, cases[index].expected == 0u ? 0u : 1u);
        if (cases[index].expected != 0u) {
            RFB_CHECK_EQ_UINT(event.keysym, cases[index].expected);
        }
    }

    static const uint8_t ss3_final[] = {'P', 'Q', 'R', 'S'};
    static const uint32_t ss3_expected[] = {XK_F1, XK_F2, XK_F3, XK_F4};
    for (size_t index = 0u; index < sizeof ss3_final; index++) {
        const uint8_t sequence[] = {0x1bu, 'O', ss3_final[index]};
        rfb_norm_key event;
        RFB_CHECK_EQ_UINT(rfb_kb_parse(
                              sequence, sizeof sequence, NULL, &event, 1u),
                          1u);
        RFB_CHECK_EQ_UINT(event.keysym, ss3_expected[index]);
    }

    static const uint8_t legacy_empty_modifier[] = {
        0x1bu, '[', '1', ';', 'A'};
    rfb_norm_key event;
    RFB_CHECK_EQ_UINT(rfb_kb_parse(
                          legacy_empty_modifier,
                          sizeof legacy_empty_modifier, NULL, &event, 1u),
                      1u);
    RFB_CHECK_EQ_UINT(event.keysym, XK_Up);
    static const uint8_t legacy_empty_number[] = {0x1bu, '[', '~'};
    RFB_CHECK_EQ_UINT(rfb_kb_parse(
                          legacy_empty_number, sizeof legacy_empty_number,
                          NULL, &event, 1u),
                      0u);
}

RFB_TEST(norm_edges, parser__bounded_params_and_trailing_escape_are_safe)
{
    uint8_t oversized[40];
    size_t length = 0u;
    oversized[length++] = 0x1bu;
    oversized[length++] = '[';
    for (size_t index = 0u; index < 35u; index++) {
        oversized[length++] = (uint8_t)'9';
    }
    oversized[length++] = (uint8_t)'u';
    rfb_norm_key event[2];
    memset(event, 0, sizeof event);
    RFB_CHECK_EQ_UINT(
        rfb_kb_parse(oversized, length, NULL, event, 2u), 0u);

    static const uint8_t with_escape[] = {(uint8_t)'a', 0x1bu};
    RFB_CHECK_EQ_UINT(rfb_kb_parse(
                          with_escape, sizeof with_escape, NULL, event, 2u),
                      2u);
    RFB_CHECK_EQ_UINT(event[0].keysym, (uint32_t)'a');
    RFB_CHECK_EQ_UINT(event[1].keysym, XK_Escape);

    rfb_kb keyboard;
    rfb_kb_init(&keyboard);
    RFB_CHECK_EQ_INT(rfb_kb_feed(&keyboard, 0xe2u, NULL, &event[0]),
                     RFB_NORM_SOURCE_NONE);
    RFB_CHECK_EQ_INT(rfb_kb_flush(&keyboard, NULL, &event[0]),
                     RFB_NORM_SOURCE_NONE);
    RFB_CHECK_EQ_INT(keyboard.state, RFB_KB_IDLE);

    keyboard.esc_pending = true;
    keyboard.state = RFB_KB_CSI;
    RFB_CHECK_EQ_INT(rfb_kb_flush(&keyboard, NULL, &event[0]),
                     RFB_NORM_SOURCE_NONE);
    RFB_CHECK_EQ_INT(keyboard.state, RFB_KB_IDLE);
}
