// SPDX-License-Identifier: Apache-2.0
//
// Keyboard mapping and Kitty/legacy parser tests.
// Table-driven: US + non-US, modifiers, and auto-repeat.

#include "rfb_test.h"
#include "farsee/normalized_input.h"

#include <string.h>

// ===========================================================================
// Keysym ←→ text mapping (deterministic, table-driven)
// ===========================================================================

RFB_TEST(norm_kmap, keysym_to_text__lowercase_letter__itself) {
    RFB_CHECK_EQ_UINT(rfb_kb_keysym_to_text(0x0061u, false), (uint32_t)'a');
    RFB_CHECK_EQ_UINT(rfb_kb_keysym_to_text(0x007Au, false), (uint32_t)'z');
}

RFB_TEST(norm_kmap, keysym_to_text__uppercase_letter_shifted) {
    // keysym 'a' (0x61) with shift → 'A'
    RFB_CHECK_EQ_UINT(rfb_kb_keysym_to_text(0x0061u, true), (uint32_t)'A');
    RFB_CHECK_EQ_UINT(rfb_kb_keysym_to_text(0x007Au, true), (uint32_t)'Z');
}

RFB_TEST(norm_kmap, keysym_to_text__shifted_symbol_row) {
    // digit '1' (0x31) shifted → '!'
    RFB_CHECK_EQ_UINT(rfb_kb_keysym_to_text(0x0031u, true), (uint32_t)'!');
    RFB_CHECK_EQ_UINT(rfb_kb_keysym_to_text(0x0032u, true), (uint32_t)'@');
    RFB_CHECK_EQ_UINT(rfb_kb_keysym_to_text(0x0037u, true), (uint32_t)'&');
    RFB_CHECK_EQ_UINT(rfb_kb_keysym_to_text(0x0030u, true), (uint32_t)')');
}

RFB_TEST(norm_kmap, keysym_to_text__function_keys_no_text) {
    RFB_CHECK_EQ_UINT(rfb_kb_keysym_to_text(XK_F1, false), 0u);
    RFB_CHECK_EQ_UINT(rfb_kb_keysym_to_text(XK_Left, false), 0u);
    RFB_CHECK_EQ_UINT(rfb_kb_keysym_to_text(XK_Shift_L, false), 0u);
}

RFB_TEST(norm_kmap, keysym_to_text__space) {
    RFB_CHECK_EQ_UINT(rfb_kb_keysym_to_text(0x0020u, false), (uint32_t)' ');
}

// ---------------------------------------------------------------------------
// Kitty code → keysym
// ---------------------------------------------------------------------------

RFB_TEST(norm_kmap, code_to_keysym__printable__identity) {
    RFB_CHECK_EQ_UINT(rfb_kb_code_to_keysym((uint32_t)'a'), 0x0061u);
    RFB_CHECK_EQ_UINT(rfb_kb_code_to_keysym((uint32_t)'A'), 0x0041u);
    RFB_CHECK_EQ_UINT(rfb_kb_code_to_keysym((uint32_t)'5'), 0x0035u);
}

RFB_TEST(norm_kmap, code_to_keysym__enter_tab_esc_backspace) {
    RFB_CHECK_EQ_UINT(rfb_kb_code_to_keysym(KITTY_CODE_ENTER), XK_Return);
    RFB_CHECK_EQ_UINT(rfb_kb_code_to_keysym(KITTY_CODE_TAB), XK_Tab);
    RFB_CHECK_EQ_UINT(rfb_kb_code_to_keysym(KITTY_CODE_ESCAPE), XK_Escape);
    RFB_CHECK_EQ_UINT(rfb_kb_code_to_keysym(KITTY_CODE_BACKSPACE), XK_BackSpace);
    RFB_CHECK_EQ_UINT(rfb_kb_code_to_keysym(KITTY_CODE_SPACE), 0x0020u);
}

// Arrow/Home/End/PageUp/PageDown via Kitty code field.
RFB_TEST(norm_kmap, code_to_keysym__arrows) {
    RFB_CHECK_EQ_UINT(rfb_kb_code_to_keysym(KITTY_CODE_LEFT), XK_Left);
    RFB_CHECK_EQ_UINT(rfb_kb_code_to_keysym(KITTY_CODE_RIGHT), XK_Right);
    RFB_CHECK_EQ_UINT(rfb_kb_code_to_keysym(KITTY_CODE_UP), XK_Up);
    RFB_CHECK_EQ_UINT(rfb_kb_code_to_keysym(KITTY_CODE_DOWN), XK_Down);
}

RFB_TEST(norm_kmap, code_to_keysym__home_end_page) {
    RFB_CHECK_EQ_UINT(rfb_kb_code_to_keysym(KITTY_CODE_HOME), XK_Home);
    RFB_CHECK_EQ_UINT(rfb_kb_code_to_keysym(KITTY_CODE_END), XK_End);
    RFB_CHECK_EQ_UINT(rfb_kb_code_to_keysym(KITTY_CODE_PAGEUP), XK_Page_Up);
    RFB_CHECK_EQ_UINT(rfb_kb_code_to_keysym(KITTY_CODE_PAGEDOWN), XK_Page_Down);
}

RFB_TEST(norm_kmap, code_to_keysym__insert_delete) {
    RFB_CHECK_EQ_UINT(rfb_kb_code_to_keysym(KITTY_CODE_INSERT), XK_Insert);
    RFB_CHECK_EQ_UINT(rfb_kb_code_to_keysym(KITTY_CODE_DELETE), XK_Delete);
}

RFB_TEST(norm_kmap, code_to_keysym__function_keys) {
    RFB_CHECK_EQ_UINT(rfb_kb_code_to_keysym(KITTY_CODE_F1), XK_F1);
    RFB_CHECK_EQ_UINT(rfb_kb_code_to_keysym(KITTY_CODE_F6), XK_F6);
    RFB_CHECK_EQ_UINT(rfb_kb_code_to_keysym(KITTY_CODE_F12), XK_F12);
}

RFB_TEST(norm_kmap, code_to_keysym__modifiers) {
    RFB_CHECK_EQ_UINT(rfb_kb_code_to_keysym(KITTY_CODE_SHIFT_L), XK_Shift_L);
    RFB_CHECK_EQ_UINT(rfb_kb_code_to_keysym(KITTY_CODE_CTRL_L), XK_Control_L);
    RFB_CHECK_EQ_UINT(rfb_kb_code_to_keysym(KITTY_CODE_ALT_L), XK_Alt_L);
    RFB_CHECK_EQ_UINT(rfb_kb_code_to_keysym(KITTY_CODE_SUPER_L), XK_Super_L);
}

RFB_TEST(norm_kmap, code_to_keysym__unknown__zero) {
    // Code beyond U+10FFFF is unmapped.
    RFB_CHECK_EQ_UINT(rfb_kb_code_to_keysym(0x110000u), 0u);
}

// ===========================================================================
// Legacy terminal parsing
// ===========================================================================

RFB_TEST(norm_parse, legacy__bare_a__keysym_a) {
    rfb_norm_key ev;
    size_t n = rfb_kb_parse((const uint8_t *)"a", 1, NULL, &ev, 1);
    RFB_CHECK_EQ_UINT(n, 1u);
    RFB_CHECK_EQ_UINT(ev.keysym, 0x0061u);
    RFB_CHECK_EQ_UINT(ev.text, (uint32_t)'a');
    RFB_CHECK(ev.down);
    RFB_CHECK(!ev.repeat);
    RFB_CHECK_EQ_INT(ev.source, RFB_NORM_SOURCE_LEGACY);
}

RFB_TEST(norm_parse, legacy__enter_crlf) {
    rfb_norm_key ev;
    size_t n = rfb_kb_parse((const uint8_t *)"\r", 1, NULL, &ev, 1);
    RFB_CHECK_EQ_UINT(n, 1u);
    RFB_CHECK_EQ_UINT(ev.keysym, XK_Return);
    RFB_CHECK_EQ_INT(ev.source, RFB_NORM_SOURCE_LEGACY);
}

RFB_TEST(norm_parse, legacy__tab) {
    rfb_norm_key ev;
    size_t n = rfb_kb_parse((const uint8_t *)"\t", 1, NULL, &ev, 1);
    RFB_CHECK_EQ_UINT(n, 1u);
    RFB_CHECK_EQ_UINT(ev.keysym, XK_Tab);
}

RFB_TEST(norm_parse, legacy__backspace_del) {
    // 0x7F DEL → Backspace
    uint8_t bs = 0x7Fu;
    rfb_norm_key ev;
    size_t n = rfb_kb_parse(&bs, 1, NULL, &ev, 1);
    RFB_CHECK_EQ_UINT(n, 1u);
    RFB_CHECK_EQ_UINT(ev.keysym, XK_BackSpace);
}

RFB_TEST(norm_parse, legacy__escape_lone_resolved_by_flush) {
    // A lone ESC in a complete slice: rfb_kb_parse flushes trailing state,
    // so a pending lone ESC resolves to Escape (one event).
    rfb_norm_key ev;
    size_t n = rfb_kb_parse((const uint8_t *)"\x1b", 1, NULL, &ev, 1);
    RFB_CHECK_EQ_UINT(n, 1u);
    RFB_CHECK_EQ_UINT(ev.keysym, XK_Escape);
    RFB_CHECK_EQ_INT(ev.source, RFB_NORM_SOURCE_LEGACY);
}

RFB_TEST(norm_parse, legacy__escape_lone_no_flush_in_feed) {
    // Via the incremental feed (no flush), a lone ESC does not yet emit.
    rfb_kb kb;
    rfb_kb_init(&kb);
    rfb_norm_key ev;
    RFB_CHECK_EQ_INT(rfb_kb_feed(&kb, 0x1Bu, NULL, &ev), RFB_NORM_SOURCE_NONE);
}

RFB_TEST(norm_parse, legacy__arrow_up_csi_A) {
    // ESC [ A = Up
    static const uint8_t seq[] = { 0x1Bu, '[', 'A' };
    rfb_norm_key ev;
    size_t n = rfb_kb_parse(seq, sizeof seq, NULL, &ev, 1);
    RFB_CHECK_EQ_UINT(n, 1u);
    RFB_CHECK_EQ_UINT(ev.keysym, XK_Up);
    RFB_CHECK_EQ_INT(ev.source, RFB_NORM_SOURCE_LEGACY);
}

RFB_TEST(norm_parse, legacy__arrows_all_four) {
    // B=Down, C=Right, D=Left (xterm convention)
    static const uint8_t up[] = { 0x1Bu, '[', 'A' };
    static const uint8_t dn[] = { 0x1Bu, '[', 'B' };
    static const uint8_t rt[] = { 0x1Bu, '[', 'C' };
    static const uint8_t lf[] = { 0x1Bu, '[', 'D' };
    rfb_norm_key ev;
    rfb_kb_parse(up, sizeof up, NULL, &ev, 1);
    RFB_CHECK_EQ_UINT(ev.keysym, XK_Up);
    rfb_kb_parse(dn, sizeof dn, NULL, &ev, 1);
    RFB_CHECK_EQ_UINT(ev.keysym, XK_Down);
    rfb_kb_parse(rt, sizeof rt, NULL, &ev, 1);
    RFB_CHECK_EQ_UINT(ev.keysym, XK_Right);
    rfb_kb_parse(lf, sizeof lf, NULL, &ev, 1);
    RFB_CHECK_EQ_UINT(ev.keysym, XK_Left);
}

RFB_TEST(norm_parse, legacy__home_end_page_csi_tilde) {
    // ESC [ H = Home, ESC [ F = End
    static const uint8_t home[] = { 0x1Bu, '[', 'H' };
    static const uint8_t end[] = { 0x1Bu, '[', 'F' };
    rfb_norm_key ev;
    rfb_kb_parse(home, sizeof home, NULL, &ev, 1);
    RFB_CHECK_EQ_UINT(ev.keysym, XK_Home);
    rfb_kb_parse(end, sizeof end, NULL, &ev, 1);
    RFB_CHECK_EQ_UINT(ev.keysym, XK_End);
}

RFB_TEST(norm_parse, legacy__fkeys_csi_tilde_codes) {
    // ESC [ 1 1 ~ = F1 (some terminals), ESC [ 1 5 ~ = F5
    static const uint8_t f1[] = { 0x1Bu, '[', '1', '1', '~' };
    rfb_norm_key ev;
    size_t n = rfb_kb_parse(f1, sizeof f1, NULL, &ev, 1);
    RFB_CHECK_EQ_UINT(n, 1u);
    RFB_CHECK_EQ_UINT(ev.keysym, XK_F1);
}

RFB_TEST(norm_parse, legacy__standard_tilde_keys_cover_navigation_and_fkeys) {
    static const struct {
        const char *sequence;
        uint32_t keysym;
    } cases[] = {
        {"\x1b[1~", XK_Home},
        {"\x1b[2~", XK_Insert},
        {"\x1b[3~", XK_Delete},
        {"\x1b[4~", XK_End},
        {"\x1b[5~", XK_Page_Up},
        {"\x1b[6~", XK_Page_Down},
        {"\x1b[12~", XK_F2},
        {"\x1b[13~", XK_F3},
        {"\x1b[14~", XK_F4},
        {"\x1b[15~", XK_F5},
        {"\x1b[17~", XK_F6},
        {"\x1b[18~", XK_F7},
        {"\x1b[19~", XK_F8},
        {"\x1b[20~", XK_F9},
        {"\x1b[21~", XK_F10},
        {"\x1b[23~", XK_F11},
        {"\x1b[24~", XK_F12},
    };
    for (size_t i = 0u; i < sizeof cases / sizeof cases[0]; i++) {
        rfb_norm_key event;
        const size_t count = rfb_kb_parse(
            (const uint8_t *)cases[i].sequence, strlen(cases[i].sequence),
            NULL, &event, 1u);
        RFB_CHECK_EQ_UINT(count, 1u);
        RFB_CHECK_EQ_UINT(event.keysym, cases[i].keysym);
        RFB_CHECK_EQ_INT(event.source, RFB_NORM_SOURCE_LEGACY);
    }
}

RFB_TEST(norm_parse, legacy__unknown_tilde_key_is_rejected) {
    static const uint8_t sequence[] = {0x1bu, '[', '9', '9', '9', '~'};
    rfb_norm_key event;
    memset(&event, 0, sizeof event);
    RFB_CHECK_EQ_UINT(rfb_kb_parse(
                          sequence, sizeof sequence, NULL, &event, 1u), 0u);
    RFB_CHECK_EQ_UINT(event.keysym, 0u);
}

RFB_TEST(norm_parse, legacy__ss3_o_f1) {
    // ESC O P = F1 (SS3 P)
    static const uint8_t f1[] = { 0x1Bu, 'O', 'P' };
    rfb_norm_key ev;
    size_t n = rfb_kb_parse(f1, sizeof f1, NULL, &ev, 1);
    RFB_CHECK_EQ_UINT(n, 1u);
    RFB_CHECK_EQ_UINT(ev.keysym, XK_F1);
}

// ===========================================================================
// Kitty keyboard protocol (CSI ... u)
// ===========================================================================

RFB_TEST(norm_parse, kitty__press_a) {
    // CSI 97 ; 1 u  = 'a' (code 97), mods 1 (no modifiers; Kitty adds 1)
    static const uint8_t seq[] = { 0x1Bu, '[', '9', '7', ';', '1', 'u' };
    rfb_norm_key ev;
    size_t n = rfb_kb_parse(seq, sizeof seq, NULL, &ev, 1);
    RFB_CHECK_EQ_UINT(n, 1u);
    RFB_CHECK_EQ_UINT(ev.keysym, 0x0061u);
    RFB_CHECK_EQ_UINT(ev.text, (uint32_t)'a');
    RFB_CHECK(ev.down);
    RFB_CHECK(!ev.repeat);
    RFB_CHECK_EQ_INT(ev.source, RFB_NORM_SOURCE_KITTY);
}

RFB_TEST(norm_parse, kitty__shift_a_uppercase) {
    // CSI 97 ; 2 u = 'a' with shift (mods=2 → shift bit). text should be 'A'.
    static const uint8_t seq[] = { 0x1Bu, '[', '9', '7', ';', '2', 'u' };
    rfb_norm_key ev;
    size_t n = rfb_kb_parse(seq, sizeof seq, NULL, &ev, 1);
    RFB_CHECK_EQ_UINT(n, 1u);
    RFB_CHECK_EQ_UINT(ev.text, (uint32_t)'A');
    RFB_CHECK_EQ_UINT(ev.modifiers, RFB_MOD_SHIFT);
}

RFB_TEST(norm_parse, kitty__release_event) {
    // CSI 97 ; 1 : 3 u = release of 'a' (Kitty event-type 3 = release)
    static const uint8_t seq[] = {
        0x1Bu, '[', '9', '7', ';', '1', ':', '3', 'u'
    };
    rfb_norm_key ev;
    size_t n = rfb_kb_parse(seq, sizeof seq, NULL, &ev, 1);
    RFB_CHECK_EQ_UINT(n, 1u);
    RFB_CHECK(!ev.down);
    RFB_CHECK(!ev.repeat);
    RFB_CHECK_EQ_UINT(ev.keysym, 0x0061u);
}

RFB_TEST(norm_parse, kitty__repeat_event) {
    // CSI 97 ; 1 : 2 u = repeat of 'a' (Kitty event-type 2 = repeat)
    static const uint8_t seq[] = {
        0x1Bu, '[', '9', '7', ';', '1', ':', '2', 'u'
    };
    rfb_norm_key ev;
    size_t n = rfb_kb_parse(seq, sizeof seq, NULL, &ev, 1);
    RFB_CHECK_EQ_UINT(n, 1u);
    RFB_CHECK(ev.down);
    RFB_CHECK(ev.repeat);
}

// Negative: event type :2 means repeat, not release.
RFB_TEST(norm_parse, kitty__event_type_2_is_repeat_not_release) {
    static const uint8_t seq[] = {
        0x1Bu, '[', '9', '7', ';', '1', ':', '2', 'u'
    };
    rfb_norm_key ev;
    size_t n = rfb_kb_parse(seq, sizeof seq, NULL, &ev, 1);
    RFB_CHECK_EQ_UINT(n, 1u);
    RFB_CHECK(ev.down);   // NOT a release
    RFB_CHECK(ev.repeat);
}

RFB_TEST(norm_parse, kitty__event_type_3_is_release) {
    static const uint8_t seq[] = {
        0x1Bu, '[', '9', '7', ';', '1', ':', '3', 'u'
    };
    rfb_norm_key ev;
    size_t n = rfb_kb_parse(seq, sizeof seq, NULL, &ev, 1);
    RFB_CHECK_EQ_UINT(n, 1u);
    RFB_CHECK(!ev.down);
    RFB_CHECK(!ev.repeat);
}

RFB_TEST(norm_parse, kitty__arrow_up_code) {
    // CSI 10 ; 1 u = Up (KITTY_CODE_UP = 10).
    static const uint8_t seq[] = { 0x1Bu, '[', '1', '0', ';', '1', 'u' };
    rfb_norm_key ev;
    size_t n = rfb_kb_parse(seq, sizeof seq, NULL, &ev, 1);
    RFB_CHECK_EQ_UINT(n, 1u);
    RFB_CHECK_EQ_UINT(ev.keysym, XK_Up);
}

RFB_TEST(norm_parse, kitty__enter_code) {
    // CSI 13 ; 1 u = Enter
    static const uint8_t seq[] = { 0x1Bu, '[', '1', '3', ';', '1', 'u' };
    rfb_norm_key ev;
    size_t n = rfb_kb_parse(seq, sizeof seq, NULL, &ev, 1);
    RFB_CHECK_EQ_UINT(n, 1u);
    RFB_CHECK_EQ_UINT(ev.keysym, XK_Return);
}

RFB_TEST(norm_parse, kitty__modifier_bits_control_alt_super) {
    // mods field: 1 + (shift|alt*2|control*4|super*8)
    // control+alt = 1 + 2 + 4 = 7
    static const uint8_t seq[] = { 0x1Bu, '[', '9', '7', ';', '7', 'u' };
    rfb_norm_key ev;
    size_t n = rfb_kb_parse(seq, sizeof seq, NULL, &ev, 1);
    RFB_CHECK_EQ_UINT(n, 1u);
    RFB_CHECK_EQ_UINT(ev.modifiers, (uint16_t)(RFB_MOD_ALT | RFB_MOD_CONTROL));
}

RFB_TEST(norm_parse, kitty__super_command_modifier) {
    // super = 1 + 8 = 9
    static const uint8_t seq[] = { 0x1Bu, '[', '9', '7', ';', '9', 'u' };
    rfb_norm_key ev;
    size_t n = rfb_kb_parse(seq, sizeof seq, NULL, &ev, 1);
    RFB_CHECK_EQ_UINT(n, 1u);
    RFB_CHECK_EQ_UINT(ev.modifiers, RFB_MOD_META);  // Command
}

RFB_TEST(norm_parse, kitty__no_mods_field_defaults_press) {
    // CSI 97 u = 'a' press, no modifier field (mods default to 1)
    static const uint8_t seq[] = { 0x1Bu, '[', '9', '7', 'u' };
    rfb_norm_key ev;
    size_t n = rfb_kb_parse(seq, sizeof seq, NULL, &ev, 1);
    RFB_CHECK_EQ_UINT(n, 1u);
    RFB_CHECK(ev.down);
    RFB_CHECK_EQ_UINT(ev.modifiers, RFB_MOD_NONE);
}

// ===========================================================================
// Multi-byte UTF-8 (non-US / composed Unicode)
// ===========================================================================

RFB_TEST(norm_parse, legacy__multibyte_utf8_german_u_umlaut) {
    // 'ü' = U+00FC = C3 BC. Legacy terminal sends raw UTF-8.
    static const uint8_t seq[] = { 0xC3u, 0xBCu };
    rfb_norm_key ev;
    size_t n = rfb_kb_parse(seq, sizeof seq, NULL, &ev, 1);
    RFB_CHECK_EQ_UINT(n, 1u);
    RFB_CHECK_EQ_UINT(ev.keysym, 0x00FCu);
    RFB_CHECK_EQ_UINT(ev.text, 0x00FCu);
}

RFB_TEST(norm_parse, legacy__composed_emoji_4byte) {
    // U+1F600 😀 = F0 9F 98 80
    static const uint8_t seq[] = { 0xF0u, 0x9Fu, 0x98u, 0x80u };
    rfb_norm_key ev;
    size_t n = rfb_kb_parse(seq, sizeof seq, NULL, &ev, 1);
    RFB_CHECK_EQ_UINT(n, 1u);
    RFB_CHECK_EQ_UINT(ev.text, 0x1F600u);
    RFB_CHECK_EQ_UINT(ev.keysym, 0x1F600u);
}

// ===========================================================================
// Incremental / fragmentation
// ===========================================================================

RFB_TEST(norm_parse, incremental__csi_split_across_feeds) {
    rfb_kb kb;
    rfb_kb_init(&kb);
    rfb_norm_key ev;
    // Feed ESC, '[', 'A' one byte at a time.
    RFB_CHECK_EQ_INT(rfb_kb_feed(&kb, 0x1Bu, NULL, &ev), RFB_NORM_SOURCE_NONE);
    RFB_CHECK_EQ_INT(rfb_kb_feed(&kb, '[', NULL, &ev), RFB_NORM_SOURCE_NONE);
    rfb_norm_source s = rfb_kb_feed(&kb, 'A', NULL, &ev);
    RFB_CHECK_EQ_INT(s, RFB_NORM_SOURCE_LEGACY);
    RFB_CHECK_EQ_UINT(ev.keysym, XK_Up);
}

RFB_TEST(norm_parse, flush__lone_esc_emits_escape) {
    rfb_kb kb;
    rfb_kb_init(&kb);
    rfb_norm_key ev;
    rfb_kb_feed(&kb, 0x1Bu, NULL, &ev);  // ESC alone, no continuation yet
    rfb_norm_source s = rfb_kb_flush(&kb, NULL, &ev);
    RFB_CHECK_EQ_INT(s, RFB_NORM_SOURCE_LEGACY);
    RFB_CHECK_EQ_UINT(ev.keysym, XK_Escape);
}

RFB_TEST(norm_parse, flush__idle_returns_none) {
    rfb_kb kb;
    rfb_kb_init(&kb);
    rfb_norm_key ev;
    RFB_CHECK_EQ_INT(rfb_kb_flush(&kb, NULL, &ev), RFB_NORM_SOURCE_NONE);
}

RFB_TEST(norm_parse, two_events_in_one_slice) {
    // "ab" → two key events
    static const uint8_t seq[] = { 'a', 'b' };
    rfb_norm_key ev[2];
    size_t n = rfb_kb_parse(seq, sizeof seq, NULL, ev, 2);
    RFB_CHECK_EQ_UINT(n, 2u);
    RFB_CHECK_EQ_UINT(ev[0].text, (uint32_t)'a');
    RFB_CHECK_EQ_UINT(ev[1].text, (uint32_t)'b');
}

RFB_TEST(norm_parse, out_cap_limits_events) {
    static const uint8_t seq[] = { 'a', 'b', 'c' };
    rfb_norm_key ev[2];
    size_t n = rfb_kb_parse(seq, sizeof seq, NULL, ev, 2);
    RFB_CHECK_EQ_UINT(n, 2u);
}

// ===========================================================================
// Legacy xterm modifier encoding: ESC [ <n> ; <mods> <letter>
// mods = 1 + (shift|alt*2|control*4|super*8), same as Kitty.
// ===========================================================================

RFB_TEST(norm_parse, legacy__csi_modifier_ctrl_up) {
    // ESC [ 1 ; 5 A = Ctrl+Up
    static const uint8_t seq[] = { 0x1Bu, '[', '1', ';', '5', 'A' };
    rfb_norm_key ev;
    size_t n = rfb_kb_parse(seq, sizeof seq, NULL, &ev, 1);
    RFB_CHECK_EQ_UINT(n, 1u);
    RFB_CHECK_EQ_UINT(ev.keysym, XK_Up);
    RFB_CHECK_EQ_UINT(ev.modifiers, RFB_MOD_CONTROL);
}

// Kitty progressive enhancement encodes Ctrl-C as CSI u (not ETX/SIGINT).
// That must remain a *remote* interrupt, not the local disconnect chord.
// A pasted CSI-u with a huge numeric field must be rejected, not wrapped:
// an unbounded accumulator could overflow uint32 and inject an arbitrary
// keysym with arbitrary modifiers.
RFB_TEST(norm_parse, kitty__csi_u_huge_field__rejected_no_wrapped_keysym) {
    static const uint8_t seq[] = {
        0x1Bu, '[', '9', '9', '9', '9', '9', '9', '9', '9', '9', '9',
        '9', '9', ';', '1', ':', '3', 'u'
    };
    rfb_norm_key ev;
    memset(&ev, 0, sizeof ev);
    size_t n = rfb_kb_parse(seq, sizeof seq, NULL, &ev, 1);
    RFB_CHECK_EQ_UINT(n, 0u);
    RFB_CHECK_EQ_UINT(ev.keysym, 0u);
}

RFB_TEST(norm_parse, kitty__csi_u_ctrl_c_is_remote_intr_not_quit) {
    // CSI 99 ; 5 u  → code 'c', mods 5 = 1+control*4
    static const uint8_t seq[] = {
        0x1Bu, '[', '9', '9', ';', '5', 'u'
    };
    rfb_norm_key ev;
    size_t n = rfb_kb_parse(seq, sizeof seq, NULL, &ev, 1);
    RFB_CHECK_EQ_UINT(n, 1u);
    RFB_CHECK_EQ_UINT(ev.keysym, (uint32_t)'c');
    RFB_CHECK_EQ_UINT(ev.modifiers, RFB_MOD_CONTROL);
    RFB_CHECK(ev.down);
    RFB_CHECK(rfb_norm_key_is_ctrl_c(&ev));
    RFB_CHECK(!rfb_norm_key_is_session_quit(&ev));
}

// Leader: Ctrl+] → CSI 93 ; 5 u
RFB_TEST(norm_parse, kitty__csi_u_ctrl_bracket_is_leader) {
    static const uint8_t seq[] = {
        0x1Bu, '[', '9', '3', ';', '5', 'u'
    };
    rfb_norm_key ev;
    size_t n = rfb_kb_parse(seq, sizeof seq, NULL, &ev, 1);
    RFB_CHECK_EQ_UINT(n, 1u);
    RFB_CHECK_EQ_UINT(ev.keysym, (uint32_t)']');
    RFB_CHECK_EQ_UINT(ev.modifiers, RFB_MOD_CONTROL);
    RFB_CHECK(ev.down);
    RFB_CHECK(rfb_norm_key_is_leader(&ev));
    RFB_CHECK(!rfb_norm_key_is_ctrl_c(&ev));
}

RFB_TEST(norm_parse, kitty__csi_u_ctrl_bracket_release_not_leader) {
    // Event-type 3 = release (Kitty keyboard protocol).
    static const uint8_t seq[] = {
        0x1Bu, '[', '9', '3', ';', '5', ':', '3', 'u'
    };
    rfb_norm_key ev;
    size_t n = rfb_kb_parse(seq, sizeof seq, NULL, &ev, 1);
    RFB_CHECK_EQ_UINT(n, 1u);
    RFB_CHECK(!ev.down);
    // Press-only helper is false on release…
    RFB_CHECK(!rfb_norm_key_is_leader(&ev));
    // …but chord identity must still match so demux can swallow the
    // release and never inject raw "[93;5:3u" to the remote.
    RFB_CHECK(rfb_norm_key_is_leader_chord(&ev, (uint32_t)']',
                                           RFB_MOD_CONTROL));
}

// Kitty progressive enhancement may send alternate key codes after ':'.
RFB_TEST(norm_parse, kitty__code_with_alternate_field) {
    // CSI 93:29 ; 5 : 1 u  — code 93 (]), alternate ignored, ctrl, press.
    static const uint8_t seq[] = {
        0x1Bu, '[', '9', '3', ':', '2', '9', ';', '5', ':', '1', 'u'
    };
    rfb_norm_key ev;
    size_t n = rfb_kb_parse(seq, sizeof seq, NULL, &ev, 1);
    RFB_CHECK_EQ_UINT(n, 1u);
    RFB_CHECK_EQ_UINT(ev.keysym, (uint32_t)']');
    RFB_CHECK_EQ_UINT(ev.modifiers, RFB_MOD_CONTROL);
    RFB_CHECK(ev.down);
    RFB_CHECK(rfb_norm_key_is_leader(&ev));
}

RFB_TEST(norm_parse, kitty__leader_press_then_release_both_chord) {
    static const uint8_t press[] = {
        0x1Bu, '[', '9', '3', ';', '5', 'u'
    };
    static const uint8_t release[] = {
        0x1Bu, '[', '9', '3', ';', '5', ':', '3', 'u'
    };
    rfb_norm_key ev;
    RFB_CHECK_EQ_UINT(rfb_kb_parse(press, sizeof press, NULL, &ev, 1), 1u);
    RFB_CHECK(ev.down);
    RFB_CHECK(rfb_norm_key_matches_leader(&ev, (uint32_t)']', RFB_MOD_CONTROL));
    RFB_CHECK(rfb_norm_key_is_leader_chord(&ev, (uint32_t)']', RFB_MOD_CONTROL));
    RFB_CHECK_EQ_UINT(rfb_kb_parse(release, sizeof release, NULL, &ev, 1), 1u);
    RFB_CHECK(!ev.down);
    RFB_CHECK(!rfb_norm_key_matches_leader(&ev, (uint32_t)']', RFB_MOD_CONTROL));
    RFB_CHECK(rfb_norm_key_is_leader_chord(&ev, (uint32_t)']', RFB_MOD_CONTROL));
}

RFB_TEST(norm_parse, legacy__csi_modifier_shift_alt_right) {
    // ESC [ 1 ; 3 C = Alt+Right (mods 3 = 1+2 = alt)
    static const uint8_t seq[] = { 0x1Bu, '[', '1', ';', '3', 'C' };
    rfb_norm_key ev;
    size_t n = rfb_kb_parse(seq, sizeof seq, NULL, &ev, 1);
    RFB_CHECK_EQ_UINT(n, 1u);
    RFB_CHECK_EQ_UINT(ev.keysym, XK_Right);
    RFB_CHECK_EQ_UINT(ev.modifiers, RFB_MOD_ALT);
}

// ===========================================================================
// Stuck-modifier recovery (modifier tracker reset on focus loss)
// ===========================================================================

RFB_TEST(norm_recover, held_shift_then_reset_releases) {
    rfb_norm_mods m;
    rfb_norm_mods_init(&m);
    rfb_norm_mods_apply(&m, XK_Shift_L, true);
    RFB_CHECK_EQ_UINT(rfb_norm_mods_bits(&m), RFB_MOD_SHIFT);
    // Simulate focus loss: reset clears all.
    rfb_norm_mods_reset(&m);
    RFB_CHECK_EQ_UINT(rfb_norm_mods_bits(&m), RFB_MOD_NONE);
    // After reset, a normal key press reports no modifiers.
    rfb_norm_key ev;
    static const uint8_t a[] = { 'a' };
    rfb_kb_parse(a, 1, &m, &ev, 1);
    RFB_CHECK_EQ_UINT(ev.modifiers, RFB_MOD_NONE);
    RFB_CHECK_EQ_UINT(ev.text, (uint32_t)'a');
}

// ===========================================================================
// Auto-repeat: Kitty reports repeat events; legacy cannot.
// ===========================================================================

RFB_TEST(norm_repeat, kitty_repeat_marked_but_legacy_press) {
    // Kitty repeat: CSI 97 ; 1 : 2 u (event-type 2 = repeat)
    static const uint8_t kr[] = {
        0x1Bu, '[', '9', '7', ';', '1', ':', '2', 'u'
    };
    rfb_norm_key ev;
    rfb_kb_parse(kr, sizeof kr, NULL, &ev, 1);
    RFB_CHECK(ev.down);
    RFB_CHECK(ev.repeat);
    // Legacy 'a' is never a repeat.
    static const uint8_t la[] = { 'a' };
    rfb_kb_parse(la, 1, NULL, &ev, 1);
    RFB_CHECK(!ev.repeat);
}
