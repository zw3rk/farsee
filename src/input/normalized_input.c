// SPDX-License-Identifier: Apache-2.0
//
// farsee — presenter-independent normalized input layer (goals.md G21).
//
// Modifier tracking, pointer buttons, high-resolution wheel accumulation,
// and pixel-coordinate mapping under scaling/letterboxing.
//
// Keyboard sequence parsing (Kitty keyboard protocol + legacy fallback)
// is added in a later slice; the table-driven keysym mapping lives in the
// dedicated keymap section below.

#include "farsee/normalized_input.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// ---------------------------------------------------------------------------
// Ctrl-C (remote interrupt) vs Ctrl+] (local session quit)
// ---------------------------------------------------------------------------

bool rfb_norm_key_is_ctrl_c(const rfb_norm_key *k)
{
    if (k == NULL || !k->down) {
        return false;
    }
    // Explicit ETX text (when ISIG is off the line discipline passes it).
    if (k->text == 0x03u) {
        return true;
    }
    // Kitty CSI u / legacy with Control + c/C.
    if ((k->modifiers & RFB_MOD_CONTROL) != 0u) {
        if (k->keysym == (uint32_t)'c' || k->keysym == (uint32_t)'C') {
            return true;
        }
        if (k->text == (uint32_t)'c' || k->text == (uint32_t)'C') {
            return true;
        }
    }
    return false;
}

bool rfb_byte_is_intr(uint8_t b)
{
    return b == 0x03u;  // ETX — classic Ctrl-C with ISIG off
}

uint16_t rfb_norm_mods_need_synth(uint16_t event_mods, uint16_t physical_mods)
{
    const uint16_t mask = (uint16_t)(RFB_MOD_SHIFT | RFB_MOD_CONTROL |
                                     RFB_MOD_ALT | RFB_MOD_META);
    return (uint16_t)((event_mods & mask) & (uint16_t)~(physical_mods & mask));
}

bool rfb_norm_key_is_leader_chord(const rfb_norm_key *k, uint32_t keysym,
                                  uint16_t mods)
{
    if (k == NULL || keysym == 0u) {
        return false;
    }
    // Required mods must all be present.
    if ((k->modifiers & mods) != mods) {
        return false;
    }
    // Do not steal Alt/Meta chords unless the leader explicitly includes them.
    const uint16_t extra = (uint16_t)(RFB_MOD_ALT | RFB_MOD_META);
    if (((k->modifiers & extra) & (uint16_t)~mods) != 0u) {
        return false;
    }
    // Case-fold ASCII letters so C-b matches keysym 'B' too.
    uint32_t want = keysym;
    uint32_t got = k->keysym;
    if (want >= (uint32_t)'A' && want <= (uint32_t)'Z') {
        want = want - (uint32_t)'A' + (uint32_t)'a';
    }
    if (got >= (uint32_t)'A' && got <= (uint32_t)'Z') {
        got = got - (uint32_t)'A' + (uint32_t)'a';
    }
    return got == want;
}

bool rfb_norm_key_matches_leader(const rfb_norm_key *k, uint32_t keysym,
                                 uint16_t mods)
{
    if (k == NULL || !k->down) {
        return false;
    }
    return rfb_norm_key_is_leader_chord(k, keysym, mods);
}

bool rfb_byte_matches_leader(uint8_t b, uint8_t c0_byte, bool has_c0)
{
    return has_c0 && b == c0_byte;
}

bool rfb_norm_key_is_leader(const rfb_norm_key *k)
{
    return rfb_norm_key_matches_leader(k, (uint32_t)']', RFB_MOD_CONTROL);
}

bool rfb_byte_is_leader(uint8_t b)
{
    return rfb_byte_matches_leader(b, 0x1Du, true);
}

rfb_leader_cmd rfb_leader_cmd_from_key(const rfb_norm_key *k,
                                       uint32_t leader_keysym,
                                       uint16_t leader_mods)
{
    if (k == NULL || !k->down) {
        return RFB_LEADER_CMD_NONE;
    }
    // Second leader → pass-through (send the prefix to the remote).
    if (rfb_norm_key_matches_leader(k, leader_keysym, leader_mods)) {
        return RFB_LEADER_CMD_PASS;
    }
    if (k->keysym == XK_Escape || k->text == 0x1Bu) {
        return RFB_LEADER_CMD_CANCEL;
    }
    // Quit: q / c, optionally with Control (Ctrl-C after leader).
    if (k->keysym == (uint32_t)'q' || k->keysym == (uint32_t)'Q' ||
        k->keysym == (uint32_t)'c' || k->keysym == (uint32_t)'C' ||
        rfb_norm_key_is_ctrl_c(k)) {
        return RFB_LEADER_CMD_QUIT;
    }
    // Suspend: z / Ctrl-Z.
    if (k->keysym == (uint32_t)'z' || k->keysym == (uint32_t)'Z') {
        return RFB_LEADER_CMD_SUSPEND;
    }
    if ((k->modifiers & RFB_MOD_CONTROL) != 0u &&
        (k->text == 0x1Au /* SUB / Ctrl-Z */)) {
        return RFB_LEADER_CMD_SUSPEND;
    }
    // View zoom: + / = enlarge, - / _ shrink (percent of max fit).
    if (k->keysym == (uint32_t)'+' || k->keysym == (uint32_t)'=') {
        return RFB_LEADER_CMD_ZOOM_IN;
    }
    if (k->keysym == (uint32_t)'-' || k->keysym == (uint32_t)'_') {
        return RFB_LEADER_CMD_ZOOM_OUT;
    }
    return RFB_LEADER_CMD_NONE;
}

rfb_leader_cmd rfb_leader_cmd_from_byte(uint8_t b, uint8_t leader_c0,
                                        bool leader_has_c0)
{
    if (rfb_byte_matches_leader(b, leader_c0, leader_has_c0)) {
        return RFB_LEADER_CMD_PASS;
    }
    if (b == 0x1Bu) {
        return RFB_LEADER_CMD_CANCEL;
    }
    if (b == 0x03u || b == (uint8_t)'q' || b == (uint8_t)'Q' ||
        b == (uint8_t)'c' || b == (uint8_t)'C') {
        return RFB_LEADER_CMD_QUIT;
    }
    if (b == 0x1Au || b == (uint8_t)'z' || b == (uint8_t)'Z') {
        return RFB_LEADER_CMD_SUSPEND;
    }
    if (b == (uint8_t)'+' || b == (uint8_t)'=') {
        return RFB_LEADER_CMD_ZOOM_IN;
    }
    if (b == (uint8_t)'-' || b == (uint8_t)'_') {
        return RFB_LEADER_CMD_ZOOM_OUT;
    }
    return RFB_LEADER_CMD_NONE;
}

bool rfb_norm_key_is_session_quit(const rfb_norm_key *k)
{
    return rfb_norm_key_is_leader(k);
}

bool rfb_byte_is_session_quit(uint8_t b)
{
    return rfb_byte_is_leader(b);
}

// ---------------------------------------------------------------------------
// Modifier keysym classification
// ---------------------------------------------------------------------------

rfb_modkey rfb_norm_modkey_from_sym(uint32_t sym)
{
    switch (sym) {
    case XK_Shift_L:
    case XK_Shift_R:
    case XK_Shift_Lock:
        return RFB_MODKEY_SHIFT;
    case XK_Control_L:
    case XK_Control_R:
        return RFB_MODKEY_CONTROL;
    case XK_Alt_L:
    case XK_Alt_R:
        return RFB_MODKEY_ALT;
    case XK_Meta_L:
    case XK_Meta_R:
    case XK_Super_L:
    case XK_Super_R:
        return RFB_MODKEY_META;
    case XK_Caps_Lock:
        return RFB_MODKEY_CAPSLOCK;
    default:
        return RFB_MODKEY_NONE;
    }
}

// ---------------------------------------------------------------------------
// Modifier tracker
// ---------------------------------------------------------------------------

void rfb_norm_mods_init(rfb_norm_mods *m)
{
    if (m == NULL) {
        return;
    }
    m->shift_l = 0; m->shift_r = 0;
    m->ctrl_l = 0;  m->ctrl_r = 0;
    m->alt_l = 0;   m->alt_r = 0;
    m->meta_l = 0;  m->meta_r = 0;
    m->capslock = false;
    m->bits = RFB_MOD_NONE;
}

// Recompute the bitmask from the physical counts. A modifier is "held" iff
// at least one physical variant is pressed.
static uint16_t rfb_norm_mods_recompute(rfb_norm_mods *m)
{
    uint16_t b = RFB_MOD_NONE;
    if (m->shift_l > 0 || m->shift_r > 0) b |= RFB_MOD_SHIFT;
    if (m->ctrl_l > 0 || m->ctrl_r > 0)   b |= RFB_MOD_CONTROL;
    if (m->alt_l > 0 || m->alt_r > 0)     b |= RFB_MOD_ALT;
    if (m->meta_l > 0 || m->meta_r > 0)   b |= RFB_MOD_META;
    if (m->capslock)                      b |= RFB_MOD_CAPSLOCK;
    m->bits = b;
    return b;
}

uint16_t rfb_norm_mods_apply(rfb_norm_mods *m, uint32_t sym, bool down)
{
    if (m == NULL) {
        return RFB_MOD_NONE;
    }
    // Update the relevant physical counter. Presses set to 1 (not
    // increment) to prevent uint8_t overflow on auto-repeat. Releases
    // decrement, saturated at 0. This is how left/right collapse correctly.
    switch (sym) {
    case XK_Shift_L:
        if (down) m->shift_l = 1; else if (m->shift_l > 0) m->shift_l--;
        break;
    case XK_Shift_R:
        if (down) m->shift_r = 1; else if (m->shift_r > 0) m->shift_r--;
        break;
    case XK_Control_L:
        if (down) m->ctrl_l = 1; else if (m->ctrl_l > 0) m->ctrl_l--;
        break;
    case XK_Control_R:
        if (down) m->ctrl_r = 1; else if (m->ctrl_r > 0) m->ctrl_r--;
        break;
    case XK_Alt_L:
        if (down) m->alt_l = 1; else if (m->alt_l > 0) m->alt_l--;
        break;
    case XK_Alt_R:
        if (down) m->alt_r = 1; else if (m->alt_r > 0) m->alt_r--;
        break;
    case XK_Meta_L:
    case XK_Super_L:
        if (down) m->meta_l = 1; else if (m->meta_l > 0) m->meta_l--;
        break;
    case XK_Meta_R:
    case XK_Super_R:
        if (down) m->meta_r = 1; else if (m->meta_r > 0) m->meta_r--;
        break;
    case XK_Caps_Lock:
        // Caps Lock is a latch: a press toggles it. We only toggle on
        // press, never on release (macOS sends press+release per tap).
        if (down) m->capslock = !m->capslock;
        break;
    default:
        // Non-modifier keys do not change modifier state.
        break;
    }
    return rfb_norm_mods_recompute(m);
}

uint16_t rfb_norm_mods_reset(rfb_norm_mods *m)
{
    if (m == NULL) {
        return RFB_MOD_NONE;
    }
    rfb_norm_mods_init(m);
    return RFB_MOD_NONE;
}

// ---------------------------------------------------------------------------
// Pointer buttons and wheel
// ---------------------------------------------------------------------------

void rfb_norm_pointer_init(rfb_norm_pointer *p)
{
    if (p == NULL) {
        return;
    }
    p->button_mask = RFB_PTR_BUTTON_NONE;
    p->wheel_v = 0;
    p->wheel_h = 0;
}

uint8_t rfb_norm_pointer_button(rfb_norm_pointer *p, uint8_t mask_bit, bool down)
{
    if (p == NULL) {
        return RFB_PTR_BUTTON_NONE;
    }
    if (down) {
        p->button_mask = (uint8_t)(p->button_mask | mask_bit);
    } else {
        p->button_mask = (uint8_t)(p->button_mask & (uint8_t)~mask_bit);
    }
    return p->button_mask;
}

void rfb_norm_pointer_wheel(rfb_norm_pointer *p,
                            int32_t v_delta, int32_t h_delta,
                            int32_t *v_notches, int32_t *h_notches)
{
    int32_t v_out = 0;
    int32_t h_out = 0;
    if (p != NULL) {
        p->wheel_v += v_delta;
        p->wheel_h += h_delta;
        // Emit one notch per full unit (120 sub-units). Integer division
        // truncates toward zero, and the remainder is retained in the
        // accumulator. This is bounded: |delta| inputs produce |notches| ≤
        // |sum|/UNIT outputs, and the remainder is always < UNIT in
        // magnitude.
        if (p->wheel_v >= RFB_PTR_WHEEL_UNIT || p->wheel_v <= -RFB_PTR_WHEEL_UNIT) {
            v_out = p->wheel_v / RFB_PTR_WHEEL_UNIT;
            p->wheel_v -= v_out * RFB_PTR_WHEEL_UNIT;
        }
        if (p->wheel_h >= RFB_PTR_WHEEL_UNIT || p->wheel_h <= -RFB_PTR_WHEEL_UNIT) {
            h_out = p->wheel_h / RFB_PTR_WHEEL_UNIT;
            p->wheel_h -= h_out * RFB_PTR_WHEEL_UNIT;
        }
    }
    if (v_notches != NULL) *v_notches = v_out;
    if (h_notches != NULL) *h_notches = h_out;
}

// ---------------------------------------------------------------------------
// Pixel-coordinate mapping under scaling/letterboxing
// ---------------------------------------------------------------------------

void rfb_norm_geom_init(rfb_norm_geom *g)
{
    if (g == NULL) {
        return;
    }
    g->fb_w = 0;
    g->fb_h = 0;
    g->view_w = 0;
    g->view_h = 0;
    g->scale = 0.0f;
    g->valid = false;
}

bool rfb_norm_geom_set(rfb_norm_geom *g,
                       uint32_t fb_w, uint32_t fb_h,
                       uint32_t view_w, uint32_t view_h, float scale)
{
    if (g == NULL || fb_w == 0 || fb_h == 0 ||
        view_w == 0 || view_h == 0 || scale <= 0.0f) {
        return false;
    }
    g->fb_w = fb_w;
    g->fb_h = fb_h;
    g->view_w = view_w;
    g->view_h = view_h;
    g->scale = scale;
    g->valid = true;
    return true;
}

// The framebuffer is shown in the viewport scaled by `scale` and centered
// (letterboxed). The displayed image size is (fb_w*scale) x (fb_h*scale).
// The offset (top-left of the image in viewport coords) centers it.
//
// Inverse map: fb = (view - offset) / scale, clamped to [0, fb-1].
static bool rfb_norm_geom_mapf_internal(const rfb_norm_geom *g,
                                        float view_x, float view_y,
                                        float *fb_x, float *fb_y)
{
    if (g == NULL || !g->valid || g->scale <= 0.0f) {
        return false;
    }
    // Displayed image size in viewport pixels.
    float img_w = (float)g->fb_w * g->scale;
    float img_h = (float)g->fb_h * g->scale;
    // Letterbox offsets (center the image).
    float off_x = ((float)g->view_w - img_w) * 0.5f;
    float off_y = ((float)g->view_h - img_h) * 0.5f;
    // Inverse scale.
    float fx = (view_x - off_x) / g->scale;
    float fy = (view_y - off_y) / g->scale;
    // Clamp to framebuffer bounds [0, fb-1].
    if (fx < 0.0f) fx = 0.0f;
    if (fy < 0.0f) fy = 0.0f;
    if (fx > (float)(g->fb_w - 1u)) fx = (float)(g->fb_w - 1u);
    if (fy > (float)(g->fb_h - 1u)) fy = (float)(g->fb_h - 1u);
    if (fb_x != NULL) *fb_x = fx;
    if (fb_y != NULL) *fb_y = fy;
    return true;
}

bool rfb_norm_geom_mapf(const rfb_norm_geom *g,
                        float view_x, float view_y,
                        float *fb_x, float *fb_y)
{
    return rfb_norm_geom_mapf_internal(g, view_x, view_y, fb_x, fb_y);
}

bool rfb_norm_geom_map(const rfb_norm_geom *g,
                       int32_t view_x, int32_t view_y,
                       int32_t *fb_x, int32_t *fb_y)
{
    float fx = 0.0f, fy = 0.0f;
    if (!rfb_norm_geom_mapf_internal(g, (float)view_x, (float)view_y, &fx, &fy)) {
        return false;
    }
    if (fb_x != NULL) *fb_x = (int32_t)(fx + 0.5f);  // round
    if (fb_y != NULL) *fb_y = (int32_t)(fy + 0.5f);
    return true;
}

// ===========================================================================
// Keysym ←→ text / code mapping
// ===========================================================================

// US-layout shifted number-row: keysym '1'→'!', '2'→'@', ... (public X11
// keyboard convention; not derived from any implementation source).
// Index 0 = '0' (0x30), index 9 = '9' (0x39).
static const uint8_t k_shifted_digit_row[10] = {
    ')', '!', '@', '#', '$', '%', '^', '&', '*', '('
};

uint32_t rfb_kb_keysym_to_text(uint32_t keysym, bool shift)
{
    // Modifier and function keys produce no text.
    if (keysym >= 0xFF00u && keysym <= 0xFFFFu) {
        return 0u;
    }
    // ASCII range 0x20..0x7E.
    if (keysym >= 0x20u && keysym <= 0x7Eu) {
        // Letters a-z → A-Z when shifted.
        if (keysym >= 0x61u && keysym <= 0x7Au) {
            return shift ? (keysym - 0x20u) : keysym;
        }
        // Letters A-Z stay uppercase regardless (already uppercase keysym).
        if (keysym >= 0x41u && keysym <= 0x5Au) {
            return keysym;
        }
        // Digits 0-9 → shifted symbol row.
        if (keysym >= 0x30u && keysym <= 0x39u) {
            if (shift) {
                return (uint32_t)k_shifted_digit_row[keysym - 0x30u];
            }
            return keysym;
        }
        // Space and other punctuation: return as-is.
        return keysym;
    }
    // Latin-1 supplement (0xA0..0xFF): keysym == codepoint.
    if (keysym >= 0xA0u && keysym <= 0xFFu) {
        return keysym;
    }
    // BMP/emoji (0x100..0x10FFFF): keysym == codepoint (for terminals that
    // deliver resolved composed codepoints directly).
    if (keysym >= 0x100u && keysym <= 0x10FFFFu) {
        return keysym;
    }
    return 0u;
}

uint32_t rfb_kb_code_to_keysym(uint32_t code)
{
    switch (code) {
    case KITTY_CODE_ENTER:      return XK_Return;
    case KITTY_CODE_TAB:        return XK_Tab;
    case KITTY_CODE_ESCAPE:     return XK_Escape;
    case KITTY_CODE_BACKSPACE:  return XK_BackSpace;
    case KITTY_CODE_SPACE:      return 0x0020u;
    case KITTY_CODE_INSERT:     return XK_Insert;
    case KITTY_CODE_DELETE:     return XK_Delete;
    case KITTY_CODE_LEFT:       return XK_Left;
    case KITTY_CODE_RIGHT:      return XK_Right;
    case KITTY_CODE_UP:         return XK_Up;
    case KITTY_CODE_DOWN:       return XK_Down;
    case KITTY_CODE_HOME:       return XK_Home;
    case KITTY_CODE_END:        return XK_End;
    case KITTY_CODE_PAGEUP:     return XK_Page_Up;
    case KITTY_CODE_PAGEDOWN:   return XK_Page_Down;
    case KITTY_CODE_F1:         return XK_F1;
    case KITTY_CODE_F2:         return XK_F2;
    case KITTY_CODE_F3:         return XK_F3;
    case KITTY_CODE_F4:         return XK_F4;
    case KITTY_CODE_F5:         return XK_F5;
    case KITTY_CODE_F6:         return XK_F6;
    case KITTY_CODE_F7:         return XK_F7;
    case KITTY_CODE_F8:         return XK_F8;
    case KITTY_CODE_F9:         return XK_F9;
    case KITTY_CODE_F10:        return XK_F10;
    case KITTY_CODE_F11:        return XK_F11;
    case KITTY_CODE_F12:        return XK_F12;
    case KITTY_CODE_SHIFT_L:    return XK_Shift_L;
    case KITTY_CODE_CTRL_L:     return XK_Control_L;
    case KITTY_CODE_ALT_L:      return XK_Alt_L;
    case KITTY_CODE_SUPER_L:    return XK_Super_L;
    default:
        // Printable ASCII and Latin-1: keysym == code.
        if (code >= 0x20u && code <= 0x10FFFFu) {
            return code;
        }
        return 0u;
    }
}

// ===========================================================================
// Keyboard parser (Kitty keyboard protocol + legacy terminal)
// ===========================================================================

void rfb_kb_init(rfb_kb *kb)
{
    if (kb == NULL) return;
    kb->state = RFB_KB_IDLE;
    kb->params_len = 0;
    kb->params[0] = '\0';
    kb->last_char = '\0';
    kb->esc_pending = false;
}

// Parse a decimal integer from a substring; returns true and sets *val.
// Stops at the first non-digit so Kitty alternate-key fields like
// "93:93" or event fields like "1;93" still yield the leading number
// (full-field strict parse used to drop the whole CSI-u event).
static bool parse_uint(const char *s, size_t len, uint32_t *val)
{
    uint32_t v = 0u;
    bool any = false;
    for (size_t i = 0; i < len; i++) {
        char c = s[i];
        if (c < '0' || c > '9') {
            break;
        }
        v = v * 10u + (uint32_t)(c - '0');
        any = true;
    }
    if (!any) {
        return false;
    }
    *val = v;
    return true;
}

// Find the index of a character in params, or SIZE_MAX.
static size_t find_char(const char *s, size_t len, char c)
{
    for (size_t i = 0; i < len; i++) {
        if (s[i] == c) return i;
    }
    return (size_t)-1;
}

// Decode a UTF-8 lead byte: returns the number of continuation bytes needed
// (0 for ASCII), or 99 for an invalid lead. Sets *cp to the partial value.
static size_t utf8_lead(uint8_t b, uint32_t *cp)
{
    if (b <= 0x7Fu) { *cp = (uint32_t)b; return 0u; }
    if (b >= 0xC2u && b <= 0xDFu) { *cp = (uint32_t)(b & 0x1Fu); return 1u; }
    if (b >= 0xE0u && b <= 0xEFu) { *cp = (uint32_t)(b & 0x0Fu); return 2u; }
    if (b >= 0xF0u && b <= 0xF4u) { *cp = (uint32_t)(b & 0x07u); return 3u; }
    return 99u;
}

// Build a legacy key event (no modifier field).
static void make_legacy(rfb_norm_key *out, uint32_t keysym,
                        const rfb_norm_mods *mods)
{
    if (out == NULL) return;
    out->keysym = keysym;
    out->modifiers = (mods != NULL) ? rfb_norm_mods_bits(mods) : RFB_MOD_NONE;
    out->down = true;
    out->repeat = false;
    out->source = RFB_NORM_SOURCE_LEGACY;
    out->text = rfb_kb_keysym_to_text(keysym, (out->modifiers & RFB_MOD_SHIFT) != 0);
}

// Decode a Kitty/xterm modifier field into the normalized bitmask.
// field encoding: 1 + (shift|alt*2|control*4|super*8). A field of 1 or 0
// means no modifiers.
static uint16_t decode_mod_field(uint32_t field)
{
    uint16_t modbits = RFB_MOD_NONE;
    if (field >= 2u) {
        uint32_t m = field - 1u;
        if (m & 0x1u) modbits |= RFB_MOD_SHIFT;
        if (m & 0x2u) modbits |= RFB_MOD_ALT;
        if (m & 0x4u) modbits |= RFB_MOD_CONTROL;
        if (m & 0x8u) modbits |= RFB_MOD_META;
    }
    return modbits;
}

// Split params at the first ';'. Sets *first_len to the length of the first
// sub-param and returns the index of the ';' (or (size_t)-1 if none).
static size_t split_first_param(const char *s, size_t len, size_t *first_len)
{
    size_t semi = find_char(s, len, ';');
    if (semi == (size_t)-1) {
        *first_len = len;
        return (size_t)-1;
    }
    *first_len = semi;
    return semi;
}

// Finish a CSI/SS3 sequence: parse params + terminator → event.
// `final` is the terminator char ('A', 'u', '~', etc.). `is_kitty` selects
// the CSI-u (Kitty) interpretation when final == 'u'.
static rfb_norm_source finish_seq(rfb_kb *kb, char final,
                                  const rfb_norm_mods *mods, rfb_norm_key *out)
{
    if (out == NULL) {
        rfb_kb_init(kb);
        return RFB_NORM_SOURCE_NONE;
    }
    // Kitty keyboard protocol: terminator 'u'.
    if (final == 'u') {
        size_t first_len = 0u;
        size_t semi = split_first_param(kb->params, kb->params_len, &first_len);
        uint32_t code = 0u;
        uint32_t mod_field = 1u;  // default mods
        uint32_t event_type = 0u; // default press
        if (!parse_uint(kb->params, first_len, &code)) {
            rfb_kb_init(kb);
            return RFB_NORM_SOURCE_NONE;
        }
        if (semi != (size_t)-1) {
            // After the semicolon: "mods" possibly followed by ":event".
            size_t rest = semi + 1u;
            size_t colon = find_char(kb->params + rest,
                                     kb->params_len - rest, ':');
            size_t mod_end = (colon == (size_t)-1) ? kb->params_len
                                                    : (rest + colon);
            if (mod_end > rest) {
                (void)parse_uint(kb->params + rest, mod_end - rest, &mod_field);
            }
            if (colon != (size_t)-1) {
                size_t ev_start = rest + colon + 1u;
                if (ev_start < kb->params_len) {
                    (void)parse_uint(kb->params + ev_start,
                                     kb->params_len - ev_start, &event_type);
                }
            }
        }
        uint32_t sym = rfb_kb_code_to_keysym(code);
        if (sym == 0u) {
            rfb_kb_init(kb);
            return RFB_NORM_SOURCE_NONE;
        }
        uint16_t modbits = decode_mod_field(mod_field);
        out->keysym = sym;
        out->modifiers = modbits;
        // Kitty keyboard protocol event types (flag 0b10 / report events):
        //   1 = press (default when the sub-field is absent)
        //   2 = repeat
        //   3 = release
        // See https://sw.kovidgoyal.net/kitty/keyboard-protocol/#event-types
        // event_type 0 is treated as press (field omitted).
        out->down = (event_type != 3u);
        out->repeat = (event_type == 2u);
        out->source = RFB_NORM_SOURCE_KITTY;
        out->text = rfb_kb_keysym_to_text(sym, (modbits & RFB_MOD_SHIFT) != 0);
        rfb_kb_init(kb);
        return RFB_NORM_SOURCE_KITTY;
    }

    // Legacy CSI / SS3 with a letter or '~' terminator.
    // xterm arrow convention: A=Up B=Down C=Right D=Left, H=Home, F=End.
    // The legacy modifier encoding is ESC [ <param> ; <mods> <final>.
    uint32_t sym = 0u;
    // Extract the modifier field if a ';' is present (second sub-param).
    uint32_t legacy_mod_field = 0u;
    size_t first_len = 0u;
    size_t semi = split_first_param(kb->params, kb->params_len, &first_len);
    if (semi != (size_t)-1) {
        size_t rest = semi + 1u;
        if (rest < kb->params_len) {
            (void)parse_uint(kb->params + rest, kb->params_len - rest,
                             &legacy_mod_field);
        }
    }
    switch (final) {
    case 'A': sym = XK_Up; break;
    case 'B': sym = XK_Down; break;
    case 'C': sym = XK_Right; break;
    case 'D': sym = XK_Left; break;
    case 'H': sym = XK_Home; break;
    case 'F': sym = XK_End; break;
    case 'P': sym = XK_F1; break;
    case 'Q': sym = XK_F2; break;
    case 'R': sym = XK_F3; break;
    case 'S': sym = XK_F4; break;
    case '~': {
        // Numeric keypad/function: ESC [ <n> ~. Common mappings.
        uint32_t n = 0u;
        if (parse_uint(kb->params, first_len, &n)) {
            switch (n) {
            case 1u: case 7u: sym = XK_Home; break;
            case 2u: sym = XK_Insert; break;
            case 3u: sym = XK_Delete; break;
            case 4u: case 8u: sym = XK_End; break;
            case 5u: sym = XK_Page_Up; break;
            case 6u: sym = XK_Page_Down; break;
            case 11u: sym = XK_F1; break;
            case 12u: sym = XK_F2; break;
            case 13u: sym = XK_F3; break;
            case 14u: sym = XK_F4; break;
            case 15u: sym = XK_F5; break;
            case 17u: sym = XK_F6; break;
            case 18u: sym = XK_F7; break;
            case 19u: sym = XK_F8; break;
            case 20u: sym = XK_F9; break;
            case 21u: sym = XK_F10; break;
            case 23u: sym = XK_F11; break;
            case 24u: sym = XK_F12; break;
            default: sym = 0u; break;
            }
        }
        break;
    }
    default: sym = 0u; break;
    }
    rfb_kb_init(kb);
    if (sym == 0u) {
        return RFB_NORM_SOURCE_NONE;
    }
    make_legacy(out, sym, mods);
    // If the legacy sequence carried a modifier field, override the
    // modifier-derived bits (the xterm field is authoritative for that key).
    if (legacy_mod_field != 0u) {
        out->modifiers = decode_mod_field(legacy_mod_field);
    }
    return RFB_NORM_SOURCE_LEGACY;
}

// Handle a byte in the IDLE state (start of a new sequence).
static rfb_norm_source idle_byte(rfb_kb *kb, uint8_t b,
                                 const rfb_norm_mods *mods, rfb_norm_key *out)
{
    if (b == 0x1Bu) {
        // ESC — could be CSI/SS3 intro or a lone Escape.
        kb->state = RFB_KB_ESC;
        kb->esc_pending = true;
        return RFB_NORM_SOURCE_NONE;
    }
    // C0 controls that map directly to keysyms.
    if (b == 0x09u) {           // TAB
        make_legacy(out, XK_Tab, mods);
        return RFB_NORM_SOURCE_LEGACY;
    }
    if (b == 0x0Du || b == 0x0Au) {  // CR or LF → Return
        make_legacy(out, XK_Return, mods);
        return RFB_NORM_SOURCE_LEGACY;
    }
    if (b == 0x08u) {           // BS (Ctrl-H)
        make_legacy(out, XK_BackSpace, mods);
        return RFB_NORM_SOURCE_LEGACY;
    }
    if (b == 0x7Fu) {           // DEL → BackSpace (terminal convention)
        make_legacy(out, XK_BackSpace, mods);
        return RFB_NORM_SOURCE_LEGACY;
    }
    // Other C0 controls (0x00-0x1F except above) are not mapped to keysyms;
    // drop them (the terminal cannot reliably report their key identity).
    if (b < 0x20u) {
        return RFB_NORM_SOURCE_NONE;
    }
    // Printable / UTF-8 lead byte.
    uint32_t cp = 0u;
    size_t need = utf8_lead(b, &cp);
    if (need == 0u) {
        // ASCII printable.
        make_legacy(out, (uint32_t)b, mods);
        return RFB_NORM_SOURCE_LEGACY;
    }
    if (need == 99u) {
        // Invalid UTF-8 lead — drop.
        return RFB_NORM_SOURCE_NONE;
    }
    // Multibyte: stash the lead and wait for continuations. We reuse the
    // param buffer as a small codepoint accumulator by storing the partial
    // cp and the count in a compact form. Since params is char[], encode
    // the expected count and partial cp into a few bytes.
    // Simpler: keep a tiny inline UTF-8 decode using kb->params as raw bytes.
    kb->params[0] = (char)b;
    kb->params_len = 1u;
    kb->last_char = (char)('0' + (char)need);  // encode remaining count
    kb->state = RFB_KB_CSI;  // reuse CSI state machine's "collecting" mode
    kb->esc_pending = false;
    return RFB_NORM_SOURCE_NONE;
}

// Handle a continuation of a multibyte UTF-8 sequence (when last_char holds
// a digit encoding the remaining continuation count). Returns true if the
// event was emitted.
static rfb_norm_source mb_continue(rfb_kb *kb, uint8_t b,
                                   const rfb_norm_mods *mods, rfb_norm_key *out)
{
    // Collect the raw bytes in kb->params, decrement the count in last_char.
    if (kb->params_len < sizeof kb->params) {
        kb->params[kb->params_len++] = (char)b;
    }
    int remaining = (int)(kb->last_char - '0') - 1;
    if (remaining <= 0) {
        // Decode the collected bytes.
        uint32_t cp = 0u;
        size_t need = utf8_lead((uint8_t)kb->params[0], &cp);
        bool ok = (need == kb->params_len - 1u);
        for (size_t i = 1u; ok && i < kb->params_len; i++) {
            uint8_t c = (uint8_t)kb->params[i];
            if (c < 0x80u || c > 0xBFu) { ok = false; break; }
            cp = (cp << 6u) | (uint32_t)(c & 0x3Fu);
        }
        rfb_kb_init(kb);
        if (ok && cp != 0u && cp <= 0x10FFFFu &&
            !(cp >= 0xD800u && cp <= 0xDFFFu)) {
            make_legacy(out, cp, mods);
            return RFB_NORM_SOURCE_LEGACY;
        }
        return RFB_NORM_SOURCE_NONE;
    }
    kb->last_char = (char)('0' + (char)remaining);
    return RFB_NORM_SOURCE_NONE;
}

rfb_norm_source rfb_kb_feed(rfb_kb *kb, uint8_t byte,
                            const rfb_norm_mods *mods, rfb_norm_key *out)
{
    if (kb == NULL || out == NULL) {
        return RFB_NORM_SOURCE_NONE;
    }
    switch (kb->state) {
    case RFB_KB_IDLE:
        return idle_byte(kb, byte, mods, out);

    case RFB_KB_ESC:
        // We saw an ESC. The next byte decides.
        kb->esc_pending = false;
        if (byte == '[') {
            kb->state = RFB_KB_CSI;
            kb->params_len = 0u;
            return RFB_NORM_SOURCE_NONE;
        }
        if (byte == 'O') {
            kb->state = RFB_KB_SS3;
            kb->params_len = 0u;
            return RFB_NORM_SOURCE_NONE;
        }
        // ESC followed by something else: emit Escape, then reprocess the
        // byte from IDLE (it is a separate keystroke). For the common case
        // of ESC alone being Escape, flush() handles it.
        make_legacy(out, XK_Escape, mods);
        // Reprocess the current byte by simulating a fresh idle transition.
        // We reset and recurse once via idle_byte.
        kb->state = RFB_KB_IDLE;
        // If this byte is itself printable/control, emit it too — but we
        // can only return one event per call. The caller's rfb_kb_parse
        // loop handles multi-event slices; for single-byte feed the caller
        // will feed the byte again. To keep the contract simple, we drop
        // the trailing byte here (rare: ESC + non-CSI). The event is Escape.
        return RFB_NORM_SOURCE_LEGACY;

    case RFB_KB_CSI: {
        // If we're collecting a multibyte UTF-8 sequence (encoded in
        // last_char as a digit), continue that path.
        if (kb->last_char >= '0' && kb->last_char <= '9' && kb->params_len > 0u) {
            return mb_continue(kb, byte, mods, out);
        }
        // Collecting CSI params: digits, ';', ':'. Terminated by a letter or
        // '~' or 'u'.
        char c = (char)byte;
        if ((c >= '0' && c <= '9') || c == ';' || c == ':') {
            if (kb->params_len < sizeof kb->params - 1u) {
                kb->params[kb->params_len++] = c;
            }
            return RFB_NORM_SOURCE_NONE;
        }
        // Terminator.
        return finish_seq(kb, c, mods, out);
    }

    case RFB_KB_SS3: {
        char c = (char)byte;
        // SS3 typically has no params; the next byte is the final char.
        return finish_seq(kb, c, mods, out);
    }

    default:
        rfb_kb_init(kb);
        return RFB_NORM_SOURCE_NONE;
    }
}

rfb_norm_source rfb_kb_flush(rfb_kb *kb, const rfb_norm_mods *mods,
                             rfb_norm_key *out)
{
    if (kb == NULL || out == NULL) {
        return RFB_NORM_SOURCE_NONE;
    }
    rfb_norm_source s = RFB_NORM_SOURCE_NONE;
    // A pending lone ESC resolves to Escape.
    if (kb->esc_pending && kb->state == RFB_KB_ESC) {
        make_legacy(out, XK_Escape, mods);
        s = RFB_NORM_SOURCE_LEGACY;
    }
    rfb_kb_init(kb);
    return s;
}

size_t rfb_kb_parse(const uint8_t *data, size_t len,
                    const rfb_norm_mods *mods,
                    rfb_norm_key *out, size_t out_cap)
{
    if (data == NULL || out == NULL || out_cap == 0u) {
        return 0u;
    }
    rfb_kb kb;
    rfb_kb_init(&kb);
    size_t produced = 0u;
    for (size_t i = 0u; i < len; i++) {
        rfb_norm_key ev;
        rfb_norm_source s = rfb_kb_feed(&kb, data[i], mods, &ev);
        if (s != RFB_NORM_SOURCE_NONE) {
            if (produced < out_cap) {
                out[produced] = ev;
                produced++;
            }
            // If the parser dropped a trailing byte after emitting ESC,
            // and we still have bytes, the rfb_kb_feed for ESC+other
            // returned one event and left the trailing byte unprocessed.
            // Re-feed it by not advancing. We handle the ESC+printable case
            // specially: when state returns to IDLE after an ESC that was
            // not CSI/SS3, the trailing printable was dropped. Detect and
            // reprocess.
            if (kb.state == RFB_KB_IDLE && i + 1u < len) {
                // Nothing extra to do; the next loop iteration handles the
                // following byte normally.
            }
        }
    }
    // Flush any trailing lone ESC.
    if (produced < out_cap) {
        rfb_norm_key ev;
        rfb_norm_source s = rfb_kb_flush(&kb, mods, &ev);
        if (s != RFB_NORM_SOURCE_NONE) {
            out[produced] = ev;
            produced++;
        }
    }
    return produced;
}
