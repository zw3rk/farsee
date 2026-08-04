// SPDX-License-Identifier: Apache-2.0
//
// Farsee RDP input bridge implementation (R4 gate, §15.11).

#include "rdp_input_bridge.h"

rdp_key_dispatch rdp_input_key_dispatch(const farsee_key_event *e)
{
    if (e == NULL) {
        return RDP_KEY_DROP;
    }
    // §15.11: prefer physical scan codes for keys whose physical identity
    // is known (EXACT or INFERRED with a physical key).
    if (e->physical != 0) {
        return RDP_KEY_SCANCODE;
    }
    // No physical identity: use Unicode for committed text.
    if (e->unicode != 0) {
        return RDP_KEY_UNICODE;
    }
    // Cannot map: terminal-only key with no physical or text identity.
    return RDP_KEY_DROP;
}

uint8_t rdp_input_button_for_transition(unsigned prev_buttons,
                                        unsigned curr_buttons)
{
    // Report the single button that changed (press or release). RDP sends
    // one button event per transition. We report the lowest-numbered
    // changed button (left > middle > right > X1 > X2 priority).
    unsigned changed = prev_buttons ^ curr_buttons;
    if (changed == 0) {
        return 0;
    }
    if (changed & FARSEE_BUTTON_LEFT)   return 1;
    if (changed & FARSEE_BUTTON_MIDDLE) return 2;
    if (changed & FARSEE_BUTTON_RIGHT)  return 3;
    if (changed & FARSEE_BUTTON_X1)     return 4;
    if (changed & FARSEE_BUTTON_X2)     return 5;
    return 0;
}

int32_t rdp_input_wheel_notches(int32_t wheel_delta)
{
    // RDP vertical wheel is reported in units of 120 per notch (Microsoft
    // PS/2 mouse standard). High-resolution deltas accumulate; integer
    // division truncates sub-notch remainder (the caller accumulates).
    if (wheel_delta >= 0) {
        return wheel_delta / 120;
    }
    // Negative: round toward zero would be wrong for -119 (should be 0,
    // same as positive truncation). Use symmetric truncation.
    return -((-wheel_delta) / 120);
}

// FreeRDP-compatible extended-bit packing (KBDEXT = 0x0100). Defined here
// as a bare constant so this TU stays FreeRDP-header free.
#define RDP_SCAN_EXT 0x0100u

// Set-1 scancodes for Latin letters a–z (index 0 = 'a'). Public IBM AT map.
static const uint8_t k_letter_scancodes[26] = {
    /* a */ 0x1E, /* b */ 0x30, /* c */ 0x2E, /* d */ 0x20, /* e */ 0x12,
    /* f */ 0x21, /* g */ 0x22, /* h */ 0x23, /* i */ 0x17, /* j */ 0x24,
    /* k */ 0x25, /* l */ 0x26, /* m */ 0x32, /* n */ 0x31, /* o */ 0x18,
    /* p */ 0x19, /* q */ 0x10, /* r */ 0x13, /* s */ 0x1F, /* t */ 0x14,
    /* u */ 0x16, /* v */ 0x2F, /* w */ 0x11, /* x */ 0x2D, /* y */ 0x15,
    /* z */ 0x2C,
};

// Digit keysyms '1'..'9','0' → set-1 0x02..0x0A, 0x0B.
static const uint8_t k_digit_scancodes[10] = {
    /* 0 */ 0x0B, /* 1 */ 0x02, /* 2 */ 0x03, /* 3 */ 0x04, /* 4 */ 0x05,
    /* 5 */ 0x06, /* 6 */ 0x07, /* 7 */ 0x08, /* 8 */ 0x09, /* 9 */ 0x0A,
};

typedef struct {
    uint32_t keysym;
    uint8_t scancode;
    bool extended;
} rdp_keysym_entry;

// Named / function / modifier / navigation keysyms (X11 keysymdef.h public
// values) → set-1 + extended. Sorted by keysym for binary search.
static const rdp_keysym_entry k_named_keysyms[] = {
    {0xFF08u, 0x0E, false},  // BackSpace
    {0xFF09u, 0x0F, false},  // Tab
    {0xFF0Du, 0x1C, false},  // Return
    {0xFF1Bu, 0x01, false},  // Escape
    {0xFF50u, 0x47, true},   // Home
    {0xFF51u, 0x4B, true},   // Left
    {0xFF52u, 0x48, true},   // Up
    {0xFF53u, 0x4D, true},   // Right
    {0xFF54u, 0x50, true},   // Down
    {0xFF55u, 0x49, true},   // Page_Up
    {0xFF56u, 0x51, true},   // Page_Down
    {0xFF57u, 0x4F, true},   // End
    {0xFF63u, 0x52, true},   // Insert
    {0xFF8Du, 0x1C, true},   // KP_Enter
    {0xFFBEu, 0x3B, false},  // F1
    {0xFFBFu, 0x3C, false},  // F2
    {0xFFC0u, 0x3D, false},  // F3
    {0xFFC1u, 0x3E, false},  // F4
    {0xFFC2u, 0x3F, false},  // F5
    {0xFFC3u, 0x40, false},  // F6
    {0xFFC4u, 0x41, false},  // F7
    {0xFFC5u, 0x42, false},  // F8
    {0xFFC6u, 0x43, false},  // F9
    {0xFFC7u, 0x44, false},  // F10
    {0xFFC8u, 0x57, false},  // F11
    {0xFFC9u, 0x58, false},  // F12
    {0xFFE1u, 0x2A, false},  // Shift_L
    {0xFFE2u, 0x36, false},  // Shift_R
    {0xFFE3u, 0x1D, false},  // Control_L
    {0xFFE4u, 0x1D, true},   // Control_R
    {0xFFE5u, 0x3A, false},  // Caps_Lock
    {0xFFE7u, 0x5B, true},   // Meta_L  → Super/Win
    {0xFFE8u, 0x5C, true},   // Meta_R
    {0xFFE9u, 0x38, false},  // Alt_L
    {0xFFEAu, 0x38, true},   // Alt_R
    {0xFFEBu, 0x5B, true},   // Super_L
    {0xFFECu, 0x5C, true},   // Super_R
    {0xFFFFu, 0x53, true},   // Delete
};

static bool named_lookup(uint32_t keysym, uint32_t *out_sc, bool *out_ext)
{
    // Linear scan: table is small (~40). Keeps the TU simple and portable.
    const size_t n = sizeof(k_named_keysyms) / sizeof(k_named_keysyms[0]);
    for (size_t i = 0; i < n; ++i) {
        if (k_named_keysyms[i].keysym == keysym) {
            *out_sc = k_named_keysyms[i].scancode;
            *out_ext = k_named_keysyms[i].extended;
            return true;
        }
    }
    return false;
}

bool rdp_input_keysym_to_scancode(uint32_t keysym, uint32_t *out_scancode,
                                  bool *out_extended)
{
    if (out_scancode == NULL || out_extended == NULL) {
        return false;
    }

    // Printable Latin letters: lowercase 0x61–0x7a, uppercase 0x41–0x5a.
    if (keysym >= 0x61u && keysym <= 0x7Au) {
        *out_scancode = k_letter_scancodes[keysym - 0x61u];
        *out_extended = false;
        return true;
    }
    if (keysym >= 0x41u && keysym <= 0x5Au) {
        *out_scancode = k_letter_scancodes[keysym - 0x41u];
        *out_extended = false;
        return true;
    }

    // Digits 0–9 (Latin-1 / ASCII).
    if (keysym >= 0x30u && keysym <= 0x39u) {
        *out_scancode = k_digit_scancodes[keysym - 0x30u];
        *out_extended = false;
        return true;
    }

    // Space is a single-byte keysym, not in the named FF-range table.
    if (keysym == 0x20u) {
        *out_scancode = 0x39u;
        *out_extended = false;
        return true;
    }

    return named_lookup(keysym, out_scancode, out_extended);
}

bool rdp_input_key_event_from_keysym(farsee_key_event *out, uint32_t keysym,
                                     uint32_t unicode, bool down, bool repeat)
{
    if (out == NULL) {
        return false;
    }
    out->physical = 0;
    out->logical = keysym;
    out->unicode = unicode;
    out->modifiers = 0;
    out->locks = 0;
    out->timestamp_ms = 0;
    if (down) {
        out->action = repeat ? FARSEE_KEY_REPEAT : FARSEE_KEY_PRESS;
    } else {
        out->action = FARSEE_KEY_RELEASE;
    }

    uint32_t sc = 0;
    bool ext = false;
    if (rdp_input_keysym_to_scancode(keysym, &sc, &ext)) {
        out->physical = (sc & 0xFFu) | (ext ? RDP_SCAN_EXT : 0u);
        out->quality = FARSEE_INPUT_QUALITY_INFERRED;
    } else if (unicode != 0) {
        out->quality = FARSEE_INPUT_QUALITY_INFERRED;
    } else {
        out->quality = FARSEE_INPUT_QUALITY_UNAVAILABLE;
    }
    return true;
}

void rdp_button_wire_init(rdp_button_wire_state *s)
{
    if (s == NULL) {
        return;
    }
    s->wire = 0u;
    s->desired = 0u;
    s->pending = false;
    s->abs_x = 0;
    s->abs_y = 0;
}

void rdp_button_wire_note_cmd(rdp_button_wire_state *s, unsigned buttons,
                              int32_t abs_x, int32_t abs_y)
{
    if (s == NULL) {
        return;
    }
    s->desired = buttons;
    s->abs_x = abs_x;
    s->abs_y = abs_y;
    s->pending = (s->wire != s->desired);
}

void rdp_button_wire_note_inject(rdp_button_wire_state *s, unsigned reached)
{
    if (s == NULL) {
        return;
    }
    s->wire = reached;
    s->pending = (s->wire != s->desired);
}

bool rdp_button_wire_needs_sync(const rdp_button_wire_state *s)
{
    return s != NULL && s->pending && (s->wire != s->desired);
}
