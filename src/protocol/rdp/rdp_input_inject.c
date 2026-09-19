// SPDX-License-Identifier: Apache-2.0
//
// Farsee RDP FreeRDP input injection implementation (R6).
//
// FreeRDP/WinPR types are confined to this translation unit. Mapping logic
// for keysym→scancode and button/wheel policy lives in the pure
// rdp_input_bridge (no FreeRDP headers).

#include "rdp_input_inject.h"
#include "rdp_input_bridge.h"

#include <freerdp/freerdp.h>
#include <freerdp/input.h>

#include <stddef.h>
#include <string.h>

// Resolve the FreeRDP rdpInput* from an opaque facade ctx. NULL if the
// instance/context/input chain is not ready.
static rdpInput *rdp_inject_input(rdp_freerdp_ctx *ctx)
{
    if (ctx == NULL) {
        return NULL;
    }
    freerdp *inst = (freerdp *)rdp_freerdp_instance_opaque(ctx);
    if (inst == NULL || inst->context == NULL) {
        return NULL;
    }
    return inst->context->input;
}

static bool send_scancode(rdpInput *input, uint32_t packed_scancode, bool down,
                          bool repeat)
{
    if (input == NULL) {
        return false;
    }
    // freerdp_input_send_keyboard_event_ex expects FreeRDP's packed form
    // (low 8 bits = set-1 code; KBDEXT/0x100 = extended). Our bridge packs
    // physical the same way, so pass through.
    return freerdp_input_send_keyboard_event_ex(input, down ? TRUE : FALSE,
                                                repeat ? TRUE : FALSE,
                                                packed_scancode)
               ? true
               : false;
}

static bool send_unicode(rdpInput *input, uint32_t unicode, bool down)
{
    if (input == NULL || unicode == 0 || unicode > 0xFFFFu) {
        return false;
    }
    const UINT16 flags = down ? (UINT16)0 : (UINT16)KBD_FLAGS_RELEASE;
    return freerdp_input_send_unicode_keyboard_event(input, flags,
                                                     (UINT16)unicode)
               ? true
               : false;
}

bool rdp_input_inject_focus_in(rdp_freerdp_ctx *ctx)
{
    rdpInput *input = rdp_inject_input(ctx);
    if (input == NULL) {
        return false;
    }
    // Send FocusIn with no caps, num, or scroll toggle bits set.
    const BOOL ok = freerdp_input_send_focus_in_event(input, 0);
    return ok ? true : false;
}

bool rdp_input_inject_key(rdp_freerdp_ctx *ctx, const farsee_key_event *e)
{
    if (ctx == NULL || e == NULL) {
        return false;
    }
    rdpInput *input = rdp_inject_input(ctx);
    if (input == NULL) {
        return false;
    }

    const bool down = (e->action != FARSEE_KEY_RELEASE);
    const bool repeat = (e->action == FARSEE_KEY_REPEAT);

    if (e->physical != 0) {
        return send_scancode(input, e->physical, down, repeat);
    }
    if (e->unicode != 0) {
        return send_unicode(input, e->unicode, down);
    }
    return false;
}

bool rdp_input_inject_key_from_keysym(rdp_freerdp_ctx *ctx, uint32_t keysym,
                                      uint32_t unicode, bool down, bool repeat)
{
    if (ctx == NULL) {
        return false;
    }
    rdpInput *input = rdp_inject_input(ctx);
    if (input == NULL) {
        return false;
    }

    uint32_t sc = 0;
    bool ext = false;
    bool ok = false;
    if (rdp_input_keysym_to_scancode(keysym, &sc, &ext)) {
        const uint32_t packed = (sc & 0xFFu) | (ext ? 0x0100u : 0u);
        ok = send_scancode(input, packed, down, down && repeat);
    } else if (unicode != 0) {
        ok = send_unicode(input, unicode, down);
    }
    return ok;
}

// Map RDP button number (1–5) + down to FreeRDP mouse / extended flags.
// Returns false for unknown button. Writes *use_extended for X1/X2.
static bool button_flags(uint8_t rdp_button, bool down, UINT16 *out_flags,
                         bool *use_extended)
{
    if (out_flags == NULL || use_extended == NULL) {
        return false;
    }
    *use_extended = false;
    *out_flags = 0;
    switch (rdp_button) {
    case 1:
        *out_flags = (UINT16)(PTR_FLAGS_BUTTON1 | (down ? PTR_FLAGS_DOWN : 0));
        return true;
    case 2:
        *out_flags = (UINT16)(PTR_FLAGS_BUTTON3 | (down ? PTR_FLAGS_DOWN : 0));
        return true;
    case 3:
        *out_flags = (UINT16)(PTR_FLAGS_BUTTON2 | (down ? PTR_FLAGS_DOWN : 0));
        return true;
    case 4:
        *use_extended = true;
        *out_flags =
            (UINT16)(PTR_XFLAGS_BUTTON1 | (down ? PTR_XFLAGS_DOWN : 0));
        return true;
    case 5:
        *use_extended = true;
        *out_flags =
            (UINT16)(PTR_XFLAGS_BUTTON2 | (down ? PTR_XFLAGS_DOWN : 0));
        return true;
    default:
        return false;
    }
}

bool rdp_input_inject_pointer(rdp_freerdp_ctx *ctx,
                              const farsee_pointer_event *e,
                              unsigned prev_buttons, unsigned *out_reached)
{
    if (ctx == NULL || e == NULL) {
        return false;
    }
    rdpInput *input = rdp_inject_input(ctx);
    if (input == NULL) {
        return false;
    }

    bool any = false;
    bool button_edge_failed = false;
    const bool coords_ok = (e->abs_x >= 0 && e->abs_y >= 0 &&
                            e->abs_x <= 0xFFFF && e->abs_y <= 0xFFFF);
    const UINT16 x = coords_ok ? (UINT16)e->abs_x : (UINT16)0;
    const UINT16 y = coords_ok ? (UINT16)e->abs_y : (UINT16)0;

    if (coords_ok) {
        if (freerdp_input_send_mouse_event(input, PTR_FLAGS_MOVE, x, y)) {
            any = true;
        }
    }

    // Emit one FreeRDP event per changed button bit (lowest-first order from
    // the pure bridge helper, applied repeatedly until stable).
    // Advance local state only after a successful FreeRDP send; a
    // failed button-up must not clear the caller's held mask.
    // Publish the progressive mask through out_reached even on mid-failure.
    unsigned prev = prev_buttons;
    if (out_reached != NULL) {
        *out_reached = prev;
    }
    unsigned curr = e->buttons;
    for (int guard = 0; guard < 8; ++guard) {
        const uint8_t btn = rdp_input_button_for_transition(prev, curr);
        if (btn == 0) {
            break;
        }
        // Which mask bit did btn correspond to?
        unsigned bit = 0;
        switch (btn) {
        case 1: bit = FARSEE_BUTTON_LEFT; break;
        case 2: bit = FARSEE_BUTTON_MIDDLE; break;
        case 3: bit = FARSEE_BUTTON_RIGHT; break;
        case 4: bit = FARSEE_BUTTON_X1; break;
        case 5: bit = FARSEE_BUTTON_X2; break;
        default: bit = 0; break;
        }
        if (bit == 0) {
            break;
        }
        const bool down = (curr & bit) != 0;
        UINT16 flags = 0;
        bool use_ext = false;
        if (!button_flags(btn, down, &flags, &use_ext)) {
            // Advance prev so we don't loop forever on an unknown bit.
            prev = (prev & ~bit) | (curr & bit);
            if (out_reached != NULL) {
                *out_reached = prev;
            }
            continue;
        }
        BOOL ok;
        if (use_ext) {
            ok = freerdp_input_send_extended_mouse_event(input, flags, x, y);
        } else {
            ok = freerdp_input_send_mouse_event(input, flags, x, y);
        }
        if (ok) {
            any = true;
            prev = (prev & ~bit) | (curr & bit);
            if (out_reached != NULL) {
                *out_reached = prev;
            }
        } else {
            button_edge_failed = true;
            break;
        }
    }

    // Vertical wheel: encode notches * 120 in the low 9 bits.
    const int32_t notches = rdp_input_wheel_notches(e->wheel_v);
    if (notches != 0) {
        int32_t rotation = notches * 120;
        UINT16 flags = (UINT16)PTR_FLAGS_WHEEL;
        if (rotation < 0) {
            flags = (UINT16)(flags | PTR_FLAGS_WHEEL_NEGATIVE);
            rotation = -rotation;
        }
        flags = (UINT16)(flags | ((UINT16)rotation & (UINT16)WheelRotationMask));
        if (freerdp_input_send_mouse_event(input, flags, x, y)) {
            any = true;
        }
    }

    // Horizontal wheel (HWHEEL): same notch encoding with PTR_FLAGS_HWHEEL.
    const int32_t h_notches = rdp_input_wheel_notches(e->wheel_h);
    if (h_notches != 0) {
        int32_t rotation = h_notches * 120;
        UINT16 flags = (UINT16)PTR_FLAGS_HWHEEL;
        if (rotation < 0) {
            flags = (UINT16)(flags | PTR_FLAGS_WHEEL_NEGATIVE);
            rotation = -rotation;
        }
        flags = (UINT16)(flags | ((UINT16)rotation & (UINT16)WheelRotationMask));
        if (freerdp_input_send_mouse_event(input, flags, x, y)) {
            any = true;
        }
    }

    // Fail-closed for button transitions: caller uses out_reached for wire.
    if (button_edge_failed ||
        (prev_buttons != e->buttons && prev != e->buttons)) {
        return false;
    }
    return any;
}

void rdp_input_inject_release_all(rdp_freerdp_ctx *ctx, farsee_key_ledger *ledger)
{
    if (ledger == NULL) {
        return;
    }
    // Resolve input first — if the peer is already gone, leave the ledger
    // intact so a retry or diagnostic can still see held keys.
    rdpInput *input = rdp_inject_input(ctx);
    if (input == NULL) {
        return;
    }
    // Snapshot without clearing; remove only after successful up.
    // Cap count at the ledger maximum before indexing.
    size_t cap = ledger->count;
    if (cap > FARSEE_KEY_LEDGER_MAX) {
        cap = FARSEE_KEY_LEDGER_MAX;
        ledger->count = FARSEE_KEY_LEDGER_MAX;
    }
    farsee_physical_key keys[FARSEE_KEY_LEDGER_MAX];
    size_t n = 0;
    for (size_t i = 0; i < cap && n < FARSEE_KEY_LEDGER_MAX; ++i) {
        if (ledger->down[i] != 0) {
            keys[n++] = ledger->down[i];
        }
    }
    for (size_t i = 0; i < n; ++i) {
        if (keys[i] == 0) {
            continue;
        }
        if (send_scancode(input, keys[i], false /* up */, false)) {
            farsee_key_event ke;
            memset(&ke, 0, sizeof ke);
            ke.physical = keys[i];
            ke.action = FARSEE_KEY_RELEASE;
            (void)farsee_key_ledger_apply(ledger, &ke);
        }
    }
}

bool rdp_input_inject_release_buttons(rdp_freerdp_ctx *ctx, unsigned *buttons_io,
                                      int32_t abs_x, int32_t abs_y)
{
    if (buttons_io == NULL) {
        return true;
    }
    if (*buttons_io == 0u) {
        return true;
    }
    if (ctx == NULL) {
        return false;
    }
    farsee_pointer_event pe;
    memset(&pe, 0, sizeof pe);
    pe.abs_x = abs_x;
    pe.abs_y = abs_y;
    pe.buttons = 0u;
    pe.quality = FARSEE_INPUT_QUALITY_INFERRED;
    unsigned reached = *buttons_io;
    if (rdp_input_inject_pointer(ctx, &pe, *buttons_io, &reached)) {
        *buttons_io = 0u;
        return true;
    }
    // Partial edges keep the progressive mask.
    *buttons_io = reached;
    return false;
}
