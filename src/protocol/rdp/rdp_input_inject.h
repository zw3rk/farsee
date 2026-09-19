// SPDX-License-Identifier: Apache-2.0
//
// Farsee RDP FreeRDP input injection (R6).
//
// PRIVATE to src/protocol/rdp/. FreeRDP types stay in the .c; this header
// only uses Farsee-owned opaque handles and common input types.

#ifndef FARSEE_SRC_PROTOCOL_RDP_RDP_INPUT_INJECT_H
#define FARSEE_SRC_PROTOCOL_RDP_RDP_INPUT_INJECT_H

#include "farsee/farsee_input.h"
#include "rdp_freerdp_facade.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Inject a normalized key event.
// 1. physical != 0 → FreeRDP keyboard scancode path (physical is the packed
//    set-1 | extended bit value, FreeRDP-compatible).
// 2. else unicode != 0 → FreeRDP unicode keyboard path (BMP only).
// 3. else false.
// Null-safe: false on NULL ctx / event / unready input.
bool rdp_input_inject_key(rdp_freerdp_ctx *ctx, const farsee_key_event *e);

// Send FreeRDP FocusIn with toggleStates=0.
bool rdp_input_inject_focus_in(rdp_freerdp_ctx *ctx);

// Map keysym → scancode and inject; fall back to unicode when unmapped.
// `down` false means release; `repeat` only matters on press.
bool rdp_input_inject_key_from_keysym(rdp_freerdp_ctx *ctx, uint32_t keysym,
                                      uint32_t unicode, bool down, bool repeat);

// Inject pointer motion / button transitions / vertical wheel.
// - Valid absolute coordinates cause a move attempt; the send can fail.
// - Button transitions via rdp_input_button_for_transition (each changed bit).
// - Vertical wheel: rdp_input_wheel_notches * 120 encoded in PTR_FLAGS_WHEEL.
// - Horizontal wheel: same notch units with PTR_FLAGS_HWHEEL.
// `prev_buttons` is the prior farsee_pointer_button mask; e->buttons is current.
// `out_reached` (optional): progressive mask after each successful edge, even
// when the function returns false mid-transition. On entry
// failure (null ctx), left unchanged.
bool rdp_input_inject_pointer(rdp_freerdp_ctx *ctx,
                              const farsee_pointer_event *e,
                              unsigned prev_buttons,
                              unsigned *out_reached);

// Release every key still held in the ledger (focus loss / cancel). Sends a
// FreeRDP scancode-up for each ledger entry; removes only after successful
// up. Null-safe.
void rdp_input_inject_release_all(rdp_freerdp_ctx *ctx, farsee_key_ledger *ledger);

// Release held mouse buttons (teardown / cancel). Injects buttons=0 against
// *buttons_io as the previous state and clears it only on success.
bool rdp_input_inject_release_buttons(rdp_freerdp_ctx *ctx, unsigned *buttons_io,
                                      int32_t abs_x, int32_t abs_y);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_SRC_PROTOCOL_RDP_RDP_INPUT_INJECT_H
