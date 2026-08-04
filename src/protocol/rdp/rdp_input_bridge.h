// SPDX-License-Identifier: Apache-2.0
//
// Farsee RDP input bridge (R4 gate, §15.11, §12.3).
//
// Maps normalized farsee_key_event / farsee_pointer_event to the RDP wire
// form (scan-code key events, Unicode keyboard events, mouse/extended
// mouse/wheel). The mapping is deterministic and testable without a live
// server. §15.11: prefer physical scan codes; use Unicode for committed
// text; preserve key-up; synchronize lock states; never synthesize a
// release for a key unless the ledger proves it is down.
//
// PRIVATE to src/protocol/rdp/.

#ifndef FARSEE_SRC_PROTOCOL_RDP_RDP_INPUT_BRIDGE_H
#define FARSEE_SRC_PROTOCOL_RDP_RDP_INPUT_BRIDGE_H

#include "farsee/farsee_input.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// RDP keyboard event types (which wire path to take).
typedef enum {
    RDP_KEY_SCANCODE = 0,   // physical scan code (preferred when known)
    RDP_KEY_UNICODE  = 1,   // committed text (no physical identity)
    RDP_KEY_DROP     = 2,   // cannot map (quality UNAVAILABLE, no unicode)
} rdp_key_dispatch;

// Decide how a normalized key event maps to the RDP wire (§15.11).
// Physical identity known -> scan code; else Unicode if present; else drop.
rdp_key_dispatch rdp_input_key_dispatch(const farsee_key_event *e);

// RDP button number (1=left,2=middle,3=right,4=X1,5=X2) for a pointer
// transition, or 0 if no button transition. §15.11 extended buttons.
uint8_t rdp_input_button_for_transition(unsigned prev_buttons,
                                        unsigned curr_buttons);

// Map a high-resolution wheel delta to the RDP wheel units (§15.11).
// RDP reports vertical wheel as a multiple of 120 (one notch). Returns the
// signed notch count.
int32_t rdp_input_wheel_notches(int32_t wheel_delta);

// Map an X11 keysym to an IBM AT/PS2 set-1 scancode (MS-RDPBCGR keyboard
// scan codes). Clean-room: public X11 keysym registry + public set-1 /
// RDP scan-code tables — no GPL/AGPL client code.
//
// On success writes the 8-bit set-1 code to *out_scancode and whether the
// key is extended (arrows, nav cluster, R-modifiers, Super, …) to
// *out_extended. Returns false if the keysym is unknown or an out pointer
// is NULL. Does not pack FreeRDP's KBDEXT bit into *out_scancode.
bool rdp_input_keysym_to_scancode(uint32_t keysym, uint32_t *out_scancode,
                                  bool *out_extended);

// Build a farsee_key_event from keysym / unicode / down / repeat.
// When the keysym maps, physical is the FreeRDP-style packed scancode
// (set-1 code | 0x100 when extended); logical holds the keysym. Returns
// false if out is NULL. Returns true even when the keysym is unmapped
// (physical stays 0; caller may still use unicode).
bool rdp_input_key_event_from_keysym(farsee_key_event *out, uint32_t keysym,
                                     uint32_t unicode, bool down, bool repeat);

// --- Protocol-owned button wire state (multi-review deferred D3) ---------
// Tracks last desired mask from input cmds and progressive wire mask after
// inject. When wire != desired, protocol retries mid-session without waiting
// for another user pointer event (or quit teardown).

typedef struct rdp_button_wire_state {
    unsigned wire;     // last progressive mask applied on FreeRDP path
    unsigned desired;  // last pe.buttons from inject queue
    bool pending;      // wire != desired; retry sync
    int32_t abs_x;
    int32_t abs_y;
} rdp_button_wire_state;

void rdp_button_wire_init(rdp_button_wire_state *s);

// New POINTER cmd: set desired (+ coords), mark pending if differs from wire.
void rdp_button_wire_note_cmd(rdp_button_wire_state *s, unsigned buttons,
                              int32_t abs_x, int32_t abs_y);

// After inject attempt: store progressive reached; clear pending iff matched.
void rdp_button_wire_note_inject(rdp_button_wire_state *s, unsigned reached);

// True when protocol should re-attempt inject toward desired.
bool rdp_button_wire_needs_sync(const rdp_button_wire_state *s);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_SRC_PROTOCOL_RDP_RDP_INPUT_BRIDGE_H
