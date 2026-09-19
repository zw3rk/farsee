// SPDX-License-Identifier: Apache-2.0
//
// Farsee common protocol-neutral input event model.
//
// A normalized keyboard event preserves enough information for RFB and RDP
// without guessing too early (§12.1): physical key, logical key, Unicode
// text, press/release/repeat, modifier/lock state, left/right modifier
// distinction, and a source-quality flag. Pointer events carry absolute
// position, relative delta, button transitions, and high-resolution wheel.
//
// The common layer MUST NOT standardize on RFB keysyms (§12.2). The
// selected engine performs the final wire mapping.

#ifndef FARSEE_INCLUDE_FARSEE_FARSEE_INPUT_H
#define FARSEE_INCLUDE_FARSEE_FARSEE_INPUT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Source quality: how reliably the physical identity of an input event is
// known. RFB keysym-only input is inferred; RDP scan codes are exact.
typedef enum {
    FARSEE_INPUT_QUALITY_UNAVAILABLE = 0,
    FARSEE_INPUT_QUALITY_INFERRED    = 1,
    FARSEE_INPUT_QUALITY_EXACT       = 2,
} farsee_input_quality;

// Physical key identity: a HID-like usage code when known, else 0. This is
// NOT an RFB keysym. Engines map it to their wire form.
typedef uint32_t farsee_physical_key;

// Keyboard action.
typedef enum {
    FARSEE_KEY_RELEASE = 0,
    FARSEE_KEY_PRESS   = 1,
    FARSEE_KEY_REPEAT  = 2,
} farsee_key_action;

// Modifier mask (left/right distinction where known, §12.1).
typedef enum {
    FARSEE_MOD_NONE        = 0,
    FARSEE_MOD_LSHIFT      = 1u << 0,
    FARSEE_MOD_RSHIFT      = 1u << 1,
    FARSEE_MOD_LCTRL       = 1u << 2,
    FARSEE_MOD_RCTRL       = 1u << 3,
    FARSEE_MOD_LALT        = 1u << 4,
    FARSEE_MOD_RALT        = 1u << 5,
    FARSEE_MOD_LMETA       = 1u << 6,
    FARSEE_MOD_RMETA       = 1u << 7,
} farsee_modifier;

// Lock-state mask.
typedef enum {
    FARSEE_LOCK_NONE       = 0,
    FARSEE_LOCK_CAPS       = 1u << 0,
    FARSEE_LOCK_NUM        = 1u << 1,
    FARSEE_LOCK_SCROLL     = 1u << 2,
} farsee_lock_state;

// A normalized keyboard event (§12.1).
typedef struct farsee_key_event {
    farsee_physical_key physical;     // HID-like usage when known, else 0
    uint32_t            logical;      // logical/keysym-ish key when known
    uint32_t            unicode;      // Unicode scalar when text committed, else 0
    farsee_key_action   action;
    unsigned            modifiers;    // farsee_modifier bitmask
    unsigned            locks;        // farsee_lock_state bitmask
    uint64_t            timestamp_ms;
    farsee_input_quality quality;
} farsee_key_event;

// Pointer button mask.
typedef enum {
    FARSEE_BUTTON_LEFT    = 1u << 0,
    FARSEE_BUTTON_MIDDLE  = 1u << 1,
    FARSEE_BUTTON_RIGHT   = 1u << 2,
    FARSEE_BUTTON_X1      = 1u << 3,
    FARSEE_BUTTON_X2      = 1u << 4,
} farsee_pointer_button;

// A normalized pointer event (§12.1). Absolute position is in display
// coordinates; relative delta is provided when the source supports it.
typedef struct farsee_pointer_event {
    int32_t  abs_x;            // display coords
    int32_t  abs_y;
    int32_t  delta_x;          // relative motion if known, else 0
    int32_t  delta_y;
    unsigned buttons;          // farsee_pointer_button bitmask (current state)
    int32_t  wheel_v;          // signed vertical wheel delta (high-res)
    int32_t  wheel_h;          // signed horizontal wheel delta
    uint64_t timestamp_ms;
    farsee_input_quality quality;
} farsee_pointer_event;

// A key-state ledger utility (§12.3, §15.11): tracks which physical keys
// are currently down so cancellation/focus-loss can release them
// deterministically (no stuck keys). Fixed-capacity, no allocation.
#define FARSEE_KEY_LEDGER_MAX 64
typedef struct farsee_key_ledger {
    farsee_physical_key down[FARSEE_KEY_LEDGER_MAX];
    size_t count;
} farsee_key_ledger;

void farsee_key_ledger_init(farsee_key_ledger *l);
// Record a key press/release. Returns false if a press would overflow the
// ledger (caller should release all keys). Idempotent for repeat/duplicate.
bool farsee_key_ledger_apply(farsee_key_ledger *l,
                             const farsee_key_event *e);
// Release every tracked key (focus loss / cancellation). Fills `out` with
// the physical keys that were down and returns the count.
size_t farsee_key_ledger_release_all(farsee_key_ledger *l,
                                     farsee_physical_key *out, size_t out_cap);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_FARSEE_INPUT_H
