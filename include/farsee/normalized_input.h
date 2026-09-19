// SPDX-License-Identifier: Apache-2.0
//
// farsee — presenter-independent normalized input layer.
//
// Normalizes keyboard, pointer, scroll, and modifier state into a single
// presenter-independent representation. Consumes terminal byte sequences
// (the Kitty keyboard protocol when available, legacy terminal escapes as
// fallback) and produces normalized events that classic and Apple sessions
// can translate into RFB KeyEvent/PointerEvent (RFC 6143 §7.5.4-6).
//
// Parser and state constraints:
//   - No sockets, terminal I/O, or mutable global state.
//   - Keyboard parameters use a fixed 23-byte payload buffer.
//   - RFB_NORM_SOURCE_NONE may mean incomplete, invalid, unsupported,
//     unmapped, no-event, or NULL kb/out; callers must not treat it as one cause.
//   - Input bytes and parser/modifier state determine emitted events.
//
// Key mapping policy:
//   Physical key identity is carried as an X11 keysym (RFC 6143 §7.5.4 uses
//   keysyms for KeyEvent). Mapping is deterministic for letters, digits,
//   punctuation, function/navigation keys, keypad, arrows, Return/Tab/
//   Escape/Delete, Control, Shift, Command, Option, and Caps Lock.
//
// CLEAN-ROOM: mapping tables are derived from the X11 keysym registry
// (X.org / standards.xml.org, public specification, not implementation
// source) and RFC 6143 §7.5.4. The Kitty keyboard protocol parsing is
// derived from the official Kitty graphics/keyboard protocol specification
// (https://sw.kovidgoyal.net/kitty/ — public spec). No GPL/AGPL/LGPL
// implementation source is consulted.

#ifndef FARSEE_INCLUDE_FARSEE_NORMALIZED_INPUT_H
#define FARSEE_INCLUDE_FARSEE_NORMALIZED_INPUT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// ---------------------------------------------------------------------------
// X11 keysyms used for key identity (RFC 6143 §7.5.4 keysym space).
// A representative, deterministic subset — not the full registry. Derived
// from the X11 keysym public specification. ASCII printable chars (0x20
// space .. 0x7E tilde) map directly to keysyms of the same value.
// ---------------------------------------------------------------------------

// Latin-1 range (keysym == codepoint for 0x20..0xFF).
#define XK_BackSpace    0xFF08u
#define XK_Tab          0xFF09u
#define XK_Return       0xFF0Du
#define XK_Escape       0xFF1Bu
#define XK_Delete       0xFFFFu

// Modifier keysyms (X11 §"Modifier Keysyms").
#define XK_Shift_L      0xFFE1u
#define XK_Shift_R      0xFFE2u
#define XK_Control_L    0xFFE3u
#define XK_Control_R    0xFFE4u
#define XK_Caps_Lock    0xFFE5u
#define XK_Shift_Lock   0xFFE6u
#define XK_Alt_L        0xFFE9u
#define XK_Alt_R        0xFFEAu
// Meta/Super/Hyper — used for Command on macOS.
#define XK_Meta_L       0xFFE7u
#define XK_Meta_R       0xFFE8u
#define XK_Super_L      0xFFEBu
#define XK_Super_R      0xFFECu

// Navigation/editing.
#define XK_Home         0xFF50u
#define XK_Left         0xFF51u
#define XK_Up           0xFF52u
#define XK_Right        0xFF53u
#define XK_Down         0xFF54u
#define XK_Page_Up      0xFF55u
#define XK_Page_Down    0xFF56u
#define XK_End          0xFF57u
#define XK_Insert       0xFF63u

// Function keys F1..F12 (0xFFBE .. 0xFFC9).
#define XK_F1           0xFFBEu
#define XK_F2           0xFFBFu
#define XK_F3           0xFFC0u
#define XK_F4           0xFFC1u
#define XK_F5           0xFFC2u
#define XK_F6           0xFFC3u
#define XK_F7           0xFFC4u
#define XK_F8           0xFFC5u
#define XK_F9           0xFFC6u
#define XK_F10          0xFFC7u
#define XK_F11          0xFFC8u
#define XK_F12          0xFFC9u

// Numeric keypad (Keypad). 0xFF80 space, 0xFFB9 = KP_9.
#define XK_KP_Space     0xFF80u
#define XK_KP_Tab       0xFF89u
#define XK_KP_Enter     0xFF8Du
#define XK_KP_F1        0xFF91u
#define XK_KP_F2        0xFF92u
#define XK_KP_F3        0xFF93u
#define XK_KP_F4        0xFF94u
#define XK_KP_Home      0xFF95u
#define XK_KP_Left      0xFF96u
#define XK_KP_Up        0xFF97u
#define XK_KP_Right     0xFF98u
#define XK_KP_Down      0xFF99u
#define XK_KP_Page_Up   0xFF9Au
#define XK_KP_Page_Down 0xFF9Bu
#define XK_KP_End       0xFF9Cu
#define XK_KP_Begin     0xFF9Du
#define XK_KP_Insert    0xFF9Eu
#define XK_KP_Delete    0xFF9Fu
#define XK_KP_Equal     0xFFBDu
#define XK_KP_Multiply  0xFFAAu
#define XK_KP_Add       0xFFABu
#define XK_KP_Separator 0xFFACu
#define XK_KP_Subtract  0xFFADu
#define XK_KP_Decimal   0xFFAEu
#define XK_KP_Divide    0xFFAFu
#define XK_KP_0         0xFFB0u
#define XK_KP_1         0xFFB1u
#define XK_KP_2         0xFFB2u
#define XK_KP_3         0xFFB3u
#define XK_KP_4         0xFFB4u
#define XK_KP_5         0xFFB5u
#define XK_KP_6         0xFFB6u
#define XK_KP_7         0xFFB7u
#define XK_KP_8         0xFFB8u
#define XK_KP_9         0xFFB9u

// ---------------------------------------------------------------------------
// Modifier bitmask (normalized, independent of physical left/right).
// These are the logical modifiers macOS and most servers care about.
// ---------------------------------------------------------------------------
#define RFB_MOD_NONE     0x00u
#define RFB_MOD_SHIFT    0x01u
#define RFB_MOD_CONTROL  0x02u
#define RFB_MOD_ALT      0x04u   // Option on macOS (Alt keysym)
#define RFB_MOD_META     0x08u   // Command on macOS (Meta/Super keysym)
#define RFB_MOD_CAPSLOCK 0x10u

// Logical modifier identity — normalized so left/right collapse to one bit.
typedef enum {
    RFB_MODKEY_NONE = 0,
    RFB_MODKEY_SHIFT,
    RFB_MODKEY_CONTROL,
    RFB_MODKEY_ALT,     // Option
    RFB_MODKEY_META,    // Command
    RFB_MODKEY_CAPSLOCK,
} rfb_modkey;

// Bits among SHIFT/CONTROL/ALT/META that are present on a Kitty (or other)
// chorded key event but not already held as physical modifier keys.
// Used to synthesize Left-Control/etc. KeyEvents on RFB/RDP when CSI-u
// encodes C-a as keysym 'a' + mod field without a separate Control press.
uint16_t rfb_norm_mods_need_synth(uint16_t event_mods, uint16_t physical_mods);

// Classify a modifier keysym into a logical modifier identity.
// Returns RFB_MODKEY_NONE if `sym` is not a modifier.
rfb_modkey rfb_norm_modkey_from_sym(uint32_t sym);

// ---------------------------------------------------------------------------
// Source protocol: which terminal protocol produced the event.
// ---------------------------------------------------------------------------
typedef enum {
    RFB_NORM_SOURCE_NONE = 0,   // no event / unrecognized
    RFB_NORM_SOURCE_LEGACY,     // legacy terminal escape (xterm-style)
    RFB_NORM_SOURCE_KITTY,      // Kitty keyboard protocol (CSI ... u)
} rfb_norm_source;

// ---------------------------------------------------------------------------
// Normalized key event.
//
// A single physical key press or release. `keysym` is the X11 keysym
// (physical identity); `text` is the produced Unicode codepoint (0 if the
// key produces no text, e.g. a bare Shift). `modifiers` is the active
// modifier bitmask AT EVENT TIME (before this event applies for a modifier
// keypress). `down` is true for press, false for release. `repeat` is true
// for an auto-repeat press (Kitty reports this; legacy cannot).
// ---------------------------------------------------------------------------
typedef struct rfb_norm_key {
    uint32_t         keysym;     // X11 keysym (physical identity); 0 if none
    uint32_t         text;       // Unicode codepoint produced; 0 if none
    uint16_t         modifiers;  // active modifier bitmask (RFB_MOD_*)
    bool             down;       // press=true, release=false
    bool             repeat;     // auto-repeat (Kitty only)
    rfb_norm_source  source;     // which protocol produced this
} rfb_norm_key;

// True for a Ctrl-C / Ctrl-c *press* (interrupt convention). Live sessions
// inject this into the remote desktop; it is NOT the local disconnect chord.
//
// Matches:
//   - keysym 'c'/'C' with RFB_MOD_CONTROL (Kitty CSI 99;5u / legacy);
//   - text == 0x03 (ETX) on a press.
// Key-up and bare Control alone return false. NULL → false.
bool rfb_norm_key_is_ctrl_c(const rfb_norm_key *k);

// True for the classic terminal interrupt byte (ETX / Ctrl-C) when ISIG is
// off so the character reaches user space instead of raising SIGINT.
bool rfb_byte_is_intr(uint8_t b);

// Leader chord match (configurable). Requires `mods` to be present on the
// event, and rejects extra Alt/Meta so we do not steal Opt/Cmd chords.
// Key-up → false (use rfb_norm_key_is_leader_chord for press+release).
// Default CLI leader is Control+']'.
bool rfb_norm_key_matches_leader(const rfb_norm_key *k, uint32_t keysym,
                                 uint16_t mods);

// Same chord identity as matches_leader but ignores press/release. Use this
// to swallow Kitty CSI-u leader *release* (event-type 3) so the sequence
// never leaks as raw "[93;5:3u" keystrokes to the remote.
bool rfb_norm_key_is_leader_chord(const rfb_norm_key *k, uint32_t keysym,
                                  uint16_t mods);

// True when `b` is the classic C0 form of a Control+letter/punctuation
// leader (e.g. 0x1D for Ctrl+]). `has_c0` false → always false.
bool rfb_byte_matches_leader(uint8_t b, uint8_t c0_byte, bool has_c0);

// Default-leader convenience for Control + ']'.
bool rfb_norm_key_is_leader(const rfb_norm_key *k);
bool rfb_byte_is_leader(uint8_t b);

// Commands after the leader is armed (tmux-style prefix).
typedef enum {
    RFB_LEADER_CMD_NONE = 0,
    RFB_LEADER_CMD_QUIT,       // q / c / Ctrl-C
    RFB_LEADER_CMD_SUSPEND,    // z / Ctrl-Z
    RFB_LEADER_CMD_PASS,       // second leader → inject leader to remote
    RFB_LEADER_CMD_CANCEL,     // Esc
    RFB_LEADER_CMD_ZOOM_IN,    // + / =  (enlarge view within terminal)
    RFB_LEADER_CMD_ZOOM_OUT,   // - / _
} rfb_leader_cmd;

// Classify a key/byte after the leader is armed. `leader_*` identify the
// configured prefix so a second press of the same chord is PASS.
rfb_leader_cmd rfb_leader_cmd_from_key(const rfb_norm_key *k,
                                       uint32_t leader_keysym,
                                       uint16_t leader_mods);
rfb_leader_cmd rfb_leader_cmd_from_byte(uint8_t b, uint8_t leader_c0,
                                        bool leader_has_c0);

// Back-compat aliases (session quit = default leader edge).
bool rfb_norm_key_is_session_quit(const rfb_norm_key *k);
bool rfb_byte_is_session_quit(uint8_t b);

// ---------------------------------------------------------------------------
// Modifier tracker.
//
// Maintains the current logical modifier state. Each modifier key has a
// left/right physical variant; both set the same logical bit. The tracker
// supports stuck-modifier recovery: rfb_norm_mods_reset() clears all state
// (used on focus loss / disconnect to release keys that never sent a
// key-up). rfb_norm_mods_apply() updates the bitmask from a key event.
// ---------------------------------------------------------------------------
typedef struct rfb_norm_mods {
    // Per-physical-key pressed count (left/right tracked separately).
    uint8_t shift_l;
    uint8_t shift_r;
    uint8_t ctrl_l;
    uint8_t ctrl_r;
    uint8_t alt_l;
    uint8_t alt_r;
    uint8_t meta_l;   // Super_L / Meta_L
    uint8_t meta_r;   // Super_R / Meta_R
    bool    capslock; // latch
    // Derived bitmask (RFB_MOD_*).
    uint16_t bits;
} rfb_norm_mods;

// Initialize a modifier tracker (zero state, no modifiers).
void rfb_norm_mods_init(rfb_norm_mods *m);

// Apply a key event to the tracker. Updates internal counts and `bits`.
// `sym` is the keysym, `down` is press/release. Returns the updated bitmask.
uint16_t rfb_norm_mods_apply(rfb_norm_mods *m, uint32_t sym, bool down);

// Reset all modifier state to released (focus loss / disconnect recovery).
// Returns the (now-zero) bitmask. Use this when focus is lost to synthesize
// key-up for any held modifiers.
uint16_t rfb_norm_mods_reset(rfb_norm_mods *m);

// Current modifier bitmask.
static inline uint16_t rfb_norm_mods_bits(const rfb_norm_mods *m)
{
    return (m != NULL) ? m->bits : RFB_MOD_NONE;
}

// ---------------------------------------------------------------------------
// Pointer state and coordinate mapping.
// ---------------------------------------------------------------------------

// Pointer button bitmask (RFC 6143 §7.5.5 values).
#define RFB_PTR_BUTTON_NONE   0x00u
#define RFB_PTR_BUTTON_LEFT   0x01u
#define RFB_PTR_BUTTON_MIDDLE 0x02u
#define RFB_PTR_BUTTON_RIGHT  0x04u

// Wheel button bits (classic RFB; transient).
#define RFB_PTR_WHEEL_UP      0x08u
#define RFB_PTR_WHEEL_DOWN    0x10u
// Horizontal wheel (high-resolution; emitted when accumulated beyond 1 unit).
#define RFB_PTR_WHEEL_LEFT    0x20u
#define RFB_PTR_WHEEL_RIGHT   0x40u

// High-resolution wheel accumulator sub-unit scale (120 = one notch, like
// the macOS NSEvent deltaScale). This lets the caller feed fractional
// deltas and the accumulator emits a discrete wheel button bit per notch.
#define RFB_PTR_WHEEL_UNIT 120

// Pointer state: tracks current logical button mask, position, and the
// high-resolution wheel accumulators.
typedef struct rfb_norm_pointer {
    uint8_t  button_mask;        // logical button bits (left/middle/right)
    int32_t  wheel_v;            // vertical accumulator (sub-units)
    int32_t  wheel_h;            // horizontal accumulator (sub-units)
} rfb_norm_pointer;

void rfb_norm_pointer_init(rfb_norm_pointer *p);

// Apply a logical button press/release. `mask_bit` is one of
// RFB_PTR_BUTTON_*. `down` selects press/release. Returns the new logical
// button_mask (wheel bits are not included here; see wheel_consume).
uint8_t rfb_norm_pointer_button(rfb_norm_pointer *p, uint8_t mask_bit, bool down);

// Feed a high-resolution wheel delta in sub-units (RFB_PTR_WHEEL_UNIT = one
// notch). Positive v/h scroll down/right; negative v/h scroll up/left.
// The signed accumulator additions are not overflow-checked. When they stay
// in range, *v_notches and *h_notches receive the discrete notch counts.
// Each sign gives direction; each magnitude unit is one wheel-button event.
void rfb_norm_pointer_wheel(rfb_norm_pointer *p,
                            int32_t v_delta, int32_t h_delta,
                            int32_t *v_notches, int32_t *h_notches);

// ---------------------------------------------------------------------------
// Pixel-coordinate mapping under scaling/letterboxing.
//
// The terminal presents a viewport of `view_w` x `view_h` pixels that shows
// a framebuffer of `fb_w` x `fb_h` pixels, scaled by `scale` and centered
// (letterboxed). This maps a viewport pixel coordinate to framebuffer
// pixel coordinates. Output is clamped to [0, fb_w-1] / [0, fb_h-1].
// ---------------------------------------------------------------------------
typedef struct rfb_norm_geom {
    uint32_t fb_w;     // framebuffer width
    uint32_t fb_h;     // framebuffer height
    uint32_t view_w;   // viewport (window) width in px
    uint32_t view_h;   // viewport (window) height in px
    float    scale;    // framebuffer→viewport scale (>1 = framebuffer bigger)
    bool     valid;    // false until geometry is set
} rfb_norm_geom;

void rfb_norm_geom_init(rfb_norm_geom *g);

// Set the geometry. view/view_w must be nonzero; scale must be > 0.
// Returns true on success, false if invalid (g stays unchanged).
bool rfb_norm_geom_set(rfb_norm_geom *g,
                       uint32_t fb_w, uint32_t fb_h,
                       uint32_t view_w, uint32_t view_h, float scale);

// Map a viewport pixel coordinate to framebuffer pixel coordinates.
// Returns false if geometry is invalid. Handles letterbox centering and
// clamps to framebuffer bounds. `fb_x`/`fb_y` are outputs (may be NULL).
bool rfb_norm_geom_map(const rfb_norm_geom *g,
                       int32_t view_x, int32_t view_y,
                       int32_t *fb_x, int32_t *fb_y);

// Map a fractional viewport coordinate (sub-pixel). Returns false if
// geometry is invalid. Same as _map but takes float input for fractional
// scales. Output is clamped to framebuffer bounds.
bool rfb_norm_geom_mapf(const rfb_norm_geom *g,
                        float view_x, float view_y,
                        float *fb_x, float *fb_y);

// ===========================================================================
// Keyboard parsing: Kitty CSI-u subset and legacy terminal input.
//
// CSI-u input is parsed as:
//   CSI <code> [ : <alternate-codes> ]
//       [ ; <modifiers> [ : <event-type> ] ] u
// The parser uses the leading decimal code and ignores alternate-code and
// text-as-codepoint fields. It decodes only the low Shift, Alt, Control, and
// Super modifier bits.
//
// Event type 1 is press, 2 is repeat, and 3 is release. An omitted or zero
// event type is press. Other values are also treated as press.
//
// Legacy input accepts bare UTF-8, selected C0 controls, CSI, and SS3.
// Each feed call consumes one byte and returns at most one event.
// Incomplete sequences, unsupported CSI/SS3 finals, and unmapped codes return
// RFB_NORM_SOURCE_NONE. A non-CSI/SS3 byte after ESC is consumed while Escape
// is emitted; the trailing byte is not reprocessed.
// CSI parameter collection retains at most 23 bytes and ignores later bytes.
//
// Protocol syntax follows the official Kitty keyboard protocol specification;
// key identity follows the public X11 keysym specification.
// ===========================================================================

// Parse state for the incremental keyboard parser.
typedef enum {
    RFB_KB_IDLE = 0,    // waiting for a new key sequence
    RFB_KB_CSI,         // inside a CSI sequence (after ESC [)
    RFB_KB_SS3,         // inside an SS3 sequence (after ESC O)
    RFB_KB_ESC,         // saw a lone ESC (may start CSI/SS3 or be Escape alone)
} rfb_kb_state;

// Incremental keyboard parser context. rfb_kb_feed consumes one byte and
// returns at most one event. NONE can mean incomplete, invalid, unsupported,
// unmapped, no-event, or NULL kb/out.
typedef struct rfb_kb {
    rfb_kb_state state;
    // CSI/SS3 parameter accumulation (bounded).
    char    params[24];
    uint8_t params_len;
    // Pending intermediate (the terminator char seen last).
    char    last_char;
    // True while a lone ESC can be completed by '[' or 'O' or emitted by flush.
    bool    esc_pending;
} rfb_kb;

// Initialize a keyboard parser.
void rfb_kb_init(rfb_kb *kb);

// Feed one byte to the parser. If a complete key event is recognized, fills
// `*out` and returns the source (RFB_NORM_SOURCE_KITTY or
// RFB_NORM_SOURCE_LEGACY). Returns RFB_NORM_SOURCE_NONE for incomplete,
// invalid, unsupported, unmapped, no-event, or NULL kb/out. `mods` is the
// current modifier bitmask (applied to the event's modifiers field for
// legacy/printable keys that don't carry their own modifier encoding).
rfb_norm_source rfb_kb_feed(rfb_kb *kb, uint8_t byte,
                            const rfb_norm_mods *mods, rfb_norm_key *out);

// Flush any pending state (e.g. a lone ESC). Call this when the caller
// knows no more bytes are coming for a partial sequence (focus loss). If a
// pending event completes, fills `*out` and returns the source; otherwise
// RFB_NORM_SOURCE_NONE. NULL kb/out returns NONE without a reset; otherwise
// the call resets the parser to IDLE.
rfb_norm_source rfb_kb_flush(rfb_kb *kb, const rfb_norm_mods *mods,
                             rfb_norm_key *out);

// ---------------------------------------------------------------------------
// Single-shot convenience: parse a complete byte slice into up to
// `out_cap` events. Returns the number of events produced (0..out_cap).
// Useful for table-driven tests. If output capacity remains, a trailing lone
// ESC emits Escape; other incomplete state produces no event.
// ---------------------------------------------------------------------------
size_t rfb_kb_parse(const uint8_t *data, size_t len,
                    const rfb_norm_mods *mods,
                    rfb_norm_key *out, size_t out_cap);

// ---------------------------------------------------------------------------
// Keysym ←→ code mapping helpers (deterministic, table-driven).
//
// rfb_kb_code_to_keysym: map a parser-recognized numeric code to an X11
//   keysym. Named constants below take precedence. Otherwise codes from
//   0x20 through 0x10FFFF pass through unchanged; smaller unmapped values
//   return 0.
//
// rfb_kb_keysym_to_text: map a keysym to its default Unicode codepoint
//   (0 if the key produces no text, e.g. a bare Shift or F-key). Applies
//   the shift modifier to letters and the shifted symbol row.
// ---------------------------------------------------------------------------

// Basic code values recognized explicitly by this parser.
#define KITTY_CODE_ENTER      13u
#define KITTY_CODE_TAB        9u
#define KITTY_CODE_BACKSPACE  127u
#define KITTY_CODE_ESCAPE     27u
#define KITTY_CODE_SPACE      32u
// Internal CSI-u mappings used by rfb_kb_code_to_keysym. These names
// document current parser behavior; they are not a transcription of Kitty's
// functional-key assignments.
// Navigation keys (arrows, Home, End, PageUp/Down) also have legacy
// CSI escape sequences (ESC [ A/B/C/D, ESC [ 1/4/5/6 ~) which are
// parsed separately in the legacy parser path.
#define KITTY_CODE_INSERT     2u
#define KITTY_CODE_DELETE     3u
#define KITTY_CODE_LEFT       4u
#define KITTY_CODE_HOME       5u
#define KITTY_CODE_END        6u
#define KITTY_CODE_PAGEUP     7u
#define KITTY_CODE_PAGEDOWN   8u
#define KITTY_CODE_UP         10u
#define KITTY_CODE_DOWN       11u
#define KITTY_CODE_RIGHT      12u
#define KITTY_CODE_F1         57446u  // Internal parser value for F1.
#define KITTY_CODE_F2         57447u
#define KITTY_CODE_F3         57448u
#define KITTY_CODE_F4         57449u
#define KITTY_CODE_F5         57450u
#define KITTY_CODE_F6         57451u
#define KITTY_CODE_F7         57452u
#define KITTY_CODE_F8         57453u
#define KITTY_CODE_F9         57454u
#define KITTY_CODE_F10        57455u
#define KITTY_CODE_F11        57456u
#define KITTY_CODE_F12        57457u
#define KITTY_CODE_SHIFT_L    57461u
#define KITTY_CODE_CTRL_L     57463u
#define KITTY_CODE_ALT_L      57465u
#define KITTY_CODE_SUPER_L    57467u

uint32_t rfb_kb_code_to_keysym(uint32_t code);
uint32_t rfb_kb_keysym_to_text(uint32_t keysym, bool shift);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_NORMALIZED_INPUT_H
