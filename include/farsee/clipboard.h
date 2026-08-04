// SPDX-License-Identifier: Apache-2.0
//
// farsee — bidirectional clipboard policy (goals.md G21).
//
// Enforces the clipboard contract for both classic RFB ClientCutText/
// ServerCutText (RFC 6143 §7.5.6 / §7.6.4) and Apple sessions:
//   - size caps (default RFB_LIMIT_CLIPBOARD_BYTES);
//   - UTF-8 validation and repair;
//   - loop suppression (don't echo back what we just received);
//   - disabled-by-default sensitive-clipboard option (passwords etc.);
//   - terminal escape sanitization (strip ESC/C0 controls before display or
//     before sending, to prevent injection through the clipboard).
//
// Pure and bounded: no sockets, no allocation beyond a caller buffer. The
// caller owns all buffers; this module only validates and transforms.
//
// CLEAN-ROOM: UTF-8 validation is derived from RFC 3629 (public standard).
// Escape sanitization follows the same C0-control policy as farsee's
// trusted-vs-remote text logging (plan.md §6.3). No copyleft source.

#ifndef FARSEE_INCLUDE_FARSEE_CLIPBOARD_H
#define FARSEE_INCLUDE_FARSEE_CLIPBOARD_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Default clipboard byte cap (mirrors farsee/limits.h; redefined here so
// the clipboard module is self-contained for tests).
#define RFB_CLIP_DEFAULT_MAX_BYTES ((size_t)16u * 1024u * 1024u)  // 16 MiB

// Sensitive-clipboard (passwords) default cap — much smaller.
#define RFB_CLIP_SENSITIVE_MAX_BYTES ((size_t)4096u)

// Clipboard transfer direction (for loop suppression).
typedef enum {
    RFB_CLIP_DIR_INBOUND = 0,   // server → us (ServerCutText)
    RFB_CLIP_DIR_OUTBOUND = 1,  // us → server (ClientCutText)
} rfb_clip_dir;

// Clipboard policy.
typedef struct rfb_clip_policy {
    size_t max_bytes;            // hard byte cap (both directions)
    bool   sensitive_enabled;    // false by default (sensitive clipboard off)
    bool   sanitize_escapes;     // strip ESC/C0 controls before display/send
    bool   loop_suppress;        // suppress echoing received text back
} rfb_clip_policy;

// Default policy: 16 MiB cap, sensitive disabled, sanitize on, loop-suppress on.
rfb_clip_policy rfb_clip_policy_default(void);

// ---------------------------------------------------------------------------
// UTF-8 validation and repair (RFC 3629).
// ---------------------------------------------------------------------------

// Validate a byte slice as well-formed UTF-8. Returns true iff the entire
// slice is valid UTF-8 (no overlongs, no truncated sequences, no surrogates,
// no codepoints > U+10FFFF). Empty slice is valid.
bool rfb_clip_utf8_valid(const uint8_t *data, size_t len);

// Repair a byte slice into well-formed UTF-8 by replacing each invalid byte
// with U+FFFD (0xEF 0xBF 0xBD). Writes at most out_cap bytes; sets *out_len.
// Returns false if out_cap is too small (output is left with a prefix of the
// repaired text up to the cap; *out_len reflects what fit). `out` and `data`
// may alias (in-place repair) only if out_cap >= len.
bool rfb_clip_utf8_repair(const uint8_t *data, size_t len,
                          uint8_t *out, size_t out_cap, size_t *out_len);

// ---------------------------------------------------------------------------
// Terminal escape sanitization.
//
// Strips C0 control bytes (except TAB 0x09, LF 0x0A, CR 0x0D) and any ESC
// (0x1B) byte, preventing terminal escape-sequence injection through the
// clipboard. This is a defensive transform applied before the clipboard
// text is displayed in the terminal or sent on the wire when sanitization
// is enabled. Writes compacted bytes into `out`; *out_len is the result
// length (<= len). `out` may equal `data` for in-place compaction.
// Returns false on NULL (with *out_len = 0).
// ---------------------------------------------------------------------------

// Sanitization keep-list: TAB, LF, CR are preserved; other C0 (< 0x20) and
// DEL (0x7F) and ESC (0x1B) are dropped.
#define RFB_CLIP_SAN_KEEP_TAB  ((uint8_t)0x09u)
#define RFB_CLIP_SAN_KEEP_LF   ((uint8_t)0x0Au)
#define RFB_CLIP_SAN_KEEP_CR   ((uint8_t)0x0Du)

bool rfb_clip_sanitize(const uint8_t *data, size_t len,
                       uint8_t *out, size_t out_cap, size_t *out_len);

// True iff `b` would be stripped by sanitization (ESC, DEL, or C0 control
// other than TAB/LF/CR).
bool rfb_clip_byte_is_dropped(uint8_t b);

// ---------------------------------------------------------------------------
// Size-cap enforcement.
//
// Returns true iff `len` is within the policy cap. Used before accepting a
// server-side clipboard or before sending a large local clipboard.
// ---------------------------------------------------------------------------

bool rfb_clip_size_ok(const rfb_clip_policy *p, size_t len);

// Decide whether an outbound clipboard of `len` bytes should be sent given
// the policy. Returns false if disabled (sensitive mode blocks outbound),
// oversized, or would be empty.
bool rfb_clip_allow_outbound(const rfb_clip_policy *p, size_t len);

// ---------------------------------------------------------------------------
// Loop suppression.
//
// Tracks the last-received clipboard fingerprint (a 32-bit hash of the
// inbound text) so we can avoid echoing back exactly what the server just
// sent us (which would loop). The caller feeds inbound text here to record
// the fingerprint, then checks outbound text against it before sending.
// ---------------------------------------------------------------------------

typedef struct rfb_clip_loop {
    uint32_t last_inbound_hash;   // FNV-1a of last received clipboard
    bool     has_last;
} rfb_clip_loop;

void rfb_clip_loop_init(rfb_clip_loop *l);

// Record an inbound clipboard (ServerCutText). Hashes the bytes and stores
// the fingerprint for loop suppression. `data` may be NULL when len==0.
void rfb_clip_loop_record_inbound(rfb_clip_loop *l,
                                  const uint8_t *data, size_t len);

// Returns true iff an outbound clipboard matches the last-received inbound
// clipboard (loop condition — should be suppressed). `data` may be NULL
// when len==0.
bool rfb_clip_loop_is_echo(const rfb_clip_loop *l,
                           const uint8_t *data, size_t len);

// Clear the loop state (e.g. on new selection that is not from the server).
void rfb_clip_loop_clear(rfb_clip_loop *l);

// FNV-1a 32-bit hash (public for test verification). Same algorithm as the
// loop-suppression hash so tests can assert fingerprints deterministically.
uint32_t rfb_clip_fnv1a32(const uint8_t *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_CLIPBOARD_H
