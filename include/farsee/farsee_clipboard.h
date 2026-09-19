// SPDX-License-Identifier: Apache-2.0
//
// Farsee common clipboard broker.
//
// RFB text clipboard is simple; RDP clipboard negotiates formats and can
// defer rendering. The common layer represents offers and bounded transfers
// even though the initial scope is plain text only (§13.3).
//
// Initial policy (§13.3):
//   - plain text only for RFB and RDP;
//   - explicit per-profile direction (disabled / local-to-remote /
//     remote-to-local / bidirectional);
//   - terminal escape-injection sanitization retained;
//   - configurable maximum text size;
//   - no file transfer, no rich formats, no automatic execution.

#ifndef FARSEE_INCLUDE_FARSEE_FARSEE_CLIPBOARD_H
#define FARSEE_INCLUDE_FARSEE_FARSEE_CLIPBOARD_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    FARSEE_CLIP_DIRECTION_DISABLED     = 0,
    FARSEE_CLIP_DIRECTION_LOCAL_TO_REMOTE  = 1,
    FARSEE_CLIP_DIRECTION_REMOTE_TO_LOCAL  = 2,
    FARSEE_CLIP_DIRECTION_BIDIRECTIONAL    = 3,
} farsee_clip_direction;

// Plain-text clipboard formats. The broker deals only in text;
// rich formats are out of scope (§13.3) and rejected.
typedef enum {
    FARSEE_CLIP_FORMAT_UTF8_TEXT = 1,
} farsee_clip_format;

// Policy bundle applied to every clipboard action.
typedef struct farsee_clip_policy {
    farsee_clip_direction direction;
    size_t max_bytes;       // hard cap on a single text transfer
    bool sanitize_escapes;  // strip/escape terminal control bytes
} farsee_clip_policy;

// Default policy: disabled, 1 MiB cap, escape sanitization on.
farsee_clip_policy farsee_clip_policy_default(void);

// Decide whether a direction is permitted by the policy. Returns false if
// the policy is DISABLED or the requested direction is not allowed.
bool farsee_clip_policy_allows(const farsee_clip_policy *p,
                               farsee_clip_direction requested);

// Sanitize text for terminal-safe handling: replace C0 control bytes
// (except CR/LF/TAB) and DEL with a literal '.' so remote text cannot
// inject terminal escape sequences (§13.3, existing sanitization retained).
// Writes at most `out_cap`-1 bytes plus a NUL terminator to `out`. Returns
// the sanitized length, or 0 if `out` is NULL/too small. Scans in place
// safely (out may alias in when out_cap >= in_len).
size_t farsee_clip_sanitize_text(char *out, size_t out_cap,
                                 const char *in, size_t in_len);

// ISO-8859-1 / CF_TEXT → freshly malloc'd UTF-8 (caller free).
// Stops at the first NUL within `n` bytes. High bytes become 2-byte UTF-8
// so C1 sanitization (C2 80–9F) can neutralize bare CSI and related controls.
// Returns UTF-8 byte length, or (size_t)-1 on OOM / bad args (*out NULL).
size_t farsee_latin1_to_utf8_alloc(const uint8_t *in, size_t n, char **out);

// Decide whether a transfer of `bytes` is permitted under the policy's cap.
bool farsee_clip_policy_size_ok(const farsee_clip_policy *p, size_t bytes);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_FARSEE_CLIPBOARD_H
