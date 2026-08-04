// SPDX-License-Identifier: Apache-2.0
//
// Farsee clipboard broker implementation (F5 gate, §13).
//
// Initial scope is plain text (§13.3). The broker enforces direction
// policy, a byte cap, and terminal-escape sanitization so remote text
// cannot inject control sequences.

#include "farsee/farsee_clipboard.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

farsee_clip_policy farsee_clip_policy_default(void)
{
    farsee_clip_policy p;
    p.direction = FARSEE_CLIP_DIRECTION_DISABLED;
    p.max_bytes = 1024u * 1024u;  // 1 MiB
    p.sanitize_escapes = true;
    return p;
}

bool farsee_clip_policy_allows(const farsee_clip_policy *p,
                               farsee_clip_direction requested)
{
    if (p == NULL || p->direction == FARSEE_CLIP_DIRECTION_DISABLED) {
        return false;
    }
    if (p->direction == FARSEE_CLIP_DIRECTION_BIDIRECTIONAL) {
        return requested == FARSEE_CLIP_DIRECTION_LOCAL_TO_REMOTE ||
               requested == FARSEE_CLIP_DIRECTION_REMOTE_TO_LOCAL;
    }
    return p->direction == requested;
}

bool farsee_clip_policy_size_ok(const farsee_clip_policy *p, size_t bytes)
{
    if (p == NULL) {
        return false;
    }
    return bytes <= p->max_bytes;
}

size_t farsee_clip_sanitize_text(char *out, size_t out_cap,
                                 const char *in, size_t in_len)
{
    if (out == NULL || out_cap == 0 || in == NULL) {
        return 0;
    }
    // We sanitize 1:1 (replacement is a single byte), so the output needs at
    // most in_len bytes plus a NUL. in-place (out == in) is safe because we
    // only ever write at or before the read position.
    size_t written = 0;
    for (size_t i = 0; i < in_len; ++i) {
        if (written + 1 >= out_cap) {
            break;  // leave room for NUL
        }
        unsigned char c = (unsigned char)in[i];
        // Permit TAB/LF/CR. Replace other C0 and DEL. Neutralize C1 only as
        // UTF-8 C2 80..C2 9F — never bare 0x80–0x9F (UTF-8 continuations;
        // multi-review 2026-08-03 post-t11 T1).
        if ((c < 32u && c != 9u && c != 10u && c != 13u) || c == 127u) {
            c = (unsigned char)'.';
        } else if (c == 0xC2u && i + 1u < in_len) {
            unsigned char c2 = (unsigned char)in[i + 1u];
            if (c2 >= 0x80u && c2 <= 0x9Fu) {
                c = (unsigned char)'.';
                i++; // consume continuation of C1 codepoint
            }
        }
        out[written++] = (char)c;
    }
    out[written] = '\0';
    return written;
}

size_t farsee_latin1_to_utf8_alloc(const uint8_t *in, size_t n, char **out)
{
    if (out == NULL) {
        return (size_t)-1;
    }
    *out = NULL;
    if (in == NULL && n > 0u) {
        return (size_t)-1;
    }
    // Count payload up to first NUL.
    size_t lim = 0;
    while (lim < n && in != NULL && in[lim] != 0u) {
        lim++;
    }
    // Worst case: every byte is high → 2 UTF-8 bytes + NUL.
    if (lim > (SIZE_MAX - 1u) / 2u) {
        return (size_t)-1;
    }
    char *buf = (char *)malloc(lim * 2u + 1u);
    if (buf == NULL) {
        return (size_t)-1;
    }
    size_t w = 0;
    for (size_t i = 0; i < lim; ++i) {
        const uint8_t b = in[i];
        if (b < 0x80u) {
            buf[w++] = (char)b;
        } else {
            // U+0080..U+00FF as two-byte UTF-8.
            buf[w++] = (char)(0xC0u | (b >> 6));
            buf[w++] = (char)(0x80u | (b & 0x3Fu));
        }
    }
    buf[w] = '\0';
    *out = buf;
    return w;
}
