// SPDX-License-Identifier: Apache-2.0
//
// farsee — bidirectional clipboard policy (goals.md G21).
//
// UTF-8 validation/repair (RFC 3629), terminal escape sanitization, size
// caps, and loop suppression via FNV-1a fingerprinting. Pure and bounded.

#include "farsee/clipboard.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

rfb_clip_policy rfb_clip_policy_default(void)
{
    rfb_clip_policy p;
    p.max_bytes = RFB_CLIP_DEFAULT_MAX_BYTES;
    p.sensitive_enabled = false;
    p.sanitize_escapes = true;
    p.loop_suppress = true;
    return p;
}

// ---------------------------------------------------------------------------
// UTF-8 validation (RFC 3629)
// ---------------------------------------------------------------------------

// Leading byte ranges:
//   0x00-0x7F  : 1-byte (ASCII)
//   0xC2-0xDF  : 2-byte lead (0xC0/0xC1 would be overlong; reject)
//   0xE0-0xEF  : 3-byte lead
//   0xF0-0xF4  : 4-byte lead (0xF5+ would exceed U+10FFFF; reject)
// Continuation bytes: 0x80-0xBF.
//
// Per RFC 3629 §3, the shortest form is required and surrogates
// (U+D800..U+DFFF) are forbidden.

bool rfb_clip_utf8_valid(const uint8_t *data, size_t len)
{
    if (data == NULL) {
        return len == 0;
    }
    size_t i = 0;
    while (i < len) {
        uint8_t b = data[i];
        if (b <= 0x7Fu) {
            // ASCII
            i += 1u;
            continue;
        }
        uint32_t cp = 0;
        size_t need = 0;
        uint32_t min_cp = 0u;
        if (b >= 0xC2u && b <= 0xDFu) {
            need = 1u;
            cp = (uint32_t)(b & 0x1Fu);
        } else if (b >= 0xE0u && b <= 0xEFu) {
            need = 2u;
            cp = (uint32_t)(b & 0x0Fu);
            // Tighten the lower bound for the first continuation to reject
            // overlongs and surrogate halves.
            if (b == 0xE0u) min_cp = 0x800u;      // reject overlong < U+0800
            // 0xED lead covers U+D000-U+DFFF. Only U+D800-U+DFFF are
            // surrogates; U+D000-U+D7FF (Hangul) are valid. We check
            // the surrogate range after full decode below.
        } else if (b >= 0xF0u && b <= 0xF4u) {
            need = 3u;
            cp = (uint32_t)(b & 0x07u);
            if (b == 0xF0u) min_cp = 0x10000u;    // reject overlong < U+10000
            else if (b == 0xF4u) min_cp = 0x100000u; // cap so F4 90.. is rejected
        } else {
            // 0x80-0xBF (lone continuation), 0xC0/0xC1 (overlong), 0xF5-0xFF
            return false;
        }
        // Need `need` continuation bytes.
        if (i + need >= len) {
            return false;  // truncated
        }
        for (size_t k = 1u; k <= need; k++) {
            uint8_t c = data[i + k];
            if (c < 0x80u || c > 0xBFu) {
                return false;  // not a continuation byte
            }
            cp = (cp << 6u) | (uint32_t)(c & 0x3Fu);
        }
        // Overlong check.
        if (cp < min_cp) {
            return false;
        }
        // Reject surrogate codepoints U+D800-U+DFFF (RFC 3629).
        if (cp >= 0xD800u && cp <= 0xDFFFu) {
            return false;
        }
        // Upper bound: RFC 3629 limits to U+10FFFF.
        if (cp > 0x10FFFFu) {
            return false;
        }
        i += 1u + need;
    }
    return true;
}

// ---------------------------------------------------------------------------
// UTF-8 repair
// ---------------------------------------------------------------------------

// Append U+FFFD (EF BF BD) to `out` at position *pos if there is room.
static void push_replacement(uint8_t *out, size_t out_cap, size_t *pos)
{
    static const uint8_t r[3] = { 0xEFu, 0xBFu, 0xBDu };
    for (size_t k = 0; k < 3u; k++) {
        if (*pos < out_cap) {
            out[*pos] = r[k];
        }
        *pos += 1u;
    }
}

static void push_byte(uint8_t *out, size_t out_cap, size_t *pos, uint8_t b)
{
    if (*pos < out_cap) {
        out[*pos] = b;
    }
    *pos += 1u;
}

// Returns the number of continuation bytes a leading byte expects, or 0 if
// the leading byte is invalid. Also sets *cp and *min_cp.
static size_t lead_info(uint8_t b, uint32_t *cp, uint32_t *min_cp)
{
    if (b <= 0x7Fu) {
        *cp = (uint32_t)b;
        *min_cp = 0u;
        return 0u;  // ASCII, no continuations
    }
    if (b >= 0xC2u && b <= 0xDFu) {
        *cp = (uint32_t)(b & 0x1Fu);
        *min_cp = 0u;
        return 1u;
    }
    if (b >= 0xE0u && b <= 0xEFu) {
        *cp = (uint32_t)(b & 0x0Fu);
        *min_cp = (b == 0xE0u) ? 0x800u : 0u; // overlong < U+0800
        return 2u;
    }
    if (b >= 0xF0u && b <= 0xF4u) {
        *cp = (uint32_t)(b & 0x07u);
        *min_cp = (b == 0xF0u) ? 0x10000u : ((b == 0xF4u) ? 0x100000u : 0u);
        return 3u;
    }
    return 99u;  // invalid lead marker (impossible count)
}

bool rfb_clip_utf8_repair(const uint8_t *data, size_t len,
                          uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (out_len != NULL) *out_len = 0u;
    if (data == NULL || out == NULL) {
        return false;
    }
    size_t i = 0;
    size_t pos = 0;
    bool fits = true;
    while (i < len) {
        uint8_t b = data[i];
        uint32_t cp = 0;
        uint32_t min_cp = 0u;
        size_t need = lead_info(b, &cp, &min_cp);
        if (b <= 0x7Fu) {
            // ASCII pass-through.
            push_byte(out, out_cap, &pos, b);
            if (pos > out_cap) fits = false;
            i += 1u;
            continue;
        }
        if (need == 99u) {
            // Invalid leading byte.
            push_replacement(out, out_cap, &pos);
            if (pos > out_cap) fits = false;
            i += 1u;
            continue;
        }
        // Multibyte: gather continuations.
        bool valid = true;
        size_t k = 1u;
        for (; k <= need; k++) {
            if (i + k >= len) { valid = false; break; }
            uint8_t c = data[i + k];
            if (c < 0x80u || c > 0xBFu) { valid = false; break; }
            cp = (cp << 6u) | (uint32_t)(c & 0x3Fu);
        }
        if (!valid || k <= need || cp < min_cp || cp > 0x10FFFFu ||
            (cp >= 0xD800u && cp <= 0xDFFFu)) {
            // Invalid sequence: emit one replacement and advance by ONE byte
            // (maximal-substitution alternative: advance past the lead only).
            push_replacement(out, out_cap, &pos);
            if (pos > out_cap) fits = false;
            i += 1u;
            continue;
        }
        // Valid multibyte: copy as-is.
        for (size_t m = 0; m <= need; m++) {
            push_byte(out, out_cap, &pos, data[i + m]);
        }
        if (pos > out_cap) fits = false;
        i += 1u + need;
    }
    if (out_len != NULL) {
        *out_len = (pos <= out_cap) ? pos : out_cap;
    }
    return fits;
}

// ---------------------------------------------------------------------------
// Terminal escape sanitization
// ---------------------------------------------------------------------------

bool rfb_clip_byte_is_dropped(uint8_t b)
{
    // Drop ESC (0x1B), DEL (0x7F), and C0 controls other than TAB/LF/CR.
    // Do NOT drop bare 0x80–0x9F: those are UTF-8 continuation bytes
    // (multi-review 2026-08-03 post-t11 T1). C1 is handled as UTF-8 C2 8x/9x
    // in rfb_clip_sanitize.
    if (b == 0x1Bu || b == 0x7Fu) return true;
    if (b < 0x20u) {
        if (b == RFB_CLIP_SAN_KEEP_TAB ||
            b == RFB_CLIP_SAN_KEEP_LF ||
            b == RFB_CLIP_SAN_KEEP_CR) {
            return false;
        }
        return true;
    }
    return false;
}

bool rfb_clip_sanitize(const uint8_t *data, size_t len,
                       uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (out_len != NULL) *out_len = 0u;
    if (data == NULL || out == NULL) {
        return false;
    }
    size_t pos = 0;
    for (size_t i = 0; i < len; i++) {
        // UTF-8 C1 (U+0080–U+009F) is C2 80..C2 9F — drop both bytes.
        if (data[i] == 0xC2u && i + 1u < len) {
            uint8_t c2 = data[i + 1u];
            if (c2 >= 0x80u && c2 <= 0x9Fu) {
                i++; // skip continuation
                continue;
            }
        }
        if (!rfb_clip_byte_is_dropped(data[i])) {
            if (pos < out_cap) {
                out[pos] = data[i];
            }
            pos += 1u;
        }
        // Dropped bytes are simply skipped (compaction).
    }
    if (out_len != NULL) {
        *out_len = (pos <= out_cap) ? pos : out_cap;
    }
    return pos <= out_cap;
}

// ---------------------------------------------------------------------------
// Size caps
// ---------------------------------------------------------------------------

bool rfb_clip_size_ok(const rfb_clip_policy *p, size_t len)
{
    if (p == NULL) return false;
    return len <= p->max_bytes;
}

bool rfb_clip_allow_outbound(const rfb_clip_policy *p, size_t len)
{
    if (p == NULL) return false;
    if (len == 0) return false;
    if (!rfb_clip_size_ok(p, len)) return false;
    // Sensitive mode disables outbound clipboard entirely (passwords etc.).
    if (p->sensitive_enabled) return false;
    return true;
}

// ---------------------------------------------------------------------------
// Loop suppression (FNV-1a 32)
// ---------------------------------------------------------------------------

uint32_t rfb_clip_fnv1a32(const uint8_t *data, size_t len)
{
    uint32_t h = 0x811c9dc5u;  // FNV offset basis
    if (data == NULL) {
        return h;
    }
    for (size_t i = 0; i < len; i++) {
        h ^= (uint32_t)data[i];
        h *= 0x01000193u;  // FNV prime
    }
    return h;
}

void rfb_clip_loop_init(rfb_clip_loop *l)
{
    if (l == NULL) return;
    l->last_inbound_hash = 0u;
    l->has_last = false;
}

void rfb_clip_loop_record_inbound(rfb_clip_loop *l,
                                  const uint8_t *data, size_t len)
{
    if (l == NULL) return;
    l->last_inbound_hash = rfb_clip_fnv1a32(data, len);
    l->has_last = true;
}

bool rfb_clip_loop_is_echo(const rfb_clip_loop *l,
                           const uint8_t *data, size_t len)
{
    if (l == NULL || !l->has_last) return false;
    return rfb_clip_fnv1a32(data, len) == l->last_inbound_hash;
}

void rfb_clip_loop_clear(rfb_clip_loop *l)
{
    if (l == NULL) return;
    l->last_inbound_hash = 0u;
    l->has_last = false;
}
