// SPDX-License-Identifier: Apache-2.0
//
// Pure CLI target URL parser + leader-spec parser (see cli_target.h).

#include "farsee/cli_target.h"
#include "farsee/normalized_input.h"  // RFB_MOD_CONTROL

#include <ctype.h>
#include <stdio.h>
#include <string.h>

static void target_clear(farsee_cli_target *out)
{
    if (out == NULL) {
        return;
    }
    memset(out, 0, sizeof(*out));
}

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return 10 + (c - 'a');
    }
    if (c >= 'A' && c <= 'F') {
        return 10 + (c - 'A');
    }
    return -1;
}

bool farsee_cli_percent_decode(const char *in, char *out, size_t cap)
{
    if (in == NULL || out == NULL || cap == 0) {
        return false;
    }
    size_t o = 0;
    for (size_t i = 0; in[i] != '\0'; i++) {
        char c = in[i];
        if (c == '%' && in[i + 1] != '\0' && in[i + 2] != '\0') {
            int hi = hex_nibble(in[i + 1]);
            int lo = hex_nibble(in[i + 2]);
            if (hi < 0 || lo < 0) {
                out[0] = '\0';
                return false;
            }
            c = (char)((hi << 4) | lo);
            i += 2;
        } else if (c == '+') {
            // Form-encoding space (harmless for passwords that use +).
            c = ' ';
        }
        if (o + 1 >= cap) {
            out[0] = '\0';
            return false;
        }
        out[o++] = c;
    }
    out[o] = '\0';
    return true;
}

static bool copy_bounded(char *dst, size_t cap, const char *src, size_t n)
{
    if (dst == NULL || cap == 0 || src == NULL) {
        return false;
    }
    if (n >= cap) {
        return false;
    }
    memcpy(dst, src, n);
    dst[n] = '\0';
    return true;
}

bool farsee_cli_target_parse(const char *s, farsee_cli_target *out)
{
    if (out == NULL) {
        return false;
    }
    target_clear(out);
    if (s == NULL || s[0] == '\0') {
        return false;
    }

    const char *rest = s;
    // Scheme: rdp:// or vnc:// (case-insensitive letters, fixed schemes).
    if (strncmp(rest, "rdp://", 6) == 0 || strncmp(rest, "RDP://", 6) == 0) {
        out->proto = FARSEE_CLI_PROTO_RDP;
        rest += 6;
    } else if (strncmp(rest, "vnc://", 6) == 0 || strncmp(rest, "VNC://", 6) == 0) {
        out->proto = FARSEE_CLI_PROTO_RFB;
        rest += 6;
    } else if (strncmp(rest, "rfb://", 6) == 0 || strncmp(rest, "RFB://", 6) == 0) {
        out->proto = FARSEE_CLI_PROTO_RFB;
        rest += 6;
    }

    // Optional userinfo before the last '@'. (host may not contain @).
    const char *at = strrchr(rest, '@');
    const char *hostpart = rest;
    if (at != NULL) {
        size_t uilen = (size_t)(at - rest);
        if (uilen == 0) {
            target_clear(out);
            return false;  // empty userinfo
        }
        // Split user:password on first ':'.
        const char *colon = memchr(rest, ':', uilen);
        char user_raw[sizeof out->user * 2];
        char pass_raw[sizeof out->password * 2];
        if (colon != NULL && (size_t)(colon - rest) < uilen) {
            size_t ulen = (size_t)(colon - rest);
            size_t plen = uilen - ulen - 1u;
            if (ulen == 0 || ulen >= sizeof user_raw ||
                plen >= sizeof pass_raw) {
                target_clear(out);
                return false;
            }
            memcpy(user_raw, rest, ulen);
            user_raw[ulen] = '\0';
            memcpy(pass_raw, colon + 1, plen);
            pass_raw[plen] = '\0';
            if (!farsee_cli_percent_decode(user_raw, out->user,
                                          sizeof out->user) ||
                !farsee_cli_percent_decode(pass_raw, out->password,
                                          sizeof out->password)) {
                target_clear(out);
                return false;
            }
            out->has_user = true;
            out->has_password = true;
        } else {
            if (uilen >= sizeof user_raw) {
                target_clear(out);
                return false;
            }
            memcpy(user_raw, rest, uilen);
            user_raw[uilen] = '\0';
            if (!farsee_cli_percent_decode(user_raw, out->user,
                                          sizeof out->user)) {
                target_clear(out);
                return false;
            }
            out->has_user = true;
        }
        hostpart = at + 1;
    }

    if (hostpart[0] == '\0') {
        target_clear(out);
        return false;
    }

    // host[:port] — last ':' introduces a decimal port when the suffix is
    // all digits. Bare IPv4 host:port works; bare hostname works.
    const char *pcolon = strrchr(hostpart, ':');
    if (pcolon != NULL && pcolon[1] != '\0') {
        bool all_digits = true;
        for (const char *p = pcolon + 1; *p != '\0'; p++) {
            if (!isdigit((unsigned char)*p)) {
                all_digits = false;
                break;
            }
        }
        if (all_digits) {
            long port = 0;
            for (const char *p = pcolon + 1; *p != '\0'; p++) {
                port = port * 10 + (*p - '0');
                if (port > 65535) {
                    target_clear(out);
                    return false;
                }
            }
            if (port <= 0 || port > 65535) {
                target_clear(out);
                return false;
            }
            size_t hlen = (size_t)(pcolon - hostpart);
            if (hlen == 0 ||
                !copy_bounded(out->host, sizeof out->host, hostpart, hlen)) {
                target_clear(out);
                return false;
            }
            out->port = (uint16_t)port;
            return true;
        }
    }

    size_t hlen = strlen(hostpart);
    if (!copy_bounded(out->host, sizeof out->host, hostpart, hlen)) {
        target_clear(out);
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Production URL-password policy (argv/ps exposure)
// ---------------------------------------------------------------------------

bool farsee_cli_url_password_allowed(const farsee_cli_target *t)
{
    if (t == NULL) {
        return true;
    }
    return !t->has_password;
}

const char *farsee_cli_url_password_policy_error(const farsee_cli_target *t)
{
    if (farsee_cli_url_password_allowed(t)) {
        return NULL;
    }
    return "farsee: passwords in URL userinfo are rejected (visible to ps). "
           "Use --password-fd N or the interactive TTY prompt.";
}

// ---------------------------------------------------------------------------
// Leader (tmux-style prefix) parser
// ---------------------------------------------------------------------------

// Map Control+key to classic C0 where the mapping is unambiguous.
// Letters a-z → 0x01..0x1A; also @[\]^_ for 0x00 and 0x1B..0x1F.
static bool ctrl_c0_byte(uint32_t keysym, uint8_t *out_c0)
{
    if (out_c0 == NULL) {
        return false;
    }
    if (keysym >= (uint32_t)'a' && keysym <= (uint32_t)'z') {
        *out_c0 = (uint8_t)(keysym & 0x1Fu);
        return true;
    }
    if (keysym >= (uint32_t)'A' && keysym <= (uint32_t)'Z') {
        *out_c0 = (uint8_t)((keysym - (uint32_t)'A' + (uint32_t)'a') & 0x1Fu);
        return true;
    }
    switch (keysym) {
    case (uint32_t)'@':
        *out_c0 = 0x00u;
        return true;
    case (uint32_t)'[':
        *out_c0 = 0x1Bu;
        return true;
    case (uint32_t)'\\':
        *out_c0 = 0x1Cu;
        return true;
    case (uint32_t)']':
        *out_c0 = 0x1Du;
        return true;
    case (uint32_t)'^':
        *out_c0 = 0x1Eu;
        return true;
    case (uint32_t)'_':
        *out_c0 = 0x1Fu;
        return true;
    default:
        return false;
    }
}

static void leader_set_display(farsee_cli_leader *out, uint32_t keysym)
{
    // Always show Emacs/tmux form: C-<key>
    char k = (char)keysym;
    if (k >= 'A' && k <= 'Z') {
        k = (char)(k - 'A' + 'a');
    }
    // Printable single-byte key; escape-ish keys still show as the glyph.
    if (k == '\\') {
        (void)snprintf(out->display, sizeof out->display, "C-\\\\");
    } else {
        (void)snprintf(out->display, sizeof out->display, "C-%c", k);
    }
}

void farsee_cli_leader_default(farsee_cli_leader *out)
{
    if (out == NULL) {
        return;
    }
    memset(out, 0, sizeof(*out));
    out->keysym = (uint32_t)']';
    out->mods = RFB_MOD_CONTROL;
    out->c0_byte = 0x1Du;
    out->has_c0 = true;
    (void)snprintf(out->display, sizeof out->display, "C-]");
}

bool farsee_cli_leader_parse(const char *s, farsee_cli_leader *out)
{
    if (out == NULL) {
        return false;
    }
    memset(out, 0, sizeof(*out));
    if (s == NULL || s[0] == '\0') {
        return false;
    }

    // Trim leading/trailing spaces (not required, but friendly).
    while (*s == ' ' || *s == '\t') {
        s++;
    }
    size_t len = strlen(s);
    while (len > 0 && (s[len - 1u] == ' ' || s[len - 1u] == '\t')) {
        len--;
    }
    if (len == 0) {
        return false;
    }

    // Reject Meta/Alt leaders because the demultiplexer handles Control only.
    if ((len >= 2 && (s[0] == 'M' || s[0] == 'm') && s[1] == '-') ||
        (len >= 4 && (s[0] == 'A' || s[0] == 'a') &&
         (s[1] == 'l' || s[1] == 'L') && (s[2] == 't' || s[2] == 'T') &&
         s[3] == '-') ||
        (len >= 5 && (s[0] == 'm' || s[0] == 'M') &&
         (s[1] == 'e' || s[1] == 'E') && (s[2] == 't' || s[2] == 'T') &&
         (s[3] == 'a' || s[3] == 'A') && s[4] == '-')) {
        return false;
    }

    const char *key = s;
    size_t key_len = len;

    // Strip optional Control prefix: C- / c- / Ctrl- / CTRL- / control-
    if (len >= 2 && (s[0] == 'C' || s[0] == 'c') && s[1] == '-') {
        key = s + 2;
        key_len = len - 2;
    } else if (len >= 5 &&
               (s[0] == 'C' || s[0] == 'c') &&
               (s[1] == 't' || s[1] == 'T') &&
               (s[2] == 'r' || s[2] == 'R') &&
               (s[3] == 'l' || s[3] == 'L') && s[4] == '-') {
        key = s + 5;
        key_len = len - 5;
    } else if (len >= 8 &&
               (s[0] == 'c' || s[0] == 'C') &&
               (s[1] == 'o' || s[1] == 'O') &&
               (s[2] == 'n' || s[2] == 'N') &&
               (s[3] == 't' || s[3] == 'T') &&
               (s[4] == 'r' || s[4] == 'R') &&
               (s[5] == 'o' || s[5] == 'O') &&
               (s[6] == 'l' || s[6] == 'L') && s[7] == '-') {
        key = s + 8;
        key_len = len - 8;
    }
    // else: bare key → Control implied (shorthand for C-<key>)

    if (key_len != 1u) {
        return false;  // only single-byte keys are supported
    }
    unsigned char kc = (unsigned char)key[0];
    // Printable ASCII only (space is silly as a leader; reject).
    if (kc <= 0x20u || kc >= 0x7Fu) {
        return false;
    }
    uint32_t keysym = (uint32_t)kc;
    if (keysym >= (uint32_t)'A' && keysym <= (uint32_t)'Z') {
        keysym = keysym - (uint32_t)'A' + (uint32_t)'a';
    }

    out->keysym = keysym;
    out->mods = RFB_MOD_CONTROL;
    out->has_c0 = ctrl_c0_byte(keysym, &out->c0_byte);
    if (!out->has_c0) {
        out->c0_byte = 0;
    }
    leader_set_display(out, keysym);
    return true;
}
