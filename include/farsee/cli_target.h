// SPDX-License-Identifier: Apache-2.0
//
// farsee — pure CLI target / endpoint URL parser.
//
// Accepts the positional connection string forms used by the CLI:
//   host[:port]
//   <proto>://host[:port]
//   <proto>://user@host[:port]
//   <proto>://user:password@host[:port]   (parsed, but production REJECTS —
//                                          see farsee_cli_url_password_allowed)
//
// Pure: no I/O, no globals. Password may contain ':' (first ':' in userinfo
// splits user/password). Host:port uses the last ':' (IPv6 not supported
// in this minimal form). Optional percent-decoding for user and password.
// The parser remains capable of reading user:pass@host for tools/tests;
// production entry (main) must refuse embedded passwords via the policy
// helpers below (argv/ps exposure — threat model).

#ifndef FARSEE_INCLUDE_FARSEE_CLI_TARGET_H
#define FARSEE_INCLUDE_FARSEE_CLI_TARGET_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Protocol hint from the scheme (or none).
typedef enum {
    FARSEE_CLI_PROTO_NONE = 0,
    FARSEE_CLI_PROTO_RDP,
    FARSEE_CLI_PROTO_RFB,  // vnc://
} farsee_cli_proto;

// Bounded parse result. Strings are always NUL-terminated when present.
typedef struct farsee_cli_target {
    farsee_cli_proto proto;
    char             host[256];
    uint16_t         port;          // 0 if absent
    char             user[128];
    char             password[256];
    bool             has_user;
    bool             has_password;
} farsee_cli_target;

// Parse `s` into *out. Returns true on success (non-empty host).
// Returns false for NULL/empty/missing-host / out-NULL / oversize fields.
// On failure *out is zeroed. Does not log; callers print usage.
// Note: a successful parse with has_password does *not* mean production
// may use that password — call farsee_cli_url_password_allowed first.
bool farsee_cli_target_parse(const char *s, farsee_cli_target *out);

// Percent-decode `in` into `out` (cap bytes including NUL). Returns false
// if the encoding is invalid or the result does not fit.
bool farsee_cli_percent_decode(const char *in, char *out, size_t cap);

// Production entry policy: passwords in URL userinfo are forbidden because
// they appear in argv and are visible to `ps` (threat model).
//
// Returns false when t is non-NULL and t->has_password (must refuse).
// Returns true when there is no password field (host-only, user@host, or
// t == NULL). Does not inspect password contents.
bool farsee_cli_url_password_allowed(const farsee_cli_target *t);

// Same policy as farsee_cli_url_password_allowed. Returns a static operator
// message when the target must be refused, or NULL when allowed.
// Suitable for fprintf(stderr, "%s\n", msg) at production entry.
const char *farsee_cli_url_password_policy_error(const farsee_cli_target *t);

// ---------------------------------------------------------------------------
// Live-session leader (tmux-style prefix).
//
// tmux defines the prefix *with* the modifier, e.g. `C-b` / `C-a` — not a
// bare letter alone. Farsee follows that:
//   C-]  ctrl-]  Ctrl-]     → Control + ]
//   C-b  ctrl-b             → Control + b
//   b    ]                  → bare char implies Control (shorthand)
// Meta/Alt leaders are rejected for now (Control-only demux path).
// ---------------------------------------------------------------------------
typedef struct farsee_cli_leader {
    uint32_t keysym;     // X11 keysym of the base key (e.g. ']' or 'b')
    uint16_t mods;       // required modifiers (RFB_MOD_CONTROL)
    uint8_t  c0_byte;    // classic C0 when ISIG off (0x1D for Ctrl+]); 0 if n/a
    bool     has_c0;     // true when c0_byte is a reliable demux signal
    char     display[16]; // status-bar form, always "C-<key>"
} farsee_cli_leader;

// Default leader: C-] (telnet-style; rare on Windows remotes).
void farsee_cli_leader_default(farsee_cli_leader *out);

// Parse a leader spec. Returns false on NULL/empty/unsupported form.
// Case-insensitive on the "C-" / "ctrl-" prefix; the key letter is
// lowercased for a-z (C-B == C-b).
bool farsee_cli_leader_parse(const char *s, farsee_cli_leader *out);

#ifdef __cplusplus
}
#endif

#endif /* FARSEE_INCLUDE_FARSEE_CLI_TARGET_H */
