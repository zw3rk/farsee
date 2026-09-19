// SPDX-License-Identifier: Apache-2.0
//
// farsee — logging with trusted/remote text distinction (plan.md §G1,
// §6.3: "output escaping or rejection for all server-provided text before
// terminal display").
//
// Two categories of text:
//   - TRUSTED: project-owned string literals (format strings, static
//     labels). Logged verbatim.
//   - REMOTE:  any byte sequence derived from the server (desktop name,
//     clipboard, failure-reason string, terminal replies). Must be
//     escaped before it appears in any diagnostic, to prevent terminal
//     escape-sequence injection (plan.md §6.2 threat).
//
// The escape function preserves printable ASCII and maps every other byte to
// a visible backslash escape. Newline, carriage return, and tab use their
// short escapes; all other bytes use `\xNN`. No control byte appears raw.

#ifndef FARSEE_INCLUDE_FARSEE_LOG_H
#define FARSEE_INCLUDE_FARSEE_LOG_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Escape `n` bytes of untrusted `remote` into `out` (capacity `out_cap`),
// producing a null-terminated C string. Returns the number of bytes
// written excluding the terminator, or the length that *would* be needed
// (excluding terminator) if out_cap is too small — so callers can
// allocate. Control bytes, ESC, and non-ASCII bytes become \xNN or one of
// the standard \r\n\t abbreviations.
size_t rfb_log_escape_remote(
    const void *remote, size_t n,
    char *out, size_t out_cap);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_LOG_H
