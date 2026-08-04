// SPDX-License-Identifier: Apache-2.0
//
// Farsee RDP host pasteboard access (R6 cliprdr text path, §15.13).
//
// Reads/writes UTF-8 plain text on the local host pasteboard so the
// cliprdr channel can bridge remote text. No FreeRDP types. PRIVATE to
// src/protocol/rdp/.
//
// Test seam: when env FARSEE_CLIP_FAKE is set to a filesystem path, get/set
// operate on that file instead of the real pasteboard (unit tests).

#ifndef FARSEE_SRC_PROTOCOL_RDP_RDP_HOST_CLIPBOARD_H
#define FARSEE_SRC_PROTOCOL_RDP_RDP_HOST_CLIPBOARD_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Get UTF-8 text from the host pasteboard into buf (NUL-terminated).
// Returns the byte length written (excluding NUL), or -1 on failure /
// empty/unavailable clipboard. Writes at most cap-1 payload bytes + NUL.
// macOS: pbpaste. Linux: xclip / wl-paste best-effort; else -1.
// FARSEE_CLIP_FAKE path: read that file.
long rdp_host_clipboard_get_utf8(char *buf, size_t cap);

// Set host pasteboard from UTF-8 text of length `len` (need not be
// NUL-terminated). Returns true on success.
// macOS: pbcopy. Linux: xclip / wl-copy best-effort; else false.
// FARSEE_CLIP_FAKE path: write that file.
bool rdp_host_clipboard_set_utf8(const char *text, size_t len);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_SRC_PROTOCOL_RDP_RDP_HOST_CLIPBOARD_H
