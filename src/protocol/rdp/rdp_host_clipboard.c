// SPDX-License-Identifier: Apache-2.0
//
// Farsee RDP host pasteboard access (R6 cliprdr text path, §15.13).
//
// No FreeRDP. Platform pasteboard via external tools (pbpaste/pbcopy,
// xclip, wl-paste/wl-copy).

#include "rdp_host_clipboard.h"

#include <stdio.h>

// Read from a fixed command's stdout into buf. cmd is a constant string
// with no user-controlled content (no shell interpolation of paths).
static long rdp_clip_popen_get(const char *cmd, char *buf, size_t cap)
{
    if (cmd == NULL || buf == NULL || cap == 0) {
        return -1;
    }
    FILE *f = popen(cmd, "r");
    if (f == NULL) {
        return -1;
    }
    size_t n = fread(buf, 1, cap - 1, f);
    int st = pclose(f);
    if (st != 0 && n == 0) {
        return -1;
    }
    buf[n] = '\0';
    return (long)n;
}

// Write text to a fixed command's stdin.
static bool rdp_clip_popen_set(const char *cmd, const char *text, size_t len)
{
    if (cmd == NULL) {
        return false;
    }
    if (text == NULL && len > 0) {
        return false;
    }
    FILE *f = popen(cmd, "w");
    if (f == NULL) {
        return false;
    }
    bool ok = true;
    if (len > 0) {
        ok = fwrite(text, 1, len, f) == len;
    }
    int st = pclose(f);
    if (st != 0) {
        ok = false;
    }
    return ok;
}

long rdp_host_clipboard_get_utf8(char *buf, size_t cap)
{
    if (buf == NULL || cap == 0) {
        return -1;
    }
    buf[0] = '\0';

#if defined(__APPLE__)
    return rdp_clip_popen_get("pbpaste 2>/dev/null", buf, cap);
#else
    // Linux best-effort: try Wayland then X11; return -1 if neither works.
    long n = rdp_clip_popen_get("wl-paste -n 2>/dev/null", buf, cap);
    if (n >= 0) {
        return n;
    }
    n = rdp_clip_popen_get("xclip -selection clipboard -o 2>/dev/null", buf, cap);
    if (n >= 0) {
        return n;
    }
    return -1;
#endif
}

bool rdp_host_clipboard_set_utf8(const char *text, size_t len)
{
    if (text == NULL && len > 0) {
        return false;
    }

#if defined(__APPLE__)
    return rdp_clip_popen_set("pbcopy 2>/dev/null", text, len);
#else
    if (rdp_clip_popen_set("wl-copy 2>/dev/null", text, len)) {
        return true;
    }
    if (rdp_clip_popen_set("xclip -selection clipboard 2>/dev/null", text, len)) {
        return true;
    }
    return false;
#endif
}
