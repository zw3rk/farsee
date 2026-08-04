// SPDX-License-Identifier: Apache-2.0
//
// Farsee RDP host pasteboard access (R6 cliprdr text path, §15.13).
//
// No FreeRDP. Platform pasteboard via external tools (pbpaste/pbcopy,
// xclip, wl-paste/wl-copy). FARSEE_CLIP_FAKE enables a file-backed
// roundtrip for unit tests without a display server.

#include "rdp_host_clipboard.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Maximum bytes we will ever read from a tool or FAKE file into the
// caller's buffer is limited by `cap`. Internal tool reads use the same
// bound so a huge pasteboard cannot balloon memory here.

static long rdp_clip_fake_get(const char *path, char *buf, size_t cap)
{
    if (path == NULL || path[0] == '\0' || buf == NULL || cap == 0) {
        return -1;
    }
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        return -1;
    }
    size_t n = fread(buf, 1, cap > 0 ? cap - 1 : 0, f);
    int err = ferror(f);
    fclose(f);
    if (err != 0) {
        return -1;
    }
    buf[n] = '\0';
    // Exact bytes for the FAKE seam (tests rely on roundtrip fidelity).
    return (long)n;
}

static bool rdp_clip_fake_set(const char *path, const char *text, size_t len)
{
    if (path == NULL || path[0] == '\0') {
        return false;
    }
    if (text == NULL && len > 0) {
        return false;
    }
    FILE *f = fopen(path, "wb");
    if (f == NULL) {
        return false;
    }
    bool ok = true;
    if (len > 0) {
        ok = fwrite(text, 1, len, f) == len;
    }
    if (fclose(f) != 0) {
        ok = false;
    }
    return ok;
}

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

    const char *fake = getenv("FARSEE_CLIP_FAKE");
    if (fake != NULL && fake[0] != '\0') {
        return rdp_clip_fake_get(fake, buf, cap);
    }

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

    const char *fake = getenv("FARSEE_CLIP_FAKE");
    if (fake != NULL && fake[0] != '\0') {
        return rdp_clip_fake_set(fake, text, len);
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
