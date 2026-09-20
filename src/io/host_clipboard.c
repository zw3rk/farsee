// SPDX-License-Identifier: Apache-2.0
//
// Host UTF-8 plain-text clipboard access through fixed platform commands.

#include "io/host_clipboard.h"

#include <stdio.h>

static long host_clipboard_command_get(const char *command, char *buffer,
                                       size_t capacity)
{
    if (command == NULL || buffer == NULL || capacity == 0u) {
        return -1;
    }
    FILE *stream = popen(command, "r");
    if (stream == NULL) {
        return -1;
    }
    const size_t length = fread(buffer, 1u, capacity - 1u, stream);
    bool oversized = false;
    if (length == capacity - 1u) {
        oversized = fgetc(stream) != EOF;
    }
    const bool read_failed = ferror(stream) != 0;
    const int status = pclose(stream);
    if (read_failed || (status != 0 && length == 0u)) {
        return -1;
    }
    if (oversized) {
        buffer[0] = '\0';
        return -2;
    }
    buffer[length] = '\0';
    return (long)length;
}

static bool host_clipboard_command_set(const char *command,
                                       const char *text, size_t length)
{
    if (command == NULL || (text == NULL && length > 0u)) {
        return false;
    }
    FILE *stream = popen(command, "w");
    if (stream == NULL) {
        return false;
    }
    bool ok = length == 0u || fwrite(text, 1u, length, stream) == length;
    if (pclose(stream) != 0) {
        ok = false;
    }
    return ok;
}

long farsee_host_clipboard_get_utf8(char *buffer, size_t capacity)
{
    if (buffer == NULL || capacity == 0u) {
        return -1;
    }
    buffer[0] = '\0';
#if defined(__APPLE__)
    return host_clipboard_command_get("pbpaste 2>/dev/null", buffer,
                                      capacity);
#else
    long length = host_clipboard_command_get(
        "wl-paste -n 2>/dev/null", buffer, capacity);
    if (length != -1) {
        return length;
    }
    return host_clipboard_command_get(
        "xclip -selection clipboard -o 2>/dev/null", buffer, capacity);
#endif
}

bool farsee_host_clipboard_set_utf8(const char *text, size_t length)
{
    if (text == NULL && length > 0u) {
        return false;
    }
#if defined(__APPLE__)
    return host_clipboard_command_set("pbcopy 2>/dev/null", text, length);
#else
    if (host_clipboard_command_set("wl-copy 2>/dev/null", text, length)) {
        return true;
    }
    return host_clipboard_command_set(
        "xclip -selection clipboard 2>/dev/null", text, length);
#endif
}
