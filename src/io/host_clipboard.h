// SPDX-License-Identifier: Apache-2.0
//
// Host UTF-8 plain-text clipboard access shared by live protocols.

#ifndef FARSEE_SRC_IO_HOST_CLIPBOARD_H
#define FARSEE_SRC_IO_HOST_CLIPBOARD_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Read at most cap-1 bytes and add NUL. Returns the byte length, -1 on host
// tool failure/unavailable text, or -2 when the clipboard exceeds the buffer.
long farsee_host_clipboard_get_utf8(char *buffer, size_t capacity);

// Write exactly length UTF-8 bytes. The input need not be NUL-terminated.
bool farsee_host_clipboard_set_utf8(const char *text, size_t length);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_SRC_IO_HOST_CLIPBOARD_H
