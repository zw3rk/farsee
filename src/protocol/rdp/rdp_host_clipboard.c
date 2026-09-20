// SPDX-License-Identifier: Apache-2.0
//
// RDP-private compatibility wrappers over the shared host clipboard adapter.

#include "rdp_host_clipboard.h"

#include "io/host_clipboard.h"

long rdp_host_clipboard_get_utf8(char *buf, size_t cap)
{
    return farsee_host_clipboard_get_utf8(buf, cap);
}

bool rdp_host_clipboard_set_utf8(const char *text, size_t len)
{
    return farsee_host_clipboard_set_utf8(text, len);
}
