// SPDX-License-Identifier: Apache-2.0
//
// farsee — remote-text escape for logging.
//
// Every byte outside printable ASCII (0x20..0x7E) is encoded so it cannot
// form a terminal escape sequence. The escape is deterministic and
// printable, so diagnostics are safe to print to any terminal.

#include "farsee/log.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>

size_t rfb_log_escape_remote(
    const void *remote, size_t n,
    char *out, size_t out_cap)
{
    static const char hexdigits[] = "0123456789ABCDEF";
    const uint8_t *src = (const uint8_t *)remote;
    size_t written = 0;

    for (size_t i = 0; i < n; i++) {
        uint8_t b = src[i];
        char seq[4];
        size_t seqlen;
        // Select the encoded form for this byte. The escapes chosen mean
        // no byte in 0x00..0x1F or 0x7F..0xFF can appear verbatim, so no
        // CSI/OSC/DCS sequence can be smuggled into a log line.
        if (b == '\n') {
            seq[0] = '\\'; seq[1] = 'n';  seqlen = 2;
        } else if (b == '\r') {
            seq[0] = '\\'; seq[1] = 'r';  seqlen = 2;
        } else if (b == '\t') {
            seq[0] = '\\'; seq[1] = 't';  seqlen = 2;
        } else if (b == '\\') {
            seq[0] = '\\'; seq[1] = '\\'; seqlen = 2;
        } else if (b >= 0x20 && b <= 0x7E) {
            seq[0] = (char)b;             seqlen = 1;
        } else {
            seq[0] = '\\';
            seq[1] = 'x';
            seq[2] = hexdigits[(b >> 4) & 0xF];
            seq[3] = hexdigits[b & 0xF];
            seqlen = 4;
        }
        // Track the total length we *would* write, even on overflow.
        // Guard against size_t overflow in the bounds check.
        if (out != NULL && seqlen <= out_cap - 1 - written &&
            written + seqlen + 1 <= out_cap) {
            memcpy(out + written, seq, seqlen);
        }
        written += seqlen;
    }
    // Always null-terminate if we have room.
    if (out != NULL && out_cap > 0) {
        size_t term = written < out_cap ? written : out_cap - 1;
        out[term] = '\0';
    }
    return written;
}
