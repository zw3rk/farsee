// SPDX-License-Identifier: Apache-2.0
//
// farsee — ServerInit parsing + SetPixelFormat/SetEncodings emission
// (plan.md §G3, RFC 6143 §7.3.2, §7.4.1, §7.5.1, §7.5.2).

#ifndef FARSEE_INCLUDE_FARSEE_SERVER_INIT_H
#define FARSEE_INCLUDE_FARSEE_SERVER_INIT_H

#include "farsee/bytes.h"
#include "farsee/error.h"
#include "farsee/pixel_format.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Parsed ServerInit (RFC 6143 §7.3.2). `name` is heap-allocated and
// null-terminated for convenience; the caller owns it and releases via
// rfb_server_init_destroy.
typedef struct rfb_server_init {
    uint16_t width;
    uint16_t height;
    rfb_pixel_format pixel_format;
    uint32_t name_length;   // bytes, excluding the null terminator
    char    *name;          // null-terminated; raw bytes (may contain ESC)
} rfb_server_init;

// Parse a ServerInit message from `in` (at least 24 + name_length bytes).
// `name_cap` bounds the acceptable name length (plan.md §6.4 desktop-name
// limit). On success, `out->name` is heap-allocated. On failure, `out` is
// left zeroed (no allocation to free).
rfb_error rfb_parse_server_init(const uint8_t *in, size_t in_len,
                                rfb_server_init *out, size_t name_cap);

// Release the parsed name storage. Safe on a zeroed struct.
void rfb_server_init_destroy(rfb_server_init *si);

// Emit a SetPixelFormat message (message-type 0, 3 pad bytes, 16-byte
// PIXEL_FORMAT) into the writer (plan.md §G3, RFC 6143 §7.5.1).
rfb_error rfb_format_set_pixel_format(rfb_writer *w, const rfb_pixel_format *pf);

// Emit a SetEncodings message (message-type 2, 1 pad byte, u16 count, then
// count big-endian i32 encodings) into the writer (RFC 6143 §7.5.2).
// `encodings` is the caller-chosen list in preference order; Raw (0)
// should always be included last as the fallback.
rfb_error rfb_format_set_encodings(rfb_writer *w,
                                   const int32_t *encodings, uint16_t count);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_SERVER_INIT_H
