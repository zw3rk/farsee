// SPDX-License-Identifier: Apache-2.0
//
// farsee — ServerInit parsing + SetPixelFormat/SetEncodings emission
// (plan.md §G3, RFC 6143 §7.3.2, §7.4.1, §7.5.1, §7.5.2).

#ifndef FARSEE_INCLUDE_FARSEE_SERVER_INIT_H
#define FARSEE_INCLUDE_FARSEE_SERVER_INIT_H

#include "farsee/allocator.h"
#include "farsee/bytes.h"
#include "farsee/error.h"
#include "farsee/pixel_format.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Parsed ServerInit (RFC 6143 §7.3.2). `name` is allocated through the
// stored allocator and is null-terminated. Release it with
// rfb_server_init_destroy.
typedef struct rfb_server_init {
    uint16_t width;
    uint16_t height;
    rfb_pixel_format pixel_format;
    uint32_t name_length;   // bytes, excluding the null terminator
    char    *name;          // null-terminated; raw bytes (may contain ESC)
    rfb_allocator *allocator; // borrowed allocator used to release name
} rfb_server_init;

// Parse a ServerInit message from `in` (at least 24 + name_length bytes).
// `name_cap` bounds the name length (plan.md §6.4). On success, the default
// allocator owns `out->name`; on failure, `out` remains zeroed.
rfb_error rfb_parse_server_init(const uint8_t *in, size_t in_len,
                                rfb_server_init *out, size_t name_cap);

// Allocator-aware form for session-scoped accounting. The allocator is
// borrowed and must outlive the parsed value. NULL selects the default.
rfb_error rfb_parse_server_init_with_allocator(
    const uint8_t *in, size_t in_len, rfb_server_init *out, size_t name_cap,
    rfb_allocator *allocator);

// Release the parsed name storage. Safe on a zeroed struct.
void rfb_server_init_destroy(rfb_server_init *si);

// Emit a SetPixelFormat message (message-type 0, 3 pad bytes, 16-byte
// PIXEL_FORMAT) into the writer (plan.md §G3, RFC 6143 §7.5.1).
rfb_error rfb_format_set_pixel_format(rfb_writer *w, const rfb_pixel_format *pf);

// Emit a SetEncodings message with `count` big-endian i32 values
// (RFC 6143 §7.5.2). The list is emitted in caller order; this function does
// not insert Raw or reorder any encoding.
rfb_error rfb_format_set_encodings(rfb_writer *w,
                                   const int32_t *encodings, uint16_t count);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_SERVER_INIT_H
