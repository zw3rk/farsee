// SPDX-License-Identifier: Apache-2.0
//
// farsee — Apple encoding 0x0450 alpha-cursor decoder.

#ifndef FARSEE_INCLUDE_FARSEE_ENCODING_APPLE_0450_H
#define FARSEE_INCLUDE_FARSEE_ENCODING_APPLE_0450_H

#include "farsee/encoding.h"
#include "farsee/error.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define APPLE_0450_PROFILE_PARAMETER 1000u
#define APPLE_0450_EXPANDED_BYTES_PER_PIXEL 5u

// Decode a 0x0450 cursor sprite. The rectangle x/y fields are the cursor
// hotspot. The inflated body is width*height negotiated 32-bit premultiplied
// pixels followed by one width*height alpha plane. Payload includes its two
// u32be envelope fields. On success cursor owns an RGBA8 sprite allocated by
// alloc; release it through rfb_cursor_destroy with the same allocator.
rfb_error rfb_decode_apple_0450(rfb_cursor *cursor,
                                const rfb_pixel_format *pf,
                                const rfb_rect_header *rh,
                                const uint8_t *payload, size_t payload_len,
                                size_t byte_limit, rfb_allocator *alloc);

#ifdef __cplusplus
}
#endif

#endif
