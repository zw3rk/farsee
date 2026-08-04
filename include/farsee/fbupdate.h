// SPDX-License-Identifier: Apache-2.0
//
// farsee — FramebufferUpdate header parser (plan.md §G4, RFC 6143 §7.6.1).
//
// The FramebufferUpdate is message-type 0: u8 type, u8 pad, u16 num-rects,
// then num-rects × (RECT_HEADER + encoding-specific payload). This header
// parser only consumes the fixed prefix; rectangle bodies are decoded by
// the encoding-specific decoders.

#ifndef FARSEE_INCLUDE_FARSEE_FBUPDATE_H
#define FARSEE_INCLUDE_FARSEE_FBUPDATE_H

#include "farsee/bytes.h"
#include "farsee/encoding.h"
#include "farsee/error.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Parse the FramebufferUpdate header (4 bytes: type=0, pad, u16 num-rects)
// from a reader. On success advances the reader past the header and fills
// `*out_num_rects`. Returns RFB_ERR_PROTOCOL on wrong message type or
// short input.
rfb_error rfb_parse_fbupdate_header(rfb_reader *r, uint16_t *out_num_rects);

// Parse a single rectangle header (12 bytes: u16 x, u16 y, u16 w, u16 h,
// i32 encoding) from a reader. Advances the reader past it.
rfb_error rfb_parse_rect_header(rfb_reader *r, rfb_rect_header *out);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_FBUPDATE_H
