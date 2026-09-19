// SPDX-License-Identifier: Apache-2.0
//
// farsee — Apple MultiVariant (0x03f3) rect validation/product seam.

#ifndef FARSEE_INCLUDE_FARSEE_ENCODING_APPLE_MVS_H
#define FARSEE_INCLUDE_FARSEE_ENCODING_APPLE_MVS_H

#include "farsee/apple_mvs_stream.h"
#include "farsee/encoding.h"
#include "farsee/error.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Payload is body after u32be data_len (same length-prefix shape as ZRLE).
//
// - Supported solid-black known-answer payload: fill opaque black.
// - Type-0 partial update: strictly validate the bounded command plane
//   and image suffix, then consume with zero damage until the
//   independent image payload is decoded.
// - Malformed recognized type-0 bodies always fail closed. skip_unknown may
//   consume only an unrecognized/unsupported whole envelope without mutation.
// qt0/qt1 configure type-0 image decoding. coeff_store remains in the
// signature for API compatibility and is not used by this entry point.
rfb_error rfb_decode_apple_mvs(rfb_framebuffer *fb, const rfb_rect_header *rh,
                               const uint8_t *payload, size_t payload_len,
                               bool skip_unknown, const uint8_t *qt0,
                               const uint8_t *qt1,
                               apple_mvs_coeff_store *coeff_store,
                               rfb_rect *out_damage);

#ifdef __cplusplus
}
#endif

#endif
