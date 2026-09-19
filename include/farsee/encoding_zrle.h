// SPDX-License-Identifier: Apache-2.0
//
// farsee — ZRLE decoder (plan.md §G8, RFC 6143 §7.7.6).
//
// ZRLE (Zlib-Run-Length-Encoding) compresses the framebuffer in 64×64
// tiles using zlib + a subencoding per tile. The zlib stream is persistent
// across all ZRLE rectangles in a connection (one stream per session).
//
// Subencodings (RFC 6143 §7.7.6, derived from the public spec):
//   0:                 raw tile (uncompressed pixels)
//   1:                 solid tile (single color for all pixels)
//   2..16:             packed-palette (N-entry palette, 1-4 bits/pixel)
//   128:               plain RLE
//   129..255:           palette RLE

#ifndef FARSEE_INCLUDE_FARSEE_ENCODING_ZRLE_H
#define FARSEE_INCLUDE_FARSEE_ENCODING_ZRLE_H

#include "farsee/encoding.h"
#include "farsee/error.h"
#include "farsee/framebuffer.h"
#include "farsee/pixel_format.h"
#include "farsee/zlib_adapter.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Decode a ZRLE rectangle. The payload is zlib-compressed; the decoder
// inflates it (using the persistent stream), then processes 64×64 tiles
// through the subencoding dispatch. Tiles are staged in a private
// rect-sized surface and committed in one pass, honouring the encoding.h
// G4 rect-level contract: on any failure the framebuffer is untouched and
// `*out_damage` is not written.
//
// `zstream` is the persistent zlib stream for this connection (RFC 6143
// §7.7.6). `payload` is the raw wire bytes (compressed). `byte_limit`
// bounds the decompressed output size (plan.md §6.4: 256 MiB per rect).
rfb_error rfb_decode_zrle(rfb_framebuffer *fb,
                          const rfb_pixel_format *pf,
                          const rfb_rect_header *rh,
                          rfb_zlib_stream *zstream,
                          const uint8_t *payload, size_t payload_len,
                          size_t byte_limit,
                          rfb_rect *out_damage);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_ENCODING_ZRLE_H
