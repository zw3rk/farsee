// SPDX-License-Identifier: Apache-2.0
//
// Copyright (c) Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
//
// farsee — Apple MultiVariant (0x03f3) type-0 IMAGE-plane decoder.
//
// The residual magnitude ladder is in `src/rfb/apple_mvs_mag.c`. The server
// supplies the quantisation tables through `apple_wire_decode_mvs_tables`.
// The zig-zag scan and integer IDCT are in `src/rfb/apple_mvs_dct.c`.
//
// The type-0 rectangle carries two independently bounded planes. The command
// plane (`apple_wire_walk_mvs_partial_commands`) assigns one class per 8x8
// tile; this module consumes the image plane, which holds one variable-length
// record per tile of a *paying* class and nothing at all for the zero-cost
// classes.
//
// Fail closed: nothing is painted until the whole image plane has been walked
// and shown to end exactly on its payload endpoint. A grammar
// miss, an unhandled tile class, an unknown quality tier, or a missing
// quantisation table leaves the framebuffer byte-identical.

#ifndef FARSEE_INCLUDE_FARSEE_APPLE_MVS_IMAGE_H
#define FARSEE_INCLUDE_FARSEE_APPLE_MVS_IMAGE_H

#include "farsee/apple_wire_decode.h"
#include "farsee/encoding.h"
#include "farsee/error.h"
#include "farsee/framebuffer.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Luma AC quantiser ladder for one quality tier.
// `normal_count - 1` is a quantiser-band boundary, not a scan limit: the scan
// always runs to zig-zag ordinal 63, with a coarser step past the boundary.
typedef struct apple_mvs_image_tier {
    uint32_t fine_max_ordinal;  // last zig-zag ordinal quantised with s_fine
    uint32_t s_fine;
    uint32_t s_coarse;
} apple_mvs_image_tier;

// Resolve the quantiser ladder for a transmitted quality pair. Only the two
// supported tiers — (15,25) and (3,5) — are known; every other pair returns
// false so the caller can fail closed rather than guess a step.
bool apple_mvs_image_tier_for(uint16_t normal_count, uint8_t large_count,
                              apple_mvs_image_tier *out);

// Decode the type-0 image plane of one rectangle and paint it.
//
// `hdr` must already have been decoded by apple_wire_decode_mvs_rect_hdr, its
// command plane validated for exactly this rectangle's tile grid, and its
// image suffix validated by apple_wire_validate_mvs_partial_image_suffix;
// `image` is that suffix result and supplies the payload bit endpoint.
// `qt0`/`qt1` are the 64-byte luma/chroma quantisation tables exactly as
// transmitted (raster order, index = vertical*8 + horizontal); both are
// required.
//
// The rectangle must already be known in-bounds for `fb`.
//
// Returns RFB_OK and sets *out_damage to the rectangle on success.
// Returns RFB_ERR_UNSUPPORTED when the body is well formed but this decoder
// cannot render it (unknown tier, unhandled tile class, no tables) and
// RFB_ERR_PROTOCOL when the image plane does not parse or does not close on
// its endpoint. In every non-OK case the framebuffer is untouched and
// *out_damage is empty.
rfb_error apple_mvs_image_paint_rect(rfb_framebuffer *fb,
                                     const rfb_rect_header *rh,
                                     const apple_wire_mvs_rect_hdr *hdr,
                                     const apple_wire_mvs_image_stats *image,
                                     const uint8_t *qt0, const uint8_t *qt1,
                                     rfb_rect *out_damage);

#ifdef __cplusplus
}
#endif

#endif
