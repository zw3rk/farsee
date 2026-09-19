// SPDX-License-Identifier: Apache-2.0
//
// farsee — MultiVariant DCT helpers: JPEG AC Huffman, integer IDCT, YCbCr→RGB.
// Tables: ITU-T T.81 Annex K (public specification).

#ifndef FARSEE_INCLUDE_FARSEE_APPLE_MVS_DCT_H
#define FARSEE_INCLUDE_FARSEE_APPLE_MVS_DCT_H

#include "farsee/apple_mvs_bits.h"
#include "farsee/error.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Zig-zag index to natural-order coefficient index.
extern const uint8_t apple_mvs_zigzag[64];

// Why the AC decode loop ended.
typedef enum apple_mvs_ac_end_reason {
    APPLE_MVS_AC_END_EOB = 0,
    APPLE_MVS_AC_END_MAX,
    APPLE_MVS_AC_END_HUFF_FAIL,
    APPLE_MVS_AC_END_BUDGET,   // reserved for a caller-reported budget stop
    APPLE_MVS_AC_END_SKIPPED   // reserved for an AC-not-attempted state
} apple_mvs_ac_end_reason;

// Decode JPEG-style AC until EOB or k reaches max_k.
// Stores into coeffs[0..63] natural order at zig-zag positions starting at k0.
// On entry k0 is first AC index (usually 1). Returns false on bitstream error.
bool apple_mvs_jpeg_ac_decode(apple_mvs_bit_reader *br, int16_t coeffs[64],
                              int k0, int max_k);

// As above, plus an optional out-parameter for why the loop ended (EOB vs
// k>max_k vs Huffman failure). end_reason may be NULL. On a false return the
// reason is APPLE_MVS_AC_END_HUFF_FAIL. apple_mvs_jpeg_ac_decode is a thin
// wrapper that passes NULL.
bool apple_mvs_jpeg_ac_decode_reason(apple_mvs_bit_reader *br,
                                     int16_t coeffs[64], int k0, int max_k,
                                     apple_mvs_ac_end_reason *end_reason);

// Integer inverse DCT (AAN-style fixed-point, 8×8). in/out natural order.
void apple_mvs_idct_8x8(const int16_t in[64], int16_t out[64]);

// YCbCr (BT.601 full-range style) → opaque RGBA8 for one 8×8 tile.
// y/cb/cr are 8×8 spatial planes (after IDCT, level-shifted +128 for Y).
void apple_mvs_ycbcr_tile_to_rgba(const int16_t y[64], const int16_t cb[64],
                                  const int16_t cr[64], uint8_t *rgba,
                                  uint32_t stride_bytes, uint16_t tw,
                                  uint16_t th);

// Clamp helper.
static inline uint8_t apple_mvs_clamp_u8(int v)
{
    if (v < 0) {
        return 0;
    }
    if (v > 255) {
        return 255;
    }
    return (uint8_t)v;
}

#ifdef __cplusplus
}
#endif

#endif
