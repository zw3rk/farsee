// SPDX-License-Identifier: Apache-2.0
//
// farsee — MultiVariant residual magnitude codes (the DC magnitude ladder).
// Carries signed residuals after a tile command prefix.

#ifndef FARSEE_INCLUDE_FARSEE_APPLE_MVS_MAG_H
#define FARSEE_INCLUDE_FARSEE_APPLE_MVS_MAG_H

#include "farsee/apple_mvs_bits.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Encode signed residual in [-63,63] except 0 uses 2-bit code 0.
// Positive mag m → code from table with sign=0; negative → sign=1.
// Returns false if out of range.
bool apple_mvs_mag_put(apple_mvs_bit_writer *bw, int32_t residual);

// Decode one residual over the full DC magnitude ladder (magnitudes 0..295).
// Zero is 2-bit 00; non-zero values carry a sign bit.
bool apple_mvs_mag_get(apple_mvs_bit_reader *br, int32_t *out_residual);

#ifdef __cplusplus
}
#endif

#endif
