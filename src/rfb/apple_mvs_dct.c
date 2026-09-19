// SPDX-License-Identifier: Apache-2.0
//
// MultiVariant DCT: Annex K JPEG AC Huffman + integer IDCT + YCbCr→RGBA.

#include "farsee/apple_mvs_dct.h"

#include <string.h>

const uint8_t apple_mvs_zigzag[64] = {
    0,  1,  8,  16, 9,  2,  3,  10, 17, 24, 32, 25, 18, 11, 4,  5,
    12, 19, 26, 33, 40, 48, 41, 34, 27, 20, 13, 6,  7,  14, 21, 28,
    35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51,
    58, 59, 52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63};

// Annex K chrominance AC BITS / VALS (ITU-T T.81 K.3.3.2). Both Annex K AC
// tables are public. Cb/Cr residuals use the chrominance table; the luminance
// table does not produce a valid chroma coefficient walk.
static const uint8_t k_bits_ac_c[16] = {0, 2, 1, 2, 4, 4, 3, 4,
                                        7, 5, 4, 4, 0, 1, 2, 0x77};
static const uint8_t k_vals_ac_c[162] = {
    0x00, 0x01, 0x02, 0x03, 0x11, 0x04, 0x05, 0x21, 0x31, 0x06, 0x12, 0x41,
    0x51, 0x07, 0x61, 0x71, 0x13, 0x22, 0x32, 0x81, 0x08, 0x14, 0x42, 0x91,
    0xa1, 0xb1, 0xc1, 0x09, 0x23, 0x33, 0x52, 0xf0, 0x15, 0x62, 0x72, 0xd1,
    0x0a, 0x16, 0x24, 0x34, 0xe1, 0x25, 0xf1, 0x17, 0x18, 0x19, 0x1a, 0x26,
    0x27, 0x28, 0x29, 0x2a, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x43, 0x44,
    0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
    0x59, 0x5a, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x73, 0x74,
    0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
    0x88, 0x89, 0x8a, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a,
    0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xb2, 0xb3, 0xb4,
    0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
    0xc8, 0xc9, 0xca, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda,
    0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xf2, 0xf3, 0xf4,
    0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa};

static bool huff_decode_sym(apple_mvs_bit_reader *br, uint8_t *out_sym)
{
    uint32_t acc = 0;
    uint32_t first_code = 0;
    size_t first_symbol = 0u;
    for (int l = 1; l <= 16; l++) {
        uint32_t bit = 0;
        if (!apple_mvs_bit_reader_get(br, 1u, &bit)) {
            return false;
        }
        acc = (acc << 1) | bit;
        const uint32_t count = k_bits_ac_c[l - 1];
        if (acc >= first_code && acc - first_code < count) {
            *out_sym = k_vals_ac_c[first_symbol +
                                    (size_t)(acc - first_code)];
            return true;
        }
        first_symbol += count;
        first_code = (first_code + count) << 1u;
    }
    return false;
}

static bool receive_extend(apple_mvs_bit_reader *br, int t, int *out)
{
    if (t == 0) {
        *out = 0;
        return true;
    }
    uint32_t v = 0;
    if (!apple_mvs_bit_reader_get(br, (unsigned)t, &v)) {
        return false;
    }
    const uint32_t threshold = 1u << (unsigned)(t - 1);
    int iv = (int)v;
    if (v < threshold) {
        iv -= (int)((threshold << 1u) - 1u);
    }
    *out = iv;
    return true;
}

bool apple_mvs_jpeg_ac_decode_reason(apple_mvs_bit_reader *br,
                                     int16_t coeffs[64], int k0, int max_k,
                                     apple_mvs_ac_end_reason *end_reason)
{
    if (br == NULL || coeffs == NULL || max_k > 63 || k0 < 0) {
        if (end_reason != NULL) {
            *end_reason = APPLE_MVS_AC_END_HUFF_FAIL;
        }
        return false;
    }
    int k = k0;
    while (k <= max_k) {
        uint8_t sym = 0;
        if (!huff_decode_sym(br, &sym)) {
            if (end_reason != NULL) {
                *end_reason = APPLE_MVS_AC_END_HUFF_FAIL;
            }
            return false;
        }
        int run = (int)(sym >> 4);
        int sz = (int)(sym & 0x0fu);
        if (sz != 0) {
            k += run;
            if (k > 63) {
                if (end_reason != NULL) {
                    *end_reason = APPLE_MVS_AC_END_HUFF_FAIL;
                }
                return false;
            }
            int val = 0;
            if (!receive_extend(br, sz, &val)) {
                if (end_reason != NULL) {
                    *end_reason = APPLE_MVS_AC_END_HUFF_FAIL;
                }
                return false;
            }
            coeffs[apple_mvs_zigzag[k]] = (int16_t)val;
            k++;
        } else {
            if (run == 15) {
                k += 16;
            } else {
                // EOB.
                if (end_reason != NULL) {
                    *end_reason = APPLE_MVS_AC_END_EOB;
                }
                return true;
            }
        }
    }
    // Loop exited because k > max_k: coefficient band filled, no EOB on wire.
    if (end_reason != NULL) {
        *end_reason = APPLE_MVS_AC_END_MAX;
    }
    return true;
}

bool apple_mvs_jpeg_ac_decode(apple_mvs_bit_reader *br, int16_t coeffs[64],
                              int k0, int max_k)
{
    return apple_mvs_jpeg_ac_decode_reason(br, coeffs, k0, max_k, NULL);
}

// AAN-style fixed-point inverse DCT.
//
// The intermediates are int64. The row-pass expression `181 * (x4 + x5)` can
// exceed a 32-bit accumulator for values within the public int16 input range.
// Using int64 keeps every accepted input defined.
#define W1 2841
#define W2 2676
#define W3 2408
#define W5 1609
#define W6 1108
#define W7 565

static int16_t idct_clamp_i16(int64_t v)
{
    if (v > INT16_MAX) {
        return INT16_MAX;
    }
    if (v < INT16_MIN) {
        return INT16_MIN;
    }
    return (int16_t)v;
}

static void idct_row(int64_t *blk)
{
    int64_t x0, x1, x2, x3, x4, x5, x6, x7, x8;
    if (!((x1 = blk[4] * 2048) | (x2 = blk[6]) | (x3 = blk[2]) |
          (x4 = blk[1]) | (x5 = blk[7]) | (x6 = blk[5]) | (x7 = blk[3]))) {
        int64_t v = blk[0] * 8;
        for (int i = 0; i < 8; i++) {
            blk[i] = v;
        }
        return;
    }
    x0 = blk[0] * 2048 + 128;
    x8 = W7 * (x4 + x5);
    x4 = x8 + (W1 - W7) * x4;
    x5 = x8 - (W1 + W7) * x5;
    x8 = W3 * (x6 + x7);
    x6 = x8 - (W3 - W5) * x6;
    x7 = x8 - (W3 + W5) * x7;
    x8 = x0 + x1;
    x0 -= x1;
    x1 = W6 * (x3 + x2);
    x2 = x1 - (W2 + W6) * x2;
    x3 = x1 + (W2 - W6) * x3;
    x1 = x4 + x6;
    x4 -= x6;
    x6 = x5 + x7;
    x5 -= x7;
    x7 = x8 + x3;
    x8 -= x3;
    x3 = x0 + x2;
    x0 -= x2;
    x2 = (181 * (x4 + x5) + 128) >> 8;
    x4 = (181 * (x4 - x5) + 128) >> 8;
    blk[0] = (x7 + x1) >> 8;
    blk[1] = (x3 + x2) >> 8;
    blk[2] = (x0 + x4) >> 8;
    blk[3] = (x8 + x6) >> 8;
    blk[4] = (x8 - x6) >> 8;
    blk[5] = (x0 - x4) >> 8;
    blk[6] = (x3 - x2) >> 8;
    blk[7] = (x7 - x1) >> 8;
}

static void idct_col(const int64_t *blk, int16_t *out, int stride)
{
    int64_t x0, x1, x2, x3, x4, x5, x6, x7, x8;
    if (!((x1 = (blk[8 * 4] * 256)) | (x2 = blk[8 * 6]) | (x3 = blk[8 * 2]) |
          (x4 = blk[8 * 1]) | (x5 = blk[8 * 7]) | (x6 = blk[8 * 5]) |
          (x7 = blk[8 * 3]))) {
        const int64_t v = (blk[0] + 32) >> 6;
        for (int i = 0; i < 8; i++) {
            out[i * stride] = idct_clamp_i16(v);
        }
        return;
    }
    x0 = blk[0] * 256 + 8192;
    x8 = W7 * (x4 + x5) + 4;
    x4 = (x8 + (W1 - W7) * x4) >> 3;
    x5 = (x8 - (W1 + W7) * x5) >> 3;
    x8 = W3 * (x6 + x7) + 4;
    x6 = (x8 - (W3 - W5) * x6) >> 3;
    x7 = (x8 - (W3 + W5) * x7) >> 3;
    x8 = x0 + x1;
    x0 -= x1;
    x1 = W6 * (x3 + x2) + 4;
    x2 = (x1 - (W2 + W6) * x2) >> 3;
    x3 = (x1 + (W2 - W6) * x3) >> 3;
    x1 = x4 + x6;
    x4 -= x6;
    x6 = x5 + x7;
    x5 -= x7;
    x7 = x8 + x3;
    x8 -= x3;
    x3 = x0 + x2;
    x0 -= x2;
    x2 = (181 * (x4 + x5) + 128) >> 8;
    x4 = (181 * (x4 - x5) + 128) >> 8;
    out[0 * stride] = idct_clamp_i16((x7 + x1) >> 14);
    out[1 * stride] = idct_clamp_i16((x3 + x2) >> 14);
    out[2 * stride] = idct_clamp_i16((x0 + x4) >> 14);
    out[3 * stride] = idct_clamp_i16((x8 + x6) >> 14);
    out[4 * stride] = idct_clamp_i16((x8 - x6) >> 14);
    out[5 * stride] = idct_clamp_i16((x0 - x4) >> 14);
    out[6 * stride] = idct_clamp_i16((x3 - x2) >> 14);
    out[7 * stride] = idct_clamp_i16((x7 - x1) >> 14);
}

void apple_mvs_idct_8x8(const int16_t in[64], int16_t out[64])
{
    int64_t block[64];
    for (int i = 0; i < 64; i++) {
        block[i] = in[i];
    }
    for (int i = 0; i < 8; i++) {
        idct_row(block + 8 * i);
    }
    for (int i = 0; i < 8; i++) {
        idct_col(block + i, out + i, 8);
    }
}

void apple_mvs_ycbcr_tile_to_rgba(const int16_t y[64], const int16_t cb[64],
                                  const int16_t cr[64], uint8_t *rgba,
                                  uint32_t stride_bytes, uint16_t tw,
                                  uint16_t th)
{
    for (uint16_t row = 0; row < th; row++) {
        uint8_t *dst = rgba + (size_t)row * stride_bytes;
        for (uint16_t col = 0; col < tw; col++) {
            int yi = (int)y[row * 8 + col] + 128;
            int cbi = (int)cb[row * 8 + col];
            int cri = (int)cr[row * 8 + col];
            int r = yi + ((cri * 91881) >> 16);
            int g = yi - ((cbi * 22554 + cri * 46802) >> 16);
            int b = yi + ((cbi * 116130) >> 16);
            dst[0] = apple_mvs_clamp_u8(r);
            dst[1] = apple_mvs_clamp_u8(g);
            dst[2] = apple_mvs_clamp_u8(b);
            dst[3] = 255u;
            dst += 4;
        }
    }
}
