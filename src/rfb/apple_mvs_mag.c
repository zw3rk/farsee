// SPDX-License-Identifier: Apache-2.0
//
// MultiVariant residual magnitude codes.
// Entry layout: bits[31:28]=nbits, low bits = base code; sign added as +0/+1.

#include "farsee/apple_mvs_mag.h"

// Encoder code table indexed by magnitude 1..63. Slot 0 is unused: a zero
// residual has its own 2-bit code and never reaches this table.
static const uint32_t k_mag_entry[64] = {
    0u, // mag 0 unused (special 2-bit 0)
    0x30000002u, 0x40000008u, 0x4000000au, 0x60000030u, 0x60000032u,
    0x60000034u, 0x60000036u, 0x800000e0u, 0x800000e2u, 0x800000e4u,
    0x800000e6u, 0x800000e8u, 0x800000eau, 0x800000ecu, 0x800000eeu,
    0x900001e0u, 0x900001e2u, 0x900001e4u, 0x900001e6u, 0x900001e8u,
    0x900001eau, 0x900001ecu, 0x900001eeu, 0xa00003e0u, 0xa00003e2u,
    0xa00003e4u, 0xa00003e6u, 0xa00003e8u, 0xa00003eau, 0xa00003ecu,
    0xa00003eeu, 0xb00007e0u, 0xb00007e2u, 0xb00007e4u, 0xb00007e6u,
    0xb00007e8u, 0xb00007eau, 0xb00007ecu, 0xb00007eeu, 0xc0000fe0u,
    0xc0000fe2u, 0xc0000fe4u, 0xc0000fe6u, 0xc0000fe8u, 0xc0000feau,
    0xc0000fecu, 0xc0000feeu, 0xd0001fe0u, 0xd0001fe2u, 0xd0001fe4u,
    0xd0001fe6u, 0xd0001fe8u, 0xd0001feau, 0xd0001fecu, 0xd0001feeu,
    0xe0003fe0u, 0xe0003fe2u, 0xe0003fe4u, 0xe0003fe6u, 0xe0003fe8u,
    0xe0003feau, 0xe0003fecu, 0xe0003feeu,
};

bool apple_mvs_mag_put(apple_mvs_bit_writer *bw, int32_t residual)
{
    if (bw == NULL) {
        return false;
    }
    if (residual == 0) {
        return apple_mvs_bit_writer_put(bw, 0u, 2u);
    }
    uint32_t mag = (residual < 0) ? (uint32_t)(-residual) : (uint32_t)residual;
    if (mag == 0u || mag > 63u) {
        return false;
    }
    uint32_t e = k_mag_entry[mag];
    unsigned nbits = (unsigned)(e >> 28);
    uint32_t sign = (residual < 0) ? 1u : 0u;
    uint32_t val = (e + sign) & 0xffffu;
    // Only low nbits are significant.
    val &= (nbits >= 16u) ? 0xffffu : ((1u << nbits) - 1u);
    return apple_mvs_bit_writer_put(bw, val, nbits);
}

bool apple_mvs_mag_get(apple_mvs_bit_reader *br, int32_t *out_residual)
{
    if (br == NULL || out_residual == NULL) {
        return false;
    }
    // Decode the DC magnitude ladder directly instead of inverting the encoder
    // table above: that table covers magnitudes 0..63, while the ladder admits
    // unary prefixes through 38 one bits (magnitudes through 295). Decoding the
    // ladder keeps legal low-fidelity residuals above the table range from
    // masquerading as truncation. The 38-bit prefix cap is this decoder's
    // defensive bound; a longer prefix is rejected before any payload is read.
    apple_mvs_bit_reader tmp = *br;
    uint32_t one_count = 0u;
    for (;;) {
        uint32_t bit = 0u;
        if (!apple_mvs_bit_reader_get(&tmp, 1u, &bit)) {
            return false;
        }
        if (bit == 0u) {
            break;
        }
        one_count++;
        if (one_count > 38u) {
            return false;
        }
    }

    uint32_t magnitude = 0u;
    uint32_t sign = 0u;
    uint32_t payload = 0u;
    if (one_count == 0u) {
        uint32_t nonzero = 0u;
        if (!apple_mvs_bit_reader_get(&tmp, 1u, &nonzero)) {
            return false;
        }
        if (nonzero != 0u) {
            magnitude = 1u;
            if (!apple_mvs_bit_reader_get(&tmp, 1u, &sign)) {
                return false;
            }
        }
    } else if (one_count == 1u) {
        if (!apple_mvs_bit_reader_get(&tmp, 2u, &payload)) {
            return false;
        }
        magnitude = 2u | (payload >> 1u);
        sign = payload & 1u;
    } else if (one_count == 2u) {
        if (!apple_mvs_bit_reader_get(&tmp, 3u, &payload)) {
            return false;
        }
        magnitude = 4u | (payload >> 1u);
        sign = payload & 1u;
    } else {
        if (!apple_mvs_bit_reader_get(&tmp, 4u, &payload)) {
            return false;
        }
        magnitude = (one_count - 2u) * 8u + (payload >> 1u);
        sign = payload & 1u;
    }

    *br = tmp;
    *out_residual = (sign != 0u) ? -(int32_t)magnitude
                                 : (int32_t)magnitude;
    return true;
}
