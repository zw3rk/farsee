// SPDX-License-Identifier: Apache-2.0
//
// MultiVariant bit packer.
//
// put(val, n) appends the n bits of val MSB-first below the pending bits
// held at the top of the 32-bit accumulator. The value is written in
// chunks bounded by the free space; each 16-bit flush group therefore
// contains only final bits, including values that span multiple flushes.
// The observable property is MSB-first packing across consecutive bytes; the
// accumulator width and the 16-bit flush granularity are internal. Byte output
// is pinned by the KAT vectors in tests/unit/apple_mvs_bits__tests.c.

#include "farsee/apple_mvs_bits.h"

#include <string.h>

void apple_mvs_bit_reader_init(apple_mvs_bit_reader *br, const uint8_t *data,
                               size_t len)
{
    if (br == NULL) {
        return;
    }
    memset(br, 0, sizeof *br);
    br->data = data;
    br->len = len;
    // free_bits = number of bits currently held in acc (low).
    // byte_i = next input byte.
    br->free_bits = 0;
    br->acc = 0u;
}

static bool pull_byte(apple_mvs_bit_reader *br)
{
    if (br->byte_i >= br->len) {
        return false;
    }
    br->acc = (br->acc << 8) | (uint32_t)br->data[br->byte_i++];
    br->free_bits += 8;
    return true;
}

bool apple_mvs_bit_reader_get(apple_mvs_bit_reader *br, unsigned nbits,
                              uint32_t *out_val)
{
    if (br == NULL || out_val == NULL || nbits == 0u || nbits > 24u) {
        return false;
    }
    while (br->free_bits < (int)nbits) {
        if (!pull_byte(br)) {
            return false;
        }
    }
    unsigned shift = (unsigned)br->free_bits - nbits;
    uint32_t mask = (nbits >= 32u) ? 0xffffffffu : ((1u << nbits) - 1u);
    uint32_t v = (br->acc >> shift) & mask;
    br->free_bits -= (int)nbits;
    if (br->free_bits > 0) {
        br->acc &= (1u << (unsigned)br->free_bits) - 1u;
    } else {
        br->acc = 0u;
    }
    *out_val = v;
    return true;
}

size_t apple_mvs_bit_reader_bits_left(const apple_mvs_bit_reader *br)
{
    if (br == NULL) {
        return 0u;
    }
    size_t in_acc = (br->free_bits > 0) ? (size_t)br->free_bits : 0u;
    size_t in_bytes =
        (br->byte_i < br->len) ? (br->len - br->byte_i) * 8u : 0u;
    return in_acc + in_bytes;
}

size_t apple_mvs_bit_reader_bits_consumed(const apple_mvs_bit_reader *br)
{
    if (br == NULL) {
        return 0u;
    }
    const size_t total = br->len * 8u;
    const size_t left = apple_mvs_bit_reader_bits_left(br);
    return (total > left) ? (total - left) : 0u;
}

void apple_mvs_bit_writer_init(apple_mvs_bit_writer *bw, uint8_t *out,
                               size_t cap)
{
    if (bw == NULL) {
        return;
    }
    memset(bw, 0, sizeof *bw);
    bw->out = out;
    bw->cap = cap;
    bw->free_bits = 32;
    bw->acc = 0u;
}

static bool flush_be16(apple_mvs_bit_writer *bw)
{
    if (bw->out == NULL || bw->len + 2u > bw->cap) {
        return false;
    }
    bw->out[bw->len++] = (uint8_t)(bw->acc >> 24);
    bw->out[bw->len++] = (uint8_t)((bw->acc >> 16) & 0xffu);
    bw->acc <<= 16;
    bw->free_bits += 16;
    return true;
}

bool apple_mvs_bit_writer_put(apple_mvs_bit_writer *bw, uint32_t value,
                              unsigned nbits)
{
    if (bw == NULL || nbits == 0u || nbits > 24u) {
        return false;
    }
    if (value >= (1u << nbits)) {
        return false;
    }
    // Append the value MSB-first in chunks that fit below the pending
    // bits. When the accumulator is exactly full (free_bits == 0) every
    // held bit is final, so flushing two groups emits 32 final bits and
    // empties the accumulator. A flush never emits unfinalized padding
    // mid-put, and a chunk never shifts bits past bit 31.
    while (nbits > 0u) {
        if (bw->free_bits == 0) {
            if (!flush_be16(bw) || !flush_be16(bw)) {
                return false;
            }
        }
        unsigned space = (unsigned)bw->free_bits;  // 1..32
        unsigned take = (nbits < space) ? nbits : space;
        unsigned down = nbits - take;
        bw->acc |= ((value >> down) << (space - take));
        bw->free_bits -= (int)take;
        if (down == 0u) {
            break;
        }
        value &= (1u << down) - 1u;
        nbits = down;
    }
    return true;
}

bool apple_mvs_bit_writer_finish(apple_mvs_bit_writer *bw)
{
    if (bw == NULL) {
        return false;
    }
    int used = 32 - bw->free_bits;
    if (used <= 0) {
        return true;
    }
    int pad = (16 - (used % 16)) % 16;
    if (pad > 0) {
        if (!apple_mvs_bit_writer_put(bw, 0u, (unsigned)pad)) {
            return false;
        }
    }
    while (bw->free_bits < 32) {
        if (!flush_be16(bw)) {
            return false;
        }
        if (bw->free_bits >= 32) {
            bw->free_bits = 32;
            bw->acc = 0u;
            break;
        }
    }
    return true;
}
