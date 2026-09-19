// SPDX-License-Identifier: Apache-2.0
//
// farsee — MultiVariant bit packer / unpacker.
// No I/O. Writer flushes the high 16 bits big-endian; the wire is MSB-first.

#ifndef FARSEE_INCLUDE_FARSEE_APPLE_MVS_BITS_H
#define FARSEE_INCLUDE_FARSEE_APPLE_MVS_BITS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Bit reader for bounded MVS Huffman or command planes.
typedef struct apple_mvs_bit_reader {
    const uint8_t *data;
    size_t len;
    size_t byte_i;   // next input byte
    uint32_t acc;    // leftover bits in high positions
    int free_bits;   // number of bits held in acc
} apple_mvs_bit_reader;

void apple_mvs_bit_reader_init(apple_mvs_bit_reader *br, const uint8_t *data,
                               size_t len);

// Read nbits (1..24). Returns false on EOF / invalid nbits.
bool apple_mvs_bit_reader_get(apple_mvs_bit_reader *br, unsigned nbits,
                              uint32_t *out_val);

// Bits still available.
size_t apple_mvs_bit_reader_bits_left(const apple_mvs_bit_reader *br);

// Absolute bits handed to callers from stream start = len*8 - bits_left.
// Bits buffered in the accumulator remain available and are not counted as
// consumed until a read returns them.
size_t apple_mvs_bit_reader_bits_consumed(const apple_mvs_bit_reader *br);

// Bit writer (for KATs / round-trip tests). Same packing as the reader.
typedef struct apple_mvs_bit_writer {
    uint8_t *out;
    size_t cap;
    size_t len;      // bytes written
    uint32_t acc;
    int free_bits;   // free slots at low end; starts at 32
} apple_mvs_bit_writer;

void apple_mvs_bit_writer_init(apple_mvs_bit_writer *bw, uint8_t *out,
                               size_t cap);

// Pack value in nbits (must fit). Returns false on overflow / bad nbits.
bool apple_mvs_bit_writer_put(apple_mvs_bit_writer *bw, uint32_t value,
                              unsigned nbits);

// Pad remaining bits with zeros and flush complete 16-bit words.
bool apple_mvs_bit_writer_finish(apple_mvs_bit_writer *bw);

#ifdef __cplusplus
}
#endif

#endif
