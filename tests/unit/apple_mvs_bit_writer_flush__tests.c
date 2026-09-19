// SPDX-License-Identifier: Apache-2.0
//
// MVS bit-writer multi-flush contracts. Values that span two flushes retain
// all high bits and round-trip through the reader.

#include "rfb_test.h"
#include "farsee/apple_mvs_bits.h"

#include <string.h>

// The documented multi-flush sequence: 2 + 20 + 8 + 20 bits.
RFB_TEST(apple_mvs_bit_writer_flush, writer__sequence_2_20_8_20__roundtrips)
{
    const uint32_t v2 = 0x00000003u;   // 2 bits
    const uint32_t v20a = 0x000ABCDEu; // 20 bits
    const uint32_t v8 = 0x0000005Au;   // 8 bits
    const uint32_t v20b = 0x000FEDCBu; // 20 bits, top 2 bits set

    uint8_t out[16];
    apple_mvs_bit_writer bw;
    apple_mvs_bit_writer_init(&bw, out, sizeof out);
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, v2, 2u));
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, v20a, 20u));
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, v8, 8u));
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, v20b, 20u));
    RFB_CHECK(apple_mvs_bit_writer_finish(&bw));

    // 50 bits of payload pad to a 16-bit boundary: 64 bits = 8 bytes.
    RFB_CHECK_EQ_UINT(bw.len, 8u);

    apple_mvs_bit_reader br;
    apple_mvs_bit_reader_init(&br, out, bw.len);
    uint32_t g2 = 0, g20a = 0, g8 = 0, g20b = 0;
    RFB_CHECK(apple_mvs_bit_reader_get(&br, 2u, &g2));
    RFB_CHECK(apple_mvs_bit_reader_get(&br, 20u, &g20a));
    RFB_CHECK(apple_mvs_bit_reader_get(&br, 8u, &g8));
    RFB_CHECK(apple_mvs_bit_reader_get(&br, 20u, &g20b));
    RFB_CHECK_EQ_UINT(g2, v2);
    RFB_CHECK_EQ_UINT(g20a, v20a);
    RFB_CHECK_EQ_UINT(g8, v8);
    // The final value retains its high bits across the second flush.
    RFB_CHECK_EQ_UINT(g20b, v20b);
}

// Two 24-bit puts back to back: the second put needs a double flush with
// only 8 free bits available (free_bits - nbits == -16).
RFB_TEST(apple_mvs_bit_writer_flush, writer__two_24bit_puts__roundtrips)
{
    const uint32_t a = 0x00ABCDEFu;  // < 2^24
    const uint32_t b = 0x00123456u;

    uint8_t out[16];
    apple_mvs_bit_writer bw;
    apple_mvs_bit_writer_init(&bw, out, sizeof out);
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, a, 24u));
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, b, 24u));
    RFB_CHECK(apple_mvs_bit_writer_finish(&bw));

    RFB_CHECK_EQ_UINT(bw.len, 6u);  // 48 bits exactly

    apple_mvs_bit_reader br;
    apple_mvs_bit_reader_init(&br, out, bw.len);
    uint32_t ga = 0, gb = 0;
    RFB_CHECK(apple_mvs_bit_reader_get(&br, 24u, &ga));
    RFB_CHECK(apple_mvs_bit_reader_get(&br, 24u, &gb));
    RFB_CHECK_EQ_UINT(ga, a);
    RFB_CHECK_EQ_UINT(gb, b);
}

// Wrap the accumulator completely: 20 bits, then 16 (exactly fills), then
// 20 more — the last put starts with free_bits == 0 - 20.
RFB_TEST(apple_mvs_bit_writer_flush, writer__20_16_20_sequence__roundtrips)
{
    const uint32_t a = 0x000ABCDEu;
    const uint32_t b = 0x00001234u;
    const uint32_t c = 0x000EDCBAu;  // 20 bits, top bits set

    uint8_t out[16];
    apple_mvs_bit_writer bw;
    apple_mvs_bit_writer_init(&bw, out, sizeof out);
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, a, 20u));
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, b, 16u));
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, c, 20u));
    RFB_CHECK(apple_mvs_bit_writer_finish(&bw));

    RFB_CHECK_EQ_UINT(bw.len, 8u);  // 56 bits pad to 64

    apple_mvs_bit_reader br;
    apple_mvs_bit_reader_init(&br, out, bw.len);
    uint32_t ga = 0, gb = 0, gc = 0;
    RFB_CHECK(apple_mvs_bit_reader_get(&br, 20u, &ga));
    RFB_CHECK(apple_mvs_bit_reader_get(&br, 16u, &gb));
    RFB_CHECK(apple_mvs_bit_reader_get(&br, 20u, &gc));
    RFB_CHECK_EQ_UINT(ga, a);
    RFB_CHECK_EQ_UINT(gb, b);
    RFB_CHECK_EQ_UINT(gc, c);
}
