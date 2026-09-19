// SPDX-License-Identifier: Apache-2.0
//
// Unit tests: MultiVariant bit packer (MSB-first byte-order KATs).

#include "rfb_test.h"
#include "farsee/apple_mvs_bits.h"

#include <string.h>

RFB_TEST(apple_mvs_bits, roundtrip_small_fields)
{
    uint8_t buf[64];
    memset(buf, 0, sizeof buf);
    apple_mvs_bit_writer bw;
    apple_mvs_bit_writer_init(&bw, buf, sizeof buf);

    // Field widths seen on the wire: 6-bit, 3-bit, 1-bit, 8-bit.
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 5u, 6u));   // fidelity-1 style
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 4u, 3u));   // tile cmd style
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 1u, 1u));
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 0xA5u, 8u));
    RFB_CHECK(apple_mvs_bit_writer_finish(&bw));
    RFB_CHECK(bw.len > 0u);

    apple_mvs_bit_reader br;
    apple_mvs_bit_reader_init(&br, buf, bw.len);
    uint32_t v = 0;
    RFB_CHECK(apple_mvs_bit_reader_get(&br, 6u, &v));
    RFB_CHECK_EQ_UINT(v, 5u);
    RFB_CHECK(apple_mvs_bit_reader_get(&br, 3u, &v));
    RFB_CHECK_EQ_UINT(v, 4u);
    RFB_CHECK(apple_mvs_bit_reader_get(&br, 1u, &v));
    RFB_CHECK_EQ_UINT(v, 1u);
    RFB_CHECK(apple_mvs_bit_reader_get(&br, 8u, &v));
    RFB_CHECK_EQ_UINT(v, 0xA5u);
}

RFB_TEST(apple_mvs_bits, put_rejects_overflow_value)
{
    uint8_t buf[16];
    apple_mvs_bit_writer bw;
    apple_mvs_bit_writer_init(&bw, buf, sizeof buf);
    RFB_CHECK(!apple_mvs_bit_writer_put(&bw, 8u, 3u)); // 8 does not fit in 3 bits
}

// bits_consumed is the number of bits returned to callers from the stream start.
// It equals len*8 - bits_left; buffered bits remain available and are not
// counted until a read returns them.
RFB_TEST(apple_mvs_bits, bits_consumed_tracks_get)
{
    uint8_t buf[4] = {0xde, 0xad, 0xbe, 0xef};
    apple_mvs_bit_reader br;
    apple_mvs_bit_reader_init(&br, buf, sizeof buf);
    RFB_CHECK_EQ_UINT(apple_mvs_bit_reader_bits_consumed(&br), 0u);

    uint32_t v = 0;
    RFB_CHECK(apple_mvs_bit_reader_get(&br, 6u, &v));
    RFB_CHECK_EQ_UINT(apple_mvs_bit_reader_bits_consumed(&br), 6u);

    RFB_CHECK(apple_mvs_bit_reader_get(&br, 10u, &v));
    RFB_CHECK_EQ_UINT(apple_mvs_bit_reader_bits_consumed(&br), 16u);

    // Drain the rest.
    while (apple_mvs_bit_reader_get(&br, 4u, &v)) {
    }
    RFB_CHECK_EQ_UINT(apple_mvs_bit_reader_bits_consumed(&br), 32u);
    RFB_CHECK_EQ_UINT(apple_mvs_bit_reader_bits_left(&br), 0u);
}

RFB_TEST(apple_mvs_bits, black_type0_planes_readable)
{
    static const uint8_t command[] = {0x41, 0xff, 0x72, 0xfb, 0x68};
    static const uint8_t image[] = {0x00, 0x20, 0x81, 0xb4};
    apple_mvs_bit_reader br;
    apple_mvs_bit_reader_init(&br, command, sizeof command);
    uint32_t v = 0;
    RFB_CHECK(apple_mvs_bit_reader_get(&br, 1u, &v));
    RFB_CHECK_EQ_UINT(v, 0u);
    RFB_CHECK(apple_mvs_bit_reader_get(&br, 3u, &v));
    RFB_CHECK_EQ_UINT(v, 4u);

    apple_mvs_bit_reader_init(&br, image, sizeof image);
    RFB_CHECK(apple_mvs_bit_reader_get(&br, 22u, &v));
    RFB_CHECK_EQ_UINT(apple_mvs_bit_reader_bits_left(&br), 10u);
}
