// SPDX-License-Identifier: Apache-2.0
//
// Unit tests: MultiVariant residual magnitude codec.

#include "rfb_test.h"
#include "farsee/apple_mvs_mag.h"

#include <string.h>

RFB_TEST(apple_mvs_mag, roundtrip_zero_and_small)
{
    uint8_t buf[64];
    apple_mvs_bit_writer bw;
    apple_mvs_bit_writer_init(&bw, buf, sizeof buf);
    RFB_CHECK(apple_mvs_mag_put(&bw, 0));
    RFB_CHECK(apple_mvs_mag_put(&bw, 1));
    RFB_CHECK(apple_mvs_mag_put(&bw, -1));
    RFB_CHECK(apple_mvs_mag_put(&bw, 7));
    RFB_CHECK(apple_mvs_mag_put(&bw, -15));
    RFB_CHECK(apple_mvs_bit_writer_finish(&bw));

    apple_mvs_bit_reader br;
    apple_mvs_bit_reader_init(&br, buf, bw.len);
    int32_t r = 99;
    RFB_CHECK(apple_mvs_mag_get(&br, &r));
    RFB_CHECK_EQ_INT(r, 0);
    RFB_CHECK(apple_mvs_mag_get(&br, &r));
    RFB_CHECK_EQ_INT(r, 1);
    RFB_CHECK(apple_mvs_mag_get(&br, &r));
    RFB_CHECK_EQ_INT(r, -1);
    RFB_CHECK(apple_mvs_mag_get(&br, &r));
    RFB_CHECK_EQ_INT(r, 7);
    RFB_CHECK(apple_mvs_mag_get(&br, &r));
    RFB_CHECK_EQ_INT(r, -15);
}

RFB_TEST(apple_mvs_mag, roundtrip_all_mags)
{
    uint8_t buf[512];
    apple_mvs_bit_writer bw;
    apple_mvs_bit_writer_init(&bw, buf, sizeof buf);
    for (int32_t m = -63; m <= 63; m++) {
        RFB_CHECK(apple_mvs_mag_put(&bw, m));
    }
    RFB_CHECK(apple_mvs_bit_writer_finish(&bw));

    apple_mvs_bit_reader br;
    apple_mvs_bit_reader_init(&br, buf, bw.len);
    for (int32_t m = -63; m <= 63; m++) {
        int32_t r = 999;
        RFB_CHECK(apple_mvs_mag_get(&br, &r));
        RFB_CHECK_EQ_INT(r, m);
    }
}

RFB_TEST(apple_mvs_mag, rejects_out_of_range)
{
    uint8_t buf[16];
    apple_mvs_bit_writer bw;
    apple_mvs_bit_writer_init(&bw, buf, sizeof buf);
    RFB_CHECK(!apple_mvs_mag_put(&bw, 64));
    RFB_CHECK(!apple_mvs_mag_put(&bw, -64));
}

// The DC magnitude ladder admits unary prefixes through 38 one bits.
// The encoder table covers [-63, 63], but the decoder must
// accept the full ladder: prefix 11111111110, payload 0000 is +64.
RFB_TEST(apple_mvs_mag, decode_accepts_range_above_table)
{
    uint8_t buf[16];
    apple_mvs_bit_writer bw;
    apple_mvs_bit_writer_init(&bw, buf, sizeof buf);
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 0x7feu, 11u));
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 0u, 4u));
    RFB_CHECK(apple_mvs_bit_writer_finish(&bw));

    apple_mvs_bit_reader br;
    apple_mvs_bit_reader_init(&br, buf, bw.len);
    int32_t residual = 0;
    RFB_CHECK(apple_mvs_mag_get(&br, &residual));
    RFB_CHECK_EQ_INT(residual, 64);
    RFB_CHECK_EQ_UINT(apple_mvs_bit_reader_bits_consumed(&br), 15u);
}

// The longest accepted prefix is 38 one bits followed by zero. Its three
// magnitude bits select 288..295 and its final bit carries the sign.
RFB_TEST(apple_mvs_mag, decode_accepts_maximum_negative)
{
    uint8_t buf[16];
    apple_mvs_bit_writer bw;
    apple_mvs_bit_writer_init(&bw, buf, sizeof buf);
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 0xffffu, 16u));
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 0xffffu, 16u));
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 0x7eu, 7u)); // 1111110
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 0xfu, 4u));  // mag bits 111, sign 1
    RFB_CHECK(apple_mvs_bit_writer_finish(&bw));

    apple_mvs_bit_reader br;
    apple_mvs_bit_reader_init(&br, buf, bw.len);
    int32_t residual = 0;
    RFB_CHECK(apple_mvs_mag_get(&br, &residual));
    RFB_CHECK_EQ_INT(residual, -295);
    RFB_CHECK_EQ_UINT(apple_mvs_bit_reader_bits_consumed(&br), 43u);
}

// At most 38 leading one bits are accepted; a 39th one is rejected before any
// payload can be interpreted.
RFB_TEST(apple_mvs_mag, decode_rejects_overlong_prefix)
{
    const uint8_t buf[] = {0xffu, 0xffu, 0xffu, 0xffu, 0xfeu, 0x00u};
    apple_mvs_bit_reader br;
    apple_mvs_bit_reader_init(&br, buf, sizeof buf);
    int32_t residual = 0;
    RFB_CHECK(!apple_mvs_mag_get(&br, &residual));
}
