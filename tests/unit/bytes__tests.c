// SPDX-License-Identifier: Apache-2.0
//
// Byte-reader and byte-writer success, truncation, and offset tests.
//
#include "rfb_test.h"
#include "farsee/bytes.h"
#include <string.h>

// ---- reader: basic reads ------------------------------------------------

RFB_TEST(bytes, reader__u8_success__advances_one_byte) {
    static const uint8_t buf[] = { 0xAB, 0xCD };
    rfb_reader r = rfb_reader_make(buf, sizeof buf);
    uint8_t v = 0;
    RFB_CHECK(rfb_read_u8(&r, &v));
    RFB_CHECK_EQ_UINT(v, 0xAB);
    RFB_CHECK_EQ_UINT(rfb_reader_remaining(&r), 1u);
}

RFB_TEST(bytes, reader__u16_big_endian__decodes_high_then_low) {
    static const uint8_t buf[] = { 0x12, 0x34 };
    rfb_reader r = rfb_reader_make(buf, sizeof buf);
    uint16_t v = 0;
    RFB_CHECK(rfb_read_u16(&r, &v));
    RFB_CHECK_EQ_UINT(v, 0x1234u);
}

RFB_TEST(bytes, reader__u32_big_endian__decodes_msb_first) {
    static const uint8_t buf[] = { 0x01, 0x02, 0x03, 0x04 };
    rfb_reader r = rfb_reader_make(buf, sizeof buf);
    uint32_t v = 0;
    RFB_CHECK(rfb_read_u32(&r, &v));
    RFB_CHECK_EQ_UINT(v, 0x01020304u);
}

RFB_TEST(bytes, reader__bytes__copies_exact_slice) {
    static const uint8_t buf[] = { 0xAA, 0xBB, 0xCC, 0xDD };
    rfb_reader r = rfb_reader_make(buf, sizeof buf);
    uint8_t dst[3] = { 0, 0, 0 };
    RFB_CHECK(rfb_read_bytes(&r, dst, 3));
    static const uint8_t expect[3] = { 0xAA, 0xBB, 0xCC };
    RFB_CHECK_MEM_EQ(dst, expect, 3);
    RFB_CHECK_EQ_UINT(rfb_reader_remaining(&r), 1u);
}

// ---- reader: one-byte-short failures, offset unchanged ------------------

RFB_TEST(bytes, reader__u8_empty__fails_offset_unchanged) {
    static const uint8_t buf[] = { 0 };
    rfb_reader r = rfb_reader_make(buf, 0);
    uint8_t v = 0xEE;
    RFB_CHECK(!rfb_read_u8(&r, &v));
    RFB_CHECK_EQ_UINT(v, 0xEE);  // untouched
    RFB_CHECK_EQ_UINT(r.offset, 0u);
}

RFB_TEST(bytes, reader__u16_one_byte_short__fails_offset_unchanged) {
    static const uint8_t buf[] = { 0x12 };  // need 2, have 1
    rfb_reader r = rfb_reader_make(buf, sizeof buf);
    uint16_t v = 0xEEEE;
    RFB_CHECK(!rfb_read_u16(&r, &v));
    RFB_CHECK_EQ_UINT(v, 0xEEEE);
    RFB_CHECK_EQ_UINT(r.offset, 0u);
    // The byte we couldn't consume must still be available for a u8 read.
    uint8_t b = 0;
    RFB_CHECK(rfb_read_u8(&r, &b));
    RFB_CHECK_EQ_UINT(b, 0x12);
}

RFB_TEST(bytes, reader__u32_three_bytes_short__fails_offset_unchanged) {
    static const uint8_t buf[] = { 0x01, 0x02, 0x03 };  // need 4, have 3
    rfb_reader r = rfb_reader_make(buf, sizeof buf);
    uint32_t v = 0xEEEEEEEEu;
    RFB_CHECK(!rfb_read_u32(&r, &v));
    RFB_CHECK_EQ_UINT(v, 0xEEEEEEEEu);
    RFB_CHECK_EQ_UINT(r.offset, 0u);
}

RFB_TEST(bytes, reader__bytes_one_byte_short__fails_offset_unchanged) {
    static const uint8_t buf[] = { 1, 2, 3, 4 };  // ask for 5
    rfb_reader r = rfb_reader_make(buf, sizeof buf);
    uint8_t dst[5] = { 0xEE, 0xEE, 0xEE, 0xEE, 0xEE };
    RFB_CHECK(!rfb_read_bytes(&r, dst, 5));
    RFB_CHECK_EQ_UINT(r.offset, 0u);
    // dst untouched (the contract is transactional: no partial fill)
    for (size_t i = 0; i < 5; i++) {
        RFB_CHECK_EQ_UINT(dst[i], 0xEEu);
    }
}

// ---- peek/skip/reset ----------------------------------------------------

RFB_TEST(bytes, reader__peek__does_not_advance) {
    static const uint8_t buf[] = { 0x11, 0x22, 0x33, 0x44 };
    rfb_reader r = rfb_reader_make(buf, sizeof buf);
    uint8_t b = 0;
    uint16_t s = 0;
    uint32_t l = 0;
    RFB_CHECK(rfb_peek_u8(&r, 0, &b));
    RFB_CHECK_EQ_UINT(b, 0x11);
    RFB_CHECK(rfb_peek_u16(&r, 1, &s));
    RFB_CHECK_EQ_UINT(s, 0x2233u);
    RFB_CHECK(rfb_peek_u32(&r, 0, &l));
    RFB_CHECK_EQ_UINT(l, 0x11223344u);
    RFB_CHECK_EQ_UINT(r.offset, 0u);
}

// peek with `at` past the end must fail, never underflow the length
// check (`r->length - at < N` wrapped for
// at > length and the guard passed, reading out of bounds).
RFB_TEST(bytes, reader__peek_at_past_end__fails) {
    static const uint8_t buf[] = { 0x11, 0x22, 0x33, 0x44 };
    rfb_reader r = rfb_reader_make(buf, sizeof buf);
    uint16_t s = 0xA5A5;
    uint32_t l = 0xA5A5A5A5u;
    RFB_CHECK(!rfb_peek_u16(&r, r.length + 1u, &s));
    RFB_CHECK_EQ_UINT(s, 0xA5A5u);
    RFB_CHECK(!rfb_peek_u32(&r, r.length + 1u, &l));
    RFB_CHECK_EQ_UINT(l, 0xA5A5A5A5u);
    // exactly at the end: 0 bytes remain, still a failure
    RFB_CHECK(!rfb_peek_u16(&r, r.length, &s));
    RFB_CHECK(!rfb_peek_u32(&r, r.length, &l));
}

RFB_TEST(bytes, reader__skip__advances_without_reading) {
    static const uint8_t buf[] = { 1, 2, 3, 4, 5 };
    rfb_reader r = rfb_reader_make(buf, sizeof buf);
    RFB_CHECK(rfb_reader_skip(&r, 2));
    uint8_t b = 0;
    RFB_CHECK(rfb_read_u8(&r, &b));
    RFB_CHECK_EQ_UINT(b, 3);
}

RFB_TEST(bytes, reader__skip_past_end__fails_offset_unchanged) {
    static const uint8_t buf[] = { 1, 2 };
    rfb_reader r = rfb_reader_make(buf, sizeof buf);
    RFB_CHECK(!rfb_reader_skip(&r, 3));
    RFB_CHECK_EQ_UINT(r.offset, 0u);
}

RFB_TEST(bytes, reader__reset__returns_to_start) {
    static const uint8_t buf[] = { 0xAB };
    rfb_reader r = rfb_reader_make(buf, sizeof buf);
    uint8_t b = 0;
    RFB_CHECK(rfb_read_u8(&r, &b));
    RFB_CHECK_EQ_UINT(rfb_reader_remaining(&r), 0u);
    rfb_reader_reset(&r);
    RFB_CHECK_EQ_UINT(rfb_reader_remaining(&r), 1u);
}

RFB_TEST(bytes, reader__remaining__tracks_offset) {
    static const uint8_t buf[] = { 1, 2, 3 };
    rfb_reader r = rfb_reader_make(buf, sizeof buf);
    RFB_CHECK_EQ_UINT(rfb_reader_remaining(&r), 3u);
    uint8_t b = 0;
    rfb_read_u8(&r, &b);
    RFB_CHECK_EQ_UINT(rfb_reader_remaining(&r), 2u);
}

// ---- writer -------------------------------------------------------------

RFB_TEST(bytes, writer__u8_u16_u32__appends_big_endian) {
    uint8_t buf[7] = { 0 };
    rfb_writer w = rfb_writer_make(buf, sizeof buf);
    RFB_CHECK(rfb_write_u8(&w, 0xAB));
    RFB_CHECK(rfb_write_u16(&w, 0x1234));
    RFB_CHECK(rfb_write_u32(&w, 0x01020304));
    static const uint8_t expect[7] = { 0xAB, 0x12, 0x34, 0x01, 0x02, 0x03, 0x04 };
    RFB_CHECK_MEM_EQ(buf, expect, 7);
    RFB_CHECK_EQ_UINT(w.length, 7u);
}

RFB_TEST(bytes, writer__overflow__fails_length_unchanged) {
    uint8_t buf[3] = { 0 };
    rfb_writer w = rfb_writer_make(buf, sizeof buf);
    RFB_CHECK(rfb_write_u16(&w, 0x1111));  // 2 bytes ok
    RFB_CHECK_EQ_UINT(w.length, 2u);
    RFB_CHECK(!rfb_write_u16(&w, 0x2222));  // need 2 more, room for 1
    RFB_CHECK_EQ_UINT(w.length, 2u);  // transactional: no partial field
    // First field still intact.
    RFB_CHECK_EQ_UINT(buf[0], 0x11);
    RFB_CHECK_EQ_UINT(buf[1], 0x11);
    RFB_CHECK_EQ_UINT(buf[2], 0x00);  // untouched
}

RFB_TEST(bytes, writer__bytes__appends_exact_slice) {
    uint8_t buf[4] = { 0 };
    rfb_writer w = rfb_writer_make(buf, sizeof buf);
    static const uint8_t src[3] = { 9, 8, 7 };
    RFB_CHECK(rfb_write_bytes(&w, src, 3));
    RFB_CHECK_EQ_UINT(w.length, 3u);
    RFB_CHECK_MEM_EQ(buf, src, 3);
    RFB_CHECK(!rfb_write_bytes(&w, src, 3));  // overflow
    RFB_CHECK_EQ_UINT(w.length, 3u);
}
