// SPDX-License-Identifier: Apache-2.0
//
// Bounded outbound-queue tests.
//
// The queue must:
//   - append and expose bytes;
//   - reject appends that exceed the hard limit (unchanged on failure);
//   - preserve unconsumed bytes across a short write (consume < length);
//   - become empty when fully consumed;
//   - survive the limit-1/limit/limit+1 boundary.

#include "rfb_test.h"
#include "farsee/outbound.h"
#include "farsee/allocator.h"
#include "farsee/error.h"

#include <string.h>

RFB_TEST(outbound, outbound__append_and_read_back) {
    rfb_outbound q;
    rfb_outbound_init(&q, rfb_default_allocator(), 1024);
    static const uint8_t data[5] = { 1, 2, 3, 4, 5 };
    RFB_CHECK_EQ_INT(rfb_outbound_append(&q, data, sizeof data), RFB_OK);
    RFB_CHECK_EQ_UINT(rfb_outbound_length(&q), 5u);
    RFB_CHECK_MEM_EQ(rfb_outbound_data(&q), data, 5);
    rfb_outbound_destroy(&q);
}

RFB_TEST(outbound, outbound__short_write_preserves_rest) {
    // Simulate a short write: append 10 bytes, consume 3, the remaining
    // 7 must stay in order at the front.
    rfb_outbound q;
    rfb_outbound_init(&q, rfb_default_allocator(), 1024);
    static const uint8_t data[10] = { 10,20,30,40,50,60,70,80,90,100 };
    rfb_outbound_append(&q, data, sizeof data);
    rfb_outbound_consume(&q, 3);  // simulate a 3-byte short write
    RFB_CHECK_EQ_UINT(rfb_outbound_length(&q), 7u);
    RFB_CHECK_EQ_UINT(rfb_outbound_data(&q)[0], 40u);
    RFB_CHECK_EQ_UINT(rfb_outbound_data(&q)[6], 100u);
    rfb_outbound_destroy(&q);
}

RFB_TEST(outbound, outbound__consume_more_than_length_empties) {
    rfb_outbound q;
    rfb_outbound_init(&q, rfb_default_allocator(), 1024);
    static const uint8_t data[4] = { 1,2,3,4 };
    rfb_outbound_append(&q, data, sizeof data);
    rfb_outbound_consume(&q, 100);
    RFB_CHECK_EQ_UINT(rfb_outbound_length(&q), 0u);
    rfb_outbound_destroy(&q);
}

RFB_TEST(outbound, outbound__limit_minus_one_succeeds) {
    rfb_outbound q;
    rfb_outbound_init(&q, rfb_default_allocator(), 8);
    uint8_t data[7] = { 0 };
    RFB_CHECK_EQ_INT(rfb_outbound_append(&q, data, sizeof data), RFB_OK);
    rfb_outbound_destroy(&q);
}

RFB_TEST(outbound, outbound__exact_limit_succeeds) {
    rfb_outbound q;
    rfb_outbound_init(&q, rfb_default_allocator(), 8);
    uint8_t data[8] = { 0 };
    RFB_CHECK_EQ_INT(rfb_outbound_append(&q, data, sizeof data), RFB_OK);
    RFB_CHECK_EQ_UINT(rfb_outbound_length(&q), 8u);
    rfb_outbound_destroy(&q);
}

RFB_TEST(outbound, outbound__limit_plus_one_fails_unchanged) {
    rfb_outbound q;
    rfb_outbound_init(&q, rfb_default_allocator(), 8);
    static const uint8_t first[4] = { 9,9,9,9 };
    rfb_outbound_append(&q, first, sizeof first);
    uint8_t more[5] = { 0 };  // 4+5=9 > 8
    RFB_CHECK_EQ_INT(rfb_outbound_append(&q, more, sizeof more), RFB_ERR_LIMIT);
    RFB_CHECK_EQ_UINT(rfb_outbound_length(&q), 4u);  // unchanged
    RFB_CHECK_EQ_UINT(rfb_outbound_data(&q)[0], 9u);
    rfb_outbound_destroy(&q);
}

RFB_TEST(outbound, outbound__multiple_appends_preserve_order) {
    rfb_outbound q;
    rfb_outbound_init(&q, rfb_default_allocator(), 1024);
    rfb_outbound_append(&q, (const uint8_t[]){ 1 }, 1);
    rfb_outbound_append(&q, (const uint8_t[]){ 2,3 }, 2);
    rfb_outbound_append(&q, (const uint8_t[]){ 4,5,6 }, 3);
    RFB_CHECK_EQ_UINT(rfb_outbound_length(&q), 6u);
    static const uint8_t expect[6] = { 1,2,3,4,5,6 };
    RFB_CHECK_MEM_EQ(rfb_outbound_data(&q), expect, 6);
    rfb_outbound_destroy(&q);
}
