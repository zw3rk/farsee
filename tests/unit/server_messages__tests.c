// SPDX-License-Identifier: Apache-2.0
//
// G6 — server message parser tests (plan.md §G6, RFC 6143 §7.6.3-4).

#include "rfb_test.h"
#include "farsee/server_messages.h"
#include "farsee/bytes.h"
#include "farsee/error.h"

#include <string.h>

// --- Bell: type byte already consumed, no payload ------------------------

RFB_TEST(server_msg, bell__no_payload__returns_ok) {
    static const uint8_t buf[1] = { 0 };
    rfb_reader r = rfb_reader_make(buf, 0);  // nothing left to read
    RFB_CHECK_EQ_INT(rfb_parse_bell(&r), RFB_OK);
}

RFB_TEST(server_msg, bell__null_reader__returns_internal) {
    RFB_CHECK_EQ_INT(rfb_parse_bell(NULL), RFB_ERR_INTERNAL);
}

// --- ServerCutText -------------------------------------------------------

RFB_TEST(server_msg, server_cut_text__short_text__exact_bytes) {
    // u8 pad[3], u32 length=3, then "abc"
    static const uint8_t buf[] = {
        0x00, 0x00, 0x00,             // pad
        0x00, 0x00, 0x00, 0x03,       // length = 3
        'a', 'b', 'c',
    };
    rfb_reader r = rfb_reader_make(buf, sizeof buf);
    uint8_t out[16] = { 0 };
    size_t out_len = 0;
    RFB_CHECK_EQ_INT(
        rfb_parse_server_cut_text(&r, out, sizeof out, &out_len, 1024),
        RFB_OK);
    RFB_CHECK_EQ_UINT(out_len, 3u);
    RFB_CHECK_EQ_UINT(out[0], 'a');
    RFB_CHECK_EQ_UINT(out[2], 'c');
}

RFB_TEST(server_msg, server_cut_text__empty_text__length_zero) {
    static const uint8_t buf[] = {
        0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,  // length = 0
    };
    rfb_reader r = rfb_reader_make(buf, sizeof buf);
    uint8_t out[4] = { 0 };
    size_t out_len = 99;
    RFB_CHECK_EQ_INT(
        rfb_parse_server_cut_text(&r, out, sizeof out, &out_len, 1024),
        RFB_OK);
    RFB_CHECK_EQ_UINT(out_len, 0u);
}

RFB_TEST(server_msg, server_cut_text__over_hard_limit__fails_limit) {
    static const uint8_t buf[] = {
        0x00, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x00,  // length = 65536 (over cap of 100)
    };
    rfb_reader r = rfb_reader_make(buf, sizeof buf);
    uint8_t out[200] = { 0 };
    size_t out_len = 0;
    RFB_CHECK_EQ_INT(
        rfb_parse_server_cut_text(&r, out, sizeof out, &out_len, 100),
        RFB_ERR_LIMIT);
}

RFB_TEST(server_msg, server_cut_text__truncated_length_field__fails) {
    static const uint8_t buf[] = {
        0x00, 0x00, 0x00,
        0x00, 0x00, 0x00,  // only 3 bytes of length (need 4)
    };
    rfb_reader r = rfb_reader_make(buf, sizeof buf);
    uint8_t out[16] = { 0 };
    size_t out_len = 0;
    RFB_CHECK_EQ_INT(
        rfb_parse_server_cut_text(&r, out, sizeof out, &out_len, 1024),
        RFB_ERR_PROTOCOL);
}

RFB_TEST(server_msg, server_cut_text__text_truncated__fails) {
    static const uint8_t buf[] = {
        0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x05,  // length = 5
        'a', 'b',  // only 2 of 5 text bytes
    };
    rfb_reader r = rfb_reader_make(buf, sizeof buf);
    uint8_t out[16] = { 0 };
    size_t out_len = 0;
    RFB_CHECK_EQ_INT(
        rfb_parse_server_cut_text(&r, out, sizeof out, &out_len, 1024),
        RFB_ERR_PROTOCOL);
}
