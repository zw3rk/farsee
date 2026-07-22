// SPDX-License-Identifier: Apache-2.0
//
// Coverage completion for fbupdate.c — drives the truncated-read
// failure branches to reach 95% line.

#include "rfb_test.h"
#include "farsee/fbupdate.h"
#include "farsee/bytes.h"

// Empty reader → rfb_read_u8(type) fails (line 16).
RFB_TEST(cov_fbu, fbupdate__empty_input__fails_protocol) {
    rfb_reader r = rfb_reader_make(NULL, 0);
    uint16_t n = 0;
    RFB_CHECK_EQ_INT(rfb_parse_fbupdate_header(&r, &n), RFB_ERR_PROTOCOL);
}

// Only type byte, no pad → rfb_read_u8(pad) fails (line 23).
RFB_TEST(cov_fbu, fbupdate__only_type_byte__fails_protocol) {
    static const uint8_t h[1] = { 0x00 };
    rfb_reader r = rfb_reader_make(h, 1);
    uint16_t n = 0;
    RFB_CHECK_EQ_INT(rfb_parse_fbupdate_header(&r, &n), RFB_ERR_PROTOCOL);
}

// Type + pad, no count → rfb_read_u16 fails.
RFB_TEST(cov_fbu, fbupdate__type_pad_no_count__fails_protocol) {
    static const uint8_t h[2] = { 0x00, 0x00 };
    rfb_reader r = rfb_reader_make(h, 2);
    uint16_t n = 0;
    RFB_CHECK_EQ_INT(rfb_parse_fbupdate_header(&r, &n), RFB_ERR_PROTOCOL);
}

// Rect header: truncated at each field (line 44 combined check).
RFB_TEST(cov_fbu, rect_header__truncated__fails_protocol) {
    // Only 2 bytes (x only, need 12).
    static const uint8_t h[2] = { 0x00, 0x01 };
    rfb_reader r = rfb_reader_make(h, sizeof h);
    rfb_rect_header rh;
    RFB_CHECK_EQ_INT(rfb_parse_rect_header(&r, &rh), RFB_ERR_PROTOCOL);
}

// Rect header: truncated mid-way (6 bytes: x,y,w but no h,enc).
RFB_TEST(cov_fbu, rect_header__partial_6_bytes__fails_protocol) {
    static const uint8_t h[6] = { 0,0, 0,0, 0,1 };
    rfb_reader r = rfb_reader_make(h, sizeof h);
    rfb_rect_header rh;
    RFB_CHECK_EQ_INT(rfb_parse_rect_header(&r, &rh), RFB_ERR_PROTOCOL);
}

// Rect header: 10 bytes (missing last 2 of encoding).
RFB_TEST(cov_fbu, rect_header__partial_10_bytes__fails_protocol) {
    static const uint8_t h[10] = { 0,0, 0,0, 0,1, 0,1, 0,0 };
    rfb_reader r = rfb_reader_make(h, sizeof h);
    rfb_rect_header rh;
    RFB_CHECK_EQ_INT(rfb_parse_rect_header(&r, &rh), RFB_ERR_PROTOCOL);
}
