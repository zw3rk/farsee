// SPDX-License-Identifier: Apache-2.0
//
// G2 — 12-byte banner parser tests (plan.md §G2, §11, RFC 6143 §7.1.1).
//
// Covers canonical 3.3/3.7/3.8 parsing and formatting, malformed or short
// input rejection, and default rejection of syntactically valid unknown
// versions, including vendor banners 3.889 and 3.890.

#include "rfb_test.h"
#include "farsee/handshake.h"

#include <string.h>

// ---- successful parses of the canonical versions ------------------------

RFB_TEST(handshake, banner__rfb_33__parses_to_version_33) {
    static const uint8_t b[] = "RFB 003.003\n";
    rfb_version v = RFB_VERSION_UNKNOWN;
    RFB_CHECK_EQ_INT(rfb_parse_banner(b, 12, &v), RFB_OK);
    RFB_CHECK_EQ_INT(v, RFB_VERSION_3_3);
}

RFB_TEST(handshake, banner__rfb_37__parses_to_version_37) {
    static const uint8_t b[] = "RFB 003.007\n";
    rfb_version v = RFB_VERSION_UNKNOWN;
    RFB_CHECK_EQ_INT(rfb_parse_banner(b, 12, &v), RFB_OK);
    RFB_CHECK_EQ_INT(v, RFB_VERSION_3_7);
}

RFB_TEST(handshake, banner__rfb_38__parses_to_version_38) {
    static const uint8_t b[] = "RFB 003.008\n";
    rfb_version v = RFB_VERSION_UNKNOWN;
    RFB_CHECK_EQ_INT(rfb_parse_banner(b, 12, &v), RFB_OK);
    RFB_CHECK_EQ_INT(v, RFB_VERSION_3_8);
}

// ---- format round-trip ---------------------------------------------------

RFB_TEST(handshake, banner__format_38__is_exact_12_bytes) {
    uint8_t out[12] = { 0 };
    RFB_CHECK_EQ_INT(rfb_format_banner(RFB_VERSION_3_8, out, sizeof out), RFB_OK);
    static const uint8_t expect[12] = {
        'R','F','B',' ','0','0','3','.','0','0','8','\n'
    };
    RFB_CHECK_MEM_EQ(out, expect, 12);
}

RFB_TEST(handshake, banner__format_33_and_37__differ_only_in_minor) {
    uint8_t a[12], b[12];
    rfb_format_banner(RFB_VERSION_3_3, a, sizeof a);
    rfb_format_banner(RFB_VERSION_3_7, b, sizeof b);
    static const uint8_t e33[12] = {
        'R','F','B',' ','0','0','3','.','0','0','3','\n'
    };
    static const uint8_t e37[12] = {
        'R','F','B',' ','0','0','3','.','0','0','7','\n'
    };
    RFB_CHECK_MEM_EQ(a, e33, 12);
    RFB_CHECK_MEM_EQ(b, e37, 12);
}

// ---- malformed banners --------------------------------------------------

RFB_TEST(handshake, banner__bad_magic_prefix__rejected) {
    static const uint8_t b[] = "RFX 003.008\n";  // RFX not RFB
    rfb_version v = RFB_VERSION_UNKNOWN;
    RFB_CHECK_EQ_INT(rfb_parse_banner(b, 12, &v), RFB_ERR_PROTOCOL);
}

RFB_TEST(handshake, banner__missing_trailing_newline__rejected) {
    static const uint8_t b[] = "RFB 003.008x";  // 'x' not '\n'
    rfb_version v = RFB_VERSION_UNKNOWN;
    RFB_CHECK_EQ_INT(rfb_parse_banner(b, 12, &v), RFB_ERR_PROTOCOL);
}

RFB_TEST(handshake, banner__wrong_space_position__rejected) {
    static const uint8_t b[] = "RFB003.008\n ";  // missing space at index 3
    rfb_version v = RFB_VERSION_UNKNOWN;
    RFB_CHECK_EQ_INT(rfb_parse_banner(b, 12, &v), RFB_ERR_PROTOCOL);
}

RFB_TEST(handshake, banner__wrong_dot_position__rejected) {
    static const uint8_t b[] = "RFB 0030008\n";  // no dot
    rfb_version v = RFB_VERSION_UNKNOWN;
    RFB_CHECK_EQ_INT(rfb_parse_banner(b, 12, &v), RFB_ERR_PROTOCOL);
}

RFB_TEST(handshake, banner__non_digit_in_version_field__rejected) {
    static const uint8_t b[] = "RFB 0a3.008\n";  // 'a' not a digit
    rfb_version v = RFB_VERSION_UNKNOWN;
    RFB_CHECK_EQ_INT(rfb_parse_banner(b, 12, &v), RFB_ERR_PROTOCOL);
}

RFB_TEST(handshake, banner__too_short_input__rejected) {
    static const uint8_t b[] = "RFB 003.008";  // 11 bytes, missing \n
    rfb_version v = RFB_VERSION_UNKNOWN;
    RFB_CHECK_EQ_INT(rfb_parse_banner(b, 11, &v), RFB_ERR_PROTOCOL);
}

RFB_TEST(handshake, banner__null_output_pointer__rejected) {
    static const uint8_t b[] = "RFB 003.008\n";
    RFB_CHECK_EQ_INT(rfb_parse_banner(b, 12, NULL), RFB_ERR_INTERNAL);
}

// ---- unknown vendor banners ---------------------------------------------
// This parser has no vendor-banner downgrade mapping. These cases exercise
// its default rejection of syntactically valid unknown versions.

RFB_TEST(handshake, banner__unknown_vendor_banner_3_889__rejected_by_default) {
    static const uint8_t b[] = "RFB 003.889\n";  // vendor version; unmapped
    rfb_version v = RFB_VERSION_UNKNOWN;
    RFB_CHECK_EQ_INT(rfb_parse_banner(b, 12, &v), RFB_ERR_UNSUPPORTED);
}

RFB_TEST(handshake, banner__unknown_vendor_banner_3_890__rejected_by_default) {
    static const uint8_t b[] = "RFB 003.890\n";
    rfb_version v = RFB_VERSION_UNKNOWN;
    RFB_CHECK_EQ_INT(rfb_parse_banner(b, 12, &v), RFB_ERR_UNSUPPORTED);
}

RFB_TEST(handshake, banner__fully_unknown_version_2_0__rejected) {
    static const uint8_t b[] = "RFB 002.000\n";
    rfb_version v = RFB_VERSION_UNKNOWN;
    RFB_CHECK_EQ_INT(rfb_parse_banner(b, 12, &v), RFB_ERR_UNSUPPORTED);
}
