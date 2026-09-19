// SPDX-License-Identifier: Apache-2.0
//
// RSA1 envelope parser and serializer tests for type-33 authentication.

#include "rfb_test.h"
#include "farsee/rsa1_envelope.h"

#include <string.h>

// --- Round-trip: serialize then parse an envelope -----------------------

RFB_TEST(g18_rsa1, envelope__serialize_parse_roundtrip) {
    rsa1_public_key key;
    memset(&key, 0, sizeof key);
    // Fill with a test pattern.
    for (size_t i = 0; i < 256; i++) key.modulus[i] = (uint8_t)(i & 0xFF);
    key.modulus_len = 256;
    key.exponent[0] = 0x00; key.exponent[1] = 0x01;
    key.exponent[2] = 0x00; key.exponent[3] = 0x01;
    key.exponent_len = 4;

    uint8_t buf[536];
    size_t out_len = 0;
    RFB_CHECK_EQ_INT(
        rsa1_serialize_envelope(&key, buf, sizeof buf, &out_len), RFB_OK);
    RFB_CHECK_EQ_UINT(out_len, 4u + 256u + 4u + 4u);  // 268

    rsa1_public_key parsed;
    RFB_CHECK_EQ_INT(
        rsa1_parse_envelope(buf, out_len, &parsed), RFB_OK);
    RFB_CHECK_EQ_UINT(parsed.modulus_len, 256u);
    RFB_CHECK_EQ_UINT(parsed.exponent_len, 4u);
    RFB_CHECK_MEM_EQ(parsed.modulus, key.modulus, 256);
    RFB_CHECK_MEM_EQ(parsed.exponent, key.exponent, 4);
}

// --- Parse truncated envelope --------------------------------------------

RFB_TEST(g18_rsa1, envelope__truncated__fails_protocol) {
    static const uint8_t partial[] = { 0x00, 0x01 };  // too short
    rsa1_public_key key;
    RFB_CHECK_EQ_INT(
        rsa1_parse_envelope(partial, sizeof partial, &key), RFB_ERR_PROTOCOL);
}

// --- Parse with modulus too large ----------------------------------------

RFB_TEST(g18_rsa1, envelope__oversized_modulus__fails) {
    // mod_len = 0x00001001 = 4097 (> RSA1_MAX_KEY_BYTES=256)
    static const uint8_t bad[] = {
        0x00, 0x00, 0x10, 0x01,
        0x00, 0x00, 0x00, 0x04,
    };
    rsa1_public_key key;
    RFB_CHECK_EQ_INT(
        rsa1_parse_envelope(bad, sizeof bad, &key), RFB_ERR_PROTOCOL);
}

// --- NULL safety ----------------------------------------------------------

RFB_TEST(g18_rsa1, envelope__null_inputs__fail_internal) {
    RFB_CHECK_EQ_INT(rsa1_parse_envelope(NULL, 0, NULL), RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(rsa1_serialize_envelope(NULL, NULL, 0, NULL), RFB_ERR_INTERNAL);
}

// --- Descriptor parse: known values --------------------------------------

RFB_TEST(g18_rsa1, descriptor__parse_known_values) {
    // Supported 26-byte descriptor.
    static const uint8_t desc[26] = {
        0x00, 0x00, 0x00, 0x16,  // length = 22
        0x00, 0x01,              // version = 1
        0x00, 0x03,              // type = 3
        0x00, 0x10,              // key_type = 16
        0x00, 0x01,              // key_version = 1
        0x52, 0x53, 0x41, 0x31,  // "RSA1"
        0x00, 0x04,              // param1 = 4
        0x00, 0x00, 0x00, 0x01,  // param2 = 1
        0x00, 0x02,              // param3 = 2
        0x00, 0x03,              // param4 = 3
    };
    rsa1_descriptor d;
    RFB_CHECK_EQ_INT(rsa1_parse_descriptor(desc, sizeof desc, &d), RFB_OK);
    RFB_CHECK_EQ_UINT(d.version, 1u);
    RFB_CHECK_EQ_UINT(d.type, 3u);
    RFB_CHECK_EQ_UINT(d.key_type, 16u);
    RFB_CHECK(memcmp(d.magic, "RSA1", 4) == 0);
    RFB_CHECK_EQ_UINT(d.param2, 1u);
}

// --- Descriptor round-trip -----------------------------------------------

RFB_TEST(g18_rsa1, descriptor__serialize_parse_roundtrip) {
    rsa1_descriptor d;
    d.version = 1; d.type = 3; d.key_type = 0x10; d.key_version = 1;
    memcpy(d.magic, "RSA1", 4);
    d.param1 = 4; d.param2 = 1; d.param3 = 2; d.param4 = 3;

    uint8_t buf[26];
    size_t out_len = 0;
    RFB_CHECK_EQ_INT(
        rsa1_serialize_descriptor(&d, buf, sizeof buf, &out_len), RFB_OK);
    RFB_CHECK_EQ_UINT(out_len, 26u);

    rsa1_descriptor parsed;
    RFB_CHECK_EQ_INT(
        rsa1_parse_descriptor(buf, out_len, &parsed), RFB_OK);
    RFB_CHECK_EQ_UINT(parsed.version, d.version);
    RFB_CHECK_EQ_UINT(parsed.type, d.type);
}

// --- Descriptor bad magic ------------------------------------------------

RFB_TEST(g18_rsa1, descriptor__bad_magic__fails) {
    static const uint8_t bad[26] = {
        0x00, 0x00, 0x00, 0x16,
        0x00, 0x01, 0x00, 0x03, 0x00, 0x10, 0x00, 0x01,
        0x42, 0x41, 0x44, 0x31,  // "BAD1" not "RSA1"
        0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03,
    };
    rsa1_descriptor d;
    RFB_CHECK_EQ_INT(
        rsa1_parse_descriptor(bad, sizeof bad, &d), RFB_ERR_PROTOCOL);
}
