// SPDX-License-Identifier: Apache-2.0
//
// Apple type-33 SRP parser, mathematics, and wire-codec tests.

#include "rfb_test.h"
#include "farsee/apple_srp.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

// RFC 5054 Appendix A 4096-bit group prime (full 512 bytes).
static const uint8_t RFC5054_N_4096[512] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2,
    0x21, 0x68, 0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
    0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6,
    0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D,
    0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
    0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9,
    0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11,
    0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D,
    0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05, 0x98, 0xDA, 0x48, 0x36,
    0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
    0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56,
    0x20, 0x85, 0x52, 0xBB, 0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D,
    0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04, 0xF1, 0x74, 0x6C, 0x08,
    0xCA, 0x18, 0x21, 0x7C, 0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
    0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03, 0x9B, 0x27, 0x83, 0xA2,
    0xEC, 0x07, 0xA2, 0x8F, 0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9,
    0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18, 0x39, 0x95, 0x49, 0x7C,
    0xEA, 0x95, 0x6A, 0xE5, 0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
    0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAA, 0xC4, 0x2D, 0xAD, 0x33, 0x17, 0x0D,
    0x04, 0x50, 0x7A, 0x33, 0xA8, 0x55, 0x21, 0xAB, 0xDF, 0x1C, 0xBA, 0x64,
    0xEC, 0xFB, 0x85, 0x04, 0x58, 0xDB, 0xEF, 0x0A, 0x8A, 0xEA, 0x71, 0x57,
    0x5D, 0x06, 0x0C, 0x7D, 0xB3, 0x97, 0x0F, 0x85, 0xA6, 0xE1, 0xE4, 0xC7,
    0xAB, 0xF5, 0xAE, 0x8C, 0xDB, 0x09, 0x33, 0xD7, 0x1E, 0x8C, 0x94, 0xE0,
    0x4A, 0x25, 0x61, 0x9D, 0xCE, 0xE3, 0xD2, 0x26, 0x1A, 0xD2, 0xEE, 0x6B,
    0xF1, 0x2F, 0xFA, 0x06, 0xD9, 0x8A, 0x08, 0x64, 0xD8, 0x76, 0x02, 0x73,
    0x3E, 0xC8, 0x6A, 0x64, 0x52, 0x1F, 0x2B, 0x18, 0x17, 0x7B, 0x20, 0x0C,
    0xBB, 0xE1, 0x17, 0x57, 0x7A, 0x61, 0x5D, 0x6C, 0x77, 0x09, 0x88, 0xC0,
    0xBA, 0xD9, 0x46, 0xE2, 0x08, 0xE2, 0x4F, 0xA0, 0x74, 0xE5, 0xAB, 0x31,
    0x43, 0xDB, 0x5B, 0xFC, 0xE0, 0xFD, 0x10, 0x8E, 0x4B, 0x82, 0xD1, 0x20,
    0xA9, 0x21, 0x08, 0x01, 0x1A, 0x72, 0x3C, 0x12, 0xA7, 0x87, 0xE6, 0xD7,
    0x88, 0x71, 0x9A, 0x10, 0xBD, 0xBA, 0x5B, 0x26, 0x99, 0xC3, 0x27, 0x18,
    0x6A, 0xF4, 0xE2, 0x3C, 0x1A, 0x94, 0x68, 0x34, 0xB6, 0x15, 0x0B, 0xDA,
    0x25, 0x83, 0xE9, 0xCA, 0x2A, 0xD4, 0x4C, 0xE8, 0xDB, 0xBB, 0xC2, 0xDB,
    0x04, 0xDE, 0x8E, 0xF9, 0x2E, 0x8E, 0xFC, 0x14, 0x1F, 0xBE, 0xCA, 0xA6,
    0x28, 0x7C, 0x59, 0x47, 0x4E, 0x6B, 0xC0, 0x5D, 0x99, 0xB2, 0x96, 0x4F,
    0xA0, 0x90, 0xC3, 0xA2, 0x23, 0x3B, 0xA1, 0x86, 0x51, 0x5B, 0xE7, 0xED,
    0x1F, 0x61, 0x29, 0x70, 0xCE, 0xE2, 0xD7, 0xAF, 0xB8, 0x1B, 0xDD, 0x76,
    0x21, 0x70, 0x48, 0x1C, 0xD0, 0x06, 0x91, 0x27, 0xD5, 0xB0, 0x5A, 0xA9,
    0x93, 0xB4, 0xEA, 0x98, 0x8D, 0x8F, 0xDD, 0xC1, 0x86, 0xFF, 0xB7, 0xDC,
    0x90, 0xA6, 0xC0, 0x8F, 0x4D, 0xF4, 0x35, 0xC9, 0x34, 0x06, 0x31, 0x99,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

static void fill_rfc5054_n(uint8_t out[512])
{
    memcpy(out, RFC5054_N_4096, 512);
}


// Build a synthetic SRP challenge for testing.
// Uses a minimal but valid structure with the RFC 5054 N.
static size_t build_challenge(uint8_t *buf, size_t cap,
                               const uint8_t *N, size_t N_len,
                               uint8_t g_val,
                               const uint8_t *salt, size_t salt_len,
                               const uint8_t *B, size_t B_len,
                               uint32_t iterations,
                               const char *options)
{
    size_t opt_len = options ? strlen(options) : 0;
    size_t g_enc_len = 1;

    // Calculate inner size
    size_t inner =
        1 +             // control
        2 + N_len +     // %m N
        2 + g_enc_len + // %m g
        1 + salt_len +  // %o salt
        2 + B_len +     // %m B
        4 +             // padding u32
        4 +             // iterations u32
        2 + opt_len;    // %s options

    size_t body = 4 + inner;  // preamble(2) + inner_len(2) + inner
    size_t total = 6 + body;  // version(2) + authtype(2) + body_len(2) + body
    size_t full = 4 + total;  // total_len(4) + total

    if (full > cap) return 0;

    size_t pos = 0;
    // u32_be total_len
    buf[pos++] = (uint8_t)(total >> 24);
    buf[pos++] = (uint8_t)(total >> 16);
    buf[pos++] = (uint8_t)(total >> 8);
    buf[pos++] = (uint8_t)(total);
    // u16_be version = 0
    buf[pos++] = 0; buf[pos++] = 0;
    // u16_be authtype = 2
    buf[pos++] = 0; buf[pos++] = 2;
    // u16_be body_len
    buf[pos++] = (uint8_t)(body >> 8);
    buf[pos++] = (uint8_t)(body);
    // u16_be preamble = 0
    buf[pos++] = 0; buf[pos++] = 0;
    // u16_be inner_len
    buf[pos++] = (uint8_t)(inner >> 8);
    buf[pos++] = (uint8_t)(inner);
    // control
    buf[pos++] = 0;
    // %m N
    buf[pos++] = (uint8_t)(N_len >> 8);
    buf[pos++] = (uint8_t)(N_len);
    memcpy(buf + pos, N, N_len);
    pos += N_len;
    // %m g
    buf[pos++] = 0; buf[pos++] = (uint8_t)g_enc_len;
    buf[pos++] = g_val;
    // %o salt
    buf[pos++] = (uint8_t)salt_len;
    memcpy(buf + pos, salt, salt_len);
    pos += salt_len;
    // %m B
    buf[pos++] = (uint8_t)(B_len >> 8);
    buf[pos++] = (uint8_t)(B_len);
    memcpy(buf + pos, B, B_len);
    pos += B_len;
    // padding u32_be
    buf[pos++] = 0; buf[pos++] = 0; buf[pos++] = 0; buf[pos++] = 0;
    // iterations u32_be
    buf[pos++] = (uint8_t)(iterations >> 24);
    buf[pos++] = (uint8_t)(iterations >> 16);
    buf[pos++] = (uint8_t)(iterations >> 8);
    buf[pos++] = (uint8_t)(iterations);
    // %s options
    buf[pos++] = (uint8_t)(opt_len >> 8);
    buf[pos++] = (uint8_t)(opt_len);
    if (opt_len > 0) {
        memcpy(buf + pos, options, opt_len);
        pos += opt_len;
    }
    return pos;
}

// Convert the synthetic type-33 envelope to the type-36 challenge envelope
// while retaining the same SRP payload.
static size_t build_type36_challenge(uint8_t *out, size_t out_cap,
                                     const uint8_t *type33, size_t type33_len)
{
    if (out == NULL || type33 == NULL || type33_len < 14u ||
        out_cap < type33_len - 6u) {
        return 0u;
    }
    const size_t len = type33_len - 6u;
    const uint32_t total = (uint32_t)(len - 4u);
    const uint16_t body = (uint16_t)(total - 4u);
    out[0] = (uint8_t)(total >> 24);
    out[1] = (uint8_t)(total >> 16);
    out[2] = (uint8_t)(total >> 8);
    out[3] = (uint8_t)total;
    out[4] = type33[4];
    out[5] = type33[5];
    out[6] = (uint8_t)(body >> 8);
    out[7] = (uint8_t)body;
    memcpy(out + 8u, type33 + 14u, type33_len - 14u);
    return len;
}

// --- Happy path: parse a valid challenge ---

RFB_TEST(g26_srp, challenge__parses_valid_structure) {
    uint8_t N[512];
    fill_rfc5054_n(N);

    static const uint8_t salt[16] = { 0xAA };
    uint8_t B[512];
    memset(B, 0xBB, sizeof B);
    // This parser requires its canonical server value 0 < B < N.
    B[0] = 0x01;

    uint8_t buf[2048];
    size_t len = build_challenge(buf, sizeof buf, N, 512, 5,
                                  salt, 16, B, 512, 19417,
                                  "mda=SHA-512,replay_detection,conf+int=ChaCha20-Poly1305,kdf=SALTED-SHA512-PBKDF2");
    RFB_CHECK(len > 0);

    apple_srp_challenge ch;
    RFB_CHECK_EQ_INT(apple_srp_parse_challenge(buf, len, &ch), RFB_OK);
    RFB_CHECK_EQ_UINT(ch.version, 0u);
    RFB_CHECK_EQ_UINT(ch.authtype, 2u);
    RFB_CHECK_EQ_UINT(ch.N_len, 512u);
    RFB_CHECK_EQ_UINT(ch.g_len, 1u);
    RFB_CHECK_EQ_UINT(ch.salt_len, 16u);
    RFB_CHECK_EQ_UINT(ch.B_len, 512u);
    RFB_CHECK_EQ_UINT(ch.iterations, 19417u);
    RFB_CHECK_EQ_UINT(ch.options_len, 80u);
    // Verify N pointer borrows into the input buffer and is full prime.
    RFB_CHECK(ch.N != NULL);
    RFB_CHECK(memcmp(ch.N, RFC5054_N_4096, 512) == 0);
    // Verify g == 5
    RFB_CHECK_EQ_UINT(ch.g[0], 5u);
}

RFB_TEST(g26_srp, type36_challenge__parses_profile_envelope)
{
    uint8_t N[512];
    fill_rfc5054_n(N);
    static const uint8_t salt[32] = {0x55u};
    uint8_t B[512];
    memset(B, 0xbbu, sizeof B);
    B[0] = 0x01u;

    uint8_t type33[2048];
    const size_t type33_len = build_challenge(
        type33, sizeof type33, N, sizeof N, 5u, salt, sizeof salt, B,
        sizeof B, 131578u,
        "mda=SHA-512,replay_detection,conf+int=ChaCha20-Poly1305,"
        "kdf=SALTED-SHA512-PBKDF2");
    uint8_t type36[2048];
    const size_t type36_len = build_type36_challenge(
        type36, sizeof type36, type33, type33_len);
    RFB_CHECK_EQ_UINT(type36_len, type33_len - 6u);

    apple_srp_challenge ch;
    RFB_CHECK_EQ_INT(
        apple_srp_parse_type36_challenge(type36, type36_len, &ch), RFB_OK);
    RFB_CHECK_EQ_UINT(ch.version, 0u);
    RFB_CHECK_EQ_UINT(ch.N_len, APPLE_SRP_N_BYTES);
    RFB_CHECK_EQ_UINT(ch.salt_len, sizeof salt);
    RFB_CHECK_EQ_UINT(ch.B_len, APPLE_SRP_N_BYTES);
    RFB_CHECK_EQ_UINT(ch.iterations, 131578u);
    RFB_CHECK_EQ_UINT(ch.options_len, 80u);
}

RFB_TEST(g26_srp, type36_challenge__bad_body_length__fails_protocol)
{
    uint8_t N[512];
    fill_rfc5054_n(N);
    static const uint8_t salt[16] = {0xaau};
    uint8_t B[512];
    memset(B, 0xbbu, sizeof B);
    B[0] = 0x01u;
    uint8_t type33[2048];
    const size_t type33_len = build_challenge(
        type33, sizeof type33, N, sizeof N, 5u, salt, sizeof salt, B,
        sizeof B, APPLE_SRP_ITER_MIN, "");
    uint8_t type36[2048];
    const size_t type36_len = build_type36_challenge(
        type36, sizeof type36, type33, type33_len);
    if (type36_len <= 7u) {
        RFB_FAIL("type-36 challenge fixture construction failed");
        return;
    }
    type36[7] ^= 0x01u;

    apple_srp_challenge ch;
    RFB_CHECK_EQ_INT(
        apple_srp_parse_type36_challenge(type36, type36_len, &ch),
        RFB_ERR_PROTOCOL);
}

// --- Truncated challenge ---

RFB_TEST(g26_srp, challenge__truncated__fails_protocol) {
    uint8_t N[512];
    fill_rfc5054_n(N);
    static const uint8_t salt[16] = { 0xAA };
    uint8_t B[512];
    memset(B, 0x01, sizeof B);

    uint8_t buf[2048];
    size_t len = build_challenge(buf, sizeof buf, N, 512, 5, salt, 16, B, 512, 1000, "");

    // Truncate to various lengths
    for (size_t trunc = 0; trunc < len; trunc += 37) {
        apple_srp_challenge ch;
        RFB_CHECK(apple_srp_parse_challenge(buf, trunc, &ch) != RFB_OK);
    }
}

// --- Wrong authtype ---

RFB_TEST(g26_srp, challenge__wrong_authtype__fails) {
    uint8_t N[512];
    fill_rfc5054_n(N);
    static const uint8_t salt[16] = { 0xAA };
    uint8_t B[512];
    memset(B, 0x01, sizeof B);

    uint8_t buf[2048];
    size_t len = build_challenge(buf, sizeof buf, N, 512, 5, salt, 16, B, 512, 1000, "");
    // Corrupt authtype (offset 6-7): change from 2 to 3
    buf[7] = 3;

    apple_srp_challenge ch;
    RFB_CHECK_EQ_INT(apple_srp_parse_challenge(buf, len, &ch), RFB_ERR_PROTOCOL);
}

// --- N too small (not 4096-bit) ---

RFB_TEST(g26_srp, challenge__N_wrong_size__fails) {
    uint8_t N[256]; // 2048-bit, too small
    memset(N, 0xFF, sizeof N);

    static const uint8_t salt[16] = { 0xAA };
    uint8_t B[256];
    memset(B, 0x01, sizeof B);

    uint8_t buf[2048];
    size_t len = build_challenge(buf, sizeof buf, N, 256, 5, salt, 16, B, 256, 1000, "");

    apple_srp_challenge ch;
    RFB_CHECK_EQ_INT(apple_srp_parse_challenge(buf, len, &ch), RFB_ERR_PROTOCOL);
}

// --- g != 5 ---

RFB_TEST(g26_srp, challenge__g_wrong_value__fails) {
    uint8_t N[512];
    fill_rfc5054_n(N);
    static const uint8_t salt[16] = { 0xAA };
    uint8_t B[512];
    memset(B, 0x01, sizeof B);

    uint8_t buf[2048];
    size_t len = build_challenge(buf, sizeof buf, N, 512, 3, salt, 16, B, 512, 1000, "");

    apple_srp_challenge ch;
    RFB_CHECK_EQ_INT(apple_srp_parse_challenge(buf, len, &ch), RFB_ERR_PROTOCOL);
}

// --- Iterations too high (DoS protection) ---

RFB_TEST(g26_srp, challenge__iterations_too_high__fails_limit) {
    uint8_t N[512];
    fill_rfc5054_n(N);
    static const uint8_t salt[16] = { 0xAA };
    uint8_t B[512];
    memset(B, 0x01, sizeof B);

    uint8_t buf[2048];
    size_t len = build_challenge(buf, sizeof buf, N, 512, 5, salt, 16, B, 512,
                                  APPLE_SRP_ITER_MAX + 1, "");

    apple_srp_challenge ch;
    RFB_CHECK_EQ_INT(apple_srp_parse_challenge(buf, len, &ch), RFB_ERR_LIMIT);
}

// --- NULL safety ---

RFB_TEST(g26_srp, challenge__null_inputs__fail_internal) {
    apple_srp_challenge ch;
    RFB_CHECK_EQ_INT(apple_srp_parse_challenge(NULL, 0, &ch), RFB_ERR_INTERNAL);
    uint8_t buf[10];
    RFB_CHECK_EQ_INT(apple_srp_parse_challenge(buf, sizeof buf, NULL), RFB_ERR_INTERNAL);
}

// --- Unexpected trailing bytes ---

RFB_TEST(g26_srp, challenge__trailing_bytes__fails) {
    uint8_t N[512];
    fill_rfc5054_n(N);
    static const uint8_t salt[16] = { 0xAA };
    uint8_t B[512];
    memset(B, 0x01, sizeof B);

    uint8_t buf[2048];
    size_t len = build_challenge(buf, sizeof buf, N, 512, 5, salt, 16, B, 512, 1000, "");
    // Append a junk byte
    buf[len] = 0xFF;

    apple_srp_challenge ch;
    RFB_CHECK_EQ_INT(apple_srp_parse_challenge(buf, len + 1, &ch), RFB_ERR_PROTOCOL);
}

// --- A mismatch past the first 10 bytes is rejected ----------------------

RFB_TEST(g26_srp, challenge__N_flipped_past_prefix__fails) {
    uint8_t N[512];
    fill_rfc5054_n(N);
    // Keep the first 10 bytes correct and corrupt a later byte.
    N[64] ^= 0x01u;

    static const uint8_t salt[16] = { 0xAA };
    uint8_t B[512];
    memset(B, 0x01, sizeof B);

    uint8_t buf[2048];
    size_t len = build_challenge(buf, sizeof buf, N, 512, 5, salt, 16, B, 512, 1000, "");
    apple_srp_challenge ch;
    RFB_CHECK_EQ_INT(apple_srp_parse_challenge(buf, len, &ch), RFB_ERR_PROTOCOL);
}

// --- Reject all-zero B --------------------------------------------------

RFB_TEST(g26_srp, challenge__B_all_zero__fails) {
    uint8_t N[512];
    fill_rfc5054_n(N);
    static const uint8_t salt[16] = { 0xAA };
    uint8_t B[512];
    memset(B, 0x00, sizeof B);

    uint8_t buf[2048];
    size_t len = build_challenge(buf, sizeof buf, N, 512, 5, salt, 16, B, 512, 1000, "");
    apple_srp_challenge ch;
    RFB_CHECK_EQ_INT(apple_srp_parse_challenge(buf, len, &ch), RFB_ERR_PROTOCOL);
}

// --- Reject B == N (B mod N == 0) --------------------------------------

RFB_TEST(g26_srp, challenge__B_equals_N__fails) {
    uint8_t N[512];
    fill_rfc5054_n(N);
    static const uint8_t salt[16] = { 0xAA };
    uint8_t B[512];
    memcpy(B, N, sizeof B);  // B == N → B mod N == 0

    uint8_t buf[2048];
    size_t len = build_challenge(buf, sizeof buf, N, 512, 5, salt, 16, B, 512, 1000, "");
    apple_srp_challenge ch;
    RFB_CHECK_EQ_INT(apple_srp_parse_challenge(buf, len, &ch), RFB_ERR_PROTOCOL);
}

// --- Reject B > N (big-endian) -----------------------------------------

RFB_TEST(g26_srp, challenge__B_greater_than_N__fails) {
    uint8_t N[512];
    fill_rfc5054_n(N);
    static const uint8_t salt[16] = { 0xAA };
    uint8_t B[512];
    fill_rfc5054_n(B);
    B[0] = 0xFF;  // same high bytes as N which start FF.. but force > N:
    // N starts with FFFFFFFF FFFFFFFFC9... so setting B to all 0xFF is > N.
    memset(B, 0xFF, sizeof B);

    uint8_t buf[2048];
    size_t len = build_challenge(buf, sizeof buf, N, 512, 5, salt, 16, B, 512, 1000, "");
    apple_srp_challenge ch;
    RFB_CHECK_EQ_INT(apple_srp_parse_challenge(buf, len, &ch), RFB_ERR_PROTOCOL);
}

// ===== SRP Mathematics Tests ============================================

#include "farsee/apple_crypto.h"
#include "farsee/secret.h"

// Build a valid challenge and compute the full SRP chain.
// Uses deterministic values for reproducibility.
static void setup_srp_pair(apple_srp_challenge *ch,
                           apple_srp_session *client_sess,
                           uint8_t B_out[512],
                           const uint8_t *a_secret, size_t a_len,
                           const uint8_t *b_secret, size_t b_len)
{
    static const uint8_t g_val[1] = { 5u };
    static const uint8_t salt[16] = { 0xAA, 0xBB, 0xCC, 0xDD };
    static const uint8_t username[] = "admin";
    static const uint8_t password[] = "admin";

    // g^b mod N
    uint8_t gb[512] = { 0 };
    RFB_CHECK(rfb_crypto_modexp(g_val, sizeof g_val, b_secret, b_len,
                                RFC5054_N_4096, sizeof RFC5054_N_4096,
                                gb, sizeof gb));
    // modexp zero-pads to out_len, so gb is already 512 bytes.

    // This helper uses g^b as its deterministic B value. The RFC 5054 vector
    // tests cover the complete B construction.
    memcpy(B_out, gb, 512);

    // Keep borrowed challenge fields valid after this helper returns.
    memset(ch, 0, sizeof *ch);
    ch->N = RFC5054_N_4096;
    ch->N_len = sizeof RFC5054_N_4096;
    ch->g = g_val;
    ch->g_len = sizeof g_val;
    ch->salt = salt;
    ch->salt_len = sizeof salt;
    ch->B = B_out;
    ch->B_len = 512u;
    ch->iterations = APPLE_SRP_ITER_MIN;

    // Compute client SRP
    memset(client_sess, 0, sizeof *client_sess);
    RFB_CHECK_EQ_INT(
        apple_srp_compute_client(ch, username, sizeof username - 1u,
                                 password, sizeof password - 1u,
                                 a_secret, a_len, client_sess),
        RFB_OK);
}

RFB_TEST(g26_srp, srp__compute_client__produces_valid_A_and_M1) {
    apple_srp_challenge ch;
    apple_srp_session sess;

    // Deterministic private exponent 'a' (32 bytes, 256 bits)
    uint8_t a_secret[32];
    memset(a_secret, 0x42, sizeof a_secret);

    // Server private exponent 'b'
    uint8_t b_secret[32];
    memset(b_secret, 0x55, sizeof b_secret);

    uint8_t B[512];
    setup_srp_pair(&ch, &sess, B, a_secret, sizeof a_secret,
                   b_secret, sizeof b_secret);

    // A must be 512 bytes
    RFB_CHECK_EQ_UINT(sess.A_len, 512u);
    // A must not be zero (g^a mod N with a != 0)
    bool a_nonzero = false;
    for (size_t i = 0; i < sess.A_len; i++) {
        if (sess.A[i] != 0) { a_nonzero = true; break; }
    }
    RFB_CHECK(a_nonzero);

    // M1 must be 64 bytes (SHA-512)
    RFB_CHECK_EQ_UINT(sess.M1_len, 64u);

    apple_srp_session_destroy(&sess);
}

RFB_TEST(g26_srp, srp__wrap_key__is_16_bytes) {
    apple_srp_challenge ch;
    apple_srp_session sess;
    uint8_t a_secret[32];
    memset(a_secret, 0x42, sizeof a_secret);
    uint8_t b_secret[32];
    memset(b_secret, 0x55, sizeof b_secret);
    uint8_t B[512];
    setup_srp_pair(&ch, &sess, B, a_secret, sizeof a_secret,
                   b_secret, sizeof b_secret);

    uint8_t wrap_key[16];
    apple_srp_derive_wrap_key(&sess, wrap_key);
    // Wrap key must be deterministic for same inputs
    uint8_t wrap_key2[16];
    apple_srp_derive_wrap_key(&sess, wrap_key2);
    RFB_CHECK_MEM_EQ(wrap_key, wrap_key2, 16);

    apple_srp_session_destroy(&sess);
}

RFB_TEST(g26_srp, srp__different_password__different_M1) {
    // Two sessions with different passwords must produce different M1.
    uint8_t N[512];
    fill_rfc5054_n(N);
    static const uint8_t salt[16] = { 0xAA };
    static const uint8_t username[] = "admin";
    uint8_t a_secret[32];
    memset(a_secret, 0x42, sizeof a_secret);

    // B = g^b for a fixed b
    uint8_t b_secret[32];
    memset(b_secret, 0x55, sizeof b_secret);
    uint8_t B[512];
    static const uint8_t g_val[1] = { 5 };
    rfb_crypto_modexp(g_val, 1, b_secret, 32, N, 512, B, 512);

    uint8_t buf[2048];
    size_t ch_len = build_challenge(buf, sizeof buf, N, 512, 5, salt, 16, B, 512, 1000, "");
    apple_srp_challenge ch;
    apple_srp_parse_challenge(buf, ch_len, &ch);

    // Session 1: correct password
    apple_srp_session s1;
    static const uint8_t pw1[] = "admin";
    apple_srp_compute_client(&ch, username, 5, pw1, 5, a_secret, 32, &s1);

    // Session 2: wrong password
    apple_srp_session s2;
    static const uint8_t pw2[] = "wrong";
    apple_srp_compute_client(&ch, username, 5, pw2, 5, a_secret, 32, &s2);

    // M1 must differ (different password → different x → different M1)
    bool m1_differs = (memcmp(s1.M1, s2.M1, 64) != 0);
    RFB_CHECK(m1_differs);

    apple_srp_session_destroy(&s1);
    apple_srp_session_destroy(&s2);
}

RFB_TEST(g26_srp, srp__session_destroy__zeroizes_secrets) {
    apple_srp_challenge ch;
    apple_srp_session sess;
    uint8_t a_secret[32];
    memset(a_secret, 0x42, sizeof a_secret);
    uint8_t b_secret[32];
    memset(b_secret, 0x55, sizeof b_secret);
    uint8_t B[512];
    setup_srp_pair(&ch, &sess, B, a_secret, 32, b_secret, 32);

    apple_srp_session_destroy(&sess);

    // All secret fields must be zero
    bool all_zero = true;
    for (size_t i = 0; i < sizeof sess.a; i++)
        if (sess.a[i] != 0) { all_zero = false; break; }
    for (size_t i = 0; i < sizeof sess.x; i++)
        if (sess.x[i] != 0) { all_zero = false; break; }
    for (size_t i = 0; i < sizeof sess.S; i++)
        if (sess.S[i] != 0) { all_zero = false; break; }
    for (size_t i = 0; i < sizeof sess.K; i++)
        if (sess.K[i] != 0) { all_zero = false; break; }
    for (size_t i = 0; i < sizeof sess.M1; i++)
        if (sess.M1[i] != 0) { all_zero = false; break; }
    RFB_CHECK(all_zero);
}

static bool srp_bytes_are_zero(const uint8_t *bytes, size_t length)
{
    for (size_t i = 0; i < length; i++) {
        if (bytes[i] != 0u) {
            return false;
        }
    }
    return true;
}

static bool srp_session_owned_state_is_zero(const apple_srp_session *session)
{
    return srp_bytes_are_zero(session->a, sizeof session->a) &&
           srp_bytes_are_zero(session->x, sizeof session->x) &&
           srp_bytes_are_zero(session->S, sizeof session->S) &&
           srp_bytes_are_zero(session->K, sizeof session->K) &&
           srp_bytes_are_zero(session->M1, sizeof session->M1) &&
           srp_bytes_are_zero(session->A, sizeof session->A) &&
           session->a_len == 0u && session->x_len == 0u &&
           session->S_len == 0u && session->M1_len == 0u &&
           session->A_len == 0u;
}

static void srp_init_compute_challenge(apple_srp_challenge *challenge,
                                       const uint8_t N[512],
                                       const uint8_t B[512],
                                       uint32_t iterations)
{
    static const uint8_t g[1] = { 5u };
    static const uint8_t salt[16] = { 0xAAu, 0xBBu, 0xCCu, 0xDDu };
    memset(challenge, 0, sizeof *challenge);
    challenge->N = N;
    challenge->N_len = 512u;
    challenge->g = g;
    challenge->g_len = sizeof g;
    challenge->salt = salt;
    challenge->salt_len = sizeof salt;
    challenge->B = B;
    challenge->B_len = 512u;
    challenge->iterations = iterations;
}

typedef struct srp_allocator_spy {
    size_t allocations;
    size_t frees;
    size_t allocation_size;
    bool reject;
    bool zero_before_free;
} srp_allocator_spy;

static void *srp_spy_alloc(rfb_allocator *allocator, size_t size)
{
    srp_allocator_spy *spy = (srp_allocator_spy *)allocator->user;
    spy->allocations++;
    spy->allocation_size = size;
    if (spy->reject) {
        return NULL;
    }
    return malloc(size);
}

static void srp_spy_free(rfb_allocator *allocator, void *allocation)
{
    srp_allocator_spy *spy = (srp_allocator_spy *)allocator->user;
    const uint8_t *bytes = (const uint8_t *)allocation;
    spy->frees++;
    if (!srp_bytes_are_zero(bytes, spy->allocation_size)) {
        spy->zero_before_free = false;
    }
    free(allocation);
}

RFB_TEST(g26_srp, srp__computation_failure__clears_partial_session)
{
    uint8_t valid_N[512];
    uint8_t zero_N[512] = { 0 };
    uint8_t B[512] = { 0 };
    uint8_t private_a[32];
    static const uint8_t password[] = "secret";
    apple_srp_challenge challenges[3];
    apple_srp_session session;
    srp_allocator_spy rejecting_spy = {
        .allocations = 0u,
        .frees = 0u,
        .allocation_size = 0u,
        .reject = true,
        .zero_before_free = true,
    };
    rfb_allocator rejecting_allocator = {
        .alloc = srp_spy_alloc,
        .free = srp_spy_free,
        .user = &rejecting_spy,
    };
    struct srp_failure_case {
        apple_srp_challenge *challenge;
        rfb_allocator *allocator;
        rfb_error expected;
    } cases[3];

    fill_rfc5054_n(valid_N);
    B[511] = 2u;
    memset(private_a, 0x42, sizeof private_a);
    srp_init_compute_challenge(&challenges[0], valid_N, B, 0u);
    srp_init_compute_challenge(&challenges[1], zero_N, B,
                               APPLE_SRP_ITER_MIN);
    srp_init_compute_challenge(&challenges[2], valid_N, B,
                               APPLE_SRP_ITER_MIN);
    cases[0] = (struct srp_failure_case){
        .challenge = &challenges[0],
        .allocator = rfb_default_allocator(),
        .expected = RFB_ERR_INTERNAL,
    };
    cases[1] = (struct srp_failure_case){
        .challenge = &challenges[1],
        .allocator = rfb_default_allocator(),
        .expected = RFB_ERR_INTERNAL,
    };
    cases[2] = (struct srp_failure_case){
        .challenge = &challenges[2],
        .allocator = &rejecting_allocator,
        .expected = RFB_ERR_NOMEM,
    };

    for (size_t i = 0; i < 3u; i++) {
        memset(&session, 0xA5, sizeof session);
        RFB_CHECK_EQ_INT(
            apple_srp_compute_client_with_allocator(
                cases[i].challenge, (const uint8_t *)"admin", 5u,
                password, sizeof password - 1u, private_a, sizeof private_a,
                &session, cases[i].allocator),
            cases[i].expected);
        RFB_CHECK(srp_session_owned_state_is_zero(&session));
    }
    RFB_CHECK_EQ_UINT(rejecting_spy.allocations, 1u);
    RFB_CHECK_EQ_UINT(rejecting_spy.frees, 0u);
}

RFB_TEST(g26_srp, srp__successful_proof_input__is_zero_before_free)
{
    uint8_t N[512];
    uint8_t B[512] = { 0 };
    uint8_t private_a[32];
    static const uint8_t password[] = "secret";
    apple_srp_challenge challenge;
    apple_srp_session session;
    srp_allocator_spy spy = {
        .allocations = 0u,
        .frees = 0u,
        .allocation_size = 0u,
        .reject = false,
        .zero_before_free = true,
    };
    rfb_allocator allocator = {
        .alloc = srp_spy_alloc,
        .free = srp_spy_free,
        .user = &spy,
    };

    fill_rfc5054_n(N);
    B[511] = 2u;
    memset(private_a, 0x42, sizeof private_a);
    srp_init_compute_challenge(&challenge, N, B, APPLE_SRP_ITER_MIN);
    RFB_CHECK_EQ_INT(
        apple_srp_compute_client_with_allocator(
            &challenge, (const uint8_t *)"admin", 5u,
            password, sizeof password - 1u, private_a, sizeof private_a,
            &session, &allocator),
        RFB_OK);
    RFB_CHECK_EQ_UINT(spy.allocations, 1u);
    RFB_CHECK_EQ_UINT(spy.frees, 1u);
    RFB_CHECK(spy.zero_before_free);
    apple_srp_session_destroy(&session);
}

// ===== Packet 2 Serialization Tests ====================================

RFB_TEST(g26_srp, packet2__serializes_correct_structure) {
    // Build a session with known values
    apple_srp_challenge ch;
    apple_srp_session sess;
    uint8_t a_secret[32];
    memset(a_secret, 0x42, sizeof a_secret);
    uint8_t b_secret[32];
    memset(b_secret, 0x55, sizeof b_secret);
    uint8_t B[512];
    setup_srp_pair(&ch, &sess, B, a_secret, 32, b_secret, 32);

    static const char opts[] = "mda=SHA-512,replay_detection";
    uint8_t client_random[16];
    memset(client_random, 0xAB, sizeof client_random);

    uint8_t pkt[2048];
    size_t pkt_len = 0;
    RFB_CHECK_EQ_INT(
        apple_srp_serialize_packet2(&sess, opts, sizeof opts - 1,
                                     client_random, pkt, sizeof pkt, &pkt_len),
        RFB_OK);

    // Verify structure
    RFB_CHECK(pkt_len > 0);
    // total_len at offset 0 (u32_be)
    uint32_t total = ((uint32_t)pkt[0] << 24) | ((uint32_t)pkt[1] << 16) |
                     ((uint32_t)pkt[2] << 8) | pkt[3];
    RFB_CHECK_EQ_UINT(total, (uint32_t)(pkt_len - 4));

    // version at offset 4 (u16_be) = 0x0100
    RFB_CHECK_EQ_UINT(pkt[4], 0x01u);
    RFB_CHECK_EQ_UINT(pkt[5], 0x00u);

    // "RSA1" at offset 6
    RFB_CHECK_MEM_EQ(pkt + 6, "RSA1", 4);

    // authtype at offset 10 = 2
    RFB_CHECK_EQ_UINT(pkt[11], 0x02u);

    apple_srp_session_destroy(&sess);
}

RFB_TEST(g26_srp, packet2__null_inputs__fail_internal) {
    apple_srp_session sess;
    memset(&sess, 0, sizeof sess);
    uint8_t client_random[16] = {0};
    uint8_t out[1024];
    size_t out_len = 0;
    RFB_CHECK_EQ_INT(
        apple_srp_serialize_packet2(NULL, "", 0, client_random,
                                     out, sizeof out, &out_len),
        RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(
        apple_srp_serialize_packet2(&sess, "", 0, client_random,
                                     out, sizeof out, NULL),
        RFB_ERR_INTERNAL);
}

RFB_TEST(g26_srp, packet2__output_too_small__fails_limit) {
    apple_srp_session sess;
    memset(&sess, 0, sizeof sess);
    sess.N_len = 512;
    sess.A_len = 512;
    sess.M1_len = 64;
    uint8_t client_random[16] = {0};
    uint8_t tiny[10];
    size_t out_len = 0;
    RFB_CHECK_EQ_INT(
        apple_srp_serialize_packet2(&sess, "", 0, client_random,
                                     tiny, sizeof tiny, &out_len),
        RFB_ERR_LIMIT);
}

// ===== Packet-2 length invariant and response parser ======================

RFB_TEST(g26_srp, packet2__total_len_invariant__equals_0x0434) {
    // The outer total_len is 1076 (0x0434) for a packet with 682 meaningful
    // bytes, a 384-byte tail, and a 10-byte RSA1 header.
    apple_srp_session sess;
    memset(&sess, 0, sizeof sess);
    sess.N_len = 512;  // required so inner size calculation uses 512-byte A
    sess.A_len = 512;
    sess.M1_len = 64;
    // Use the real 80-byte options string
    static const char opts[] =
        "mda=SHA-512,replay_detection,conf+int=ChaCha20-Poly1305,kdf=SALTED-SHA512-PBKDF2";
    uint8_t client_random[16] = {0};

    uint8_t pkt[2048];
    size_t pkt_len = 0;
    RFB_CHECK_EQ_INT(
        apple_srp_serialize_packet2(&sess, opts, sizeof opts - 1,
                                     client_random, pkt, sizeof pkt, &pkt_len),
        RFB_OK);
    // Full packet must be 1080 bytes
    RFB_CHECK_EQ_UINT(pkt_len, 1080u);
    // First 4 bytes must be 00 00 04 34 (total_len = 1076)
    RFB_CHECK_EQ_UINT(pkt[0], 0x00u);
    RFB_CHECK_EQ_UINT(pkt[1], 0x00u);
    RFB_CHECK_EQ_UINT(pkt[2], 0x04u);
    RFB_CHECK_EQ_UINT(pkt[3], 0x34u);
}

RFB_TEST(g26_srp, type36_packet2__matches_profile_lengths)
{
    apple_srp_session sess;
    memset(&sess, 0, sizeof sess);
    sess.N_len = APPLE_SRP_N_BYTES;
    sess.A_len = APPLE_SRP_N_BYTES;
    sess.M1_len = APPLE_SRP_M1_BYTES;
    static const char opts[] =
        "mda=SHA-512,replay_detection,conf+int=ChaCha20-Poly1305,"
        "kdf=SALTED-SHA512-PBKDF2";
    uint8_t client_random[16] = {0u};
    uint8_t packet[1024];
    size_t packet_len = 0u;

    RFB_CHECK_EQ_INT(
        apple_srp_serialize_type36_packet2(
            &sess, opts, sizeof opts - 1u, client_random, packet,
            sizeof packet, &packet_len),
        RFB_OK);
    RFB_CHECK_EQ_UINT(packet_len, 686u);
    static const uint8_t expected_prefix[] = {
        0u, 0u, 0x02u, 0xaau, 0u, 0u, 0x02u, 0xa6u, 0x02u, 0u,
    };
    RFB_CHECK_MEM_EQ(packet, expected_prefix, sizeof expected_prefix);
}

RFB_TEST(g26_srp, type36_response__parses_proof_and_bare_rejection)
{
    uint8_t response[100];
    memset(response, 0, sizeof response);
    response[3] = 92u;
    response[7] = 88u;
    response[8] = APPLE_SRP_M1_BYTES;
    for (size_t i = 0u; i < APPLE_SRP_M1_BYTES; i++) {
        response[9u + i] = (uint8_t)i;
    }
    response[73] = 16u;
    for (size_t i = 0u; i < 16u; i++) {
        response[74u + i] = (uint8_t)(0xa0u + i);
    }

    apple_srp_auth_response parsed;
    RFB_CHECK_EQ_INT(
        apple_srp_parse_type36_auth_response(response, sizeof response,
                                             &parsed),
        RFB_OK);
    RFB_CHECK_EQ_UINT(parsed.total_len, 92u);
    RFB_CHECK_EQ_UINT(parsed.meaningful_len, 88u);
    RFB_CHECK_EQ_UINT(parsed.M2_len, APPLE_SRP_M1_BYTES);
    RFB_CHECK_EQ_UINT(parsed.server_random_len, 16u);
    RFB_CHECK_EQ_UINT(parsed.security_result, 0u);

    static const uint8_t rejected[] = {0u, 0u, 0u, 1u};
    RFB_CHECK_EQ_INT(
        apple_srp_parse_type36_auth_response(rejected, sizeof rejected,
                                             &parsed),
        RFB_OK);
    RFB_CHECK_EQ_UINT(parsed.security_result, 1u);
    RFB_CHECK(parsed.M2 == NULL);

    static const uint8_t unsupported_result[] = {0u, 0u, 0u, 2u};
    RFB_CHECK_EQ_INT(
        apple_srp_parse_type36_auth_response(
            unsupported_result, sizeof unsupported_result, &parsed),
        RFB_ERR_PROTOCOL);
}

RFB_TEST(g26_srp, type36_guards_and_malformed_fields_fail_closed)
{
    apple_srp_challenge challenge;
    uint8_t short_challenge[8] = {0u};
    RFB_CHECK_EQ_INT(
        apple_srp_parse_type36_challenge(NULL, 0u, &challenge),
        RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(
        apple_srp_parse_type36_challenge(short_challenge,
                                         sizeof short_challenge, NULL),
        RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(
        apple_srp_parse_type36_challenge(short_challenge, 0u, &challenge),
        RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(
        apple_srp_parse_type36_challenge(short_challenge, 4u, &challenge),
        RFB_ERR_PROTOCOL);

    short_challenge[3] = 4u;
    short_challenge[5] = 1u;
    RFB_CHECK_EQ_INT(
        apple_srp_parse_type36_challenge(
            short_challenge, sizeof short_challenge, &challenge),
        RFB_ERR_PROTOCOL);
    short_challenge[5] = 0u;
    short_challenge[7] = 1u;
    RFB_CHECK_EQ_INT(
        apple_srp_parse_type36_challenge(
            short_challenge, sizeof short_challenge, &challenge),
        RFB_ERR_PROTOCOL);

    apple_srp_session session;
    memset(&session, 0, sizeof session);
    session.N_len = APPLE_SRP_N_BYTES;
    session.A_len = APPLE_SRP_N_BYTES;
    session.M1_len = APPLE_SRP_M1_BYTES;
    uint8_t random[16] = {0u};
    uint8_t packet[1024];
    size_t packet_len = 0u;
    RFB_CHECK_EQ_INT(apple_srp_serialize_type36_packet2(
                         NULL, NULL, 0u, random, packet, sizeof packet,
                         &packet_len),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(apple_srp_serialize_type36_packet2(
                         &session, NULL, 0u, random, NULL, sizeof packet,
                         &packet_len),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(apple_srp_serialize_type36_packet2(
                         &session, NULL, 0u, random, packet, sizeof packet,
                         NULL),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(apple_srp_serialize_type36_packet2(
                         &session, NULL, 0u, NULL, packet, sizeof packet,
                         &packet_len),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(apple_srp_serialize_type36_packet2(
                         &session, NULL, 1u, random, packet, sizeof packet,
                         &packet_len),
                     RFB_ERR_INTERNAL);

    session.N_len = APPLE_SRP_N_BYTES - 1u;
    RFB_CHECK_EQ_INT(apple_srp_serialize_type36_packet2(
                         &session, NULL, 0u, random, packet, sizeof packet,
                         &packet_len),
                     RFB_ERR_PROTOCOL);
    session.N_len = APPLE_SRP_N_BYTES;
    session.A_len = APPLE_SRP_N_BYTES - 1u;
    RFB_CHECK_EQ_INT(apple_srp_serialize_type36_packet2(
                         &session, NULL, 0u, random, packet, sizeof packet,
                         &packet_len),
                     RFB_ERR_PROTOCOL);
    session.A_len = APPLE_SRP_N_BYTES;
    session.M1_len = APPLE_SRP_M1_BYTES - 1u;
    RFB_CHECK_EQ_INT(apple_srp_serialize_type36_packet2(
                         &session, NULL, 0u, random, packet, sizeof packet,
                         &packet_len),
                     RFB_ERR_PROTOCOL);
    session.M1_len = APPLE_SRP_M1_BYTES;
    RFB_CHECK_EQ_INT(apple_srp_serialize_type36_packet2(
                         &session, "x", (size_t)UINT16_MAX + 1u, random,
                         packet, sizeof packet, &packet_len),
                     RFB_ERR_LIMIT);
    RFB_CHECK_EQ_INT(apple_srp_serialize_type36_packet2(
                         &session, NULL, 0u, random, packet, 1u, &packet_len),
                     RFB_ERR_LIMIT);

    apple_srp_auth_response response;
    uint8_t auth[100];
    memset(auth, 0, sizeof auth);
    auth[3] = 92u;
    auth[7] = 88u;
    auth[8] = APPLE_SRP_M1_BYTES;
    auth[73] = 16u;
    RFB_CHECK_EQ_INT(
        apple_srp_parse_type36_auth_response(NULL, 0u, &response),
        RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(
        apple_srp_parse_type36_auth_response(auth, sizeof auth, NULL),
        RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(
        apple_srp_parse_type36_auth_response(auth, 0u, &response),
        RFB_ERR_PROTOCOL);

    auth[3] = 91u;
    RFB_CHECK_EQ_INT(apple_srp_parse_type36_auth_response(
                         auth, sizeof auth, &response),
                     RFB_ERR_PROTOCOL);
    auth[3] = 92u;
    auth[4] = 1u;
    RFB_CHECK_EQ_INT(apple_srp_parse_type36_auth_response(
                         auth, sizeof auth, &response),
                     RFB_ERR_PROTOCOL);
    auth[4] = 0u;
    auth[7] = 87u;
    RFB_CHECK_EQ_INT(apple_srp_parse_type36_auth_response(
                         auth, sizeof auth, &response),
                     RFB_ERR_PROTOCOL);
    auth[7] = 88u;
    auth[8] = APPLE_SRP_M1_BYTES - 1u;
    RFB_CHECK_EQ_INT(apple_srp_parse_type36_auth_response(
                         auth, sizeof auth, &response),
                     RFB_ERR_PROTOCOL);
    auth[8] = APPLE_SRP_M1_BYTES;
    auth[73] = 15u;
    RFB_CHECK_EQ_INT(apple_srp_parse_type36_auth_response(
                         auth, sizeof auth, &response),
                     RFB_ERR_PROTOCOL);
    auth[73] = 16u;
    auth[90] = 1u;
    RFB_CHECK_EQ_INT(apple_srp_parse_type36_auth_response(
                         auth, sizeof auth, &response),
                     RFB_ERR_PROTOCOL);
}

RFB_TEST(g26_srp, response__parse_14_byte_rejection) {
    // The server's 14-byte response:
    // 00 00 00 06 00 00 00 02 00 00 00 00 00 01
    // Parse as RSA1 envelope + SecurityResult:
    //   u32 total_len=6 | u16 version=0 | u16 authtype=2 | u16 body_len=0
    //   (6 bytes payload)
    //   u32 SecurityResult=1
    static const uint8_t resp[14] = {
        0x00, 0x00, 0x00, 0x06,  // total_len = 6
        0x00, 0x00,              // version = 0
        0x00, 0x02,              // authtype = 2
        0x00, 0x00,              // body_len = 0
        0x00, 0x00, 0x00, 0x01,  // SecurityResult = 1
    };
    // Verify the RSA1 envelope interpretation
    uint32_t total_len = ((uint32_t)resp[0] << 24) | ((uint32_t)resp[1] << 16) |
                         ((uint32_t)resp[2] << 8) | resp[3];
    RFB_CHECK_EQ_UINT(total_len, 6u);
    // The SecurityResult is at the END, not at offset 4
    uint32_t sr = ((uint32_t)resp[10] << 24) | ((uint32_t)resp[11] << 16) |
                  ((uint32_t)resp[12] << 8) | resp[13];
    RFB_CHECK_EQ_UINT(sr, 1u);  // NOT 2!
    // The value at offset 4 is the RSA1 version field (0x0000), not SecurityResult
}

// ===== Server response parser tests ====================================

// 10-byte failure response: 00 00 00 06 00 00 00 02 00 00
// This is an empty RSA1 envelope. NOT SecurityResult=2 at offset 4.
// The SecurityResult follows AFTER the envelope.
RFB_TEST(g26_srp, response__empty_envelope_failure_10_bytes) {
    static const uint8_t data[] = {
        0x00, 0x00, 0x00, 0x06,  // total_len = 6
        0x00, 0x00,              // version = 0
        0x00, 0x02,              // authtype = 2
        0x00, 0x00,              // body_len = 0
    };
    apple_srp_auth_response resp;
    // 10 bytes = envelope only, no SecurityResult → should fail
    RFB_CHECK_EQ_INT(
        apple_srp_parse_auth_response(data, sizeof data, &resp),
        RFB_ERR_PROTOCOL);
}

// 14-byte failure response: empty envelope + SecurityResult=1
RFB_TEST(g26_srp, response__empty_envelope_plus_result_1) {
    static const uint8_t data[] = {
        0x00, 0x00, 0x00, 0x06,  // total_len = 6
        0x00, 0x00,              // version = 0
        0x00, 0x02,              // authtype = 2
        0x00, 0x00,              // body_len = 0
        0x00, 0x00, 0x00, 0x01,  // SecurityResult = 1 (FAILURE)
    };
    apple_srp_auth_response resp;
    RFB_CHECK_EQ_INT(
        apple_srp_parse_auth_response(data, sizeof data, &resp),
        RFB_OK);
    RFB_CHECK_EQ_UINT(resp.total_len, 6u);
    RFB_CHECK_EQ_UINT(resp.version, 0u);
    RFB_CHECK_EQ_UINT(resp.authtype, 2u);
    RFB_CHECK_EQ_UINT(resp.meaningful_len, 0u);
    RFB_CHECK_EQ_UINT(resp.security_result, 1u);
    RFB_CHECK(resp.M2 == NULL);
    RFB_CHECK(resp.server_random == NULL);
}

// Success response: 98-byte RSA1 envelope with M2 + server_random + result=0
RFB_TEST(g26_srp, response__success_envelope_plus_result_0) {
    uint8_t data[106];
    size_t pos = 0;
    // total_len = 98 (6 header + 4 preamble/inner + 1+64 M2 + 1+16 sr + 6 trailing zeros)
    data[pos++]=0; data[pos++]=0; data[pos++]=0; data[pos++]=98; // total_len
    data[pos++]=0; data[pos++]=0; // version
    data[pos++]=0; data[pos++]=2; // authtype
    // meaningful_len = 92
    data[pos++]=0; data[pos++]=92;
    // preamble=0, inner_len=88
    data[pos++]=0; data[pos++]=0;
    data[pos++]=0; data[pos++]=88;
    // M2: u8 len=64 + 64 bytes
    data[pos++]=64;
    for (int i=0; i<64; i++) data[pos++]=0xAA;
    // server_random: u8 len=16 + 16 bytes
    data[pos++]=16;
    for (int i=0; i<16; i++) data[pos++]=0xBB;
    // Remaining body: fill to total_len
    while (pos < 4 + 98) data[pos++]=0;
    // SecurityResult = 0
    data[pos++]=0; data[pos++]=0; data[pos++]=0; data[pos++]=0;

    apple_srp_auth_response resp;
    RFB_CHECK_EQ_INT(
        apple_srp_parse_auth_response(data, pos, &resp),
        RFB_OK);
    RFB_CHECK_EQ_UINT(resp.total_len, 98u);
    RFB_CHECK_EQ_UINT(resp.security_result, 0u);
    RFB_CHECK_EQ_UINT(resp.M2_len, 64u);
    RFB_CHECK(resp.M2 != NULL);
    RFB_CHECK_EQ_UINT(resp.M2[0], 0xAAu);
    RFB_CHECK_EQ_UINT(resp.server_random_len, 16u);
    RFB_CHECK(resp.server_random != NULL);
    RFB_CHECK_EQ_UINT(resp.server_random[0], 0xBBu);
}

// Every proper response prefix is rejected; the complete buffer succeeds.
RFB_TEST(g26_srp, response__every_split_point) {
    static const uint8_t full[] = {
        0x00, 0x00, 0x00, 0x06,
        0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01,
    };
    for (size_t split = 1; split < sizeof full; split++) {
        apple_srp_auth_response resp;
        // First part only
        RFB_CHECK(apple_srp_parse_auth_response(full, split, &resp) != RFB_OK);
    }
    // Full buffer
    apple_srp_auth_response resp;
    RFB_CHECK_EQ_INT(
        apple_srp_parse_auth_response(full, sizeof full, &resp),
        RFB_OK);
    RFB_CHECK_EQ_UINT(resp.security_result, 1u);
}

// NULL safety
RFB_TEST(g26_srp, response__null_inputs) {
    apple_srp_auth_response resp;
    static const uint8_t data[14] = {0};
    RFB_CHECK_EQ_INT(apple_srp_parse_auth_response(NULL, 14, &resp), RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(apple_srp_parse_auth_response(data, 14, NULL), RFB_ERR_INTERNAL);
}

// ===== M2 (server proof) — H(PAD(A) || M1 || K) =========================

RFB_TEST(g26_srp, srp__compute_m2__matches_independent_H_of_A_M1_K) {
    apple_srp_challenge ch;
    apple_srp_session sess;
    uint8_t a_secret[32];
    memset(a_secret, 0x42, sizeof a_secret);
    uint8_t b_secret[32];
    memset(b_secret, 0x55, sizeof b_secret);
    uint8_t B[512];
    setup_srp_pair(&ch, &sess, B, a_secret, sizeof a_secret,
                   b_secret, sizeof b_secret);

    uint8_t m2_actual[APPLE_SRP_M1_BYTES];
    RFB_CHECK_EQ_INT(
        apple_srp_compute_m2(&sess, ch.B, ch.B_len, m2_actual),
        RFB_OK);

    // Independently recompute H(PAD(A) || M1 || K).
    uint8_t m2_input[APPLE_SRP_N_BYTES + 64 + 64];
    memcpy(m2_input, sess.A, 512);
    memcpy(m2_input + 512, sess.M1, 64);
    memcpy(m2_input + 576, sess.K, 64);

    uint8_t m2_expected[64];
    rfb_crypto_sha512(m2_input, sizeof m2_input, m2_expected);
    rfb_secret_zero(m2_input, sizeof m2_input);

    RFB_CHECK_MEM_EQ(m2_actual, m2_expected, 64);
    apple_srp_session_destroy(&sess);
}

RFB_TEST(g26_srp, srp__compute_m2__null_inputs__fail_internal) {
    apple_srp_session sess;
    memset(&sess, 0, sizeof sess);
    uint8_t out[APPLE_SRP_M1_BYTES];
    RFB_CHECK_EQ_INT(apple_srp_compute_m2(NULL, NULL, 0, out),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(apple_srp_compute_m2(&sess, NULL, 0, NULL),
                     RFB_ERR_INTERNAL);
}

// ===== noUsernameInX — username must not affect SRP output ================

RFB_TEST(g26_srp, srp__noUsernameInX__varying_only_username__M1_K_S_identical) {
    uint8_t N[512];
    fill_rfc5054_n(N);
    static const uint8_t salt[16] = { 0xAA, 0xBB, 0xCC, 0xDD };
    uint8_t a_secret[32];
    memset(a_secret, 0x42, sizeof a_secret);
    uint8_t b_secret[32];
    memset(b_secret, 0x55, sizeof b_secret);
    uint8_t B[512];
    static const uint8_t g_val[1] = { 5 };
    rfb_crypto_modexp(g_val, 1, b_secret, 32, N, 512, B, 512);

    uint8_t buf[2048];
    size_t ch_len = build_challenge(buf, sizeof buf, N, 512, 5,
                                     salt, 16, B, 512, 1000, "");
    apple_srp_challenge ch;
    RFB_CHECK_EQ_INT(apple_srp_parse_challenge(buf, ch_len, &ch), RFB_OK);

    static const uint8_t password[] = "hunter2";

    // Session 1: username "admin"
    apple_srp_session s1;
    RFB_CHECK_EQ_INT(
        apple_srp_compute_client(&ch, (const uint8_t *)"admin", 5,
                                  password, 7,
                                  a_secret, sizeof a_secret, &s1),
        RFB_OK);

    // Session 2: completely different username "root"
    apple_srp_session s2;
    RFB_CHECK_EQ_INT(
        apple_srp_compute_client(&ch, (const uint8_t *)"root", 4,
                                  password, 7,
                                  a_secret, sizeof a_secret, &s2),
        RFB_OK);

    // M1, K, S must be byte-identical despite different usernames.
    RFB_CHECK_MEM_EQ(s1.A, s2.A, s1.A_len);
    RFB_CHECK_MEM_EQ(s1.x, s2.x, sizeof s1.x);
    RFB_CHECK_MEM_EQ(s1.S, s2.S, s1.S_len);
    RFB_CHECK_MEM_EQ(s1.K, s2.K, sizeof s1.K);
    RFB_CHECK_MEM_EQ(s1.M1, s2.M1, sizeof s1.M1);

    apple_srp_session_destroy(&s1);
    apple_srp_session_destroy(&s2);
}

// The parser rejects server-supplied PBKDF2 iteration counts below the
// project floor and accepts the floor itself. RFC 5054 does not define this
// Apple-variant iteration field.
RFB_TEST(g26_srp, challenge__iterations_below_floor__fails_limit)
{
    uint8_t N[512];
    fill_rfc5054_n(N);
    uint8_t buf[2048];
    const uint8_t salt[16] = {0};
    uint8_t B[512];
    memset(B, 0xAB, sizeof B);
    B[0] = 0x01;
    size_t len = build_challenge(buf, sizeof buf, N, 512, 5, salt, 16,
                                 B, 512, 999, "");
    apple_srp_challenge ch;
    RFB_CHECK_EQ_INT(apple_srp_parse_challenge(buf, len, &ch),
                     RFB_ERR_LIMIT);

    len = build_challenge(buf, sizeof buf, N, 512, 5, salt, 16,
                          B, 512, 1, "");
    RFB_CHECK_EQ_INT(apple_srp_parse_challenge(buf, len, &ch),
                     RFB_ERR_LIMIT);

    // The floor itself remains valid.
    len = build_challenge(buf, sizeof buf, N, 512, 5, salt, 16,
                          B, 512, APPLE_SRP_ITER_MIN, "");
    RFB_CHECK_EQ_INT(apple_srp_parse_challenge(buf, len, &ch), RFB_OK);
}

static size_t build_auth_response(uint8_t *out, size_t cap,
                                  uint8_t m2_len, uint8_t random_len)
{
    const size_t inner_len = 1u + m2_len + 1u + random_len;
    const size_t body_len = 4u + inner_len;
    const size_t total_len = 6u + body_len;
    const size_t full_len = 4u + total_len + 4u;
    if (full_len > cap) {
        return 0u;
    }

    size_t pos = 0u;
    out[pos++] = (uint8_t)(total_len >> 24);
    out[pos++] = (uint8_t)(total_len >> 16);
    out[pos++] = (uint8_t)(total_len >> 8);
    out[pos++] = (uint8_t)total_len;
    out[pos++] = 0u;
    out[pos++] = 0u;
    out[pos++] = 0u;
    out[pos++] = 2u;
    out[pos++] = (uint8_t)(body_len >> 8);
    out[pos++] = (uint8_t)body_len;
    out[pos++] = 0u;
    out[pos++] = 0u;
    out[pos++] = (uint8_t)(inner_len >> 8);
    out[pos++] = (uint8_t)inner_len;
    out[pos++] = m2_len;
    memset(out + pos, 0xAA, m2_len);
    pos += m2_len;
    out[pos++] = random_len;
    memset(out + pos, 0xBB, random_len);
    pos += random_len;
    out[pos++] = 0u;
    out[pos++] = 0u;
    out[pos++] = 0u;
    out[pos++] = 0u;
    return pos;
}

RFB_TEST(g26_srp, response__noncanonical_fields__fail_closed)
{
    uint8_t valid[128];
    const size_t valid_len = build_auth_response(
        valid, sizeof valid, APPLE_SRP_M1_BYTES, 16u);
    apple_srp_auth_response response;
    RFB_CHECK(valid_len > 0u);
    RFB_CHECK_EQ_INT(
        apple_srp_parse_auth_response(valid, valid_len, &response), RFB_OK);

    uint8_t mutated[128];
    memcpy(mutated, valid, valid_len);
    mutated[5] = 1u;
    RFB_CHECK_EQ_INT(
        apple_srp_parse_auth_response(mutated, valid_len, &response),
        RFB_ERR_PROTOCOL);

    memcpy(mutated, valid, valid_len);
    mutated[7] = 3u;
    RFB_CHECK_EQ_INT(
        apple_srp_parse_auth_response(mutated, valid_len, &response),
        RFB_ERR_PROTOCOL);

    memcpy(mutated, valid, valid_len);
    mutated[9]--;
    RFB_CHECK_EQ_INT(
        apple_srp_parse_auth_response(mutated, valid_len, &response),
        RFB_ERR_PROTOCOL);

    size_t len = build_auth_response(mutated, sizeof mutated,
                                     APPLE_SRP_M1_BYTES - 1u, 16u);
    RFB_CHECK_EQ_INT(
        apple_srp_parse_auth_response(mutated, len, &response),
        RFB_ERR_PROTOCOL);

    len = build_auth_response(mutated, sizeof mutated,
                              APPLE_SRP_M1_BYTES, 15u);
    RFB_CHECK_EQ_INT(
        apple_srp_parse_auth_response(mutated, len, &response),
        RFB_ERR_PROTOCOL);
}

RFB_TEST(g26_srp, srp__compute_m2__rejects_oversized_session_width)
{
    apple_srp_session session;
    memset(&session, 0, sizeof session);
    session.N_len = APPLE_SRP_N_BYTES + 1u;
    uint8_t m2[APPLE_SRP_M1_BYTES];
    srp_allocator_spy spy = {
        .allocations = 0u,
        .frees = 0u,
        .allocation_size = 0u,
        .reject = true,
        .zero_before_free = true,
    };
    rfb_allocator allocator = {
        .alloc = srp_spy_alloc,
        .free = srp_spy_free,
        .user = &spy,
    };

    RFB_CHECK_EQ_INT(
        apple_srp_compute_m2_with_allocator(
            &session, NULL, 0u, m2, &allocator),
        RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_UINT(spy.allocations, 0u);
}

static void srp_test_put_u16(uint8_t *buffer, size_t offset, uint16_t value)
{
    buffer[offset] = (uint8_t)(value >> 8);
    buffer[offset + 1u] = (uint8_t)value;
}

static void srp_test_put_u32(uint8_t *buffer, size_t offset, uint32_t value)
{
    buffer[offset] = (uint8_t)(value >> 24);
    buffer[offset + 1u] = (uint8_t)(value >> 16);
    buffer[offset + 2u] = (uint8_t)(value >> 8);
    buffer[offset + 3u] = (uint8_t)value;
}

static void srp_test_set_challenge_lengths(uint8_t *buffer, size_t length)
{
    if (length >= 4u) {
        srp_test_put_u32(buffer, 0u, (uint32_t)(length - 4u));
    }
    if (length >= 10u) {
        srp_test_put_u16(buffer, 8u, (uint16_t)(length - 10u));
    }
    if (length >= 14u) {
        srp_test_put_u16(buffer, 12u, (uint16_t)(length - 14u));
    }
}

RFB_TEST(g26_srp, challenge__field_and_read_boundaries__fail_closed)
{
    uint8_t N[APPLE_SRP_N_BYTES];
    fill_rfc5054_n(N);
    static const uint8_t salt[16] = {0xAAu};
    uint8_t B[APPLE_SRP_N_BYTES] = {0u};
    B[0] = 1u;
    uint8_t valid[2048];
    const size_t valid_len = build_challenge(
        valid, sizeof valid, N, sizeof N, 5u, salt, sizeof salt,
        B, sizeof B, APPLE_SRP_ITER_MIN, "");
    RFB_CHECK(valid_len > 0u);

    static const size_t truncations[] = {
        3u, 5u, 7u, 9u, 11u, 13u, 14u, 16u,
        528u, 530u, 531u, 532u, 548u, 550u,
        1062u, 1066u, 1070u, 1072u,
    };
    uint8_t mutated[2048];
    apple_srp_challenge challenge;
    for (size_t i = 0u; i < sizeof truncations / sizeof truncations[0]; i++) {
        memcpy(mutated, valid, valid_len);
        srp_test_set_challenge_lengths(mutated, truncations[i]);
        RFB_CHECK_EQ_INT(
            apple_srp_parse_challenge(
                mutated, truncations[i], &challenge),
            RFB_ERR_PROTOCOL);
    }

    struct mutation_case {
        size_t offset;
        uint8_t value;
        rfb_error expected;
    } cases[] = {
        {9u, 0u, RFB_ERR_PROTOCOL},
        {11u, 1u, RFB_ERR_PROTOCOL},
        {13u, 0u, RFB_ERR_PROTOCOL},
        {14u, 1u, RFB_ERR_PROTOCOL},
        {530u, 2u, RFB_ERR_PROTOCOL},
        {532u, APPLE_SRP_SALT_MAX + 1u, RFB_ERR_LIMIT},
        {532u, 0u, RFB_ERR_PROTOCOL},
        {550u, 1u, RFB_ERR_PROTOCOL},
        {1066u, 1u, RFB_ERR_PROTOCOL},
        {1071u, 2u, RFB_ERR_LIMIT},
    };
    for (size_t i = 0u; i < sizeof cases / sizeof cases[0]; i++) {
        memcpy(mutated, valid, valid_len);
        mutated[cases[i].offset] = cases[i].value;
        RFB_CHECK_EQ_INT(
            apple_srp_parse_challenge(mutated, valid_len, &challenge),
            cases[i].expected);
    }

    memcpy(mutated, valid, valid_len);
    mutated[valid_len] = 0xEEu;
    srp_test_put_u32(mutated, 0u, (uint32_t)(valid_len - 3u));
    srp_test_put_u16(mutated, 8u, (uint16_t)(valid_len - 9u));
    srp_test_put_u16(mutated, 12u, (uint16_t)(valid_len - 13u));
    RFB_CHECK_EQ_INT(
        apple_srp_parse_challenge(mutated, valid_len + 1u, &challenge),
        RFB_ERR_PROTOCOL);
}

RFB_TEST(g26_srp, srp__argument_and_provider_bounds__fail_closed)
{
    uint8_t N[APPLE_SRP_N_BYTES];
    fill_rfc5054_n(N);
    uint8_t B[APPLE_SRP_N_BYTES] = {0u};
    B[APPLE_SRP_N_BYTES - 1u] = 2u;
    apple_srp_challenge challenge;
    srp_init_compute_challenge(
        &challenge, N, B, APPLE_SRP_ITER_MIN);
    static const uint8_t byte = 1u;
    apple_srp_session session;
    rfb_allocator missing_alloc = {
        .alloc = NULL,
        .free = srp_spy_free,
        .user = NULL,
    };
    rfb_allocator missing_free = {
        .alloc = srp_spy_alloc,
        .free = NULL,
        .user = NULL,
    };

    RFB_CHECK_EQ_INT(
        apple_srp_compute_client_with_allocator(
            NULL, NULL, 0u, &byte, 1u, &byte, 1u,
            &session, rfb_default_allocator()),
        RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(
        apple_srp_compute_client_with_allocator(
            &challenge, NULL, 0u, &byte, 1u, &byte, 1u,
            NULL, rfb_default_allocator()),
        RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(
        apple_srp_compute_client_with_allocator(
            &challenge, NULL, 0u, &byte, 1u, NULL, 1u,
            &session, rfb_default_allocator()),
        RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(
        apple_srp_compute_client_with_allocator(
            &challenge, NULL, 0u, NULL, 1u, &byte, 1u,
            &session, rfb_default_allocator()),
        RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(
        apple_srp_compute_client_with_allocator(
            &challenge, NULL, 0u, &byte, 1u, &byte, 1u,
            &session, NULL),
        RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(
        apple_srp_compute_client_with_allocator(
            &challenge, NULL, 0u, &byte, 1u, &byte, 1u,
            &session, &missing_alloc),
        RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(
        apple_srp_compute_client_with_allocator(
            &challenge, NULL, 0u, &byte, 1u, &byte, 1u,
            &session, &missing_free),
        RFB_ERR_INTERNAL);

    memset(&session, 0xA5, sizeof session);
    RFB_CHECK_EQ_INT(
        apple_srp_compute_client(
            &challenge, NULL, 0u, &byte, 1u, &byte,
            APPLE_SRP_N_BYTES + 1u, &session),
        RFB_ERR_PROTOCOL);
    RFB_CHECK(srp_session_owned_state_is_zero(&session));

    const size_t above_int = (size_t)INT_MAX + 1u;
    challenge.salt_len = above_int;
    memset(&session, 0xA5, sizeof session);
    RFB_CHECK_EQ_INT(
        apple_srp_compute_client(
            &challenge, NULL, 0u, &byte, 1u, &byte, 1u, &session),
        RFB_ERR_INTERNAL);
    RFB_CHECK(srp_session_owned_state_is_zero(&session));

    RFB_CHECK(!apple_srp_derive_session_key_32(NULL, session.K));
    RFB_CHECK(!apple_srp_derive_session_key_32(&session, NULL));
    RFB_CHECK(!apple_srp_derive_wrap_key(NULL, session.K));
    RFB_CHECK(!apple_srp_derive_wrap_key(&session, NULL));
    apple_srp_session_destroy(NULL);
}

RFB_TEST(g26_srp, response__read_and_length_boundaries__fail_closed)
{
    uint8_t valid[128];
    const size_t valid_len = build_auth_response(
        valid, sizeof valid, APPLE_SRP_M1_BYTES, 16u);
    RFB_CHECK(valid_len > 0u);
    apple_srp_auth_response response;
    static const size_t truncations[] = {11u, 13u, 14u, 15u, 79u, 80u};
    for (size_t i = 0u; i < sizeof truncations / sizeof truncations[0]; i++) {
        RFB_CHECK_EQ_INT(
            apple_srp_parse_auth_response(
                valid, truncations[i], &response),
            RFB_ERR_PROTOCOL);
    }

    uint8_t mutated[129];
    memcpy(mutated, valid, valid_len);
    srp_test_put_u32(mutated, 0u, 5u);
    RFB_CHECK_EQ_INT(
        apple_srp_parse_auth_response(mutated, valid_len, &response),
        RFB_ERR_PROTOCOL);

    memcpy(mutated, valid, valid_len);
    srp_test_put_u32(mutated, 0u, 7u);
    srp_test_put_u16(mutated, 8u, 1u);
    RFB_CHECK_EQ_INT(
        apple_srp_parse_auth_response(mutated, valid_len, &response),
        RFB_ERR_PROTOCOL);

    memcpy(mutated, valid, valid_len);
    mutated[11u] = 1u;
    RFB_CHECK_EQ_INT(
        apple_srp_parse_auth_response(mutated, valid_len, &response),
        RFB_ERR_PROTOCOL);

    memcpy(mutated, valid, valid_len);
    srp_test_put_u16(mutated, 12u, 81u);
    RFB_CHECK_EQ_INT(
        apple_srp_parse_auth_response(mutated, valid_len, &response),
        RFB_ERR_PROTOCOL);

    memcpy(mutated, valid, valid_len);
    srp_test_put_u16(mutated, 12u, 83u);
    RFB_CHECK_EQ_INT(
        apple_srp_parse_auth_response(mutated, 96u, &response),
        RFB_ERR_PROTOCOL);

    memcpy(mutated, valid, valid_len);
    mutated[valid_len] = 0xEEu;
    RFB_CHECK_EQ_INT(
        apple_srp_parse_auth_response(mutated, valid_len + 1u, &response),
        RFB_ERR_PROTOCOL);
}

RFB_TEST(g26_srp, packet2__empty_options_and_argument_bounds)
{
    apple_srp_session session;
    memset(&session, 0, sizeof session);
    session.N_len = APPLE_SRP_N_BYTES;
    session.A_len = APPLE_SRP_N_BYTES;
    session.M1_len = APPLE_SRP_M1_BYTES;
    uint8_t random[16] = {0u};
    uint8_t out[1024];
    size_t out_len = 0u;
    RFB_CHECK_EQ_INT(
        apple_srp_serialize_packet2(
            &session, NULL, 0u, random, out, sizeof out, &out_len),
        RFB_OK);
    RFB_CHECK(out_len > 0u);
    RFB_CHECK_EQ_INT(
        apple_srp_serialize_packet2(
            &session, NULL, 0u, random, NULL, sizeof out, &out_len),
        RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(
        apple_srp_serialize_packet2(
            &session, NULL, 0u, NULL, out, sizeof out, &out_len),
        RFB_ERR_INTERNAL);
}

RFB_TEST(g26_srp, packet2__invalid_lengths_and_options__fail_before_write)
{
    apple_srp_session session;
    memset(&session, 0, sizeof session);
    session.N_len = APPLE_SRP_N_BYTES;
    session.A_len = APPLE_SRP_N_BYTES;
    session.M1_len = APPLE_SRP_M1_BYTES;
    uint8_t random[16] = {0u};
    uint8_t out = 0u;
    size_t out_len = 0u;

    session.N_len--;
    RFB_CHECK_EQ_INT(
        apple_srp_serialize_packet2(
            &session, NULL, 0u, random, &out, 0u, &out_len),
        RFB_ERR_PROTOCOL);
    session.N_len++;

    session.A_len--;
    RFB_CHECK_EQ_INT(
        apple_srp_serialize_packet2(
            &session, NULL, 0u, random, &out, 0u, &out_len),
        RFB_ERR_PROTOCOL);
    session.A_len += 2u;
    RFB_CHECK_EQ_INT(
        apple_srp_serialize_packet2(
            &session, NULL, 0u, random, &out, 0u, &out_len),
        RFB_ERR_PROTOCOL);
    session.A_len--;

    session.M1_len--;
    RFB_CHECK_EQ_INT(
        apple_srp_serialize_packet2(
            &session, NULL, 0u, random, &out, 0u, &out_len),
        RFB_ERR_PROTOCOL);
    session.M1_len += 2u;
    RFB_CHECK_EQ_INT(
        apple_srp_serialize_packet2(
            &session, NULL, 0u, random, &out, 0u, &out_len),
        RFB_ERR_PROTOCOL);
    session.M1_len--;

    RFB_CHECK_EQ_INT(
        apple_srp_serialize_packet2(
            &session, NULL, 1u, random, &out, 0u, &out_len),
        RFB_ERR_INTERNAL);
}
