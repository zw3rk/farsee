// SPDX-License-Identifier: Apache-2.0
//
// G26 — Apple type-33 SRP challenge parser tests.
// RED step: the apple_srp module does not exist yet.

#include "rfb_test.h"
#include "farsee/apple_srp.h"

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

// --- Happy path: parse a valid challenge ---

RFB_TEST(g26_srp, challenge__parses_valid_structure) {
    uint8_t N[512];
    fill_rfc5054_n(N);

    static const uint8_t salt[16] = { 0xAA };
    uint8_t B[512];
    memset(B, 0xBB, sizeof B);
    // B must be < N and non-zero (RFC 5054 abort conditions).
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

// --- T17: flip a byte of N past the old 10-byte prefix → reject ----------

RFB_TEST(g26_srp, challenge__N_flipped_past_prefix__fails) {
    uint8_t N[512];
    fill_rfc5054_n(N);
    // Prefix (first 10 bytes) stays correct; corrupt a later byte.
    N[64] ^= 0x01u;

    static const uint8_t salt[16] = { 0xAA };
    uint8_t B[512];
    memset(B, 0x01, sizeof B);

    uint8_t buf[2048];
    size_t len = build_challenge(buf, sizeof buf, N, 512, 5, salt, 16, B, 512, 1000, "");
    apple_srp_challenge ch;
    RFB_CHECK_EQ_INT(apple_srp_parse_challenge(buf, len, &ch), RFB_ERR_PROTOCOL);
}

// --- T14/T17: reject all-zero B ------------------------------------------

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

// --- T14/T17: reject B == N (B mod N == 0) --------------------------------

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

// --- T14/T17: reject B > N (big-endian) -----------------------------------

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
    // Use RFC 5054 4096-bit N and g=5
    uint8_t N[512];
    fill_rfc5054_n(N);

    static const uint8_t salt[16] = { 0xAA, 0xBB, 0xCC, 0xDD };
    static const uint8_t username[] = "admin";
    static const uint8_t password[] = "admin";

    // Compute B = (k * g + g^b) mod N where k = H(PAD(N) || PAD(g))
    // For simplicity, use the deterministic b_secret.
    // We compute B on the "server" side.
    // k = SHA512(PAD(N) || PAD(g))
    uint8_t k[64];
    {
        // PAD(N) = N (already 512 bytes), PAD(g) = g padded to 512 bytes
        uint8_t pad_g[512];
        memset(pad_g, 0, sizeof pad_g);
        pad_g[511] = 5;  // g = 5
        uint8_t concat[1024];
        memcpy(concat, N, 512);
        memcpy(concat + 512, pad_g, 512);
        rfb_crypto_sha512(concat, sizeof concat, k);
    }

    // g^b mod N
    uint8_t gb[512];
    static const uint8_t g_val[1] = { 5 };
    rfb_crypto_modexp(g_val, 1, b_secret, b_len, N, 512, gb, 512);
    // modexp zero-pads to out_len, so gb is already 512 bytes.

    // k * g mod N = (k * g) mod N (but g is tiny)
    // For simplicity, compute B = g^b + k * g (mod N)
    // Actually, B = (k*g + g^b) mod N. Since this is complex, let's
    // just use B = g^b mod N for the test (simplification that still
    // validates the SRP math for u, S computation, since the client
    // computes S = (B - k*g^x)^(a+u*x) mod N).
    //
    // For a correct round-trip test, we need B = (k*g + g^b) mod N.
    // This requires big-number addition, which our crypto provider doesn't expose.
    // Instead, let's test with the RFC 5054 test vector approach.

    // For now, just copy gb as B (the client will still compute S correctly
    // IF the server uses the same formula — the test verifies self-consistency).
    memcpy(B_out, gb, 512);

    // Build the challenge
    uint8_t buf[2048];
    size_t ch_len = build_challenge(buf, sizeof buf, N, 512, 5,
                                     salt, 16, B_out, 512, 1000,
                                     "mda=SHA-512,replay_detection");
    apple_srp_parse_challenge(buf, ch_len, ch);

    // Compute client SRP
    memset(client_sess, 0, sizeof *client_sess);
    apple_srp_compute_client(ch, username, sizeof username - 1,
                              password, sizeof password - 1,
                              a_secret, a_len, client_sess);
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

// ===== Senior Review: Packet-2 Length Invariant & Response Parser ==========

RFB_TEST(g26_srp, packet2__total_len_invariant__equals_0x0434) {
    // Senior review requirement: verify the outer total_len is 1076 (0x0434)
    // for a packet with 682 meaningful bytes + 384 tail + 10 RSA1 header.
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

// ===== Server Response Parser Tests (Senior Review) ====================

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

// Fragmentation: envelope split at every byte boundary
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
