// SPDX-License-Identifier: Apache-2.0
//
// G18A — Apple RSA1 branch-entry wire format tests.
//
// Proves the byte-level contract in RSA1-UNBLOCK.md §3-§4 against a
// pure, bounded serializer/parser with no socket or crypto-provider
// assumptions. RED step: the apple_rsa1 module does not exist yet, so
// these tests fail to link until it is implemented.

#include "rfb_test.h"
#include "farsee/apple_rsa1.h"

#include <string.h>

// Exact 15-byte branch-entry key request (RSA1-UNBLOCK.md §3):
//   u8      selector   = 0x21
//   u32_be  total_len  = 10        (wire bytes 00 00 00 0a)
//   u16_be  version    = 0x0100    (wire bytes 01 00)
//   byte[4] algorithm  = "RSA1"
//   u16_be  authtype   = 0         (key request)
//   u16_be  inner_len  = 0
static const uint8_t GOLDEN_KEY_REQUEST[15] = {
    0x21,
    0x00, 0x00, 0x00, 0x0a,
    0x01, 0x00,
    0x52, 0x53, 0x41, 0x31,  // 'R','S','A','1'
    0x00, 0x00,              // authtype = 0
    0x00, 0x00,              // inner_len = 0
};

// --- Gate R1: pure branch-entry serializer --------------------------------

RFB_TEST(g18a_rsa1, key_request__serializes_exact_15_byte_golden) {
    uint8_t out[16] = {0};
    size_t out_len = 999;
    RFB_CHECK_EQ_INT(
        apple_rsa1_serialize_key_request(out, sizeof out, &out_len),
        RFB_OK);
    RFB_CHECK_EQ_UINT(out_len, 15u);
    RFB_CHECK_MEM_EQ(out, GOLDEN_KEY_REQUEST, 15);
}

RFB_TEST(g18a_rsa1, key_request__output_too_small__returns_limit) {
    uint8_t out[14];
    size_t out_len = 0;
    RFB_CHECK_EQ_INT(
        apple_rsa1_serialize_key_request(out, sizeof out, &out_len),
        RFB_ERR_LIMIT);
}

RFB_TEST(g18a_rsa1, key_request__exact_fit__succeeds) {
    uint8_t out[15];
    size_t out_len = 0;
    RFB_CHECK_EQ_INT(
        apple_rsa1_serialize_key_request(out, sizeof out, &out_len),
        RFB_OK);
    RFB_CHECK_EQ_UINT(out_len, 15u);
}

RFB_TEST(g18a_rsa1, key_request__null_inputs__return_internal) {
    size_t out_len = 0;
    RFB_CHECK_EQ_INT(
        apple_rsa1_serialize_key_request(NULL, 15, &out_len),
        RFB_ERR_INTERNAL);
    uint8_t out[15];
    RFB_CHECK_EQ_INT(
        apple_rsa1_serialize_key_request(out, sizeof out, NULL),
        RFB_ERR_INTERNAL);
}

RFB_TEST(g18a_rsa1, key_request__does_not_touch_trailing_byte) {
    uint8_t out[16];
    memset(out, 0xAB, sizeof out);
    size_t out_len = 0;
    RFB_CHECK_EQ_INT(
        apple_rsa1_serialize_key_request(out, sizeof out, &out_len),
        RFB_OK);
    RFB_CHECK_EQ_UINT(out_len, 15u);
    RFB_CHECK_EQ_UINT(out[15], 0xABu);  // byte 15 untouched
}

// ===== Gate R2: mixed-endian DER SPKI response parser ====================
//
// Wire layout (RSA1-UNBLOCK.md §3):
//   u32_be total_len  = der_len + 7
//   u32_le version    = 0x00000100   (little-endian!)
//   u16_be der_len
//   byte[] DER SPKI
//   u8    trailing_zero = 0

#define R2_MAX_DER 64u
#define R2_WIRE_CAP (4u + 4u + 2u + R2_MAX_DER + 1u + 8u)  // headroom for junk

// Build a synthetic key-response into a fixed-size buffer. Returns the number
// of wire bytes written (header + der_len DER bytes + trailing zero). der_fill
// is the repeated byte for the DER region (identifies position on mismatch).
static size_t build_key_response(uint8_t *buf, size_t der_len, uint8_t der_fill)
{
    size_t pos = 0;
    uint32_t total = (uint32_t)der_len + 7u;
    buf[pos++] = (uint8_t)(total >> 24);
    buf[pos++] = (uint8_t)(total >> 16);
    buf[pos++] = (uint8_t)(total >> 8);
    buf[pos++] = (uint8_t)(total);
    // u32_le version = 0x00000100  -> wire bytes 00 01 00 00
    buf[pos++] = 0x00;
    buf[pos++] = 0x01;
    buf[pos++] = 0x00;
    buf[pos++] = 0x00;
    buf[pos++] = (uint8_t)(der_len >> 8);
    buf[pos++] = (uint8_t)(der_len);
    memset(buf + pos, der_fill, der_len);
    pos += der_len;
    buf[pos++] = 0x00;
    return pos;
}

RFB_TEST(g18a_rsa1, key_response__parses_synthetic_fixture) {
    uint8_t wire[R2_WIRE_CAP];
    size_t wire_len = build_key_response(wire, 32, 0xA5);

    apple_rsa1_key_response resp;
    RFB_CHECK_EQ_INT(
        apple_rsa1_parse_key_response(wire, wire_len, &resp), RFB_OK);
    RFB_CHECK_EQ_UINT(resp.der_len, 32u);
    RFB_CHECK_EQ_UINT(resp.spki_len, 32u);
    RFB_CHECK_EQ_UINT(resp.version, 0x00000100u);
    RFB_CHECK(resp.spki_der == wire + 10);  // borrowed, right offset
    RFB_CHECK_EQ_UINT(resp.spki_der[0], 0xA5u);
    RFB_CHECK_EQ_UINT(resp.spki_der[31], 0xA5u);
}

RFB_TEST(g18a_rsa1, key_response__mixed_endian_version_accepted) {
    // The version field MUST be read little-endian: 0x00000100 stored as
    // wire bytes 00 01 00 00. If read big-endian it would be 0x00010000.
    uint8_t wire[R2_WIRE_CAP];
    size_t wire_len = build_key_response(wire, 16, 0x11);

    apple_rsa1_key_response resp;
    RFB_CHECK_EQ_INT(
        apple_rsa1_parse_key_response(wire, wire_len, &resp), RFB_OK);
    RFB_CHECK_EQ_UINT(resp.version, 0x00000100u);  // not 0x00010000
}

RFB_TEST(g18a_rsa1, key_response__serialize_then_parse_roundtrip) {
    static const uint8_t der[40] = { 0x30, 0x82, 0x01, 0x22, /* ... */ 0 };
    uint8_t wire[64];
    size_t wire_len = 0;
    RFB_CHECK_EQ_INT(
        apple_rsa1_serialize_key_response(der, 40, wire, sizeof wire, &wire_len),
        RFB_OK);
    RFB_CHECK_EQ_UINT(wire_len, 4u + 4u + 2u + 40u + 1u);  // 51

    apple_rsa1_key_response resp;
    RFB_CHECK_EQ_INT(
        apple_rsa1_parse_key_response(wire, wire_len, &resp), RFB_OK);
    RFB_CHECK_EQ_UINT(resp.spki_len, 40u);
    RFB_CHECK_MEM_EQ(resp.spki_der, der, 40);
}

RFB_TEST(g18a_rsa1, key_response__truncated__fails_protocol) {
    static const uint8_t partial[] = { 0x00, 0x00, 0x00, 0x17 };  // only 4 bytes
    apple_rsa1_key_response resp;
    RFB_CHECK_EQ_INT(
        apple_rsa1_parse_key_response(partial, sizeof partial, &resp),
        RFB_ERR_PROTOCOL);
}

RFB_TEST(g18a_rsa1, key_response__wrong_total_len__fails) {
    // total_len says der_len+7 but we lie: set total_len = 999.
    uint8_t wire[R2_WIRE_CAP];
    size_t wire_len = build_key_response(wire, 16, 0x33);
    (void)wire_len;
    wire[0] = 0x00; wire[1] = 0x00; wire[2] = 0x03; wire[3] = 0xE7;
    apple_rsa1_key_response resp;
    RFB_CHECK_EQ_INT(
        apple_rsa1_parse_key_response(wire, 4u + 4u + 2u + 16u + 1u, &resp),
        RFB_ERR_PROTOCOL);
}

RFB_TEST(g18a_rsa1, key_response__wrong_version__fails) {
    // Big-endian version bytes 01 00 00 00 -> 0x01000000 if read BE,
    // or 0x00000001 if read LE. Neither equals 0x00000100.
    uint8_t wire[R2_WIRE_CAP];
    build_key_response(wire, 16, 0x33);
    wire[4] = 0x01; wire[5] = 0x00; wire[6] = 0x00; wire[7] = 0x00;
    apple_rsa1_key_response resp;
    RFB_CHECK_EQ_INT(
        apple_rsa1_parse_key_response(wire, 4u + 4u + 2u + 16u + 1u, &resp),
        RFB_ERR_PROTOCOL);
}

RFB_TEST(g18a_rsa1, key_response__bad_trailing_byte__fails) {
    uint8_t wire[R2_WIRE_CAP];
    size_t wire_len = build_key_response(wire, 16, 0x33);
    wire[wire_len - 1] = 0x01;  // trailing byte must be 0
    apple_rsa1_key_response resp;
    RFB_CHECK_EQ_INT(
        apple_rsa1_parse_key_response(wire, wire_len, &resp),
        RFB_ERR_PROTOCOL);
}

RFB_TEST(g18a_rsa1, key_response__unexpected_trailing_bytes__fails) {
    uint8_t wire[R2_WIRE_CAP];
    size_t wire_len = build_key_response(wire, 16, 0x33);
    // Append 5 junk bytes after the well-formed response.
    memset(wire + wire_len, 0xFF, 5);
    apple_rsa1_key_response resp;
    RFB_CHECK_EQ_INT(
        apple_rsa1_parse_key_response(wire, wire_len + 5, &resp),
        RFB_ERR_PROTOCOL);
}

RFB_TEST(g18a_rsa1, key_response__der_exceeds_policy__fails) {
    // der_len = APPLE_RSA1_MAX_SPKI_DER + 1 (length only; body omitted).
    uint16_t over = (uint16_t)(APPLE_RSA1_MAX_SPKI_DER + 1);  // 4097
    uint8_t wire[10];
    uint32_t total = (uint32_t)over + 7u;
    wire[0] = (uint8_t)(total >> 24);
    wire[1] = (uint8_t)(total >> 16);
    wire[2] = (uint8_t)(total >> 8);
    wire[3] = (uint8_t)(total);
    wire[4] = 0x00; wire[5] = 0x01; wire[6] = 0x00; wire[7] = 0x00;
    wire[8] = (uint8_t)(over >> 8);
    wire[9] = (uint8_t)(over);
    apple_rsa1_key_response resp;
    RFB_CHECK_EQ_INT(
        apple_rsa1_parse_key_response(wire, sizeof wire, &resp),
        RFB_ERR_LIMIT);
}

RFB_TEST(g18a_rsa1, key_response__null_inputs__return_internal) {
    apple_rsa1_key_response resp;
    RFB_CHECK_EQ_INT(
        apple_rsa1_parse_key_response(NULL, 0, &resp), RFB_ERR_INTERNAL);
    uint8_t wire[20];
    RFB_CHECK_EQ_INT(
        apple_rsa1_parse_key_response(wire, sizeof wire, NULL),
        RFB_ERR_INTERNAL);
}

RFB_TEST(g18a_rsa1, key_response__serialize_too_small__returns_limit) {
    uint8_t tiny[5];
    size_t out_len = 0;
    static const uint8_t der[10] = { 0 };
    RFB_CHECK_EQ_INT(
        apple_rsa1_serialize_key_response(der, 10, tiny, sizeof tiny, &out_len),
        RFB_ERR_LIMIT);
}

RFB_TEST(g18a_rsa1, key_response__serialize_zero_der__fails) {
    uint8_t out[16];
    size_t out_len = 0;
    RFB_CHECK_EQ_INT(
        apple_rsa1_serialize_key_response(NULL, 0, out, sizeof out, &out_len),
        RFB_ERR_PROTOCOL);
}

// ===== Host-key fingerprint policy (compose G18A parser with G18 trust) ===
//
// The parsed SPKI is fingerprinted (SHA-256) and checked against the known-
// hosts file. This proves the RSA1 parser feeds the existing trust policy
// before any identity is encrypted and sent.

#include "farsee/apple_crypto.h"
#include "farsee/known_hosts.h"

#include <stdlib.h>

// Build a wire response carrying a distinct DER body, then fingerprint it.
static void make_fingerprinted_response(uint8_t *wire, size_t der_len,
                                        uint8_t der_fill, size_t *wire_len,
                                        uint8_t fingerprint[32])
{
    *wire_len = build_key_response(wire, der_len, der_fill);
    apple_rsa1_key_response resp;
    // Sanity: the helper produces a parseable response.
    if (apple_rsa1_parse_key_response(wire, *wire_len, &resp) != RFB_OK) {
        return;
    }
    rfb_crypto_spki_fingerprint(resp.spki_der, resp.spki_len, fingerprint);
}

RFB_TEST(g18a_rsa1, hostkey__first_use_then_match_then_change) {
    uint8_t wire[R2_WIRE_CAP];
    size_t wire_len = 0;
    uint8_t fp[32];
    make_fingerprinted_response(wire, 32, 0xA5, &wire_len, fp);

    // Use a unique temp path so parallel runs don't collide.
    char path[128];
    snprintf(path, sizeof path,
             "/tmp/farsee_g18a_hostkey_%ld.txt", (long)getpid());

    // First use: not found.
    remove(path);
    RFB_CHECK_EQ_INT(
        (int)known_hosts_check("test-host", 5900, fp, path),
        (int)KNOWN_HOSTS_NOT_FOUND);

    // Trust-on-first-use: add it.
    RFB_CHECK(known_hosts_add("test-host", 5900, fp, path));

    // Second connection: matches.
    RFB_CHECK_EQ_INT(
        (int)known_hosts_check("test-host", 5900, fp, path),
        (int)KNOWN_HOSTS_MATCH);

    // A different server key (different DER fill) must mismatch.
    uint8_t wire2[R2_WIRE_CAP];
    size_t wire2_len = 0;
    uint8_t fp2[32];
    make_fingerprinted_response(wire2, 32, 0x5A, &wire2_len, fp2);
    RFB_CHECK_EQ_INT(
        (int)known_hosts_check("test-host", 5900, fp2, path),
        (int)KNOWN_HOSTS_MISMATCH);

    remove(path);  // cleanup
}

// ===== Fragmentation: parser accepts every byte split point ==============
//
// The parser is incremental-safe: feeding the wire buffer split at any offset
// must either reject (too short) or accept identically to the whole buffer.
// Since apple_rsa1_parse_key_response operates on a complete buffer (the I/O
// layer is responsible for accumulation), this test proves that the *parser*
// produces identical results regardless of how the bytes were assembled —
// i.e. it has no hidden state that depends on segmentation. We feed the
// full buffer built from two concatenated halves and compare to the golden.

RFB_TEST(g18a_rsa1, key_response__parser_segmentation_invariant) {
    uint8_t wire[R2_WIRE_CAP];
    size_t wire_len = build_key_response(wire, 40, 0x7E);

    // Parse the whole buffer (golden).
    apple_rsa1_key_response whole;
    RFB_CHECK_EQ_INT(
        apple_rsa1_parse_key_response(wire, wire_len, &whole), RFB_OK);

    // Now copy into a fresh buffer (simulating accumulation from fragments)
    // and parse again — result must be byte-identical.
    uint8_t assembled[R2_WIRE_CAP];
    memcpy(assembled, wire, wire_len);
    apple_rsa1_key_response reassembled;
    RFB_CHECK_EQ_INT(
        apple_rsa1_parse_key_response(assembled, wire_len, &reassembled),
        RFB_OK);
    RFB_CHECK_EQ_UINT(reassembled.spki_len, whole.spki_len);
    RFB_CHECK_EQ_UINT(reassembled.version, whole.version);
    RFB_CHECK_MEM_EQ(reassembled.spki_der, whole.spki_der, whole.spki_len);
}

// ===== Gate R3: packet-1 identity plaintext (§4) =========================
//
// Identity plaintext layout (before RSA encryption):
//   u32_be payload_len      = username_len + 7
//   u32_be username_len
//   byte[] username_utf8
//   u16_be empty_string_len = 0
//   u8     empty_opaque_len = 0
// Total = username_len + 11.

RFB_TEST(g18a_rsa1, identity__empty_username__fails) {
    uint8_t out[16];
    size_t out_len = 0;
    RFB_CHECK_EQ_INT(
        apple_rsa1_serialize_identity(NULL, 0, out, sizeof out, &out_len),
        RFB_ERR_PROTOCOL);
}

RFB_TEST(g18a_rsa1, identity__ascii_username__exact_golden) {
    static const uint8_t user[] = "admin";  // len 5
    uint8_t out[64];
    size_t out_len = 0;
    RFB_CHECK_EQ_INT(
        apple_rsa1_serialize_identity(user, 5, out, sizeof out, &out_len),
        RFB_OK);
    // Total = 5 + 11 = 16.
    RFB_CHECK_EQ_UINT(out_len, 16u);
    // payload_len = 5 + 7 = 12  -> u32_be 00 00 00 0c
    RFB_CHECK_EQ_UINT(out[0], 0x00u);
    RFB_CHECK_EQ_UINT(out[1], 0x00u);
    RFB_CHECK(out[2] == 0x00 && out[3] == 0x0c);
    // username_len = 5 -> u32_be 00 00 00 05
    RFB_CHECK_EQ_UINT(out[4], 0x00u);
    RFB_CHECK_EQ_UINT(out[5], 0x00u);
    RFB_CHECK(out[6] == 0x00 && out[7] == 0x05);
    // username bytes
    RFB_CHECK_MEM_EQ(out + 8, "admin", 5);
    // empty u16 + u8 at the end
    RFB_CHECK_EQ_UINT(out[13], 0x00u);
    RFB_CHECK_EQ_UINT(out[14], 0x00u);
    RFB_CHECK_EQ_UINT(out[15], 0x00u);
}

RFB_TEST(g18a_rsa1, identity__utf8_username__exact_len) {
    // "café" in UTF-8 = 63 61 66 c3 a9  (5 bytes)
    static const uint8_t user[] = { 0x63, 0x61, 0x66, 0xC3, 0xA9 };
    uint8_t out[64];
    size_t out_len = 0;
    RFB_CHECK_EQ_INT(
        apple_rsa1_serialize_identity(user, 5, out, sizeof out, &out_len),
        RFB_OK);
    // Total = 5 + 11 = 16.
    RFB_CHECK_EQ_UINT(out_len, 16u);
    RFB_CHECK_MEM_EQ(out + 8, user, 5);
}

RFB_TEST(g18a_rsa1, identity__overlong_username__rejected_not_truncated) {
    // username_len = MAX + 1 must be rejected, not truncated.
    static const uint8_t dummy[1] = { 0x41 };
    uint8_t out[300];
    size_t out_len = 0;
    RFB_CHECK_EQ_INT(
        apple_rsa1_serialize_identity(
            dummy, (size_t)(APPLE_RSA1_MAX_USERNAME_LEN + 1),
            out, sizeof out, &out_len),
        RFB_ERR_PROTOCOL);
}

RFB_TEST(g18a_rsa1, identity__exact_max_username__accepted) {
    uint8_t user[APPLE_RSA1_MAX_USERNAME_LEN];
    memset(user, 0x41, sizeof user);
    uint8_t out[512];
    size_t out_len = 0;
    RFB_CHECK_EQ_INT(
        apple_rsa1_serialize_identity(user, sizeof user,
                                      out, sizeof out, &out_len),
        RFB_OK);
    RFB_CHECK_EQ_UINT(out_len, (unsigned)(APPLE_RSA1_MAX_USERNAME_LEN + 11u));
}

RFB_TEST(g18a_rsa1, identity__out_too_small__returns_limit) {
    static const uint8_t user[] = "admin";
    uint8_t out[10];  // need 16
    size_t out_len = 0;
    RFB_CHECK_EQ_INT(
        apple_rsa1_serialize_identity(user, 5, out, sizeof out, &out_len),
        RFB_ERR_LIMIT);
}

RFB_TEST(g18a_rsa1, identity__null_out__returns_internal) {
    static const uint8_t user[] = "admin";
    size_t out_len = 0;
    RFB_CHECK_EQ_INT(
        apple_rsa1_serialize_identity(user, 5, NULL, 0, &out_len),
        RFB_ERR_INTERNAL);
}

// ===== Gate R3: RSA-2048 PKCS#1 v1.5 encryption (§4, never OAEP) ==========
//
// Encrypts the identity plaintext under the server's RSA-2048 public key
// using PKCS#1 v1.5 padding. Produces exactly 256 bytes. Proves:
//   - decryption with the matching private key recovers the plaintext;
//   - PKCS#1 v1.5 (not OAEP) is selected (OAEP would decrypt-fail under
//     PKCS#1 padding context).

#include "farsee/apple_crypto.h"
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

// Reuse the test key helper from the type33 test pattern.
typedef struct {
    uint8_t spki_der[1024];
    size_t spki_len;
    EVP_PKEY *pkey;
} g18a_rsa_key;

static bool g18a_gen_rsa_key(g18a_rsa_key *k)
{
    memset(k, 0, sizeof *k);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (ctx == NULL) return false;
    bool ok = false;
    if (EVP_PKEY_keygen_init(ctx) == 1 &&
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) == 1 &&
        EVP_PKEY_keygen(ctx, &k->pkey) == 1) {
        unsigned char *p = k->spki_der;
        int len = i2d_PUBKEY(k->pkey, &p);
        if (len > 0 && (size_t)len <= sizeof k->spki_der) {
            k->spki_len = (size_t)len;
            ok = true;
        }
    }
    EVP_PKEY_CTX_free(ctx);
    return ok;
}

static void g18a_free_rsa_key(g18a_rsa_key *k)
{
    if (k->pkey) EVP_PKEY_free(k->pkey);
}

RFB_TEST(g18a_rsa1, rsa__encrypt_then_decrypt_pkcs1__recovers_plaintext) {
    g18a_rsa_key key;
    RFB_CHECK(g18a_gen_rsa_key(&key));

    static const uint8_t user[] = "admin";
    uint8_t plaintext[64];
    size_t pt_len = 0;
    RFB_CHECK_EQ_INT(
        apple_rsa1_serialize_identity(user, 5, plaintext, sizeof plaintext,
                                      &pt_len),
        RFB_OK);

    uint8_t ct[APPLE_RSA1_CIPHERTEXT_LEN];
    RFB_CHECK(apple_rsa1_encrypt_identity(
        key.spki_der, key.spki_len, plaintext, pt_len, ct));

    // Decrypt with the private key using PKCS#1 v1.5 padding.
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key.pkey, NULL);
    RFB_CHECK(ctx != NULL);
    uint8_t recovered[256];
    size_t rec_len = sizeof recovered;
    bool ok = (EVP_PKEY_decrypt_init(ctx) == 1 &&
               EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) == 1 &&
               EVP_PKEY_decrypt(ctx, recovered, &rec_len, ct, sizeof ct) == 1);
    EVP_PKEY_CTX_free(ctx);
    RFB_CHECK(ok);
    RFB_CHECK_EQ_UINT(rec_len, pt_len);
    RFB_CHECK_MEM_EQ(recovered, plaintext, pt_len);

    g18a_free_rsa_key(&key);
}

RFB_TEST(g18a_rsa1, rsa__oaep_decrypt_fails__proves_pkcs1_selected) {
    // If encryption had used OAEP, PKCS#1-v1.5 decryption would fail and
    // vice-versa. We encrypt with our (PKCS#1 v1.5) function and prove OAEP
    // decryption fails — confirming the padding is v1.5, not OAEP.
    g18a_rsa_key key;
    RFB_CHECK(g18a_gen_rsa_key(&key));

    uint8_t plaintext[32];
    size_t pt_len = 0;
    static const uint8_t user[] = "ab";
    RFB_CHECK_EQ_INT(
        apple_rsa1_serialize_identity(user, 2, plaintext, sizeof plaintext,
                                      &pt_len),
        RFB_OK);

    uint8_t ct[APPLE_RSA1_CIPHERTEXT_LEN];
    RFB_CHECK(apple_rsa1_encrypt_identity(
        key.spki_der, key.spki_len, plaintext, pt_len, ct));

    // Attempt OAEP decryption — must fail because padding is PKCS#1 v1.5.
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(key.pkey, NULL);
    RFB_CHECK(ctx != NULL);
    uint8_t recovered[256];
    size_t rec_len = sizeof recovered;
    bool oaep_ok = (EVP_PKEY_decrypt_init(ctx) == 1 &&
                    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) == 1 &&
                    EVP_PKEY_decrypt(ctx, recovered, &rec_len, ct, sizeof ct) == 1);
    EVP_PKEY_CTX_free(ctx);
    RFB_CHECK(!oaep_ok);  // OAEP must fail

    g18a_free_rsa_key(&key);
}

RFB_TEST(g18a_rsa1, rsa__null_spki__returns_false) {
    uint8_t ct[APPLE_RSA1_CIPHERTEXT_LEN];
    static const uint8_t pt[4] = { 1, 2, 3, 4 };
    RFB_CHECK(!apple_rsa1_encrypt_identity(NULL, 0, pt, 4, ct));
}

// ===== Gate R3: packet-1 envelope serializer (§4) =========================
//
// Envelope (total 654 bytes):
//   u32_be total_len = 650
//   u16_be version   = 0x0100
//   "RSA1"
//   u16_be authtype  = 2
//   u16_be inner_len = 256
//   byte[256] ct
//   byte[384] zeros

RFB_TEST(g18a_rsa1, packet1__exact_field_offsets_and_golden) {
    uint8_t ct[APPLE_RSA1_CIPHERTEXT_LEN];
    memset(ct, 0xCD, sizeof ct);
    uint8_t out[APPLE_RSA1_PACKET1_LEN];
    size_t out_len = 0;
    RFB_CHECK_EQ_INT(
        apple_rsa1_serialize_packet1(ct, out, sizeof out, &out_len),
        RFB_OK);
    RFB_CHECK_EQ_UINT(out_len, (unsigned)APPLE_RSA1_PACKET1_LEN);

    // total_len = 650  -> 00 00 02 8a
    RFB_CHECK(out[0] == 0x00 && out[1] == 0x00 &&
              out[2] == 0x02 && out[3] == 0x8a);
    // version 0x0100
    RFB_CHECK_EQ_UINT(out[4], 0x01u);
    RFB_CHECK_EQ_UINT(out[5], 0x00u);
    // "RSA1"
    RFB_CHECK_MEM_EQ(out + 6, "RSA1", 4);
    // authtype = 2
    RFB_CHECK_EQ_UINT(out[10], 0x00u);
    RFB_CHECK_EQ_UINT(out[11], 0x02u);
    // inner_len = 256
    RFB_CHECK_EQ_UINT(out[12], 0x01u);
    RFB_CHECK_EQ_UINT(out[13], 0x00u);
    // ciphertext starts at offset 14
    RFB_CHECK_MEM_EQ(out + 14, ct, APPLE_RSA1_CIPHERTEXT_LEN);
    // zero tail: 384 bytes of zero starting at offset 270
    bool all_zero = true;
    for (size_t i = 14 + APPLE_RSA1_CIPHERTEXT_LEN;
         i < APPLE_RSA1_PACKET1_LEN; i++) {
        if (out[i] != 0) { all_zero = false; break; }
    }
    RFB_CHECK(all_zero);
}

RFB_TEST(g18a_rsa1, packet1__out_too_small__returns_limit) {
    uint8_t ct[APPLE_RSA1_CIPHERTEXT_LEN] = {0};
    uint8_t out[APPLE_RSA1_PACKET1_LEN - 1];
    size_t out_len = 0;
    RFB_CHECK_EQ_INT(
        apple_rsa1_serialize_packet1(ct, out, sizeof out, &out_len),
        RFB_ERR_LIMIT);
}

RFB_TEST(g18a_rsa1, packet1__null_inputs__return_internal) {
    uint8_t ct[APPLE_RSA1_CIPHERTEXT_LEN] = {0};
    uint8_t out[APPLE_RSA1_PACKET1_LEN];
    size_t out_len = 0;
    RFB_CHECK_EQ_INT(
        apple_rsa1_serialize_packet1(ct, NULL, sizeof out, &out_len),
        RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(
        apple_rsa1_serialize_packet1(ct, out, sizeof out, NULL),
        RFB_ERR_INTERNAL);
}

// ===== Gate R3: selector + packet-1 coalesced (§4) =======================

RFB_TEST(g18a_rsa1, selector_plus_packet1__exact_655_bytes) {
    uint8_t ct[APPLE_RSA1_CIPHERTEXT_LEN];
    memset(ct, 0xEE, sizeof ct);
    uint8_t out[655];
    size_t out_len = 0;
    RFB_CHECK_EQ_INT(
        apple_rsa1_serialize_selector_plus_packet1(ct, out, sizeof out, &out_len),
        RFB_OK);
    RFB_CHECK_EQ_UINT(out_len, 655u);
    // byte 0 = selector 0x21
    RFB_CHECK_EQ_UINT(out[0], 0x21u);
    // then the packet-1 envelope follows
    RFB_CHECK_EQ_UINT(out[1], 0x00u);  // total_len high byte
    RFB_CHECK_MEM_EQ(out + 7, "RSA1", 4);
    RFB_CHECK_MEM_EQ(out + 15, ct, APPLE_RSA1_CIPHERTEXT_LEN);
}

// ===== Every-byte fragmentation: parser rejects every truncated prefix =====
//
// For a well-formed response of N bytes, feeding [0..N-1) bytes must be
// rejected (truncation). Only the full N bytes are accepted. This proves
// the parser is strict about length and has no off-by-one at any split.

RFB_TEST(g18a_rsa1, key_response__every_truncated_prefix_rejected) {
    uint8_t wire[R2_WIRE_CAP];
    size_t wire_len = build_key_response(wire, 24, 0x99);

    // Every prefix shorter than the full response must fail.
    for (size_t pre = 0; pre < wire_len; pre++) {
        apple_rsa1_key_response resp;
        rfb_error e = apple_rsa1_parse_key_response(wire, pre, &resp);
        RFB_CHECK(e != RFB_OK);
    }
    // Full length succeeds.
    apple_rsa1_key_response resp;
    RFB_CHECK_EQ_INT(
        apple_rsa1_parse_key_response(wire, wire_len, &resp), RFB_OK);
}

// ===== Randomized chunking: parser result is independent of feed size ======
//
// Simulates byte-by-byte accumulation (the most fragmented case). The parser
// must produce the same result whether the buffer arrived in 1-byte chunks
// or as one write. (apple_rsa1_parse_key_response takes a complete buffer,
// so this verifies the accumulation contract: once fully assembled, parsing
// is identical regardless of segmentation.)

RFB_TEST(g18a_rsa1, key_response__one_byte_chunk_assembly_matches_whole) {
    uint8_t wire[R2_WIRE_CAP];
    size_t wire_len = build_key_response(wire, 20, 0x42);

    // Parse the whole buffer.
    apple_rsa1_key_response whole;
    RFB_CHECK_EQ_INT(
        apple_rsa1_parse_key_response(wire, wire_len, &whole), RFB_OK);

    // Simulate 1-byte chunk accumulation into a second buffer.
    uint8_t assembled[R2_WIRE_CAP];
    for (size_t i = 0; i < wire_len; i++) {
        assembled[i] = wire[i];
        // Partial assembly must NOT parse successfully until complete.
        apple_rsa1_key_response partial;
        rfb_error e = apple_rsa1_parse_key_response(assembled, i + 1, &partial);
        if (i + 1 < wire_len) {
            RFB_CHECK(e != RFB_OK);
        }
    }
    // Fully assembled: must match the whole-buffer parse.
    apple_rsa1_key_response assembled_resp;
    RFB_CHECK_EQ_INT(
        apple_rsa1_parse_key_response(assembled, wire_len, &assembled_resp),
        RFB_OK);
    RFB_CHECK_EQ_UINT(assembled_resp.spki_len, whole.spki_len);
    RFB_CHECK_EQ_UINT(assembled_resp.version, whole.version);
    RFB_CHECK_MEM_EQ(assembled_resp.spki_der, whole.spki_der, whole.spki_len);
}

// ===== Secret-canary: serializers never leak the plaintext username ========
//
// The RSA1 module serializes the identity *plaintext* (pre-encryption) only
// into a caller buffer that is immediately RSA-encrypted. The envelope and
// selector serializers must contain zero username bytes — they operate only
// on the ciphertext. This test plants a recognizable canary username and
// confirms it never appears in any serialized output except the identity
// plaintext buffer itself (which the caller is responsible for zeroizing).

// Portable sub-buffer search (memmem is not C99). Returns true if [needle,
// needle+n) occurs within [hay, hay+hay_len).
static bool contains_bytes(const uint8_t *hay, size_t hay_len,
                           const uint8_t *needle, size_t n)
{
    if (n == 0 || n > hay_len) return false;
    for (size_t i = 0; i + n <= hay_len; i++) {
        if (memcmp(hay + i, needle, n) == 0) return true;
    }
    return false;
}

RFB_TEST(g18a_rsa1, secret_canary__username_not_in_envelope_or_selector) {
    static const uint8_t canary_user[] = "CANARY_USER_SECRET_12345";
    const size_t canary_len = sizeof canary_user - 1;

    // Build the identity plaintext (this *should* contain the canary).
    uint8_t plaintext[64];
    size_t pt_len = 0;
    RFB_CHECK_EQ_INT(
        apple_rsa1_serialize_identity(canary_user, canary_len,
                                      plaintext, sizeof plaintext, &pt_len),
        RFB_OK);
    // Confirm the canary is in the plaintext (control).
    RFB_CHECK(contains_bytes(plaintext, pt_len, canary_user, canary_len));

    // The packet-1 envelope uses a neutral ciphertext (not derived from the
    // username here) and must NOT contain the canary.
    uint8_t ct[APPLE_RSA1_CIPHERTEXT_LEN];
    memset(ct, 0x00, sizeof ct);
    uint8_t envelope[APPLE_RSA1_PACKET1_LEN];
    size_t env_len = 0;
    RFB_CHECK_EQ_INT(
        apple_rsa1_serialize_packet1(ct, envelope, sizeof envelope, &env_len),
        RFB_OK);
    RFB_CHECK(!contains_bytes(envelope, env_len, canary_user, canary_len));

    // Selector + packet1 must also not contain the canary.
    uint8_t sel_pkt[655];
    size_t sp_len = 0;
    RFB_CHECK_EQ_INT(
        apple_rsa1_serialize_selector_plus_packet1(ct, sel_pkt, sizeof sel_pkt,
                                                    &sp_len),
        RFB_OK);
    RFB_CHECK(!contains_bytes(sel_pkt, sp_len, canary_user, canary_len));

    // Zeroize the plaintext (caller's responsibility).
    memset(plaintext, 0, pt_len);
}

// ===== Outbound-queue integration (§3-§4 contiguity) =====================
//
// RSA1-UNBLOCK.md §3: "construct this as one 15-byte outbound buffer and
// make one send attempt. Enable TCP_NODELAY. Do not enqueue the selector
// and envelope as separately flushable messages."
//
// The regression test proves the queue receives exactly ONE contiguous
// element — the selector and envelope are never split.

#include "farsee/outbound.h"
#include "farsee/allocator.h"

RFB_TEST(g18a_rsa1, queue__selector_plus_packet1_is_one_contiguous_element) {
    rfb_outbound q;
    rfb_outbound_init(&q, rfb_default_allocator(), 4096);

    uint8_t ct[APPLE_RSA1_CIPHERTEXT_LEN];
    memset(ct, 0x77, sizeof ct);

    RFB_CHECK_EQ_INT(
        apple_rsa1_queue_selector_plus_packet1(ct, &q), RFB_OK);

    // Exactly 655 bytes, contiguous.
    RFB_CHECK_EQ_UINT(rfb_outbound_length(&q), 655u);
    const uint8_t *queued = rfb_outbound_data(&q);
    RFB_CHECK(queued != NULL);

    // byte 0 = selector 0x21
    RFB_CHECK_EQ_UINT(queued[0], 0x21u);
    // version 01 00 at offset 5
    RFB_CHECK_EQ_UINT(queued[5], 0x01u);
    RFB_CHECK_EQ_UINT(queued[6], 0x00u);
    // "RSA1" at offset 7
    RFB_CHECK_MEM_EQ(queued + 7, "RSA1", 4);
    // ciphertext at offset 15
    RFB_CHECK_MEM_EQ(queued + 15, ct, APPLE_RSA1_CIPHERTEXT_LEN);
    // zero tail from offset 271 to 654
    bool all_zero = true;
    for (size_t i = 15u + APPLE_RSA1_CIPHERTEXT_LEN; i < 655u; i++) {
        if (queued[i] != 0) { all_zero = false; break; }
    }
    RFB_CHECK(all_zero);

    rfb_outbound_destroy(&q);
}

RFB_TEST(g18a_rsa1, queue__key_request_is_one_contiguous_element) {
    rfb_outbound q;
    rfb_outbound_init(&q, rfb_default_allocator(), 4096);

    RFB_CHECK_EQ_INT(
        apple_rsa1_queue_key_request(&q), RFB_OK);

    // Exactly 15 bytes.
    RFB_CHECK_EQ_UINT(rfb_outbound_length(&q), 15u);
    const uint8_t *queued = rfb_outbound_data(&q);
    RFB_CHECK(queued != NULL);
    RFB_CHECK_EQ_UINT(queued[0], 0x21u);
    RFB_CHECK_MEM_EQ(queued + 7, "RSA1", 4);

    rfb_outbound_destroy(&q);
}

RFB_TEST(g18a_rsa1, queue__null_queue__returns_internal) {
    uint8_t ct[APPLE_RSA1_CIPHERTEXT_LEN] = {0};
    RFB_CHECK_EQ_INT(
        apple_rsa1_queue_selector_plus_packet1(ct, NULL), RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(
        apple_rsa1_queue_key_request(NULL), RFB_ERR_INTERNAL);
}

RFB_TEST(g18a_rsa1, queue__limit_too_small__returns_limit) {
    rfb_outbound q;
    // Queue holds only 100 bytes — cannot fit the 655-byte element.
    rfb_outbound_init(&q, rfb_default_allocator(), 100);
    uint8_t ct[APPLE_RSA1_CIPHERTEXT_LEN];
    RFB_CHECK_EQ_INT(
        apple_rsa1_queue_selector_plus_packet1(ct, &q), RFB_ERR_LIMIT);
    RFB_CHECK_EQ_UINT(rfb_outbound_length(&q), 0u);  // unchanged
    rfb_outbound_destroy(&q);
}

RFB_TEST(g18a_rsa1, queue__selector_plus_packet1_drains_as_one_send) {
    // Prove the queued bytes drain in one contiguous write: the drain
    // (consume) sees the complete selector+envelope as a single unit.
    rfb_outbound q;
    rfb_outbound_init(&q, rfb_default_allocator(), 4096);
    uint8_t ct[APPLE_RSA1_CIPHERTEXT_LEN];
    memset(ct, 0x44, sizeof ct);
    apple_rsa1_queue_selector_plus_packet1(ct, &q);

    // The I/O layer would call write(queued, 655). We simulate a full
    // write: consume all 655 bytes.
    RFB_CHECK_EQ_UINT(rfb_outbound_length(&q), 655u);
    rfb_outbound_consume(&q, 655);
    RFB_CHECK_EQ_UINT(rfb_outbound_length(&q), 0u);  // fully drained

    rfb_outbound_destroy(&q);
}

// ===== Gate R4: fake server acceptance oracle =============================
//
// A deterministic fake Apple server that validates the client's RSA1 branch
// entry and packet 1, decrypts the identity with a test private key, and
// emits a synthetic SRP challenge. Receipt of the challenge is the RSA1
// acceptance oracle (RSA1-UNBLOCK.md §4 lines 138-141): after it, failures
// belong to SRP, not RSA1.
//
// This is a pure in-process oracle (no sockets) so it is hermetic and
// ASan-safe. It proves the client's serialized bytes satisfy the server
// contract end-to-end.

#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

// The fake server's state after processing the client's branch entry.
typedef enum {
    FAKE_SVR_ACCEPTED = 0,   // packet 1 valid; SRP challenge emitted
    FAKE_SVR_REJECTED = 1,   // branch-entry or packet-1 framing invalid
} fake_svr_result;

// Synthetic SRP challenge: a fixed 64-byte deterministic blob. The exact
// SRP challenge format is out of scope for G18A (it belongs to SRP, not
// RSA1); the oracle only proves the challenge *arrives* after RSA1
// acceptance.
static const uint8_t SYNTHETIC_SRP_CHALLENGE[64] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
    0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
    0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
};

// Validate the client's selector+packet1 branch entry and decrypt the
// identity. On success, writes the decrypted username to username_out
// (NUL-terminated) and copies the synthetic challenge to challenge_out.
// Returns FAKE_SVR_ACCEPTED on valid packet 1, FAKE_SVR_REJECTED otherwise.
static fake_svr_result fake_svr_validate(
    const uint8_t *client_bytes, size_t client_len,
    EVP_PKEY *server_privkey,
    char *username_out, size_t username_cap,
    uint8_t challenge_out[64])
{
    if (client_bytes == NULL || server_privkey == NULL) return FAKE_SVR_REJECTED;

    // --- Validate selector + packet-1 framing (§4) ----------------------
    // Expected: 1 (selector) + 654 (packet 1) = 655 bytes.
    if (client_len != 1u + APPLE_RSA1_PACKET1_LEN) {
        return FAKE_SVR_REJECTED;
    }
    // byte 0 = selector 0x21
    if (client_bytes[0] != (uint8_t)APPLE_RSA1_SELECTOR) {
        return FAKE_SVR_REJECTED;
    }
    const uint8_t *pkt = client_bytes + 1;

    // total_len = 650 (u32_be at pkt[0..3])
    if (!(pkt[0] == 0x00 && pkt[1] == 0x00 &&
          pkt[2] == 0x02 && pkt[3] == 0x8a)) {
        return FAKE_SVR_REJECTED;
    }
    // version 01 00
    if (!(pkt[4] == 0x01 && pkt[5] == 0x00)) {
        return FAKE_SVR_REJECTED;
    }
    // "RSA1"
    if (memcmp(pkt + 6, "RSA1", 4) != 0) {
        return FAKE_SVR_REJECTED;
    }
    // authtype = 2
    if (!(pkt[10] == 0x00 && pkt[11] == 0x02)) {
        return FAKE_SVR_REJECTED;
    }
    // inner_len = 256
    if (!(pkt[12] == 0x01 && pkt[13] == 0x00)) {
        return FAKE_SVR_REJECTED;
    }

    // --- Extract and decrypt the 256-byte ciphertext (§4) ----------------
    const uint8_t *ct = pkt + 14;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(server_privkey, NULL);
    if (ctx == NULL) return FAKE_SVR_REJECTED;
    uint8_t recovered[256];
    size_t rec_len = sizeof recovered;
    bool ok = (EVP_PKEY_decrypt_init(ctx) == 1 &&
               EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) == 1 &&
               EVP_PKEY_decrypt(ctx, recovered, &rec_len, ct, 256) == 1);
    EVP_PKEY_CTX_free(ctx);
    if (!ok) {
        return FAKE_SVR_REJECTED;
    }

    // --- Validate identity plaintext structure (§4) ----------------------
    // u32_be payload_len, u32_be username_len, username, u16 0, u8 0
    if (rec_len < 11) {
        return FAKE_SVR_REJECTED;
    }
    uint32_t payload_len = ((uint32_t)recovered[0] << 24) |
                           ((uint32_t)recovered[1] << 16) |
                           ((uint32_t)recovered[2] << 8) |
                           (uint32_t)recovered[3];
    uint32_t user_len = ((uint32_t)recovered[4] << 24) |
                        ((uint32_t)recovered[5] << 16) |
                        ((uint32_t)recovered[6] << 8) |
                        (uint32_t)recovered[7];
    // payload_len must equal user_len + 7
    if (payload_len != user_len + 7u) {
        return FAKE_SVR_REJECTED;
    }
    // rec_len must equal user_len + 11
    if (rec_len != (size_t)user_len + 11u) {
        return FAKE_SVR_REJECTED;
    }
    // trailing u16 + u8 must be zero
    if (recovered[8 + user_len] != 0 || recovered[9 + user_len] != 0 ||
        recovered[10 + user_len] != 0) {
        return FAKE_SVR_REJECTED;
    }

    // Copy out the username (NUL-terminated).
    if (username_out != NULL && username_cap > 0) {
        size_t copy = user_len < username_cap - 1 ? user_len : username_cap - 1;
        memcpy(username_out, recovered + 8, copy);
        username_out[copy] = '\0';
    }

    // --- Emit synthetic SRP challenge (acceptance oracle) ----------------
    if (challenge_out != NULL) {
        memcpy(challenge_out, SYNTHETIC_SRP_CHALLENGE, 64);
    }
    OPENSSL_cleanse(recovered, sizeof recovered);
    return FAKE_SVR_ACCEPTED;
}

RFB_TEST(g18a_rsa1, fake_server__accepts_valid_packet1_and_emits_challenge) {
    // The client side: generate a key, build identity, encrypt, serialize.
    g18a_rsa_key key;
    RFB_CHECK(g18a_gen_rsa_key(&key));

    static const uint8_t username[] = "testadmin";
    const size_t ulen = sizeof username - 1;

    uint8_t plaintext[64];
    size_t pt_len = 0;
    RFB_CHECK_EQ_INT(
        apple_rsa1_serialize_identity(username, ulen,
                                      plaintext, sizeof plaintext, &pt_len),
        RFB_OK);

    uint8_t ct[APPLE_RSA1_CIPHERTEXT_LEN];
    RFB_CHECK(apple_rsa1_encrypt_identity(
        key.spki_der, key.spki_len, plaintext, pt_len, ct));
    memset(plaintext, 0, pt_len);  // zeroize after encryption

    uint8_t client_out[655];
    size_t client_len = 0;
    RFB_CHECK_EQ_INT(
        apple_rsa1_serialize_selector_plus_packet1(
            ct, client_out, sizeof client_out, &client_len),
        RFB_OK);

    // The server side: validate + decrypt + emit challenge.
    char recovered_user[64];
    uint8_t challenge[64];
    RFB_CHECK_EQ_INT(
        (int)fake_svr_validate(client_out, client_len, key.pkey,
                               recovered_user, sizeof recovered_user,
                               challenge),
        (int)FAKE_SVR_ACCEPTED);
    // Username recovered correctly.
    RFB_CHECK(strcmp(recovered_user, "testadmin") == 0);
    // Challenge matches the synthetic oracle.
    RFB_CHECK_MEM_EQ(challenge, SYNTHETIC_SRP_CHALLENGE, 64);

    g18a_free_rsa_key(&key);
}

RFB_TEST(g18a_rsa1, fake_server__rejects_wrong_selector) {
    g18a_rsa_key key;
    RFB_CHECK(g18a_gen_rsa_key(&key));

    uint8_t ct[APPLE_RSA1_CIPHERTEXT_LEN];
    memset(ct, 0x01, sizeof ct);
    uint8_t client_out[655];
    size_t client_len = 0;
    RFB_CHECK_EQ_INT(
        apple_rsa1_serialize_selector_plus_packet1(
            ct, client_out, sizeof client_out, &client_len),
        RFB_OK);
    // Corrupt the selector byte.
    client_out[0] = 0x20;

    uint8_t challenge[64];
    RFB_CHECK_EQ_INT(
        (int)fake_svr_validate(client_out, client_len, key.pkey,
                               NULL, 0, challenge),
        (int)FAKE_SVR_REJECTED);

    g18a_free_rsa_key(&key);
}

RFB_TEST(g18a_rsa1, fake_server__rejects_wrong_authtype) {
    g18a_rsa_key key;
    RFB_CHECK(g18a_gen_rsa_key(&key));

    uint8_t ct[APPLE_RSA1_CIPHERTEXT_LEN];
    memset(ct, 0x02, sizeof ct);
    uint8_t client_out[655];
    size_t client_len = 0;
    RFB_CHECK_EQ_INT(
        apple_rsa1_serialize_selector_plus_packet1(
            ct, client_out, sizeof client_out, &client_len),
        RFB_OK);
    // Corrupt authtype (offset 1 + 11 = 12): change 0x02 to 0x03.
    client_out[12] = 0x03;

    uint8_t challenge[64];
    RFB_CHECK_EQ_INT(
        (int)fake_svr_validate(client_out, client_len, key.pkey,
                               NULL, 0, challenge),
        (int)FAKE_SVR_REJECTED);

    g18a_free_rsa_key(&key);
}

RFB_TEST(g18a_rsa1, fake_server__rejects_truncated_branch_entry) {
    g18a_rsa_key key;
    RFB_CHECK(g18a_gen_rsa_key(&key));

    uint8_t ct[APPLE_RSA1_CIPHERTEXT_LEN];
    memset(ct, 0x03, sizeof ct);
    uint8_t client_out[655];
    size_t client_len = 0;
    RFB_CHECK_EQ_INT(
        apple_rsa1_serialize_selector_plus_packet1(
            ct, client_out, sizeof client_out, &client_len),
        RFB_OK);

    // Feed only the first 100 bytes (truncated).
    uint8_t challenge[64];
    RFB_CHECK_EQ_INT(
        (int)fake_svr_validate(client_out, 100, key.pkey,
                               NULL, 0, challenge),
        (int)FAKE_SVR_REJECTED);

    g18a_free_rsa_key(&key);
}

RFB_TEST(g18a_rsa1, fake_server__rejects_wrong_key_ciphertext) {
    // Encrypt with key A, validate with key B -> decryption must fail.
    g18a_rsa_key key_a, key_b;
    RFB_CHECK(g18a_gen_rsa_key(&key_a));
    RFB_CHECK(g18a_gen_rsa_key(&key_b));

    static const uint8_t username[] = "admin";
    uint8_t plaintext[32];
    size_t pt_len = 0;
    RFB_CHECK_EQ_INT(
        apple_rsa1_serialize_identity(username, 5,
                                      plaintext, sizeof plaintext, &pt_len),
        RFB_OK);
    uint8_t ct[APPLE_RSA1_CIPHERTEXT_LEN];
    RFB_CHECK(apple_rsa1_encrypt_identity(
        key_a.spki_der, key_a.spki_len, plaintext, pt_len, ct));
    memset(plaintext, 0, pt_len);

    uint8_t client_out[655];
    size_t client_len = 0;
    RFB_CHECK_EQ_INT(
        apple_rsa1_serialize_selector_plus_packet1(
            ct, client_out, sizeof client_out, &client_len),
        RFB_OK);

    // Validate with key_b (wrong key) — must reject.
    uint8_t challenge[64];
    RFB_CHECK_EQ_INT(
        (int)fake_svr_validate(client_out, client_len, key_b.pkey,
                               NULL, 0, challenge),
        (int)FAKE_SVR_REJECTED);

    g18a_free_rsa_key(&key_a);
    g18a_free_rsa_key(&key_b);
}
