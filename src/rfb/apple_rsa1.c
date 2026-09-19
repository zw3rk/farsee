// SPDX-License-Identifier: Apache-2.0
//
// farsee — Apple RSA1 branch-entry wire format.
//
// Pure byte codecs: no socket, no crypto provider, no global state. All
// serialization is bounded by a caller-supplied capacity and uses checked
// writes via rfb_writer (farsee/bytes.h).

#include "farsee/apple_rsa1.h"
#include "farsee/apple_crypto.h"
#include "farsee/bytes.h"
#include "farsee/outbound.h"

#include <string.h>

// --- Gate R1: branch-entry key request (§3) --------------------------------
//
// Layout (15 bytes, one contiguous send):
//   u8      selector   = 0x21
//   u32_be  total_len  = 10   (counts bytes after the leading u32)
//   u16_be  version    = 0x0100  (wire bytes 01 00)
//   byte[4] algorithm  = "RSA1"
//   u16_be  authtype   = 0      (key request)
//   u16_be  inner_len  = 0
//
// Exact golden:
//   21 00 00 00 0a 01 00 52 53 41 31 00 00 00 00

rfb_error apple_rsa1_serialize_key_request(uint8_t *out, size_t out_cap,
                                           size_t *out_len)
{
    if (out == NULL || out_len == NULL) {
        return RFB_ERR_INTERNAL;
    }
    if (out_cap < APPLE_RSA1_KEY_REQUEST_LEN) {
        return RFB_ERR_LIMIT;
    }

    rfb_writer w = rfb_writer_make(out, out_cap);

    // selector
    if (!rfb_write_u8(&w, APPLE_RSA1_SELECTOR)) {
        return RFB_ERR_LIMIT;
    }
    // total_len = 2 + 4 + 2 + 2 = 10 (everything after the leading u32)
    if (!rfb_write_u32(&w, 10u)) {
        return RFB_ERR_LIMIT;
    }
    // version 0x0100
    if (!rfb_write_u16(&w, APPLE_RSA1_VERSION_BE)) {
        return RFB_ERR_LIMIT;
    }
    // algorithm "RSA1"
    if (!rfb_write_bytes(&w, "RSA1", APPLE_RSA1_ALGORITHM_LEN)) {
        return RFB_ERR_LIMIT;
    }
    // authtype = 0 (key request)
    if (!rfb_write_u16(&w, APPLE_RSA1_AUTHTYPE_KEYREQ)) {
        return RFB_ERR_LIMIT;
    }
    // inner_len = 0
    if (!rfb_write_u16(&w, 0u)) {
        return RFB_ERR_LIMIT;
    }

    *out_len = w.length;
    return RFB_OK;
}

// --- Gate R2: server public-key response (§3, mixed-endian) ----------------
//
// Wire layout:
//   u32_be total_len  = der_len + 7
//   u32_le version    = 0x00000100   (NOTE: little-endian on the wire)
//   u16_be der_len
//   byte[] DER SubjectPublicKeyInfo (der_len bytes)
//   u8     trailing_zero = 0
//
// Fixed header size preceding the DER body:
//   4 (total_len) + 4 (version) + 2 (der_len) = 10
// Trailing byte after DER body: 1
// So total_len == der_len + 7  (10 - 4 [the total_len u32 itself] + 1).

// Read a little-endian u32 from a byte array.
static uint32_t read_le32(const uint8_t *p)
{
    return (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

// Expected little-endian version wire bytes for 0x00000100.
static const uint32_t APPLE_RSA1_VERSION_EXPECTED = 0x00000100u;

rfb_error apple_rsa1_parse_key_response(const uint8_t *data, size_t len,
                                        apple_rsa1_key_response *out)
{
    if (data == NULL || out == NULL) {
        return RFB_ERR_INTERNAL;
    }
    // Zero the output so no field is left uninitialized on failure.
    memset(out, 0, sizeof *out);

    rfb_reader r = rfb_reader_make(data, len);

    // Header: total_len (BE), version (LE), der_len (BE).
    uint32_t total_len = 0;
    uint32_t version_le = 0;
    uint16_t der_len = 0;
    if (!rfb_read_u32(&r, &total_len)) {
        return RFB_ERR_PROTOCOL;
    }
    // version is little-endian: read 4 raw bytes and decode manually.
    uint8_t ver_bytes[4];
    if (!rfb_read_bytes(&r, ver_bytes, 4)) {
        return RFB_ERR_PROTOCOL;
    }
    version_le = read_le32(ver_bytes);
    if (!rfb_read_u16(&r, &der_len)) {
        return RFB_ERR_PROTOCOL;
    }

    // Policy cap on DER length before any arithmetic.
    if (der_len > APPLE_RSA1_MAX_SPKI_DER) {
        return RFB_ERR_LIMIT;
    }

    // total_len must equal der_len + 7 (checked arithmetic).
    // der_len <= APPLE_RSA1_MAX_SPKI_DER (4096), so der_len + 7 cannot overflow.
    if (total_len != (uint32_t)der_len + 7u) {
        return RFB_ERR_PROTOCOL;
    }
    // Version must be exactly 0x00000100.
    if (version_le != APPLE_RSA1_VERSION_EXPECTED) {
        return RFB_ERR_PROTOCOL;
    }

    // DER body: borrow a pointer into the input buffer (zero-copy).
    // r.offset now points just past der_len.
    const uint8_t *der_ptr = r.data + r.offset;
    if (!rfb_reader_skip(&r, der_len)) {
        return RFB_ERR_PROTOCOL;
    }

    // Trailing zero byte.
    uint8_t trailing = 0;
    if (!rfb_read_u8(&r, &trailing)) {
        return RFB_ERR_PROTOCOL;
    }
    if (trailing != 0u) {
        return RFB_ERR_PROTOCOL;
    }

    // No unexpected trailing bytes allowed.
    if (rfb_reader_remaining(&r) != 0u) {
        return RFB_ERR_PROTOCOL;
    }

    out->spki_der = der_ptr;
    out->spki_len = der_len;
    out->der_len = der_len;
    out->version = version_le;
    return RFB_OK;
}

rfb_error apple_rsa1_serialize_key_response(const uint8_t *spki_der,
                                            size_t der_len,
                                            uint8_t *out, size_t out_cap,
                                            size_t *out_len)
{
    if (out == NULL || out_len == NULL) {
        return RFB_ERR_INTERNAL;
    }
    if (spki_der == NULL || der_len == 0u) {
        return RFB_ERR_PROTOCOL;
    }
    if (der_len > APPLE_RSA1_MAX_SPKI_DER) {
        return RFB_ERR_LIMIT;
    }
    // der_len <= 4096 here, so der_len + 7 cannot overflow uint32_t.
    uint32_t total_len = (uint32_t)der_len + 7u;

    rfb_writer w = rfb_writer_make(out, out_cap);
    if (!rfb_write_u32(&w, total_len)) {
        return RFB_ERR_LIMIT;
    }
    // version written little-endian: 0x00000100 -> 00 01 00 00
    if (!rfb_write_u8(&w, 0x00)) return RFB_ERR_LIMIT;
    if (!rfb_write_u8(&w, 0x01)) return RFB_ERR_LIMIT;
    if (!rfb_write_u8(&w, 0x00)) return RFB_ERR_LIMIT;
    if (!rfb_write_u8(&w, 0x00)) return RFB_ERR_LIMIT;
    if (!rfb_write_u16(&w, (uint16_t)der_len)) {
        return RFB_ERR_LIMIT;
    }
    if (!rfb_write_bytes(&w, spki_der, der_len)) {
        return RFB_ERR_LIMIT;
    }
    if (!rfb_write_u8(&w, 0x00)) {
        return RFB_ERR_LIMIT;
    }

    *out_len = w.length;
    return RFB_OK;
}

// --- Gate R3: packet-1 identity plaintext (§4) -----------------------------
//
// Identity plaintext layout:
//   u32_be payload_len      = username_len + 7
//   u32_be username_len
//   byte[] username_utf8
//   u16_be empty_string_len = 0
//   u8     empty_opaque_len = 0
//
// payload_len counts the 7 bytes after itself: 4 (username_len) + 2 + 1.
// Total plaintext = username_len + 11.
//
// PKCS#1 v1.5 max plaintext for RSA-2048 = 256 - 11 = 245 bytes.
// identity = username_len + 11  => username_len <= 234.

rfb_error apple_rsa1_serialize_identity(const uint8_t *username,
                                        size_t username_len,
                                        uint8_t *out, size_t out_cap,
                                        size_t *out_len)
{
    if (out == NULL || out_len == NULL) {
        return RFB_ERR_INTERNAL;
    }
    if (username == NULL || username_len == 0u) {
        return RFB_ERR_PROTOCOL;
    }
    // Reject overlong usernames rather than truncating (§4 line 112).
    if (username_len > APPLE_RSA1_MAX_USERNAME_LEN) {
        return RFB_ERR_PROTOCOL;
    }

    // payload_len = username_len + 7. username_len <= 234 so no overflow.
    uint32_t payload_len = (uint32_t)username_len + 7u;

    // Total plaintext length = username_len + 11. Checked against out_cap.
    // username_len <= 234 so + 11 cannot overflow size_t.
    size_t total = username_len + 11u;
    if (total > out_cap) {
        return RFB_ERR_LIMIT;
    }

    rfb_writer w = rfb_writer_make(out, out_cap);
    if (!rfb_write_u32(&w, payload_len)) {
        return RFB_ERR_LIMIT;
    }
    if (!rfb_write_u32(&w, (uint32_t)username_len)) {
        return RFB_ERR_LIMIT;
    }
    if (!rfb_write_bytes(&w, username, username_len)) {
        return RFB_ERR_LIMIT;
    }
    if (!rfb_write_u16(&w, 0u)) {  // empty string length
        return RFB_ERR_LIMIT;
    }
    if (!rfb_write_u8(&w, 0u)) {   // empty opaque length
        return RFB_ERR_LIMIT;
    }

    *out_len = w.length;
    return RFB_OK;
}

// --- Gate R3: RSA-2048 PKCS#1 v1.5 encryption (§4, never OAEP) -------------

bool apple_rsa1_encrypt_identity(const uint8_t *spki_der, size_t spki_len,
                                 const uint8_t *plaintext, size_t plaintext_len,
                                 uint8_t ciphertext[APPLE_RSA1_CIPHERTEXT_LEN])
{
    if (spki_der == NULL || plaintext == NULL || ciphertext == NULL) {
        return false;
    }
    // rfb_crypto_rsa_encrypt_pkcs1 uses PKCS#1 v1.5 padding (apple_crypto.c).
    // It never selects OAEP.
    return rfb_crypto_rsa_encrypt_pkcs1(spki_der, spki_len,
                                        plaintext, plaintext_len,
                                        ciphertext);
}

// --- Gate R3: packet-1 envelope serializer (§4) ----------------------------
//
// Envelope (total 654 bytes):
//   u32_be total_len = 650   (= 2 + 4 + 2 + 2 + 256 + 384)
//   u16_be version   = 0x0100
//   "RSA1"
//   u16_be authtype  = 2
//   u16_be inner_len = 256
//   byte[256] ct
//   byte[384] zeros

rfb_error apple_rsa1_serialize_packet1(const uint8_t ciphertext[APPLE_RSA1_CIPHERTEXT_LEN],
                                       uint8_t *out, size_t out_cap,
                                       size_t *out_len)
{
    if (out == NULL || out_len == NULL || ciphertext == NULL) {
        return RFB_ERR_INTERNAL;
    }
    if (out_cap < APPLE_RSA1_PACKET1_LEN) {
        return RFB_ERR_LIMIT;
    }

    rfb_writer w = rfb_writer_make(out, out_cap);
    if (!rfb_write_u32(&w, APPLE_RSA1_PACKET1_TOTAL_LEN)) {  // 650
        return RFB_ERR_LIMIT;
    }
    if (!rfb_write_u16(&w, APPLE_RSA1_VERSION_BE)) {  // 0x0100
        return RFB_ERR_LIMIT;
    }
    if (!rfb_write_bytes(&w, "RSA1", APPLE_RSA1_ALGORITHM_LEN)) {
        return RFB_ERR_LIMIT;
    }
    if (!rfb_write_u16(&w, APPLE_RSA1_AUTHTYPE_IDENT)) {  // 2
        return RFB_ERR_LIMIT;
    }
    if (!rfb_write_u16(&w, APPLE_RSA1_CIPHERTEXT_LEN)) {  // inner_len = 256
        return RFB_ERR_LIMIT;
    }
    if (!rfb_write_bytes(&w, ciphertext, APPLE_RSA1_CIPHERTEXT_LEN)) {
        return RFB_ERR_LIMIT;
    }
    // 384-byte zero tail (required, §4 line 124-126).
    static const uint8_t zeros[APPLE_RSA1_PACKET1_ZERO_TAIL_LEN];
    if (!rfb_write_bytes(&w, zeros, APPLE_RSA1_PACKET1_ZERO_TAIL_LEN)) {
        return RFB_ERR_LIMIT;
    }

    *out_len = w.length;
    return RFB_OK;
}

// --- Gate R3: selector + packet-1 coalesced (§4) ---------------------------
//
// "When no key-request exchange is needed, concatenate selector 0x21 and
//  packet 1 into one 655-byte outbound buffer." (§4 line 136-137)

rfb_error apple_rsa1_serialize_selector_plus_packet1(
    const uint8_t ciphertext[APPLE_RSA1_CIPHERTEXT_LEN],
    uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (out == NULL || out_len == NULL || ciphertext == NULL) {
        return RFB_ERR_INTERNAL;
    }
    // 1 (selector) + 654 (packet 1) = 655.
    if (out_cap < 1u + APPLE_RSA1_PACKET1_LEN) {
        return RFB_ERR_LIMIT;
    }

    rfb_writer w = rfb_writer_make(out, out_cap);
    if (!rfb_write_u8(&w, APPLE_RSA1_SELECTOR)) {  // 0x21
        return RFB_ERR_LIMIT;
    }

    // Append the packet-1 envelope starting at offset 1.
    size_t pkt_len = 0;
    rfb_error e = apple_rsa1_serialize_packet1(
        ciphertext, out + 1u, out_cap - 1u, &pkt_len);
    if (e != RFB_OK) {
        return e;
    }

    *out_len = 1u + pkt_len;
    return RFB_OK;
}

// --- Gate R3+: outbound-queue integration (§3-§4 contiguity) ---------------
//
// Keep the selector and envelope in one contiguous outbound element. The
// selector-plus-packet-1 form is one 655-byte outbound element.
//
// Serialize directly into the queue as a single contiguous element (one
// append call) so the selector and RSA1 envelope are never split into
// separately flushable messages.

rfb_error apple_rsa1_queue_selector_plus_packet1(
    const uint8_t ciphertext[APPLE_RSA1_CIPHERTEXT_LEN],
    rfb_outbound *q)
{
    if (q == NULL || ciphertext == NULL) {
        return RFB_ERR_INTERNAL;
    }
    // Serialize into a stack buffer first, then append as one element.
    // This guarantees one contiguous queue element (one append call).
    uint8_t buf[1u + APPLE_RSA1_PACKET1_LEN];  // 655 bytes
    size_t len = 0;
    rfb_error e = apple_rsa1_serialize_selector_plus_packet1(
        ciphertext, buf, sizeof buf, &len);
    if (e != RFB_OK) {
        return e;
    }
    return rfb_outbound_append(q, buf, len);
}

rfb_error apple_rsa1_queue_key_request(rfb_outbound *q)
{
    if (q == NULL) {
        return RFB_ERR_INTERNAL;
    }
    uint8_t buf[APPLE_RSA1_KEY_REQUEST_LEN];  // 15 bytes
    size_t len = 0;
    rfb_error e = apple_rsa1_serialize_key_request(
        buf, sizeof buf, &len);
    if (e != RFB_OK) {
        return e;
    }
    return rfb_outbound_append(q, buf, len);
}
