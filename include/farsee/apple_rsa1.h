// SPDX-License-Identifier: Apache-2.0
//
// farsee — Apple RSA1 branch-entry wire format.
//
// Pure, bounded serializers/parsers for the Apple type-33 RSA1 key-exchange
// envelope. No socket, crypto-provider, or allocator assumptions — these are
// byte-level codecs over caller-owned buffers, so they are ASan-safe and
// trivially fragmentable for testing.
//
// Controlling spec: docs/apple/rsa1-wire-format.md.

#ifndef FARSEE_INCLUDE_FARSEE_APPLE_RSA1_H
#define FARSEE_INCLUDE_FARSEE_APPLE_RSA1_H

#include "farsee/error.h"
#include "farsee/outbound.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// RSA1 wire-format constants.
#define APPLE_RSA1_SELECTOR        0x21u   // security type 33
#define APPLE_RSA1_VERSION_BE      0x0100u // wire bytes 01 00
#define APPLE_RSA1_AUTHTYPE_KEYREQ 0u      // request the server public key
#define APPLE_RSA1_AUTHTYPE_IDENT  2u      // packet-1 identity (modern)
#define APPLE_RSA1_KEY_REQUEST_LEN 15u     // selector + key-request envelope
#define APPLE_RSA1_ALGORITHM_LEN   4u      // "RSA1"

// Size of the RSA-2048 ciphertext in packet 1 (256 bytes = 2048 bits).
#define APPLE_RSA1_CIPHERTEXT_LEN 256u
// Fixed zero-padding tail of packet 1.
#define APPLE_RSA1_PACKET1_ZERO_TAIL_LEN 384u

// Serialized sizes for the supported packet-1 profile:
//   total_len = 2 + 4 + 2 + 2 + 256 + 384 = 650
//   packet bytes = 4 (total_len) + total_len = 654
#define APPLE_RSA1_PACKET1_TOTAL_LEN 650u
#define APPLE_RSA1_PACKET1_LEN       654u

// ---- Gate R1: branch-entry key request (§3) -------------------------------

// Serialize the authtype-0 key request as one contiguous 15-byte outbound
// buffer (selector + RSA1 envelope). The caller must coalesce this with the
// first identity packet into one send when no key exchange is needed
// (see docs/apple/rsa1-wire-format.md).
//
// Returns RFB_OK and sets *out_len = 15 on success, RFB_ERR_LIMIT if out_cap
// < 15, RFB_ERR_INTERNAL on NULL. Never writes past out_cap.
rfb_error apple_rsa1_serialize_key_request(uint8_t *out, size_t out_cap,
                                           size_t *out_len);

// ---- Gate R2: server public-key response parser (§3, mixed-endian) --------
//
// Wire layout:
//   u32_be  total_len      = der_len + 7
//   u32_le  version        = 0x00000100   (NOTE: little-endian on the wire)
//   u16_be  der_len
//   byte[]  DER SubjectPublicKeyInfo (der_len bytes)
//   u8      trailing_zero  = 0
//
// The version field uses the byte order specified above.
//
// Parsed SPKI is returned as a borrowed pointer into the input buffer
// (zero-copy); the caller copies/fingerprints it before the buffer is reused.

// Maximum DER SubjectPublicKeyInfo size accepted (policy cap, §3 line 91).
#define APPLE_RSA1_MAX_SPKI_DER 4096u

typedef struct apple_rsa1_key_response {
    const uint8_t *spki_der;   // borrowed; der_len bytes
    size_t         spki_len;   // == der_len
    uint16_t       der_len;    // big-endian wire value
    uint32_t       version;    // host-endian 0x00000100
} apple_rsa1_key_response;

// Parse a server public-key response. On success, out->spki_der points into
// the input buffer for exactly out->spki_len bytes.
//
// Returns RFB_OK, or:
//   RFB_ERR_PROTOCOL — truncated, wrong total_len, wrong version, bad trailing
//                      byte, der_len exceeds policy cap, unexpected trailing
//                      bytes after the response.
//   RFB_ERR_LIMIT     — der_len > APPLE_RSA1_MAX_SPKI_DER.
//   RFB_ERR_INTERNAL  — NULL argument.
rfb_error apple_rsa1_parse_key_response(const uint8_t *data, size_t len,
                                        apple_rsa1_key_response *out);

// ---- Gate R2: server public-key response serializer (test fixture helper) --
//
// Serializes a synthetic response for fake-server and round-trip tests. The
// version field is written little-endian per the wire format. Expects a
// pre-serialized DER blob (the caller is responsible for key validity).

// Serialize a server public-key response envelope around a caller-supplied
// DER SPKI blob. Returns RFB_OK and sets *out_len; RFB_ERR_LIMIT if the
// serialized form does not fit in out_cap; RFB_ERR_PROTOCOL if der_len is 0
// or exceeds APPLE_RSA1_MAX_SPKI_DER; RFB_ERR_INTERNAL on NULL.
rfb_error apple_rsa1_serialize_key_response(const uint8_t *spki_der,
                                            size_t der_len,
                                            uint8_t *out, size_t out_cap,
                                            size_t *out_len);

// ---- Gate R3: packet-1 identity plaintext (§4) ----------------------------
//
// Identity plaintext layout (before RSA encryption):
//   u32_be  payload_len      = username_len + 7
//   u32_be  username_len
//   byte[]  username_utf8
//   u16_be  empty_string_len = 0
//   u8      empty_opaque_len = 0
//
// Total plaintext length = username_len + 11.
// payload_len counts the 7 bytes after itself: 4 (username_len) + 2 + 1.

// Maximum username length that fits RSA-2048 PKCS#1 v1.5:
//   max_plaintext = 256 - 11 = 245 bytes
//   identity plaintext   = username_len + 11
//   => username_len <= 234
#define APPLE_RSA1_MAX_USERNAME_LEN 234u

// Identity plaintext length for a username of given length (= username_len + 11).
#define APPLE_RSA1_IDENTITY_LEN(username_len) ((username_len) + 11u)

// Serialize the packet-1 identity plaintext.
// Returns RFB_OK; RFB_ERR_PROTOCOL if username is NULL or username_len is 0
// or exceeds APPLE_RSA1_MAX_USERNAME_LEN (never truncates); RFB_ERR_LIMIT if
// out_cap is too small; RFB_ERR_INTERNAL on NULL out/out_len.
rfb_error apple_rsa1_serialize_identity(const uint8_t *username,
                                        size_t username_len,
                                        uint8_t *out, size_t out_cap,
                                        size_t *out_len);

// ---- Gate R3: RSA-2048 PKCS#1 v1.5 encryption (§4, never OAEP) ------------
//
// Encrypts the identity plaintext under the server's RSA-2048 public key
// using PKCS#1 v1.5 padding. Produces exactly APPLE_RSA1_CIPHERTEXT_LEN
// (256) bytes. Delegates to the crypto provider (rfb_crypto_rsa_encrypt_pkcs1).
//
// Returns true on success, false on provider failure or invalid key.
bool apple_rsa1_encrypt_identity(const uint8_t *spki_der, size_t spki_len,
                                 const uint8_t *plaintext, size_t plaintext_len,
                                 uint8_t ciphertext[APPLE_RSA1_CIPHERTEXT_LEN]);

// ---- Gate R3: packet-1 envelope serializer (§4) ---------------------------
//
// Envelope layout (total 654 bytes):
//   u32_be  total_len   = 650   (= 2 + 4 + 2 + 2 + 256 + 384)
//   u16_be  version     = 0x0100
//   byte[4] algorithm   = "RSA1"
//   u16_be  authtype    = 2     (modern identity)
//   u16_be  inner_len   = 256
//   byte[256] rsa_ciphertext
//   byte[384] zero_tail
//
// total_len counts everything after the leading u32.

// Serialize the packet-1 envelope around a pre-computed 256-byte ciphertext.
// out must hold at least APPLE_RSA1_PACKET1_LEN (654) bytes.
// Returns RFB_OK; RFB_ERR_LIMIT if out_cap < 654; RFB_ERR_INTERNAL on NULL.
rfb_error apple_rsa1_serialize_packet1(const uint8_t ciphertext[APPLE_RSA1_CIPHERTEXT_LEN],
                                       uint8_t *out, size_t out_cap,
                                       size_t *out_len);

// Concatenate selector 0x21 + packet-1 into one 655-byte outbound buffer.
// Use when the server key is already trusted (no key-request exchange needed).
// Concatenate selector 0x21 and packet 1 into one 655-byte outbound buffer.
rfb_error apple_rsa1_serialize_selector_plus_packet1(
    const uint8_t ciphertext[APPLE_RSA1_CIPHERTEXT_LEN],
    uint8_t *out, size_t out_cap, size_t *out_len);

// ---- Gate R3+: outbound-queue integration (§3-§4 contiguity) --------------
//
// Construct the key request as one 15-byte outbound buffer. Keep the selector
// and envelope together. Likewise, concatenate selector 0x21 and packet 1 into
// one 655-byte outbound buffer.
//
// These functions serialize directly into the outbound queue as a single
// contiguous element (one append call), guaranteeing the selector and the
// RSA1 envelope are never split into separately flushable messages.

// Enqueue the selector+packet1 branch entry as one 655-byte contiguous
// queue element. Returns RFB_OK; RFB_ERR_LIMIT if the queue would exceed
// its hard limit; RFB_ERR_INTERNAL on NULL.
rfb_error apple_rsa1_queue_selector_plus_packet1(
    const uint8_t ciphertext[APPLE_RSA1_CIPHERTEXT_LEN],
    rfb_outbound *q);

// Enqueue the authtype-0 key request as one 15-byte contiguous queue
// element. Used when the server key is not already trusted.
rfb_error apple_rsa1_queue_key_request(rfb_outbound *q);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_APPLE_RSA1_H
