// SPDX-License-Identifier: Apache-2.0
//
// farsee — RSA1 envelope parser/serializer.
//
// Parses and serializes the Apple RSA1 key exchange envelope format
// defined by docs/apple/apple-wire-spec.md.
// The RSA1 format is: header metadata + RSA public key components.

#ifndef FARSEE_INCLUDE_FARSEE_RSA1_ENVELOPE_H
#define FARSEE_INCLUDE_FARSEE_RSA1_ENVELOPE_H

#include "farsee/error.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Maximum RSA key size supported (2048 bits = 256 bytes).
#define RSA1_MAX_KEY_BYTES 256

// RSA1 key descriptor (26 bytes in the wire format).
typedef struct rsa1_descriptor {
    uint16_t version;      // required: 0x0001
    uint16_t type;         // required: 0x0003
    uint16_t key_type;     // required: 0x0010
    uint16_t key_version;  // required: 0x0001
    char magic[4];         // "RSA1"
    uint16_t param1;       // required: 0x0004
    uint32_t param2;       // required: 0x00000001
    uint16_t param3;       // required: 0x0002
    uint16_t param4;       // required: 0x0003
} rsa1_descriptor;

// RSA1 public key (modulus + exponent).
typedef struct rsa1_public_key {
    uint8_t modulus[RSA1_MAX_KEY_BYTES];
    size_t modulus_len;
    uint8_t exponent[4];
    size_t exponent_len;
} rsa1_public_key;

// Parse a raw RSA1 envelope (as sent by the client).
// Returns RFB_OK on success, RFB_ERR_PROTOCOL on malformed data.
rfb_error rsa1_parse_envelope(const uint8_t *data, size_t len,
                              rsa1_public_key *out_key);

// Serialize an RSA1 envelope for sending.
// Returns RFB_OK, sets *out_len to bytes written.
rfb_error rsa1_serialize_envelope(const rsa1_public_key *key,
                                  uint8_t *out, size_t out_cap, size_t *out_len);

// Parse the server's RSA1 key descriptor (26 bytes).
rfb_error rsa1_parse_descriptor(const uint8_t *data, size_t len,
                                rsa1_descriptor *out_desc);

// Serialize a key descriptor.
rfb_error rsa1_serialize_descriptor(const rsa1_descriptor *desc,
                                    uint8_t *out, size_t out_cap, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_RSA1_ENVELOPE_H
