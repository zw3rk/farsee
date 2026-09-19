// SPDX-License-Identifier: Apache-2.0
//
// farsee — RSA1 envelope parser/serializer.

#include "farsee/rsa1_envelope.h"
#include "farsee/bytes.h"

#include <string.h>

// Read a big-endian u16 from a byte array.
static uint16_t read_be16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] << 8 | (uint16_t)p[1]);
}

// Read a big-endian u32 from a byte array.
static uint32_t read_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

// Write a big-endian u16 to a byte array.
static void write_be16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xFF);
}

// Write a big-endian u32 to a byte array.
static void write_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)((v >> 24) & 0xFF);
    p[1] = (uint8_t)((v >> 16) & 0xFF);
    p[2] = (uint8_t)((v >> 8) & 0xFF);
    p[3] = (uint8_t)(v & 0xFF);
}

rfb_error rsa1_parse_envelope(const uint8_t *data, size_t len,
                              rsa1_public_key *out_key)
{
    if (data == NULL || out_key == NULL) return RFB_ERR_INTERNAL;
    if (len < 8) return RFB_ERR_PROTOCOL;  // minimum: u32 mod_len + u32 exp_len

    // Client envelope: u32 modulus length and bytes, then u32 exponent length
    // and bytes.
    size_t pos = 0;
    uint32_t mod_len = read_be32(data + pos);
    pos += 4;
    if (mod_len > RSA1_MAX_KEY_BYTES || pos + mod_len > len) {
        return RFB_ERR_PROTOCOL;
    }
    memcpy(out_key->modulus, data + pos, mod_len);
    out_key->modulus_len = mod_len;
    pos += mod_len;

    if (pos + 4 > len) return RFB_ERR_PROTOCOL;
    uint32_t exp_len = read_be32(data + pos);
    pos += 4;
    if (exp_len > 4 || pos + exp_len > len) {
        return RFB_ERR_PROTOCOL;
    }
    memcpy(out_key->exponent, data + pos, exp_len);
    out_key->exponent_len = exp_len;

    return RFB_OK;
}

rfb_error rsa1_serialize_envelope(const rsa1_public_key *key,
                                  uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (key == NULL || out == NULL || out_len == NULL) return RFB_ERR_INTERNAL;
    size_t needed = 4 + key->modulus_len + 4 + key->exponent_len;
    if (needed > out_cap) return RFB_ERR_LIMIT;
    if (key->modulus_len > RSA1_MAX_KEY_BYTES) return RFB_ERR_PROTOCOL;
    if (key->exponent_len > 4) return RFB_ERR_PROTOCOL;

    size_t pos = 0;
    write_be32(out + pos, (uint32_t)key->modulus_len);
    pos += 4;
    memcpy(out + pos, key->modulus, key->modulus_len);
    pos += key->modulus_len;
    write_be32(out + pos, (uint32_t)key->exponent_len);
    pos += 4;
    memcpy(out + pos, key->exponent, key->exponent_len);
    pos += key->exponent_len;

    *out_len = pos;
    return RFB_OK;
}

rfb_error rsa1_parse_descriptor(const uint8_t *data, size_t len,
                                rsa1_descriptor *out_desc)
{
    if (data == NULL || out_desc == NULL) return RFB_ERR_INTERNAL;
    // The descriptor is preceded by a u32 length (0x00000016 = 22 bytes).
    if (len < 4 + 22) return RFB_ERR_PROTOCOL;

    size_t pos = 0;
    uint32_t desc_len = read_be32(data + pos);
    pos += 4;
    if (desc_len != 22) return RFB_ERR_PROTOCOL;

    out_desc->version = read_be16(data + pos); pos += 2;
    out_desc->type = read_be16(data + pos); pos += 2;
    out_desc->key_type = read_be16(data + pos); pos += 2;
    out_desc->key_version = read_be16(data + pos); pos += 2;
    memcpy(out_desc->magic, data + pos, 4);
    pos += 4;
    if (memcmp(out_desc->magic, "RSA1", 4) != 0) return RFB_ERR_PROTOCOL;
    out_desc->param1 = read_be16(data + pos); pos += 2;
    out_desc->param2 = read_be32(data + pos); pos += 4;
    out_desc->param3 = read_be16(data + pos); pos += 2;
    out_desc->param4 = read_be16(data + pos);

    return RFB_OK;
}

rfb_error rsa1_serialize_descriptor(const rsa1_descriptor *desc,
                                    uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (desc == NULL || out == NULL || out_len == NULL) return RFB_ERR_INTERNAL;
    if (out_cap < 26) return RFB_ERR_LIMIT;

    size_t pos = 0;
    write_be32(out + pos, 22); pos += 4;  // descriptor length
    write_be16(out + pos, desc->version); pos += 2;
    write_be16(out + pos, desc->type); pos += 2;
    write_be16(out + pos, desc->key_type); pos += 2;
    write_be16(out + pos, desc->key_version); pos += 2;
    memcpy(out + pos, "RSA1", 4); pos += 4;
    write_be16(out + pos, desc->param1); pos += 2;
    write_be32(out + pos, desc->param2); pos += 4;
    write_be16(out + pos, desc->param3); pos += 2;
    write_be16(out + pos, desc->param4); pos += 2;

    *out_len = pos;
    return RFB_OK;
}
