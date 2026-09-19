// SPDX-License-Identifier: Apache-2.0
//
// farsee — modern Apple post-auth wire framing with AES-CBC records.

#include "farsee/apple_wire_record.h"

#include "farsee/apple_crypto.h"
#include "farsee/bytes.h"

#include <stdlib.h>
#include <string.h>

// Record layout:
//   padded = ceil16(msg_len + 2 + 20)   // u16be mlen + msg + SHA-1
//   pt     = u16be(msg_len) || msg || zero_pad || SHA1(be32(seq) || body)
//   body   = pt without the trailing 20-byte packet checksum
//   seq    = per-direction counter (0 on first record after enable)
// Sequence numbers start at zero and increase once per direction.

// msg14 body: 14 00 00 04 00 01 00 0c
const uint8_t apple_wire_msg14[APPLE_WIRE_MSG14_LEN] = {
    0x14u, 0x00u, 0x00u, 0x04u, 0x00u, 0x01u, 0x00u, 0x0cu
};

// msg12 acknowledgement: 12 00 00 02 00 01 00 00
const uint8_t apple_wire_msg12_ack[APPLE_WIRE_MSG12_ACK_LEN] = {
    0x12u, 0x00u, 0x00u, 0x02u, 0x00u, 0x01u, 0x00u, 0x00u
};

// Client post-ServerInit bytes:
// cfg21(66) || msg12-part(16) || SetEncodings(56) = 138.
const uint8_t apple_wire_modern_post_si[APPLE_WIRE_MODERN_POST_SI_LEN] = {
    // cfg21 66 B
    0x21u, 0x00u, 0x00u, 0x3eu, 0x00u, 0x01u, 0x00u, 0x00u, 0x00u, 0x02u,
    0x00u, 0x00u, 0x00u, 0x06u, 0x00u, 0x00u, 0x00u, 0x01u, 0x00u, 0x00u,
    0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x1au, 0x00u, 0x00u, 0x00u, 0x05u,
    0x00u, 0x00u, 0x00u, 0x02u, 0xb0u, 0x00u, 0x0cu, 0x03u, 0x90u, 0x00u,
    0x00u, 0x00u, 0x00u, 0x00u, 0x40u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
    0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
    0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
    // msg12-part 16 B
    0x12u, 0x00u, 0x00u, 0x01u, 0x00u, 0x01u, 0x00u, 0x01u, 0x00u, 0x00u,
    0x00u, 0x01u, 0x0au, 0x00u, 0x00u, 0x01u,
    // SetEncodings 56 B
    0x02u, 0x00u, 0x00u, 0x0du, 0x00u, 0x00u, 0x03u, 0xf3u, 0x00u, 0x00u,
    0x03u, 0xeau, 0x00u, 0x00u, 0x00u, 0x06u, 0x00u, 0x00u, 0x00u, 0x10u,
    0xffu, 0xffu, 0xffu, 0x11u, 0x00u, 0x00u, 0x04u, 0x50u, 0x00u, 0x00u,
    0x04u, 0x4cu, 0xffu, 0xffu, 0xffu, 0x21u, 0x00u, 0x00u, 0x04u, 0x4du,
    0x00u, 0x00u, 0x04u, 0x51u, 0x00u, 0x00u, 0x04u, 0x53u, 0x00u, 0x00u,
    0x04u, 0x55u, 0x00u, 0x00u, 0x04u, 0x56u
};

bool apple_wire_product_wants_sealed_fbur(bool silence)
{
    return !silence;
}

static uint32_t wire_u32be(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

size_t apple_wire_setup_inspect(const uint8_t *data, size_t len,
                                apple_wire_setup_info *out)
{
    if (out == NULL) {
        return (size_t)-1;
    }
    out->consume = 0u;
    out->type = 0u;
    out->method = 0u;
    out->payload32 = NULL;
    out->supported = false;
    if (data == NULL) {
        return 0u;
    }

    size_t off = 0u;
    // Optional leading msg14.
    if (len >= APPLE_WIRE_MSG14_LEN &&
        memcmp(data, apple_wire_msg14, APPLE_WIRE_MSG14_LEN) == 0) {
        off = APPLE_WIRE_MSG14_LEN;
    }

    if (len < off + APPLE_WIRE_SETUP_LEN) {
        return 0u; // incomplete
    }

    // Envelope marker: u32be 1, 0, 0. The next two words are the cipher
    // suite and are read, not asserted.
    const uint8_t *s = data + off;
    if (wire_u32be(s) != 1u || wire_u32be(s + 4) != 0u ||
        wire_u32be(s + 8) != 0u) {
        return (size_t)-1;
    }

    out->consume = off + APPLE_WIRE_SETUP_LEN;
    out->type = wire_u32be(s + 12);
    out->method = wire_u32be(s + 16);
    out->payload32 = s + 20;
    out->supported = out->type == APPLE_WIRE_TYPE_ENABLE &&
                     out->method == APPLE_WIRE_SETUP_METHOD_AES_CBC;
    return out->consume;
}

size_t apple_wire_setup_consume_len(const uint8_t *data, size_t len,
                                    const uint8_t **out_payload32)
{
    if (out_payload32 != NULL) {
        *out_payload32 = NULL;
    }
    apple_wire_setup_info info;
    const size_t n = apple_wire_setup_inspect(data, len, &info);
    if (n == 0u || n == (size_t)-1) {
        return n;
    }
    if (!info.supported) {
        return (size_t)-1;
    }
    if (out_payload32 != NULL) {
        *out_payload32 = info.payload32;
    }
    return n;
}

bool apple_wire_msg_is_typed(const uint8_t *msg, size_t msg_len,
                             uint32_t *out_type)
{
    if (out_type != NULL) {
        *out_type = 0u;
    }
    if (msg == NULL || msg_len < 16u) {
        return false;
    }
    uint32_t a = ((uint32_t)msg[0] << 24) | ((uint32_t)msg[1] << 16) |
                 ((uint32_t)msg[2] << 8) | (uint32_t)msg[3];
    uint32_t b = ((uint32_t)msg[4] << 24) | ((uint32_t)msg[5] << 16) |
                 ((uint32_t)msg[6] << 8) | (uint32_t)msg[7];
    uint32_t c = ((uint32_t)msg[8] << 24) | ((uint32_t)msg[9] << 16) |
                 ((uint32_t)msg[10] << 8) | (uint32_t)msg[11];
    uint32_t t = ((uint32_t)msg[12] << 24) | ((uint32_t)msg[13] << 16) |
                 ((uint32_t)msg[14] << 8) | (uint32_t)msg[15];
    if (a != 1u || b != 0u || c != 0u) {
        return false;
    }
    if (out_type != NULL) {
        *out_type = t;
    }
    return true;
}

bool apple_wire_msg_is_msg14(const uint8_t *msg, size_t msg_len)
{
    // msg14 classification accepts any eight-byte body whose first byte is
    // 0x14; the remaining seven bytes are not validated.
    return msg != NULL && msg_len == APPLE_WIRE_MSG14_LEN && msg[0] == 0x14u;
}

const char *apple_wire_msg_kind_name(apple_wire_msg_kind k)
{
    switch (k) {
    case APPLE_WIRE_KIND_EMPTY:
        return "empty";
    case APPLE_WIRE_KIND_MSG14:
        return "msg14";
    case APPLE_WIRE_KIND_MSG12:
        return "msg12";
    case APPLE_WIRE_KIND_CFG21:
        return "cfg21";
    case APPLE_WIRE_KIND_SET_ENCODINGS:
        return "set_encodings";
    case APPLE_WIRE_KIND_FBUR:
        return "fbur";
    case APPLE_WIRE_KIND_FBU:
        return "fbu";
    case APPLE_WIRE_KIND_KEY:
        return "key";
    case APPLE_WIRE_KIND_POINTER:
        return "pointer";
    case APPLE_WIRE_KIND_CUT_TEXT:
        return "cut_text";
    case APPLE_WIRE_KIND_TYPED:
        return "typed";
    case APPLE_WIRE_KIND_CLASSIC:
        return "classic";
    case APPLE_WIRE_KIND_UNKNOWN:
    default:
        return "unknown";
    }
}

apple_wire_msg_kind apple_wire_classify_msg(const uint8_t *msg, size_t msg_len,
                                            uint32_t *out_code)
{
    if (out_code != NULL) {
        *out_code = 0u;
    }
    if (msg == NULL || msg_len == 0u) {
        return APPLE_WIRE_KIND_EMPTY;
    }
    if (apple_wire_msg_is_msg14(msg, msg_len)) {
        if (out_code != NULL) {
            *out_code = 0x14u;
        }
        return APPLE_WIRE_KIND_MSG14;
    }
    {
        uint32_t t = 0u;
        if (apple_wire_msg_is_typed(msg, msg_len, &t)) {
            if (out_code != NULL) {
                *out_code = t;
            }
            return APPLE_WIRE_KIND_TYPED;
        }
    }
    // Apple cleartext control heads (pre-enable and sealed).
    if (msg[0] == 0x21u) {
        if (out_code != NULL) {
            *out_code = 0x21u;
        }
        return APPLE_WIRE_KIND_CFG21;
    }
    if (msg[0] == 0x12u) {
        if (out_code != NULL) {
            *out_code = 0x12u;
        }
        return APPLE_WIRE_KIND_MSG12;
    }
    // Classic RFB client/server types (RFC 6143).
    if (out_code != NULL) {
        *out_code = (uint32_t)msg[0];
    }
    switch (msg[0]) {
    case 0x00u:
        return APPLE_WIRE_KIND_FBU;
    case 0x02u:
        if (msg_len >= 4u) {
            return APPLE_WIRE_KIND_SET_ENCODINGS;
        }
        return APPLE_WIRE_KIND_CLASSIC;
    case 0x03u:
        return APPLE_WIRE_KIND_FBUR;
    case 0x04u:
        return APPLE_WIRE_KIND_KEY;
    case 0x05u:
        return APPLE_WIRE_KIND_POINTER;
    case 0x06u:
        return APPLE_WIRE_KIND_CUT_TEXT;
    default:
        if (msg[0] <= 0x06u) {
            return APPLE_WIRE_KIND_CLASSIC;
        }
        return APPLE_WIRE_KIND_UNKNOWN;
    }
}

size_t apple_wire_cipher_record_len(const uint8_t *data, size_t len,
                                    size_t max_body)
{
    if (data == NULL || len < 2u) {
        return 0u;
    }
    const uint16_t ct_len =
        (uint16_t)(((uint16_t)data[0] << 8) | (uint16_t)data[1]);
    // The checksum layout has a natural 32-byte minimum.
    if (ct_len < APPLE_WIRE_RECORD_MIN_BODY ||
        (ct_len % APPLE_BLOCK_SIZE) != 0u) {
        return (size_t)-1;
    }
    if ((size_t)ct_len > max_body) {
        return (size_t)-1;
    }
    const size_t total = 2u + (size_t)ct_len;
    if (len < total) {
        return 0u;
    }
    return total;
}

rfb_error apple_wire_record_seal(apple_record_layer *rl,
                                 const uint8_t *msg, size_t msg_len,
                                 uint8_t *out, size_t out_cap,
                                 size_t *out_len)
{
    return apple_wire_record_seal_with_allocator(
        rl, msg, msg_len, out, out_cap, out_len, rfb_default_allocator());
}

rfb_error apple_wire_record_seal_with_allocator(
    apple_record_layer *rl, const uint8_t *msg, size_t msg_len, uint8_t *out,
    size_t out_cap, size_t *out_len, rfb_allocator *allocator)
{
    if (out_len != NULL) {
        *out_len = 0u;
    }
    if (rl == NULL || msg == NULL || out == NULL || out_len == NULL) {
        return RFB_ERR_INTERNAL;
    }
    if (msg_len == 0u || msg_len > 0xffffu) {
        return RFB_ERR_PROTOCOL;
    }
    if (!rl->encrypt.active) {
        return RFB_ERR_STATE;
    }
    rfb_allocator *a = allocator != NULL ? allocator : rfb_default_allocator();
    if (a->alloc == NULL || a->free == NULL) {
        return RFB_ERR_INTERNAL;
    }

    // padded = ceil16(msg_len + 2 + SHA1)
    size_t padded =
        ((msg_len + 2u + APPLE_WIRE_SHA1_LEN + (APPLE_BLOCK_SIZE - 1u)) /
         APPLE_BLOCK_SIZE) *
        APPLE_BLOCK_SIZE;
    if (padded > APPLE_RECORD_MAX_BODY) {
        return RFB_ERR_LIMIT;
    }
    if (out_cap < 2u + padded) {
        return RFB_ERR_LIMIT;
    }
    if (padded < 2u + msg_len + APPLE_WIRE_SHA1_LEN) {
        return RFB_ERR_INTERNAL;
    }

    enum { k_stage_max = 64u * 1024u };
    if (padded > k_stage_max) {
        return RFB_ERR_LIMIT;
    }

    // Heap staging keeps the two large work buffers off the call stack. Fail
    // closed on allocation failure and zeroize the buffers before release.
    uint8_t *pt = (uint8_t *)a->alloc(a, padded);
    uint8_t *sha_in = (uint8_t *)a->alloc(a, 4u + padded);
    if (pt == NULL || sha_in == NULL) {
        if (pt != NULL) {
            a->free(a, pt);
        }
        if (sha_in != NULL) {
            a->free(a, sha_in);
        }
        return RFB_ERR_NOMEM;
    }
    const size_t body_len = padded - APPLE_WIRE_SHA1_LEN;
    pt[0] = (uint8_t)((msg_len >> 8) & 0xffu);
    pt[1] = (uint8_t)(msg_len & 0xffu);
    memcpy(pt + 2, msg, msg_len);
    // Zero-pad between the message and SHA-1.
    if (body_len > 2u + msg_len) {
        memset(pt + 2u + msg_len, 0, body_len - (2u + msg_len));
    }

    // SHA1(be32(seq) || body) → trailing 20 bytes. seq is encrypt counter
    // *before* this record (apple_record_encrypt increments after CBC).
    const uint32_t seq = (uint32_t)rl->encrypt.sequence;
    sha_in[0] = (uint8_t)((seq >> 24) & 0xffu);
    sha_in[1] = (uint8_t)((seq >> 16) & 0xffu);
    sha_in[2] = (uint8_t)((seq >> 8) & 0xffu);
    sha_in[3] = (uint8_t)(seq & 0xffu);
    memcpy(sha_in + 4, pt, body_len);
    if (!rfb_crypto_sha1(sha_in, 4u + body_len, pt + body_len)) {
        memset(pt, 0, padded);
        memset(sha_in, 0, 4u + body_len);
        a->free(a, pt);
        a->free(a, sha_in);
        return RFB_ERR_INTERNAL;
    }
    memset(sha_in, 0, 4u + body_len);

    size_t ct_len = 0u;
    rfb_error e =
        apple_record_encrypt(rl, pt, padded, out + 2, out_cap - 2u, &ct_len);
    memset(pt, 0, padded);
    a->free(a, pt);
    a->free(a, sha_in);
    if (e != RFB_OK) {
        return e;
    }
    if (ct_len != padded) {
        return RFB_ERR_INTERNAL;
    }
    out[0] = (uint8_t)((ct_len >> 8) & 0xffu);
    out[1] = (uint8_t)(ct_len & 0xffu);
    *out_len = 2u + ct_len;
    return RFB_OK;
}

rfb_error apple_wire_record_open(apple_record_layer *rl,
                                 const uint8_t *ct, size_t ct_len,
                                 uint8_t *msg_out, size_t msg_cap,
                                 size_t *msg_len)
{
    return apple_wire_record_open_with_allocator(
        rl, ct, ct_len, msg_out, msg_cap, msg_len,
        rfb_default_allocator());
}

rfb_error apple_wire_record_open_with_allocator(
    apple_record_layer *rl, const uint8_t *ct, size_t ct_len,
    uint8_t *msg_out, size_t msg_cap, size_t *msg_len,
    rfb_allocator *allocator)
{
    if (msg_len != NULL) {
        *msg_len = 0u;
    }
    if (rl == NULL || ct == NULL || msg_out == NULL || msg_len == NULL) {
        return RFB_ERR_INTERNAL;
    }
    if (ct_len == 0u || (ct_len % APPLE_BLOCK_SIZE) != 0u) {
        return RFB_ERR_PROTOCOL;
    }
    if (ct_len < 2u + APPLE_WIRE_SHA1_LEN) {
        return RFB_ERR_PROTOCOL;
    }
    if (ct_len > APPLE_RECORD_MAX_BODY) {
        return RFB_ERR_LIMIT;
    }
    if (msg_cap < ct_len) {
        return RFB_ERR_LIMIT;
    }
    if (!rl->decrypt.active) {
        return RFB_ERR_STATE;
    }
    rfb_allocator *a = allocator != NULL ? allocator : rfb_default_allocator();
    if (a->alloc == NULL || a->free == NULL) {
        return RFB_ERR_INTERNAL;
    }

    // Sequence for this record (before decrypt increments).
    const uint32_t seq = (uint32_t)rl->decrypt.sequence;

    const size_t body_len = ct_len - APPLE_WIRE_SHA1_LEN;
    enum { k_open_stage_max = 64u * 1024u };
    if (4u + body_len > k_open_stage_max) {
        return RFB_ERR_LIMIT;
    }
    uint8_t expect[APPLE_WIRE_SHA1_LEN];
    uint8_t *sha_in = (uint8_t *)a->alloc(a, 4u + body_len);
    if (sha_in == NULL) {
        return RFB_ERR_NOMEM;
    }

    size_t pt_len = 0u;
    rfb_error e =
        apple_record_decrypt(rl, ct, ct_len, msg_out, msg_cap, &pt_len);
    if (e != RFB_OK) {
        memset(sha_in, 0, 4u + body_len);
        a->free(a, sha_in);
        return e;
    }
    if (pt_len < 2u + APPLE_WIRE_SHA1_LEN || pt_len != ct_len) {
        memset(sha_in, 0, 4u + body_len);
        a->free(a, sha_in);
        return RFB_ERR_PROTOCOL;
    }

    // Use heap staging and compare the packet checksum in constant time. Fail
    // closed on allocation failure or checksum mismatch.
    // The staging bound mirrors the seal side (k_stage_max): no sealed
    // body can exceed it, and the wire ct_len is u16 anyway.
    sha_in[0] = (uint8_t)((seq >> 24) & 0xffu);
    sha_in[1] = (uint8_t)((seq >> 16) & 0xffu);
    sha_in[2] = (uint8_t)((seq >> 8) & 0xffu);
    sha_in[3] = (uint8_t)(seq & 0xffu);
    memcpy(sha_in + 4, msg_out, body_len);
    if (!rfb_crypto_sha1(sha_in, 4u + body_len, expect)) {
        memset(sha_in, 0, 4u + body_len);
        a->free(a, sha_in);
        return RFB_ERR_INTERNAL;
    }
    memset(sha_in, 0, 4u + body_len);
    a->free(a, sha_in);
    if (!rfb_crypto_ct_eq(expect, msg_out + body_len, APPLE_WIRE_SHA1_LEN)) {
        // Reject the record through the peer checksum-error path.
        return RFB_ERR_PROTOCOL;
    }

    const size_t mlen =
        ((size_t)msg_out[0] << 8) | (size_t)msg_out[1];
    if (mlen + 2u > body_len) {
        return RFB_ERR_PROTOCOL;
    }

    if (mlen > 0u) {
        memmove(msg_out, msg_out + 2, mlen);
    }
    *msg_len = mlen;
    return RFB_OK;
}
