// SPDX-License-Identifier: Apache-2.0
//
// farsee — modern Apple post-auth wire framing with AES-CBC records.
//
// Post-authentication sequence after type-33:
//   Client: cfg21(66) || msg12-part(16) || SetEncodings(56)   [cleartext]
//   Server: [optional 8 B msg14] || setup52 (type 0x044f + payload32)
//   Client: msg12 ack 8 B                                      [cleartext]
//   Both:   u16be(ct_len) || AES-128-CBC(content_key, chained_iv)[pt]
//   pt:     u16be(msg_len) || msg || zero-pad || SHA1(be32(seq)||body)
//           body = pt without trailing 20-byte SHA-1; seq per-direction
//           counter from 0 after enable
//           padded = ceil16(msg_len + 2 + 20)
//   Note: SHA-1 is an unkeyed *packet checksum* inside CBC (Apple design),
//   not a cryptographic MAC — key holder can forge.
//
// content_key||iv0 = AES-ECB-dec(wrap_key, payload32) via
// apple_record_enable_wrapped().
//
// Pure helpers: no sockets. Session owns the record layer + demux loop.

#ifndef FARSEE_INCLUDE_FARSEE_APPLE_WIRE_RECORD_H
#define FARSEE_INCLUDE_FARSEE_APPLE_WIRE_RECORD_H

#include "farsee/allocator.h"
#include "farsee/apple_record.h"
#include "farsee/error.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Cleartext 0x14 tick seen before setup and inside encrypted records.
#define APPLE_WIRE_MSG14_LEN 8u
// Cleartext crypto enable: 5×u32be + payload32.
#define APPLE_WIRE_SETUP_LEN 52u
#define APPLE_WIRE_TYPE_ENABLE 0x044fu
// Fifth setup word for the supported AES-128-CBC record suite with the SHA-1
// packet checksum. Other method values are unsupported.
#define APPLE_WIRE_SETUP_METHOD_AES_CBC 1u
// Cleartext client msg12 acknowledgement after setup.
#define APPLE_WIRE_MSG12_ACK_LEN 8u
// Post-ServerInit client cleartext (cfg||msg16||setenc).
#define APPLE_WIRE_MODERN_POST_SI_LEN 138u

// Natural minimum of the SHA-1 layout: msg14 mlen=8 yields
// ceil16(8+22)=32.
#define APPLE_WIRE_RECORD_MIN_BODY 32u
// Trailing SHA-1 packet-checksum length inside each CBC plaintext body.
#define APPLE_WIRE_SHA1_LEN 20u

// Eight-byte msg14 body (also the cleartext prefix form).
extern const uint8_t apple_wire_msg14[APPLE_WIRE_MSG14_LEN];
// msg12 acknowledgement: 12 00 00 02 00 01 00 00
extern const uint8_t apple_wire_msg12_ack[APPLE_WIRE_MSG12_ACK_LEN];
// Client post-ServerInit cleartext (138 B).
extern const uint8_t apple_wire_modern_post_si[APPLE_WIRE_MODERN_POST_SI_LEN];

// Post-authentication crypto-enable envelope.
//
//   [optional 8 B msg14] || u32be 1 | u32be 0 | u32be 0
//                        || u32be type | u32be method | u8 payload[32]
//
// `type` and `method` are retained so callers can reject unsupported suites
// with a specific protocol error.
typedef struct apple_wire_setup_info {
    size_t consume;             // total bytes of msg14 + setup52
    uint32_t type;              // setup type word (supported: 0x044f)
    uint32_t method;            // method word (supported: 1)
    const uint8_t *payload32;   // 32 B wrapped key material inside `data`
    bool supported;             // type/method match the AES-CBC suite
} apple_wire_setup_info;

// Pure: recognise the setup ENVELOPE without demanding a particular cipher
// suite, then report whether the suite is one we can key from.
//
// Returns:
//   >0  — consume this many bytes; *out is filled (check out->supported
//         before installing keys; payload32 stays valid until the caller
//         consumes/moves the buffer)
//   0   — incomplete (need more input) or `data` is NULL
//   (size_t)-1 — not a setup envelope at all (marker words wrong), or `out`
//         is NULL
size_t apple_wire_setup_inspect(const uint8_t *data, size_t len,
                                apple_wire_setup_info *out);

// Pure: how many leading bytes form optional msg14 + complete 0x044f setup.
// Thin wrapper over apple_wire_setup_inspect that also refuses any suite
// other than the supported AES-CBC one.
//
// Returns:
//   >0  — consume this many bytes; non-NULL out_payload32 is set to the 32 B
//         payload inside `data` (valid until caller consumes/moves the buffer)
//   0   — incomplete (need more input); non-NULL out_payload32 is cleared
//   (size_t)-1 — present bytes are not a valid supported setup prefix
size_t apple_wire_setup_consume_len(const uint8_t *data, size_t len,
                                    const uint8_t **out_payload32);

// Pure: true if msg looks like Apple typed control
//   u32be 1 | u32be 0 | u32be 0 | u32be type | …
bool apple_wire_msg_is_typed(const uint8_t *msg, size_t msg_len,
                             uint32_t *out_type);

// Pure: true if msg is the 8-byte msg14 tick.
bool apple_wire_msg_is_msg14(const uint8_t *msg, size_t msg_len);

// Pure taxonomy for plaintext demultiplexing and diagnostics.
typedef enum apple_wire_msg_kind {
    APPLE_WIRE_KIND_EMPTY = 0,
    APPLE_WIRE_KIND_MSG14,
    APPLE_WIRE_KIND_MSG12,
    APPLE_WIRE_KIND_CFG21,
    APPLE_WIRE_KIND_SET_ENCODINGS,
    APPLE_WIRE_KIND_FBUR,
    APPLE_WIRE_KIND_FBU,
    APPLE_WIRE_KIND_KEY,
    APPLE_WIRE_KIND_POINTER,
    APPLE_WIRE_KIND_CUT_TEXT,
    APPLE_WIRE_KIND_TYPED,
    APPLE_WIRE_KIND_CLASSIC,
    APPLE_WIRE_KIND_UNKNOWN
} apple_wire_msg_kind;

// Pure: stable kind name for logs (never NULL).
const char *apple_wire_msg_kind_name(apple_wire_msg_kind k);

// Pure: classify one plaintext message body (after seal open / before seal).
// *out_code: RFB type byte, or Apple typed u32 type, or 0.
apple_wire_msg_kind apple_wire_classify_msg(const uint8_t *msg, size_t msg_len,
                                            uint32_t *out_code);

// Seal one plaintext RFB/Apple message into a wire record:
//   body = u16be(msg_len) || msg || zero-pad
//   out = u16be(ct_len) || CBC(body || SHA1(be32(seq) || body))
// Requires encrypt direction already enabled on rl.
rfb_error apple_wire_record_seal(apple_record_layer *rl,
                                 const uint8_t *msg, size_t msg_len,
                                 uint8_t *out, size_t out_cap,
                                 size_t *out_len);

// Allocator-aware form for session-scoped staging. The allocator is borrowed
// for the duration of the call. NULL selects the default allocator.
rfb_error apple_wire_record_seal_with_allocator(
    apple_record_layer *rl, const uint8_t *msg, size_t msg_len, uint8_t *out,
    size_t out_cap, size_t *out_len, rfb_allocator *allocator);

// Open one ciphertext body (ct_len already known; no u16 prefix):
//   CBC-decrypt, validate SHA1(be32(seq)||body), read u16be(msg_len),
//   and copy msg to msg_out.
// Requires decrypt direction enabled. ct_len must be a multiple of 16.
rfb_error apple_wire_record_open(apple_record_layer *rl,
                                 const uint8_t *ct, size_t ct_len,
                                 uint8_t *msg_out, size_t msg_cap,
                                 size_t *msg_len);

rfb_error apple_wire_record_open_with_allocator(
    apple_record_layer *rl, const uint8_t *ct, size_t ct_len,
    uint8_t *msg_out, size_t msg_cap, size_t *msg_len,
    rfb_allocator *allocator);

// Pure: if data starts with a complete u16be-framed ciphertext record,
// return total wire length (2+ct_len). Returns 0 if incomplete; (size_t)-1
// if ct_len is below APPLE_WIRE_RECORD_MIN_BODY, not a multiple of 16, or
// above max_body.
size_t apple_wire_cipher_record_len(const uint8_t *data, size_t len,
                                    size_t max_body);

// Product post-enable behavior: sealed FBUR unless silence (NO_FBUR). Pure.
// This never implies a sealed msg14-first sequence.
bool apple_wire_product_wants_sealed_fbur(bool silence);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_APPLE_WIRE_RECORD_H
