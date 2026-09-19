// SPDX-License-Identifier: Apache-2.0
//
// farsee — Apple type-33 SRP challenge parser and SRP mathematics.
// Protocol contract: docs/apple/srp-challenge-offsets.md and RFC 5054.

#ifndef FARSEE_INCLUDE_FARSEE_APPLE_SRP_H
#define FARSEE_INCLUDE_FARSEE_APPLE_SRP_H

#include "farsee/allocator.h"
#include "farsee/error.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Maximum sizes for SRP parameters (RFC 5054 4096-bit group).
#define APPLE_SRP_N_BYTES  512u   // 4096-bit modulus
#define APPLE_SRP_M1_BYTES 64u    // SHA-512 output
#define APPLE_SRP_SALT_MAX 64u    // salt length cap
#define APPLE_SRP_OPTIONS_MAX 256u // options string cap
// The parser accepts server-supplied PBKDF2 iteration counts only within this
// project policy range. RFC 5054 does not define this Apple-variant field.
#define APPLE_SRP_ITER_MIN 1000u
#define APPLE_SRP_ITER_MAX 10000000u  // 10M cap (prevents DoS)

// Parsed SRP challenge from the server.
typedef struct apple_srp_challenge {
    // RSA1 envelope fields
    uint16_t version;
    uint16_t authtype;
    uint16_t body_len;
    uint16_t preamble;
    uint16_t inner_len;

    // SRP parameters (borrowed pointers into the input buffer)
    const uint8_t *N;         size_t N_len;    // modulus (512 bytes)
    const uint8_t *g;         size_t g_len;    // generator (1 byte, value 5)
    const uint8_t *salt;      size_t salt_len; // random salt
    const uint8_t *B;         size_t B_len;    // server public value
    uint32_t iterations;                        // PBKDF2 iterations
    const uint8_t *options;   size_t options_len; // crypto params string

    // Padding field between B and iterations
    uint32_t padding;
} apple_srp_challenge;

// Parse a server SRP challenge from a complete buffer.
// All pointers in the result borrow into the input buffer (zero-copy).
// Returns RFB_OK on success, or:
//   RFB_ERR_PROTOCOL — truncated, wrong lengths, bad N/g/B, malformed
//   RFB_ERR_LIMIT — iterations or salt exceeds policy
//   RFB_ERR_INTERNAL — NULL argument
rfb_error apple_srp_parse_challenge(const uint8_t *data, size_t len,
                                    apple_srp_challenge *out);

// Parse the supported type-36 challenge envelope:
//   u32be total_len | u16be version | u16be body_len | SRP payload
// The SRP payload and validation rules are identical to type 33.
rfb_error apple_srp_parse_type36_challenge(const uint8_t *data, size_t len,
                                           apple_srp_challenge *out);

// ---- SRP mathematics (RFC 5054 §2.6, Apple variant) ----------------------

// SRP session context. All secrets are zeroized on destroy.
typedef struct apple_srp_session {
    // Public parameters (from challenge)
    const uint8_t *N;
    size_t N_len;
    const uint8_t *g;
    size_t g_len;
    const uint8_t *salt;
    size_t salt_len;
    uint32_t iterations;

    // Client secrets (zeroized on destroy)
    uint8_t a[APPLE_SRP_N_BYTES];    // caller-supplied private exponent copy
    size_t a_len;
    uint8_t x[APPLE_SRP_M1_BYTES];   // password-derived exponent
    size_t x_len;
    uint8_t S[APPLE_SRP_N_BYTES];    // shared secret
    size_t S_len;
    uint8_t K[64];                   // session key (SHA-512 of S)
    uint8_t M1[APPLE_SRP_M1_BYTES];  // client proof
    size_t M1_len;

    // Public values
    uint8_t A[APPLE_SRP_N_BYTES];    // client public value (g^a mod N)
    size_t A_len;
} apple_srp_session;

// Compute P', x, A, u, S, K, and M1 from a parsed challenge, password, and
// caller-supplied private exponent bytes. The live authenticator supplies 32
// CSPRNG bytes; this function accepts up to the N-width and does not enforce a
// minimum. Destroy the session to zero its stored secrets.
//
// Returns RFB_OK on success, RFB_ERR_PROTOCOL when `a` exceeds the N-width or
// the computed scrambler is zero, or RFB_ERR_INTERNAL on NULL/provider failure.
// After argument validation succeeds, every failure clears all session-owned
// output arrays and their lengths.
rfb_error apple_srp_compute_client(
    const apple_srp_challenge *challenge,
    const uint8_t *username, size_t username_len,
    const uint8_t *password, size_t password_len,
    const uint8_t *a, size_t a_len,
    apple_srp_session *out);

rfb_error apple_srp_compute_client_with_allocator(
    const apple_srp_challenge *challenge,
    const uint8_t *username, size_t username_len,
    const uint8_t *password, size_t password_len,
    const uint8_t *a, size_t a_len, apple_srp_session *out,
    rfb_allocator *allocator);

// Compute M2 (server proof verification): H(PAD(A) || M1 || K).
// Used to verify the server's proof before accepting SecurityResult=0.
rfb_error apple_srp_compute_m2(
    const apple_srp_session *session,
    const uint8_t *B, size_t B_len,
    uint8_t m2_out[APPLE_SRP_M1_BYTES]);

rfb_error apple_srp_compute_m2_with_allocator(
    const apple_srp_session *session, const uint8_t *B, size_t B_len,
    uint8_t m2_out[APPLE_SRP_M1_BYTES], rfb_allocator *allocator);

// Derive SHA-256(K) as 32 bytes. The session retains this value for its
// candidate record-setup modes; the wrap key is its first 16 bytes.
bool apple_srp_derive_session_key_32(
    const apple_srp_session *session,
    uint8_t out_key[32]);

// Derive the wrap key from K: SHA256(K)[0:16]. Returns false on crypto fail.
bool apple_srp_derive_wrap_key(
    const apple_srp_session *session,
    uint8_t wrap_key[16]);

// Zeroize all secrets in the session. Safe to call on partially-initialized.
void apple_srp_session_destroy(apple_srp_session *session);

// ---- Packet 2 serialization ----------------------------------------------

// Serialize packet 2 (the client's SRP response) from a computed session.
// Layout:
//   u32_be total_len      = computed
//   u16_be version        = 0x0100
//   "RSA1"                 (4 bytes)
//   u16_be authtype       = 2
//   u16_be meaningful_len = inner_len + 4 (preamble + inner_len fields)
//   u16_be preamble       = 0
//   u16_be inner_len      = computed
//   inner:
//     u16_be A_len + A (512 bytes)
//     u8 M1_len + M1 (64 bytes)
//     u16_be options_len + options (exact echo)
//     u8 client_random_len + client_random (16 bytes)
//   u8[384] compatibility tail (zero-initialized)
//
// Returns RFB_OK, RFB_ERR_LIMIT if out_cap too small, RFB_ERR_INTERNAL on NULL.
rfb_error apple_srp_serialize_packet2(
    const apple_srp_session *session,
    const char *options, size_t options_len,
    const uint8_t client_random[16],
    uint8_t *out, size_t out_cap, size_t *out_len);

// Serialize the supported type-36 client proof envelope. Its payload fields
// match packet 2 above, but its envelope is:
//   u32be total_len | u32be inner_len | inner
// It has no RSA1 header and no 384-byte compatibility tail.
rfb_error apple_srp_serialize_type36_packet2(
    const apple_srp_session *session,
    const char *options, size_t options_len,
    const uint8_t client_random[16],
    uint8_t *out, size_t out_cap, size_t *out_len);

// ---- Server response parser (RSA1 envelope + SecurityResult) --------------
//
// After packet 2, the server sends an RSA1 envelope followed by a u32_be
// SecurityResult. The envelope format:
//   u32_be total_len
//   u16_be version
//   u16_be authtype
//   u16_be meaningful_body_len  (= 0 on failure)
//   [on success: preamble, inner_len, M2(64), server_random(16)]
//
// Then a u32_be SecurityResult (0=success, 1=failure).
//
// On failure the envelope is empty (total_len=6, body_len=0), followed by
// SecurityResult=1. The full failure sequence is 14 bytes:
//   00 00 00 06  00 00 00 02  00 00  00 00 00 01
// A 10-byte read is an INCOMPLETE read — only the envelope, not the result.

typedef struct apple_srp_auth_response {
    // RSA1 envelope
    uint32_t total_len;
    uint16_t version;
    uint16_t authtype;
    uint16_t meaningful_len;

    // On success only (borrowed pointers into input buffer)
    const uint8_t *M2;           size_t M2_len;
    const uint8_t *server_random; size_t server_random_len;

    // SecurityResult (after the envelope)
    uint32_t security_result;
} apple_srp_auth_response;

// Parse a server authentication response.
// The input must contain BOTH the RSA1 envelope AND the trailing SecurityResult.
// For a failure response (empty envelope), total input = 14 bytes minimum.
// For a success response, total input = 4 + total_len + 4 bytes.
//
// Returns RFB_OK on success, RFB_ERR_PROTOCOL on truncated/malformed data.
rfb_error apple_srp_parse_auth_response(const uint8_t *data, size_t len,
                                        apple_srp_auth_response *out);

// Parse the type-36 server proof envelope plus SecurityResult. A rejected
// proof can be the bare four-byte SecurityResult=1. A successful response
// must carry M2, server_random, six zero compatibility bytes, and result 0.
rfb_error apple_srp_parse_type36_auth_response(
    const uint8_t *data, size_t len, apple_srp_auth_response *out);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_APPLE_SRP_H
