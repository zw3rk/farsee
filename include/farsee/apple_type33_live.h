// SPDX-License-Identifier: Apache-2.0
//
// farsee — blocking Apple type-33 live authentication (RSA1 + SRP).
//
// Performs the full type-33 branch after RFB 003.889 banner exchange:
// key request → identity encrypt → SRP challenge → packet 2 → M2 verify
// → wrap_key. Pure crypto/parsers live in apple_rsa1 / apple_srp; this
// module only orchestrates them over caller-supplied blocking I/O.
//
// The session owns post-authentication record setup.

#ifndef FARSEE_INCLUDE_FARSEE_APPLE_TYPE33_LIVE_H
#define FARSEE_INCLUDE_FARSEE_APPLE_TYPE33_LIVE_H

#include "farsee/allocator.h"
#include "farsee/error.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Blocking I/O callbacks. Session implements these with poll+read/write
// over the nonblocking socket (or tests use scripted I/O).
//
// send_all: transmit exactly n bytes (or fail).
// recv_exact: receive exactly n bytes (or fail).
typedef struct apple_type33_io {
    rfb_error (*send_all)(void *ctx, const uint8_t *data, size_t n);
    rfb_error (*recv_exact)(void *ctx, uint8_t *data, size_t n);
    void *ctx;
} apple_type33_io;

// Run type-33 RSA1 + SRP authentication.
//
// Precondition: TCP connected, RFB 003.889 banners exchanged, and the
// server's security-type list has been read. This function performs the
// branch entry itself: it sends the 15-byte RSA1 key request (which
// begins with selector 0x21 / type 33). The caller must NOT have already
// sent a separate type-33 security-type byte (the RSA1 selector
// and first envelope must be one contiguous send).
//
// On success: wrap_key_out is filled with 16 bytes (SHA256(K)[0:16]),
// returns RFB_OK. Caller owns wrap_key_out and must zeroize when done.
//
// When `host` is nonempty, `known_hosts_path` must also be nonempty. The
// function checks the peer SPKI before identity encryption and rejects a
// mismatch. An empty host skips the store.
//
// On bad password / SecurityResult != 0: RFB_ERR_AUTH.
// On M2 mismatch: RFB_ERR_AUTH.
// On protocol / framing errors: RFB_ERR_PROTOCOL.
// On missing credentials or NULL args: RFB_ERR_INTERNAL / PROTOCOL.
// On crypto provider failure: RFB_ERR_INTERNAL / UNSUPPORTED.
//
// Secrets (a, identity plaintext, SRP session K/M1/S) are zeroized before
// return on every path.
rfb_error apple_type33_authenticate(
    const apple_type33_io *io,
    const uint8_t *username, size_t username_len,
    const uint8_t *password, size_t password_len,
    uint8_t wrap_key_out[16],
    const char *host, uint16_t port,
    const char *known_hosts_path);

// Optional KDF and AEAD material. All secrets must be
// zeroized by the caller when done. Public fields (salt, iters, randoms)
// may be logged; never log srp_k / session_key_32 / wrap_key.
typedef struct apple_type33_kdf_material {
    uint8_t  session_key_32[32];   // SHA-256(K)
    uint8_t  srp_k[64];            // SRP K = SHA-512(S)
    uint8_t  srp_s[512];           // SRP shared secret S (N-width)
    size_t   srp_s_len;
    uint8_t  m1[64];               // client proof M1
    uint8_t  server_random[16];
    uint8_t  client_random[16];
    uint8_t  salt[64];
    size_t   salt_len;
    uint32_t iterations;
    uint8_t  options[256];
    size_t   options_len;
    bool     has_server_random;
    bool     has_client_random;
    bool     has_m1;
    bool     has_srp_s;
} apple_type33_kdf_material;

// Same as apple_type33_authenticate; when kdf_out is non-NULL, fills
// authentication-derived material. The session retains SHA-256(K) for its
// candidate record-setup modes.
//
// Host-key policy: first use of an unknown host key fails
// closed (RFB_ERR_AUTH) with the SPKI fingerprint printed, matching the
// known_hosts.h contract; pass accept_new_host=true (CLI
// --accept-new-host) to accept a first-use key and pin it after the
// server proves itself via M2. MISMATCH always fails.
rfb_error apple_type33_authenticate_ex(
    const apple_type33_io *io,
    const uint8_t *username, size_t username_len,
    const uint8_t *password, size_t password_len,
    uint8_t wrap_key_out[16],
    apple_type33_kdf_material *kdf_out,
    const char *host, uint16_t port,
    const char *known_hosts_path,
    bool accept_new_host);

rfb_error apple_type33_authenticate_ex_with_allocator(
    const apple_type33_io *io,
    const uint8_t *username, size_t username_len,
    const uint8_t *password, size_t password_len,
    uint8_t wrap_key_out[16], apple_type33_kdf_material *kdf_out,
    const char *host, uint16_t port, const char *known_hosts_path,
    bool accept_new_host, rfb_allocator *allocator);

void apple_type33_kdf_material_zero(apple_type33_kdf_material *m);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_APPLE_TYPE33_LIVE_H
