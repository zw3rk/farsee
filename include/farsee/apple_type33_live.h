// SPDX-License-Identifier: Apache-2.0
//
// farsee — blocking Apple type-33 live authentication (RSA1 + SRP).
//
// Performs the full type-33 branch after RFB 003.889 banner exchange:
// key request → identity encrypt → SRP challenge → packet 2 → M2 verify
// → wrap_key. Pure crypto/parsers live in apple_rsa1 / apple_srp; this
// module only orchestrates them over caller-supplied blocking I/O.
//
// Derived from authorized capture evidence (docs/apple/G26-AUTH-SUCCESS.md)
// and RSA1-UNBLOCK.md. Clean-room: no third-party VNC source inspected.
//
// Do NOT apply G17 AES-CBC against real peers. Do not fake post-auth
// encryption here; wrap_key is returned for a future ChaCha record layer.

#ifndef FARSEE_INCLUDE_FARSEE_APPLE_TYPE33_LIVE_H
#define FARSEE_INCLUDE_FARSEE_APPLE_TYPE33_LIVE_H

#include "farsee/error.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Blocking I/O callbacks. Session implements these with poll+read/write
// over the nonblocking socket (or tests use a scripted fake).
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
// sent a separate type-33 security-type byte (RSA1-UNBLOCK.md: selector
// and first envelope must be one contiguous send).
//
// On success: wrap_key_out is filled with 16 bytes (SHA256(K)[0:16]),
// returns RFB_OK. Caller owns wrap_key_out and must zeroize when done.
//
// host / known_hosts_path: when known_hosts_path is non-NULL, pin and
// check the peer SPKI fingerprint (TOFU) before identity encrypt. NULL
// path skips the store (unit tests only). MISMATCH → RFB_ERR_AUTH.
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

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_APPLE_TYPE33_LIVE_H
