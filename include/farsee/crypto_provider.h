// SPDX-License-Identifier: Apache-2.0
//
// farsee — VNC Authentication provider interface (plan.md §G2, ADR-0002).
//
// The RFB core depends only on this abstract interface. The macOS
// (CommonCrypto) and Linux/cross (OpenSSL) providers implement it behind
// separate translation units selected by the build. No provider-specific
// type ever appears in farsee/handshake.h or the core.
//
// VNC Authentication (RFC 6143 §7.2.2):
//   1. Take the first 8 bytes of the password, zero-padded to 8 bytes.
//   2. Bit-permute those 8 bytes using the fixed VNC key schedule
//      (each byte's bits are reversed in a specific way — see
//      vnc_key_schedule below, derived from the RFC's public table).
//   3. Use the permuted 8 bytes as a DES key, DES-ECB encrypt the server's
//      16-byte challenge (two 8-byte blocks), and send the 16-byte response.
//
// We do not implement DES from memory: the provider supplies DES-ECB via
// its documented API (CommonCrypto `CCCrypt` / OpenSSL `EVP_*`). The key
// schedule is a pure byte transform implemented once here, covered by
// known-answer tests against independently-derived vectors.

#ifndef FARSEE_INCLUDE_FARSEE_CRYPTO_PROVIDER_H
#define FARSEE_INCLUDE_FARSEE_CRYPTO_PROVIDER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Apply the VNC key schedule to 8 password bytes in-place (plan.md §G2,
// RFC 6143 §7.2.2). Each byte's bits are reversed individually, producing
// the DES key. This is the pure byte-permutation step; DES itself is done
// by the provider.
void rfb_vnc_key_schedule(uint8_t key[8]);

// DES-ECB encrypt a single 8-byte block with the given 8-byte key.
// Returns true on success. The provider's concrete implementation is
// linked at build time (CommonCrypto on macOS, OpenSSL on Linux).
typedef bool (*rfb_des_ecb_encrypt_fn)(
    const uint8_t key[8], const uint8_t in[8], uint8_t out[8]);

// High-level VNC auth response: key-schedule the password, DES-ECB encrypt
// both 8-byte blocks of the 16-byte challenge into the 16-byte response.
// `des` is the provider's DES primitive. Returns true on success.
bool rfb_vnc_auth_respond(
    const uint8_t password[8],
    const uint8_t challenge[16],
    uint8_t response[16],
    rfb_des_ecb_encrypt_fn des);

// --- Concrete provider implementations -----------------------------------
// Each is a rfb_des_ecb_encrypt_fn-compatible function. The build links
// the one matching the host platform; on macOS that is CommonCrypto, on
// Linux that is OpenSSL (gated by RFB_USE_OPENSSL). They return false on
// any platform that did not compile them in.
bool rfb_des_commoncrypto(const uint8_t key[8], const uint8_t in[8], uint8_t out[8]);
bool rfb_des_openssl(const uint8_t key[8], const uint8_t in[8], uint8_t out[8]);

// The default provider for the current platform. On macOS this resolves
// to CommonCrypto; otherwise to OpenSSL (which returns false if the build
// did not enable it).
static inline rfb_des_ecb_encrypt_fn rfb_des_default_provider(void)
{
#if defined(__APPLE__)
    return rfb_des_commoncrypto;
#else
    return rfb_des_openssl;
#endif
}

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_CRYPTO_PROVIDER_H
