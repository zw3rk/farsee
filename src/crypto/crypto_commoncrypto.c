// SPDX-License-Identifier: Apache-2.0
//
// farsee — macOS CommonCrypto DES-ECB provider (plan.md §G2, ADR-0002).
//
// Provides rfb_des_commoncrypto: a DES-ECB encrypt of one 8-byte block
// using the system CommonCrypto framework. Used only on macOS; on Linux
// the OpenSSL provider is linked instead. The selection is made by the
// build (this TU compiles only when targeting Apple platforms).
//
// Clean-room: the CommonCrypto API is public and documented at
// https://developer.apple.com/documentation/commoncrypto. We call it per
// its documented contract; no implementation source is reproduced.

#include "farsee/crypto_provider.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#if defined(__APPLE__)
#  include <CommonCrypto/CommonCryptor.h>
#endif

bool rfb_des_commoncrypto(const uint8_t key[8], const uint8_t in[8], uint8_t out[8])
{
#if defined(__APPLE__)
    if (key == NULL || in == NULL || out == NULL) {
        return false;
    }
    // DES with no padding, single-block ECB. CCCrypt performs the whole
    // operation synchronously.
    CCCryptorStatus rc = CCCrypt(
        kCCEncrypt,
        kCCAlgorithmDES,
        kCCOptionECBMode,  // no padding, no chaining
        key, kCCKeySizeDES,
        NULL,              // no IV for ECB
        in, 8,
        out, 8,
        NULL);
    return rc == kCCSuccess;
#else
    (void)key; (void)in; (void)out;
    return false;  // not built on this platform
#endif
}
