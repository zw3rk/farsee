// SPDX-License-Identifier: Apache-2.0
//
// farsee — OpenSSL 3.x DES-ECB provider (plan.md §G2, ADR-0002).
//
// Provides rfb_des_openssl: a DES-ECB encrypt of one 8-byte block using
// OpenSSL 3.x's EVP API. Linked on Linux and as the optional cross-
// platform provider; on macOS CommonCrypto is preferred.
//
// API reference: https://docs.openssl.org/. OpenSSL is Apache-2.0 licensed
// and is included in the dependency allowlist.
//
// The implementation guards the build so that a macOS build (which uses
// CommonCrypto) does not need an OpenSSL link dependency. The Makefile
// links -lcrypto only when RFB_USE_OPENSSL is defined.

#include "farsee/crypto_provider.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef RFB_USE_OPENSSL
#  include <openssl/evp.h>
#  include <openssl/provider.h>
#endif

#ifdef RFB_USE_OPENSSL
#  include <pthread.h>

// OpenSSL 3.x keeps DES in the "legacy" provider. Load default + legacy
// once so EVP_des_ecb / DES-ECB fetch succeeds (VNC Auth requirement).
// pthread_once ensures concurrent first use cannot observe completion before
// both provider loads finish.
static OSSL_PROVIDER *openssl_default_provider = NULL;
static OSSL_PROVIDER *openssl_legacy_provider = NULL;

static void openssl_unload_des_providers(void)
{
    if (openssl_legacy_provider != NULL) {
        (void)OSSL_PROVIDER_unload(openssl_legacy_provider);
        openssl_legacy_provider = NULL;
    }
    if (openssl_default_provider != NULL) {
        (void)OSSL_PROVIDER_unload(openssl_default_provider);
        openssl_default_provider = NULL;
    }
}

static void openssl_load_des_providers_once(void)
{
    openssl_default_provider = OSSL_PROVIDER_load(NULL, "default");
    openssl_legacy_provider = OSSL_PROVIDER_load(NULL, "legacy");
    if ((openssl_default_provider != NULL ||
         openssl_legacy_provider != NULL) &&
        atexit(openssl_unload_des_providers) != 0) {
        openssl_unload_des_providers();
    }
}

static void openssl_ensure_des_providers(void)
{
    static pthread_once_t once = PTHREAD_ONCE_INIT;
    (void)pthread_once(&once, openssl_load_des_providers_once);
}
#endif

bool rfb_des_openssl(const uint8_t key[8], const uint8_t in[8], uint8_t out[8])
{
#ifdef RFB_USE_OPENSSL
    if (key == NULL || in == NULL || out == NULL) {
        return false;
    }
    openssl_ensure_des_providers();

    // Prefer fetch-by-name so we hit the legacy provider after load.
    EVP_CIPHER *cipher = EVP_CIPHER_fetch(NULL, "DES-ECB", NULL);
    if (cipher == NULL) {
        // Fallback to the classic constructor (some builds still expose it).
        const EVP_CIPHER *legacy = EVP_des_ecb();
        if (legacy == NULL) {
            return false;
        }
        // EVP_des_ecb returns a const static cipher; wrap via EncryptInit only.
        EVP_CIPHER_CTX *ctx0 = EVP_CIPHER_CTX_new();
        if (ctx0 == NULL) {
            return false;
        }
        bool ok0 = false;
        if (EVP_EncryptInit_ex(ctx0, legacy, NULL, key, NULL) == 1 &&
            EVP_CIPHER_CTX_set_padding(ctx0, 0) == 1) {
            int outl = 0;
            if (EVP_EncryptUpdate(ctx0, out, &outl, in, 8) == 1 && outl == 8) {
                int finl = 0;
                if (EVP_EncryptFinal_ex(ctx0, out + outl, &finl) == 1) {
                    ok0 = (finl == 0);
                }
            }
        }
        EVP_CIPHER_CTX_free(ctx0);
        return ok0;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        EVP_CIPHER_free(cipher);
        return false;
    }
    bool ok = false;
    if (EVP_EncryptInit_ex(ctx, cipher, NULL, key, NULL) == 1) {
        // Disable padding: VNC auth uses exactly one 8-byte block per call.
        if (EVP_CIPHER_CTX_set_padding(ctx, 0) == 1) {
            int outl = 0;
            if (EVP_EncryptUpdate(ctx, out, &outl, in, 8) == 1 && outl == 8) {
                int finl = 0;
                if (EVP_EncryptFinal_ex(ctx, out + outl, &finl) == 1) {
                    ok = (finl == 0);
                }
            }
        }
    }
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    return ok;
#else
    (void)key; (void)in; (void)out;
    return false;  // not built with OpenSSL on this platform
#endif
}
