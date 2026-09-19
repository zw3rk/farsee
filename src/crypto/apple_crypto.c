// SPDX-License-Identifier: Apache-2.0
//
// Apple-auth OpenSSL crypto-provider implementation (ADR-0007).
//
// Uses the documented OpenSSL 3.x EVP/BN/RAND interfaces.

#include "farsee/apple_crypto.h"
#include "farsee/secret.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>

#include <limits.h>
#include <stdlib.h>
#include <string.h>

static bool size_fits_int(size_t n)
{
    return n <= (size_t)INT_MAX;
}

static bool size_fits_long(size_t n)
{
    return n <= (size_t)LONG_MAX;
}

// --- Secure random -------------------------------------------------------

bool rfb_crypto_random_bytes(uint8_t *buf, size_t n)
{
    if (buf == NULL || n == 0 || !size_fits_int(n)) return false;
    return RAND_bytes(buf, (int)n) == 1;
}

// --- Constant-time compare -----------------------------------------------

bool rfb_crypto_ct_eq(const uint8_t *a, const uint8_t *b, size_t n)
{
    if (a == NULL || b == NULL) return a == b;
    return CRYPTO_memcmp(a, b, n) == 0;
}

// --- Hash digests --------------------------------------------------------

bool rfb_crypto_sha256(const uint8_t *data, size_t len, uint8_t out[32])
{
    if (data == NULL || out == NULL) return false;
    memset(out, 0, 32);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL) return false;
    unsigned int outlen = 0;
    bool ok = (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
               EVP_DigestUpdate(ctx, data, len) == 1 &&
               EVP_DigestFinal_ex(ctx, out, &outlen) == 1);
    EVP_MD_CTX_free(ctx);
    return ok;
}

bool rfb_crypto_sha512(const uint8_t *data, size_t len, uint8_t out[64])
{
    if (data == NULL || out == NULL) return false;
    memset(out, 0, 64);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL) return false;
    unsigned int outlen = 0;
    bool ok = (EVP_DigestInit_ex(ctx, EVP_sha512(), NULL) == 1 &&
               EVP_DigestUpdate(ctx, data, len) == 1 &&
               EVP_DigestFinal_ex(ctx, out, &outlen) == 1);
    EVP_MD_CTX_free(ctx);
    return ok;
}

bool rfb_crypto_sha1(const uint8_t *data, size_t len, uint8_t out[20])
{
    if (data == NULL || out == NULL) return false;
    memset(out, 0, 20);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL) return false;
    unsigned int outlen = 0;
    bool ok = (EVP_DigestInit_ex(ctx, EVP_sha1(), NULL) == 1 &&
               EVP_DigestUpdate(ctx, data, len) == 1 &&
               EVP_DigestFinal_ex(ctx, out, &outlen) == 1);
    EVP_MD_CTX_free(ctx);
    return ok;
}

bool rfb_crypto_md5(const uint8_t *data, size_t len, uint8_t out[16])
{
    if (data == NULL || out == NULL) return false;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL) return false;
    unsigned int outlen = 0;
    bool ok = (EVP_DigestInit_ex(ctx, EVP_md5(), NULL) == 1 &&
               EVP_DigestUpdate(ctx, data, len) == 1 &&
               EVP_DigestFinal_ex(ctx, out, &outlen) == 1);
    EVP_MD_CTX_free(ctx);
    return ok;
}

// --- HMAC ----------------------------------------------------------------

bool rfb_crypto_hmac_sha512(const uint8_t *key, size_t key_len,
                            const uint8_t *data, size_t data_len,
                            uint8_t out[64])
{
    if (key == NULL || data == NULL || out == NULL ||
        !size_fits_int(key_len)) return false;
    memset(out, 0, 64);
    unsigned int outlen = 0;
    unsigned char *r = HMAC(EVP_sha512(), key, (int)key_len, data, data_len,
                            out, &outlen);
    return r != NULL && outlen == 64u;
}

// --- PBKDF2 --------------------------------------------------------------

bool rfb_crypto_pbkdf2_sha512(const uint8_t *password, size_t password_len,
                              const uint8_t *salt, size_t salt_len,
                              uint32_t iterations,
                              uint8_t *out, size_t out_len)
{
    if (password == NULL || salt == NULL || out == NULL) return false;
    if (iterations == 0 || iterations > 10000000u) return false;  // cap
    if (!size_fits_int(password_len) || !size_fits_int(salt_len) ||
        !size_fits_int(out_len)) return false;
    return PKCS5_PBKDF2_HMAC((const char *)password, (int)password_len,
                             salt, (int)salt_len, (int)iterations,
                             EVP_sha512(), (int)out_len, out) == 1;
}

// --- RSA-2048 PKCS#1 v1.5 encryption ------------------------------------

bool rfb_crypto_rsa_encrypt_pkcs1(const uint8_t *spki_der, size_t spki_len,
                                  const uint8_t *data, size_t data_len,
                                  uint8_t out[256])
{
    if (spki_der == NULL || data == NULL || out == NULL) return false;
    if (!size_fits_long(spki_len) || data_len > 245u) return false;
    // Parse DER SubjectPublicKeyInfo.
    const unsigned char *p = spki_der;
    EVP_PKEY *pkey = d2i_PUBKEY(NULL, &p, (long)spki_len);
    if (pkey == NULL) return false;
    if ((size_t)(p - spki_der) != spki_len) {
        EVP_PKEY_free(pkey);
        return false;
    }
    // Encrypt with PKCS#1 v1.5 padding.
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    size_t outlen = 256;
    bool ok = false;
    if (ctx != NULL &&
        EVP_PKEY_encrypt_init(ctx) == 1 &&
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) == 1) {
        if (EVP_PKEY_encrypt(ctx, out, &outlen, data, data_len) == 1) {
            ok = (outlen == 256);
        }
    }
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return ok;
}

// --- DER SPKI fingerprint ------------------------------------------------

bool rfb_crypto_spki_fingerprint(const uint8_t *spki_der, size_t spki_len,
                                 uint8_t out_sha256[32])
{
    return rfb_crypto_sha256(spki_der, spki_len, out_sha256);
}

// --- AES-128-ECB single-block decrypt ------------------------------------

bool rfb_crypto_aes128_ecb_decrypt(const uint8_t key[16],
                                   const uint8_t in[16], uint8_t out[16])
{
    if (key == NULL || in == NULL || out == NULL) return false;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) return false;
    bool ok = false;
    int outlen = 0;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL) == 1 &&
        EVP_CIPHER_CTX_set_padding(ctx, 0) == 1 &&
        EVP_DecryptUpdate(ctx, out, &outlen, in, 16) == 1 &&
        outlen == 16) {
        ok = true;
    }
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

bool rfb_crypto_aes128_ecb_encrypt(const uint8_t key[16],
                                   const uint8_t in[16], uint8_t out[16])
{
    if (key == NULL || in == NULL || out == NULL) {
        return false;
    }
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        return false;
    }
    bool ok = false;
    int outlen = 0;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL) == 1 &&
        EVP_CIPHER_CTX_set_padding(ctx, 0) == 1 &&
        EVP_EncryptUpdate(ctx, out, &outlen, in, 16) == 1 &&
        outlen == 16) {
        ok = true;
    }
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

// --- AES-128-CBC context -------------------------------------------------

struct rfb_crypto_cbc_ctx {
    EVP_CIPHER_CTX *evp;
    bool encrypt;
};

rfb_crypto_cbc_ctx *rfb_crypto_cbc_new(void)
{
    rfb_crypto_cbc_ctx *c = calloc(1, sizeof *c);
    if (c == NULL) return NULL;
    c->evp = EVP_CIPHER_CTX_new();
    if (c->evp == NULL) { free(c); return NULL; }
    return c;
}

void rfb_crypto_cbc_free(rfb_crypto_cbc_ctx *ctx)
{
    if (ctx == NULL) return;
    if (ctx->evp != NULL) EVP_CIPHER_CTX_free(ctx->evp);
    free(ctx);
}

bool rfb_crypto_cbc_init(rfb_crypto_cbc_ctx *ctx, bool encrypt,
                         const uint8_t key[16], const uint8_t iv[16])
{
    if (ctx == NULL || key == NULL || iv == NULL) return false;
    ctx->encrypt = encrypt;
    int rc;
    if (encrypt) {
        rc = EVP_EncryptInit_ex(ctx->evp, EVP_aes_128_cbc(), NULL, key, iv);
    } else {
        rc = EVP_DecryptInit_ex(ctx->evp, EVP_aes_128_cbc(), NULL, key, iv);
    }
    return rc == 1 && EVP_CIPHER_CTX_set_padding(ctx->evp, 0) == 1;
}

bool rfb_crypto_cbc_update(rfb_crypto_cbc_ctx *ctx,
                           const uint8_t *in, size_t in_len,
                           uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (out_len != NULL) *out_len = 0u;
    if (ctx == NULL || in == NULL || out == NULL || out_len == NULL) return false;
    // This provider is used as a persistent record stream without padding.
    // Whole blocks ensure EVP cannot emit more bytes than this call consumes.
    if (in_len > out_cap || !size_fits_int(in_len) || in_len % 16u != 0u)
        return false;
    int outl = 0;
    int rc;
    if (ctx->encrypt) {
        rc = EVP_EncryptUpdate(ctx->evp, out, &outl, in, (int)in_len);
    } else {
        rc = EVP_DecryptUpdate(ctx->evp, out, &outl, in, (int)in_len);
    }
    if (rc != 1 || outl < 0 || (size_t)outl > out_cap) return false;
    *out_len = (size_t)outl;
    return true;
}

bool rfb_crypto_cbc_final(rfb_crypto_cbc_ctx *ctx,
                          uint8_t *out, size_t out_cap, size_t *out_len)
{
    (void)out_cap;  // EVP_Final won't produce output when padding is disabled
    if (out_len != NULL) *out_len = 0u;
    if (ctx == NULL || out == NULL || out_len == NULL) return false;
    int outl = 0;
    int rc;
    if (ctx->encrypt) {
        rc = EVP_EncryptFinal_ex(ctx->evp, out, &outl);
    } else {
        rc = EVP_DecryptFinal_ex(ctx->evp, out, &outl);
    }
    if (rc != 1 || outl < 0 || (size_t)outl > out_cap) return false;
    *out_len = (size_t)outl;
    return true;
}

// --- ChaCha20-Poly1305 AEAD -----------------------------------------------

bool rfb_crypto_chacha20_poly1305_encrypt(
    const uint8_t key[32], const uint8_t nonce[12],
    const uint8_t *aad, size_t aad_len,
    const uint8_t *pt, size_t pt_len,
    uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (out_len != NULL) *out_len = 0u;
    if (key == NULL || nonce == NULL || pt == NULL || out == NULL || out_len == NULL)
        return false;
    if ((aad_len > 0u && aad == NULL) || !size_fits_int(aad_len) ||
        !size_fits_int(pt_len) || pt_len > SIZE_MAX - 16u ||
        pt_len + 16u > out_cap) return false;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) return false;
    bool ok = false;
    int outl = 0;
    int final_len = 0;
    if (EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, key, nonce) == 1) {
        if (aad != NULL && aad_len > 0) {
            if (EVP_EncryptUpdate(ctx, NULL, &outl, aad, (int)aad_len) != 1) goto done;
        }
        if (EVP_EncryptUpdate(ctx, out, &outl, pt, (int)pt_len) == 1) {
            if (outl < 0 || (size_t)outl > out_cap - 16u) goto done;
            size_t written = (size_t)outl;
            if (EVP_EncryptFinal_ex(ctx, out + written, &final_len) == 1) {
                if (final_len < 0 ||
                    (size_t)final_len > out_cap - written - 16u) goto done;
                written += (size_t)final_len;
                // Append the 16-byte Poly1305 tag.
                if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16,
                                        out + written) == 1) {
                    *out_len = written + 16;
                    ok = true;
                }
            }
        }
    }
done:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

bool rfb_crypto_chacha20_poly1305_decrypt(
    const uint8_t key[32], const uint8_t nonce[12],
    const uint8_t *aad, size_t aad_len,
    const uint8_t *ct, size_t ct_len,
    uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (out_len != NULL) *out_len = 0u;
    if (key == NULL || nonce == NULL || ct == NULL || out == NULL || out_len == NULL)
        return false;
    if (ct_len < 16) return false;  // need at least the tag
    size_t actual_ct_len = ct_len - 16;
    if ((aad_len > 0u && aad == NULL) || !size_fits_int(aad_len) ||
        !size_fits_int(actual_ct_len) || actual_ct_len > out_cap) return false;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) return false;
    bool ok = false;
    int outl = 0;
    int final_len = 0;
    if (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, key, nonce) == 1) {
        if (aad != NULL && aad_len > 0) {
            if (EVP_DecryptUpdate(ctx, NULL, &outl, aad, (int)aad_len) != 1) goto done;
        }
        if (EVP_DecryptUpdate(ctx, out, &outl, ct, (int)actual_ct_len) == 1) {
            if (outl < 0 || (size_t)outl > out_cap) goto done;
            size_t written = (size_t)outl;
            // Set the expected tag from the last 16 bytes.
            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16,
                                    (void *)(uintptr_t)(ct + actual_ct_len)) == 1) {
                if (EVP_DecryptFinal_ex(ctx, out + written, &final_len) == 1) {
                    if (final_len < 0 ||
                        (size_t)final_len > out_cap - written) goto done;
                    *out_len = written + (size_t)final_len;
                    ok = true;
                }
            }
        }
    }
done:
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

bool rfb_crypto_modexp(const uint8_t *base, size_t base_len,
                       const uint8_t *exp, size_t exp_len,
                       const uint8_t *mod, size_t mod_len,
                       uint8_t *out, size_t out_len)
{
    if (base == NULL || exp == NULL || mod == NULL || out == NULL) return false;
    if (out_len == 0u || !size_fits_int(base_len) || !size_fits_int(exp_len) ||
        !size_fits_int(mod_len) || !size_fits_int(out_len)) return false;
    BN_CTX *bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL) return false;
    BIGNUM *bn_base = BN_bin2bn(base, (int)base_len, NULL);
    BIGNUM *bn_exp = BN_bin2bn(exp, (int)exp_len, NULL);
    BIGNUM *bn_mod = BN_bin2bn(mod, (int)mod_len, NULL);
    BIGNUM *bn_result = BN_new();
    bool ok = false;
    if (bn_base != NULL && bn_exp != NULL && bn_mod != NULL && bn_result != NULL) {
        // Use constant-time exponentiation for SRP secrets such as g^x and S.
        BN_set_flags(bn_exp, BN_FLG_CONSTTIME);
        if (BN_mod_exp(bn_result, bn_base, bn_exp, bn_mod, bn_ctx) == 1) {
            // Produce bounded, zero-padded output.
            int written = BN_bn2binpad(bn_result, out, (int)out_len);
            ok = (written == (int)out_len);
        }
    }
    BN_clear_free(bn_base);
    BN_clear_free(bn_exp);
    BN_clear_free(bn_mod);
    BN_clear_free(bn_result);
    BN_CTX_free(bn_ctx);
    return ok;
}

bool rfb_crypto_modmul(const uint8_t *a, size_t a_len,
                       const uint8_t *b, size_t b_len,
                       const uint8_t *mod, size_t mod_len,
                       uint8_t *out, size_t out_len)
{
    if (a == NULL || b == NULL || mod == NULL || out == NULL) return false;
    if (out_len == 0u || !size_fits_int(a_len) || !size_fits_int(b_len) ||
        !size_fits_int(mod_len) || !size_fits_int(out_len)) return false;
    BN_CTX *bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL) return false;
    BIGNUM *bn_a = BN_bin2bn(a, (int)a_len, NULL);
    BIGNUM *bn_b = BN_bin2bn(b, (int)b_len, NULL);
    BIGNUM *bn_mod = BN_bin2bn(mod, (int)mod_len, NULL);
    BIGNUM *bn_result = BN_new();
    bool ok = false;
    if (bn_a != NULL && bn_b != NULL && bn_mod != NULL && bn_result != NULL) {
        if (BN_mod_mul(bn_result, bn_a, bn_b, bn_mod, bn_ctx) == 1) {
            int written = BN_bn2binpad(bn_result, out, (int)out_len);
            ok = (written == (int)out_len);
        }
    }
    BN_clear_free(bn_a);
    BN_clear_free(bn_b);
    BN_clear_free(bn_mod);
    BN_clear_free(bn_result);
    BN_CTX_free(bn_ctx);
    return ok;
}

bool rfb_crypto_modadd(const uint8_t *a, size_t a_len,
                       const uint8_t *b, size_t b_len,
                       const uint8_t *mod, size_t mod_len,
                       uint8_t *out, size_t out_len)
{
    if (a == NULL || b == NULL || mod == NULL || out == NULL) return false;
    if (out_len == 0u || !size_fits_int(a_len) || !size_fits_int(b_len) ||
        !size_fits_int(mod_len) || !size_fits_int(out_len)) return false;
    BN_CTX *bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL) return false;
    BIGNUM *bn_a = BN_bin2bn(a, (int)a_len, NULL);
    BIGNUM *bn_b = BN_bin2bn(b, (int)b_len, NULL);
    BIGNUM *bn_mod = BN_bin2bn(mod, (int)mod_len, NULL);
    BIGNUM *bn_result = BN_new();
    bool ok = false;
    if (bn_a != NULL && bn_b != NULL && bn_mod != NULL && bn_result != NULL) {
        if (BN_mod_add(bn_result, bn_a, bn_b, bn_mod, bn_ctx) == 1) {
            int written = BN_bn2binpad(bn_result, out, (int)out_len);
            ok = (written == (int)out_len);
        }
    }
    BN_clear_free(bn_a);
    BN_clear_free(bn_b);
    BN_clear_free(bn_mod);
    BN_clear_free(bn_result);
    BN_CTX_free(bn_ctx);
    return ok;
}

bool rfb_crypto_modsub(const uint8_t *a, size_t a_len,
                       const uint8_t *b, size_t b_len,
                       const uint8_t *mod, size_t mod_len,
                       uint8_t *out, size_t out_len)
{
    if (a == NULL || b == NULL || mod == NULL || out == NULL) return false;
    if (out_len == 0u || !size_fits_int(a_len) || !size_fits_int(b_len) ||
        !size_fits_int(mod_len) || !size_fits_int(out_len)) return false;
    BN_CTX *bn_ctx = BN_CTX_new();
    if (bn_ctx == NULL) return false;
    BIGNUM *bn_a = BN_bin2bn(a, (int)a_len, NULL);
    BIGNUM *bn_b = BN_bin2bn(b, (int)b_len, NULL);
    BIGNUM *bn_mod = BN_bin2bn(mod, (int)mod_len, NULL);
    BIGNUM *bn_result = BN_new();
    bool ok = false;
    if (bn_a != NULL && bn_b != NULL && bn_mod != NULL && bn_result != NULL) {
        if (BN_mod_sub(bn_result, bn_a, bn_b, bn_mod, bn_ctx) == 1) {
            int written = BN_bn2binpad(bn_result, out, (int)out_len);
            ok = (written == (int)out_len);
        }
    }
    BN_clear_free(bn_a);
    BN_clear_free(bn_b);
    BN_clear_free(bn_mod);
    BN_clear_free(bn_result);
    BN_CTX_free(bn_ctx);
    return ok;
}
