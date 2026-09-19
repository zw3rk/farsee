// SPDX-License-Identifier: Apache-2.0
//
// farsee — Apple encrypted record layer.
//
// Independent of sockets and presenters. Uses a caller-provided wrap key.
// Supports AES-128-CBC record encryption and decryption, wrap-key rotation,
// sequence counters, and zeroization.

#include "farsee/apple_record.h"
#include "farsee/secret.h"

#include <string.h>

void apple_record_init(apple_record_layer *rl, const uint8_t wrap_key[APPLE_BLOCK_SIZE])
{
    if (rl == NULL || wrap_key == NULL) return;
    memset(rl, 0, sizeof *rl);
    memcpy(rl->wrap_key, wrap_key, APPLE_BLOCK_SIZE);
    rl->decrypt.cbc = NULL;
    rl->encrypt.cbc = NULL;
    rl->initialized = true;
}

bool apple_record_set_direction(apple_record_layer *rl, apple_record_dir dir,
                                const uint8_t key[APPLE_BLOCK_SIZE],
                                const uint8_t iv[APPLE_BLOCK_SIZE])
{
    if (rl == NULL || key == NULL || iv == NULL ||
        (dir != APPLE_DIR_DECRYPT && dir != APPLE_DIR_ENCRYPT)) return false;
    apple_record_direction *d = (dir == APPLE_DIR_DECRYPT) ? &rl->decrypt : &rl->encrypt;
    rfb_crypto_cbc_ctx *replacement = rfb_crypto_cbc_new();
    if (replacement == NULL) return false;
    bool enc = (dir == APPLE_DIR_ENCRYPT);
    if (!rfb_crypto_cbc_init(replacement, enc, key, iv)) {
        rfb_crypto_cbc_free(replacement);
        return false;
    }
    // Commit only after the replacement is fully constructed. The old
    // direction stays usable on allocation or provider initialization failure.
    rfb_crypto_cbc_ctx *old = d->cbc;
    d->cbc = replacement;
    memcpy(d->content_key, key, APPLE_BLOCK_SIZE);
    memcpy(d->iv, iv, APPLE_BLOCK_SIZE);
    d->sequence = 0;
    d->active = true;
    if (old != NULL) rfb_crypto_cbc_free(old);
    return true;
}

bool apple_record_enable_wrapped(apple_record_layer *rl, apple_record_dir dir,
                                 const uint8_t wrapped_key[APPLE_BLOCK_SIZE],
                                 const uint8_t wrapped_iv[APPLE_BLOCK_SIZE])
{
    if (rl == NULL || !rl->initialized || wrapped_key == NULL || wrapped_iv == NULL) {
        return false;
    }
    if (dir != APPLE_DIR_DECRYPT && dir != APPLE_DIR_ENCRYPT) {
        return false;
    }

    uint8_t new_key[APPLE_BLOCK_SIZE] = { 0 };
    uint8_t new_iv[APPLE_BLOCK_SIZE] = { 0 };
    bool ok = false;
    if (!rfb_crypto_aes128_ecb_decrypt(rl->wrap_key, wrapped_key, new_key)) {
        goto cleanup;
    }
    if (!rfb_crypto_aes128_ecb_decrypt(rl->wrap_key, wrapped_iv, new_iv)) {
        goto cleanup;
    }

    ok = apple_record_set_direction(rl, dir, new_key, new_iv);
cleanup:
    rfb_secret_zero(new_key, sizeof new_key);
    rfb_secret_zero(new_iv, sizeof new_iv);
    return ok;
}

bool apple_record_rekey(apple_record_layer *rl, apple_record_dir dir,
                        const uint8_t wrapped_key[APPLE_BLOCK_SIZE],
                        const uint8_t wrapped_iv[APPLE_BLOCK_SIZE],
                        const uint8_t new_wrap_key[APPLE_BLOCK_SIZE])
{
    if (rl == NULL || !rl->initialized || wrapped_key == NULL || wrapped_iv == NULL || new_wrap_key == NULL) {
        return false;
    }
    if (dir != APPLE_DIR_DECRYPT && dir != APPLE_DIR_ENCRYPT) {
        return false;
    }
    apple_record_direction *d = (dir == APPLE_DIR_DECRYPT) ? &rl->decrypt : &rl->encrypt;
    if (!d->active) return false;  // never partially activate

    // Unwrap new content key and IV using the current wrap key (AES-128-ECB).
    uint8_t new_key[APPLE_BLOCK_SIZE] = { 0 };
    uint8_t new_iv[APPLE_BLOCK_SIZE] = { 0 };
    bool ok = false;
    if (!rfb_crypto_aes128_ecb_decrypt(rl->wrap_key, wrapped_key, new_key))
        goto cleanup;
    if (!rfb_crypto_aes128_ecb_decrypt(rl->wrap_key, wrapped_iv, new_iv))
        goto cleanup;

    // Install the new key/IV atomically.
    if (!apple_record_set_direction(rl, dir, new_key, new_iv)) {
        goto cleanup;
    }

    // Rotate the wrap key.
    memcpy(rl->wrap_key, new_wrap_key, APPLE_BLOCK_SIZE);
    ok = true;
cleanup:
    rfb_secret_zero(new_key, sizeof new_key);
    rfb_secret_zero(new_iv, sizeof new_iv);
    return ok;
}

rfb_error apple_record_decrypt(apple_record_layer *rl,
                               const uint8_t *ciphertext, size_t ct_len,
                               uint8_t *plaintext, size_t pt_cap, size_t *pt_len)
{
    if (rl == NULL || ciphertext == NULL || plaintext == NULL || pt_len == NULL) {
        return RFB_ERR_INTERNAL;
    }
    *pt_len = 0;
    if (ct_len == 0) return RFB_ERR_PROTOCOL;
    if (ct_len % APPLE_BLOCK_SIZE != 0) return RFB_ERR_PROTOCOL;
    if (ct_len > APPLE_RECORD_MAX_BODY) return RFB_ERR_LIMIT;
    if (pt_cap < ct_len) return RFB_ERR_LIMIT;

    apple_record_direction *d = &rl->decrypt;
    if (!d->active || d->cbc == NULL) return RFB_ERR_STATE;

    size_t out_len = 0;
    if (!rfb_crypto_cbc_update(d->cbc, ciphertext, ct_len,
                               plaintext, pt_cap, &out_len)) {
        return RFB_ERR_PROTOCOL;
    }
    *pt_len = out_len;
    d->sequence++;
    return RFB_OK;
}

rfb_error apple_record_encrypt(apple_record_layer *rl,
                               const uint8_t *plaintext, size_t pt_len,
                               uint8_t *ciphertext, size_t ct_cap, size_t *ct_len)
{
    if (rl == NULL || plaintext == NULL || ciphertext == NULL || ct_len == NULL) {
        return RFB_ERR_INTERNAL;
    }
    *ct_len = 0;
    if (pt_len == 0) return RFB_ERR_PROTOCOL;
    if (pt_len % APPLE_BLOCK_SIZE != 0) return RFB_ERR_PROTOCOL;
    if (pt_len > APPLE_RECORD_MAX_BODY) return RFB_ERR_LIMIT;
    if (ct_cap < pt_len) return RFB_ERR_LIMIT;

    apple_record_direction *d = &rl->encrypt;
    if (!d->active || d->cbc == NULL) return RFB_ERR_STATE;

    size_t out_len = 0;
    if (!rfb_crypto_cbc_update(d->cbc, plaintext, pt_len,
                               ciphertext, ct_cap, &out_len)) {
        return RFB_ERR_PROTOCOL;
    }
    *ct_len = out_len;
    d->sequence++;
    return RFB_OK;
}

void apple_record_destroy(apple_record_layer *rl)
{
    if (rl == NULL) return;
    // Zeroize all keys, IVs, and free CBC contexts.
    rfb_secret_zero(rl->wrap_key, sizeof rl->wrap_key);
    rfb_secret_zero(rl->next_wrap_key, sizeof rl->next_wrap_key);
    rfb_secret_zero(rl->decrypt.content_key, sizeof rl->decrypt.content_key);
    rfb_secret_zero(rl->decrypt.iv, sizeof rl->decrypt.iv);
    rfb_secret_zero(rl->encrypt.content_key, sizeof rl->encrypt.content_key);
    rfb_secret_zero(rl->encrypt.iv, sizeof rl->encrypt.iv);
    if (rl->decrypt.cbc != NULL) rfb_crypto_cbc_free(rl->decrypt.cbc);
    if (rl->encrypt.cbc != NULL) rfb_crypto_cbc_free(rl->encrypt.cbc);
    memset(rl, 0, sizeof *rl);
}
