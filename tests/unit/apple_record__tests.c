// SPDX-License-Identifier: Apache-2.0
//
// Apple encrypted record layer tests.
// Uses deterministic wrap keys and record payloads.

#include "rfb_test.h"
#include "farsee/apple_record.h"
#include "farsee/apple_crypto.h"
#include "farsee/secret.h"

#include <string.h>

static const uint8_t TEST_KEY[16] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
};
static const uint8_t TEST_IV[16] = {
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
    0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
};
static const uint8_t TEST_WRAP[16] = {
    0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00,0x11,
    0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99
};

// --- encrypt/decrypt roundtrip -------------------------------------------

RFB_TEST(g17, record__encrypt_decrypt_roundtrip) {
    apple_record_layer rl;
    apple_record_init(&rl, TEST_WRAP);
    RFB_CHECK(apple_record_set_direction(&rl, APPLE_DIR_ENCRYPT, TEST_KEY, TEST_IV));
    RFB_CHECK(apple_record_set_direction(&rl, APPLE_DIR_DECRYPT, TEST_KEY, TEST_IV));

    static const uint8_t pt[32] = "Hello Apple Record Layer!!!!!!!";  // 32 bytes, 16-aligned
    uint8_t ct[32] = { 0 };
    uint8_t decrypted[32] = { 0 };
    size_t ct_len = 0, pt_len = 0;

    RFB_CHECK_EQ_INT(
        apple_record_encrypt(&rl, pt, 32, ct, sizeof ct, &ct_len), RFB_OK);
    RFB_CHECK_EQ_UINT(ct_len, 32u);

    RFB_CHECK_EQ_INT(
        apple_record_decrypt(&rl, ct, ct_len, decrypted, sizeof decrypted, &pt_len), RFB_OK);
    RFB_CHECK_EQ_UINT(pt_len, 32u);
    RFB_CHECK_MEM_EQ(decrypted, pt, 32);

    apple_record_destroy(&rl);
}

// --- bad ciphertext length -----------------------------------------------

RFB_TEST(g17, record__decrypt_non_block_aligned__fails) {
    apple_record_layer rl;
    apple_record_init(&rl, TEST_WRAP);
    apple_record_set_direction(&rl, APPLE_DIR_DECRYPT, TEST_KEY, TEST_IV);

    static const uint8_t bad_ct[17] = { 0 };  // not 16-aligned
    uint8_t pt[32] = { 0 };
    size_t pt_len = 0;
    RFB_CHECK_EQ_INT(
        apple_record_decrypt(&rl, bad_ct, 17, pt, sizeof pt, &pt_len),
        RFB_ERR_PROTOCOL);

    apple_record_destroy(&rl);
}

// --- decrypt without direction set ---------------------------------------

RFB_TEST(g17, record__decrypt_without_direction__fails) {
    apple_record_layer rl;
    apple_record_init(&rl, TEST_WRAP);
    // Don't set decrypt direction.
    static const uint8_t ct[16] = { 0 };
    uint8_t pt[16] = { 0 };
    size_t pt_len = 0;
    RFB_CHECK_EQ_INT(
        apple_record_decrypt(&rl, ct, 16, pt, sizeof pt, &pt_len),
        RFB_ERR_STATE);
    apple_record_destroy(&rl);
}

// --- rekey: unwrap and install -------------------------------------------

RFB_TEST(g17, record__rekey_decrypt__new_key_works) {
    apple_record_layer rl;
    apple_record_init(&rl, TEST_WRAP);

    // Set up initial direction.
    RFB_CHECK(apple_record_set_direction(&rl, APPLE_DIR_DECRYPT, TEST_KEY, TEST_IV));

    // Prepare wrapped new key/IV: encrypt the new key/IV with the wrap key.
    static const uint8_t new_key[16] = {
        0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10,
        0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF
    };
    static const uint8_t new_iv[16] = {
        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
        0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10
    };
    // A single CBC block with a zero IV produces the ECB ciphertext required
    // by the rekey unwrap operation.
    uint8_t wrapped_key[16], wrapped_iv[16];
    rfb_crypto_cbc_ctx *enc = rfb_crypto_cbc_new();
    static const uint8_t zero_iv[16] = { 0 };
    rfb_crypto_cbc_init(enc, true, TEST_WRAP, zero_iv);
    size_t outl = 0;
    rfb_crypto_cbc_update(enc, new_key, 16, wrapped_key, sizeof wrapped_key, &outl);
    rfb_crypto_cbc_free(enc);
    enc = rfb_crypto_cbc_new();
    rfb_crypto_cbc_init(enc, true, TEST_WRAP, zero_iv);
    rfb_crypto_cbc_update(enc, new_iv, 16, wrapped_iv, sizeof wrapped_iv, &outl);
    rfb_crypto_cbc_free(enc);

    static const uint8_t new_wrap[16] = { 0xFF };
    RFB_CHECK(apple_record_rekey(&rl, APPLE_DIR_DECRYPT,
                                 wrapped_key, wrapped_iv, new_wrap));

    // The wrap key should have rotated.
    RFB_CHECK_MEM_EQ(rl.wrap_key, new_wrap, 16);

    // Rekeying preserves the active decrypt direction and resets its sequence.
    RFB_CHECK(rl.decrypt.active);

    apple_record_destroy(&rl);
}

// --- rekey fails if direction not active ---------------------------------

RFB_TEST(g17, record__rekey_inactive_direction__fails) {
    apple_record_layer rl;
    apple_record_init(&rl, TEST_WRAP);
    // Don't set any direction.
    static const uint8_t dummy[16] = { 0 };
    static const uint8_t new_wrap[16] = { 0xFF };
    RFB_CHECK(!apple_record_rekey(&rl, APPLE_DIR_DECRYPT,
                                  dummy, dummy, new_wrap));
    apple_record_destroy(&rl);
}

RFB_TEST(g17, record__invalid_direction__preserves_active_state)
{
    apple_record_layer rl;
    apple_record_init(&rl, TEST_WRAP);
    RFB_CHECK(apple_record_set_direction(&rl, APPLE_DIR_ENCRYPT,
                                         TEST_KEY, TEST_IV));
    rfb_crypto_cbc_ctx *old_cbc = rl.encrypt.cbc;
    uint8_t old_key[16];
    uint8_t old_iv[16];
    memcpy(old_key, rl.encrypt.content_key, sizeof old_key);
    memcpy(old_iv, rl.encrypt.iv, sizeof old_iv);

    uint8_t replacement_key[16] = { 0xC3u };
    uint8_t replacement_iv[16] = { 0xD4u };
    RFB_CHECK(!apple_record_set_direction(
        &rl, (apple_record_dir)99, replacement_key, replacement_iv));
    RFB_CHECK(rl.encrypt.active);
    RFB_CHECK(rl.encrypt.cbc == old_cbc);
    RFB_CHECK_MEM_EQ(rl.encrypt.content_key, old_key, sizeof old_key);
    RFB_CHECK_MEM_EQ(rl.encrypt.iv, old_iv, sizeof old_iv);

    uint8_t wrapped[16] = { 0 };
    RFB_CHECK(!apple_record_enable_wrapped(
        &rl, (apple_record_dir)99, wrapped, wrapped));
    RFB_CHECK(!apple_record_rekey(
        &rl, (apple_record_dir)99, wrapped, wrapped, replacement_key));
    RFB_CHECK(rl.encrypt.cbc == old_cbc);
    RFB_CHECK_MEM_EQ(rl.encrypt.content_key, old_key, sizeof old_key);
    RFB_CHECK_MEM_EQ(rl.encrypt.iv, old_iv, sizeof old_iv);
    apple_record_destroy(&rl);
}

// --- destroy zeroizes all keys -------------------------------------------

RFB_TEST(g17, record__destroy_zeroizes_keys) {
    apple_record_layer rl;
    apple_record_init(&rl, TEST_WRAP);
    apple_record_set_direction(&rl, APPLE_DIR_ENCRYPT, TEST_KEY, TEST_IV);
    apple_record_set_direction(&rl, APPLE_DIR_DECRYPT, TEST_KEY, TEST_IV);
    apple_record_destroy(&rl);

    // All keys should be zero.
    for (int i = 0; i < 16; i++) {
        RFB_CHECK_EQ_UINT(rl.wrap_key[i], 0u);
        RFB_CHECK_EQ_UINT(rl.decrypt.content_key[i], 0u);
        RFB_CHECK_EQ_UINT(rl.encrypt.content_key[i], 0u);
    }
}

// --- sequence counter increments -----------------------------------------

RFB_TEST(g17, record__sequence_increments) {
    apple_record_layer rl;
    apple_record_init(&rl, TEST_WRAP);
    apple_record_set_direction(&rl, APPLE_DIR_ENCRYPT, TEST_KEY, TEST_IV);
    apple_record_set_direction(&rl, APPLE_DIR_DECRYPT, TEST_KEY, TEST_IV);

    static const uint8_t pt[16] = "0123456789ABCDE";
    uint8_t ct[16] = { 0 };
    uint8_t dec[16] = { 0 };
    size_t outl = 0;

    apple_record_encrypt(&rl, pt, 16, ct, sizeof ct, &outl);
    RFB_CHECK_EQ_UINT(rl.encrypt.sequence, 1u);

    apple_record_decrypt(&rl, ct, 16, dec, sizeof dec, &outl);
    RFB_CHECK_EQ_UINT(rl.decrypt.sequence, 1u);

    apple_record_destroy(&rl);
}

// --- helpers: AES-128-ECB wrap one block via CBC(IV=0) --------------------

static void ecb_encrypt_block(const uint8_t key[16], const uint8_t in[16],
                              uint8_t out[16])
{
    rfb_crypto_cbc_ctx *enc = rfb_crypto_cbc_new();
    static const uint8_t zero_iv[16] = { 0 };
    size_t outl = 0;
    RFB_CHECK(enc != NULL);
    RFB_CHECK(rfb_crypto_cbc_init(enc, true, key, zero_iv));
    RFB_CHECK(rfb_crypto_cbc_update(enc, in, 16, out, 16, &outl));
    RFB_CHECK_EQ_UINT(outl, 16u);
    rfb_crypto_cbc_free(enc);
}

// --- initial enable from 0x044f wrapped payload --------------------------

RFB_TEST(g17, record__enable_wrapped__inactive_ok) {
    apple_record_layer rl;
    apple_record_init(&rl, TEST_WRAP);

    uint8_t wrapped_key[16], wrapped_iv[16];
    ecb_encrypt_block(TEST_WRAP, TEST_KEY, wrapped_key);
    ecb_encrypt_block(TEST_WRAP, TEST_IV, wrapped_iv);

    RFB_CHECK(apple_record_enable_wrapped(&rl, APPLE_DIR_DECRYPT,
                                          wrapped_key, wrapped_iv));
    RFB_CHECK(rl.decrypt.active);
    RFB_CHECK_MEM_EQ(rl.decrypt.content_key, TEST_KEY, 16);
    RFB_CHECK_MEM_EQ(rl.decrypt.iv, TEST_IV, 16);
    // wrap_key must NOT rotate on enable (only on rekey)
    RFB_CHECK_MEM_EQ(rl.wrap_key, TEST_WRAP, 16);

    apple_record_destroy(&rl);
}

RFB_TEST(g17, record__enable_wrapped__null_args__fail) {
    apple_record_layer rl;
    apple_record_init(&rl, TEST_WRAP);
    uint8_t wrapped[16] = { 0 };
    RFB_CHECK(!apple_record_enable_wrapped(NULL, APPLE_DIR_DECRYPT, wrapped, wrapped));
    RFB_CHECK(!apple_record_enable_wrapped(&rl, APPLE_DIR_DECRYPT, NULL, wrapped));
    RFB_CHECK(!apple_record_enable_wrapped(&rl, APPLE_DIR_DECRYPT, wrapped, NULL));
    apple_record_destroy(&rl);
}

// Post-authentication record sequence:
//   cleartext setup 0x044f: u32×3 || type 0x044f || u32 1 || wrapped_key||wrapped_iv
//   then records: u16be(ct_len) || AES-128-CBC(content_key, chained_iv)[pt]
//   pt: u16be(msg_len) || msg[msg_len] || pad to 16
// CBC IV chains across successive record *bodies* (not including the u16 len).
RFB_TEST(g17, record__044f_enable_chained_u16_records) {
    apple_record_layer enc_rl;
    apple_record_layer dec_rl;
    apple_record_init(&enc_rl, TEST_WRAP);
    apple_record_init(&dec_rl, TEST_WRAP);

    uint8_t wrapped_key[16], wrapped_iv[16];
    ecb_encrypt_block(TEST_WRAP, TEST_KEY, wrapped_key);
    ecb_encrypt_block(TEST_WRAP, TEST_IV, wrapped_iv);

    // Server would send cleartext 0x044f with payload = wrapped_key||wrapped_iv.
    // Client enables decrypt (and typically encrypt with the same material).
    RFB_CHECK(apple_record_enable_wrapped(&dec_rl, APPLE_DIR_DECRYPT,
                                          wrapped_key, wrapped_iv));
    RFB_CHECK(apple_record_enable_wrapped(&enc_rl, APPLE_DIR_ENCRYPT,
                                          wrapped_key, wrapped_iv));

    // Two deterministic plaintexts using the required inner shape:
    //   u16be msg_len || u32 1 || u32 0 || u32 0 || u32 type || ...
    // Pad each to a multiple of 16 with zeros.
    uint8_t pt0[32];
    uint8_t pt1[32];
    memset(pt0, 0, sizeof pt0);
    memset(pt1, 0, sizeof pt1);
    // msg_len = 20 (header 16 + 4 bytes payload)
    pt0[0] = 0x00;
    pt0[1] = 0x14;
    pt0[2] = 0x00;
    pt0[3] = 0x00;
    pt0[4] = 0x00;
    pt0[5] = 0x01;  // u32 1
    // type 0x0451 at offset 2+12 = 14
    pt0[14] = 0x04;
    pt0[15] = 0x51;
    pt0[16] = 0xDE;
    pt0[17] = 0xAD;
    pt0[18] = 0xBE;
    pt0[19] = 0xEF;

    pt1[0] = 0x00;
    pt1[1] = 0x08;
    // 8-byte body: the cleartext-style 0x14 message
    static const uint8_t k14[8] = {
        0x14, 0x00, 0x00, 0x04, 0x00, 0x01, 0x00, 0x0c
    };
    memcpy(pt1 + 2, k14, 8);

    uint8_t ct0[32] = { 0 };
    uint8_t ct1[32] = { 0 };
    size_t ct0_len = 0, ct1_len = 0;
    RFB_CHECK_EQ_INT(
        apple_record_encrypt(&enc_rl, pt0, 32, ct0, sizeof ct0, &ct0_len), RFB_OK);
    RFB_CHECK_EQ_INT(
        apple_record_encrypt(&enc_rl, pt1, 32, ct1, sizeof ct1, &ct1_len), RFB_OK);
    RFB_CHECK_EQ_UINT(ct0_len, 32u);
    RFB_CHECK_EQ_UINT(ct1_len, 32u);

    // Wire framing: u16be(len) || body  (len checked by caller)
    uint8_t wire[2 + 32 + 2 + 32];
    wire[0] = 0x00;
    wire[1] = 0x20;  // 32
    memcpy(wire + 2, ct0, 32);
    wire[34] = 0x00;
    wire[35] = 0x20;
    memcpy(wire + 36, ct1, 32);

    // Client demux: read u16be, decrypt body with chained CBC state.
    uint8_t got0[32] = { 0 };
    uint8_t got1[32] = { 0 };
    size_t g0 = 0, g1 = 0;
    uint16_t L0 = (uint16_t)(((uint16_t)wire[0] << 8) | wire[1]);
    uint16_t L1 = (uint16_t)(((uint16_t)wire[34] << 8) | wire[35]);
    RFB_CHECK_EQ_UINT(L0, 32u);
    RFB_CHECK_EQ_UINT(L1, 32u);
    RFB_CHECK_EQ_INT(
        apple_record_decrypt(&dec_rl, wire + 2, L0, got0, sizeof got0, &g0), RFB_OK);
    RFB_CHECK_EQ_INT(
        apple_record_decrypt(&dec_rl, wire + 36, L1, got1, sizeof got1, &g1), RFB_OK);
    RFB_CHECK_EQ_UINT(g0, 32u);
    RFB_CHECK_EQ_UINT(g1, 32u);
    RFB_CHECK_MEM_EQ(got0, pt0, 32);
    RFB_CHECK_MEM_EQ(got1, pt1, 32);
    // Inner type / 0x14 body visible after u16be msg_len
    RFB_CHECK_EQ_UINT(got0[14], 0x04u);
    RFB_CHECK_EQ_UINT(got0[15], 0x51u);
    RFB_CHECK_MEM_EQ(got1 + 2, k14, 8);

    apple_record_destroy(&enc_rl);
    apple_record_destroy(&dec_rl);
}

// --- rekey on a never-initialized layer fails closed -----------------------

RFB_TEST(g17, record__rekey_active_but_uninitialized__fails_closed) {
    // set_direction() does not require apple_record_init(), so this state
    // is constructible through the public API: a direction is active but
    // rl->initialized is false and rl->wrap_key is all-zero. Rekey must fail
    // closed rather than unwrap under that key.
    apple_record_layer rl;
    memset(&rl, 0, sizeof rl);
    RFB_CHECK(apple_record_set_direction(&rl, APPLE_DIR_ENCRYPT,
                                         TEST_KEY, TEST_IV));
    RFB_CHECK(rl.encrypt.active);
    RFB_CHECK(!rl.initialized);

    static const uint8_t dummy[16] = { 0 };
    static const uint8_t new_wrap[16] = { 0xFF };
    RFB_CHECK(!apple_record_rekey(&rl, APPLE_DIR_ENCRYPT,
                                  dummy, dummy, new_wrap));
    apple_record_destroy(&rl);
}

RFB_TEST(g17, record__public_argument_and_size_guards__fail_closed) {
    apple_record_layer rl;
    uint8_t block[APPLE_BLOCK_SIZE] = { 0 };
    uint8_t output[APPLE_BLOCK_SIZE] = { 0 };
    size_t output_len = 99u;
    const size_t oversized = (size_t)APPLE_RECORD_MAX_BODY + APPLE_BLOCK_SIZE;

    memset(&rl, 0, sizeof rl);
    apple_record_init(NULL, TEST_WRAP);
    apple_record_init(&rl, NULL);
    RFB_CHECK(!rl.initialized);
    RFB_CHECK(!apple_record_set_direction(NULL, APPLE_DIR_ENCRYPT,
                                           TEST_KEY, TEST_IV));
    RFB_CHECK(!apple_record_set_direction(&rl, APPLE_DIR_ENCRYPT,
                                           NULL, TEST_IV));
    RFB_CHECK(!apple_record_set_direction(&rl, APPLE_DIR_ENCRYPT,
                                           TEST_KEY, NULL));
    RFB_CHECK(!apple_record_enable_wrapped(&rl, APPLE_DIR_ENCRYPT,
                                            block, block));

    apple_record_init(&rl, TEST_WRAP);
    RFB_CHECK(!apple_record_rekey(NULL, APPLE_DIR_ENCRYPT,
                                  block, block, TEST_WRAP));
    RFB_CHECK(!apple_record_rekey(&rl, APPLE_DIR_ENCRYPT,
                                  NULL, block, TEST_WRAP));
    RFB_CHECK(!apple_record_rekey(&rl, APPLE_DIR_ENCRYPT,
                                  block, NULL, TEST_WRAP));
    RFB_CHECK(!apple_record_rekey(&rl, APPLE_DIR_ENCRYPT,
                                  block, block, NULL));
    RFB_CHECK(!apple_record_rekey(&rl, APPLE_DIR_ENCRYPT,
                                  block, block, TEST_WRAP));

    RFB_CHECK_EQ_INT(
        apple_record_encrypt(NULL, block, sizeof block,
                             output, sizeof output, &output_len),
        RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(
        apple_record_encrypt(&rl, NULL, sizeof block,
                             output, sizeof output, &output_len),
        RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(
        apple_record_encrypt(&rl, block, sizeof block,
                             NULL, sizeof output, &output_len),
        RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(
        apple_record_encrypt(&rl, block, sizeof block,
                             output, sizeof output, NULL),
        RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(
        apple_record_encrypt(&rl, block, 0u,
                             output, sizeof output, &output_len),
        RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_UINT(output_len, 0u);
    RFB_CHECK_EQ_INT(
        apple_record_encrypt(&rl, block, APPLE_BLOCK_SIZE - 1u,
                             output, sizeof output, &output_len),
        RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(
        apple_record_encrypt(&rl, block, oversized,
                             output, oversized, &output_len),
        RFB_ERR_LIMIT);
    RFB_CHECK_EQ_INT(
        apple_record_encrypt(&rl, block, sizeof block,
                             output, sizeof output - 1u, &output_len),
        RFB_ERR_LIMIT);
    RFB_CHECK_EQ_INT(
        apple_record_encrypt(&rl, block, sizeof block,
                             output, sizeof output, &output_len),
        RFB_ERR_STATE);

    RFB_CHECK_EQ_INT(
        apple_record_decrypt(NULL, block, sizeof block,
                             output, sizeof output, &output_len),
        RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(
        apple_record_decrypt(&rl, NULL, sizeof block,
                             output, sizeof output, &output_len),
        RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(
        apple_record_decrypt(&rl, block, sizeof block,
                             NULL, sizeof output, &output_len),
        RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(
        apple_record_decrypt(&rl, block, sizeof block,
                             output, sizeof output, NULL),
        RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(
        apple_record_decrypt(&rl, block, 0u,
                             output, sizeof output, &output_len),
        RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_UINT(output_len, 0u);
    RFB_CHECK_EQ_INT(
        apple_record_decrypt(&rl, block, APPLE_BLOCK_SIZE - 1u,
                             output, sizeof output, &output_len),
        RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(
        apple_record_decrypt(&rl, block, oversized,
                             output, oversized, &output_len),
        RFB_ERR_LIMIT);
    RFB_CHECK_EQ_INT(
        apple_record_decrypt(&rl, block, sizeof block,
                             output, sizeof output - 1u, &output_len),
        RFB_ERR_LIMIT);
    RFB_CHECK_EQ_INT(
        apple_record_decrypt(&rl, block, sizeof block,
                             output, sizeof output, &output_len),
        RFB_ERR_STATE);

    RFB_CHECK(apple_record_set_direction(&rl, APPLE_DIR_ENCRYPT,
                                         TEST_KEY, TEST_IV));
    rfb_crypto_cbc_ctx *encrypt_cbc = rl.encrypt.cbc;
    rl.encrypt.active = false;
    RFB_CHECK_EQ_INT(
        apple_record_encrypt(&rl, block, sizeof block,
                             output, sizeof output, &output_len),
        RFB_ERR_STATE);
    rl.encrypt.active = true;
    rl.encrypt.cbc = NULL;
    RFB_CHECK_EQ_INT(
        apple_record_encrypt(&rl, block, sizeof block,
                             output, sizeof output, &output_len),
        RFB_ERR_STATE);
    rl.encrypt.cbc = encrypt_cbc;

    RFB_CHECK(apple_record_set_direction(&rl, APPLE_DIR_DECRYPT,
                                         TEST_KEY, TEST_IV));
    rfb_crypto_cbc_ctx *decrypt_cbc = rl.decrypt.cbc;
    rl.decrypt.active = false;
    RFB_CHECK_EQ_INT(
        apple_record_decrypt(&rl, block, sizeof block,
                             output, sizeof output, &output_len),
        RFB_ERR_STATE);
    rl.decrypt.active = true;
    rl.decrypt.cbc = NULL;
    RFB_CHECK_EQ_INT(
        apple_record_decrypt(&rl, block, sizeof block,
                             output, sizeof output, &output_len),
        RFB_ERR_STATE);
    rl.decrypt.cbc = decrypt_cbc;

    apple_record_destroy(NULL);
    apple_record_destroy(&rl);
}
