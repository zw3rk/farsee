// SPDX-License-Identifier: Apache-2.0
//
// Record-layer input validation, rekey-state, teardown, and bounded-output
// tests. AES-CBC decryption in this layer does not authenticate ciphertext.

#include "rfb_test.h"
#include "farsee/apple_record.h"
#include "farsee/apple_crypto.h"
#include "farsee/secret.h"

#include <string.h>

static const uint8_t G25_RL_KEY[16] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
};
static const uint8_t G25_RL_IV[16] = {
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
    0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
};
static const uint8_t G25_RL_WRAP[16] = {
    0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,0x00,0x11,
    0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99
};

// --- Structural input validation ----------------------------------------
// These cases exercise invalid length, NULL ciphertext, and output-capacity
// inputs. They check rejection, not a uniform error category.

RFB_TEST(security_record, corruption__truncated_returns_protocol_error) {
    apple_record_layer rl;
    apple_record_init(&rl, G25_RL_WRAP);
    apple_record_set_direction(&rl, APPLE_DIR_DECRYPT, G25_RL_KEY, G25_RL_IV);

    static const uint8_t junk[15] = { 0 };  // not a multiple of 16
    uint8_t out[32]; size_t out_len = 0;
    rfb_error e = apple_record_decrypt(&rl, junk, sizeof junk, out, sizeof out, &out_len);
    RFB_CHECK(e != RFB_OK);
    RFB_CHECK(e == RFB_ERR_PROTOCOL || e == RFB_ERR_INTERNAL);
    apple_record_destroy(&rl);
}

RFB_TEST(security_record, corruption__empty_input_is_not_ok) {
    apple_record_layer rl;
    apple_record_init(&rl, G25_RL_WRAP);
    apple_record_set_direction(&rl, APPLE_DIR_DECRYPT, G25_RL_KEY, G25_RL_IV);

    uint8_t out[32]; size_t out_len = 0;
    rfb_error e = apple_record_decrypt(&rl, NULL, 0, out, sizeof out, &out_len);
    RFB_CHECK(e != RFB_OK);  // empty is not a valid record
    apple_record_destroy(&rl);
}

RFB_TEST(security_record, invalid_inputs__four_cases_return_error) {
    // Each of the four invalid inputs returns a non-OK result.
    apple_record_layer rl;
    apple_record_init(&rl, G25_RL_WRAP);
    apple_record_set_direction(&rl, APPLE_DIR_DECRYPT, G25_RL_KEY, G25_RL_IV);
    apple_record_set_direction(&rl, APPLE_DIR_ENCRYPT, G25_RL_KEY, G25_RL_IV);

    uint8_t out[48]; size_t out_len = 0;
    rfb_error e;

    // Mode A: length not a multiple of 16.
    static const uint8_t odd[17] = { 0 };
    e = apple_record_decrypt(&rl, odd, 17, out, sizeof out, &out_len);
    RFB_CHECK(e != RFB_OK);

    // Mode B: zero length.
    e = apple_record_decrypt(&rl, odd, 0, out, sizeof out, &out_len);
    RFB_CHECK(e != RFB_OK);

    // Mode C: NULL ciphertext with nonzero length.
    e = apple_record_decrypt(&rl, NULL, 16, out, sizeof out, &out_len);
    RFB_CHECK(e != RFB_OK);

    // Mode D: output cap too small.
    static const uint8_t ok_block[16] = { 0 };
    e = apple_record_decrypt(&rl, ok_block, 16, out, 8, &out_len);
    RFB_CHECK(e != RFB_OK);

    apple_record_destroy(&rl);
}

RFB_TEST(security_record, bit_flip__decrypt_result_length_is_bounded) {
    // Flip one ciphertext bit and check only that the reported output length
    // does not exceed the ciphertext length.
    apple_record_layer rl;
    apple_record_init(&rl, G25_RL_WRAP);
    apple_record_set_direction(&rl, APPLE_DIR_DECRYPT, G25_RL_KEY, G25_RL_IV);
    apple_record_set_direction(&rl, APPLE_DIR_ENCRYPT, G25_RL_KEY, G25_RL_IV);

    uint8_t pt[32]; memset(pt, 0xAB, sizeof pt);
    uint8_t ct[32]; size_t ct_len = 0;
    RFB_CHECK_EQ_INT(apple_record_encrypt(&rl, pt, sizeof pt, ct, sizeof ct, &ct_len), RFB_OK);

    // Flip one bit in the second block.
    ct[16] ^= 0x01;
    uint8_t out[32]; size_t out_len = 0;
    rfb_error e = apple_record_decrypt(&rl, ct, ct_len, out, sizeof out, &out_len);
    // The test accepts either status and checks the reported length.
    (void)e;
    RFB_CHECK(out_len <= ct_len);
    apple_record_destroy(&rl);
}

// --- Rekey state transitions --------------------------------------------

RFB_TEST(security_record, rekey__inactive_direction_does_not_activate) {
    apple_record_layer rl;
    apple_record_init(&rl, G25_RL_WRAP);
    // No direction set.
    static const uint8_t dummy[16] = { 0 };
    static const uint8_t new_wrap[16] = { 0xFF };
    RFB_CHECK(!apple_record_rekey(&rl, APPLE_DIR_DECRYPT, dummy, dummy, new_wrap));
    // The direction must still be inactive (no partial activation).
    RFB_CHECK(!rl.decrypt.active);
    // The wrap key must NOT have rotated on a failed rekey.
    RFB_CHECK_MEM_EQ(rl.wrap_key, G25_RL_WRAP, 16);
    apple_record_destroy(&rl);
}

RFB_TEST(security_record, rekey__successful_rekey_rotates_wrap_key) {
    apple_record_layer rl;
    apple_record_init(&rl, G25_RL_WRAP);
    apple_record_set_direction(&rl, APPLE_DIR_DECRYPT, G25_RL_KEY, G25_RL_IV);

    // Wrap new key/IV by AES-128-ECB-encrypting with the wrap key (CBC with
    // zero IV for a single block == ECB).
    static const uint8_t new_key[16] = {
        0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10,
        0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF
    };
    static const uint8_t new_iv[16] = {
        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
        0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10
    };
    uint8_t wrapped_key[16], wrapped_iv[16];
    static const uint8_t zero_iv[16] = { 0 };
    rfb_crypto_cbc_ctx *enc = rfb_crypto_cbc_new();
    rfb_crypto_cbc_init(enc, true, G25_RL_WRAP, zero_iv);
    size_t outl = 0;
    rfb_crypto_cbc_update(enc, new_key, 16, wrapped_key, sizeof wrapped_key, &outl);
    rfb_crypto_cbc_free(enc);
    enc = rfb_crypto_cbc_new();
    rfb_crypto_cbc_init(enc, true, G25_RL_WRAP, zero_iv);
    rfb_crypto_cbc_update(enc, new_iv, 16, wrapped_iv, sizeof wrapped_iv, &outl);
    rfb_crypto_cbc_free(enc);

    static const uint8_t new_wrap[16] = { 0xDE,0xAD,0xBE,0xEF };
    RFB_CHECK(apple_record_rekey(&rl, APPLE_DIR_DECRYPT,
                                 wrapped_key, wrapped_iv, new_wrap));
    // Wrap key rotated atomically.
    RFB_CHECK_MEM_EQ(rl.wrap_key, new_wrap, 16);
    // Direction active with new content key.
    RFB_CHECK(rl.decrypt.active);
    RFB_CHECK_MEM_EQ(rl.decrypt.content_key, new_key, 16);
    RFB_CHECK_MEM_EQ(rl.decrypt.iv, new_iv, 16);
    apple_record_destroy(&rl);
}

// --- Destroy zeroizes all key material -----------------------------------

RFB_TEST(security_record, destroy__zeroizes_all_keys_and_ivs) {
    apple_record_layer rl;
    apple_record_init(&rl, G25_RL_WRAP);
    apple_record_set_direction(&rl, APPLE_DIR_ENCRYPT, G25_RL_KEY, G25_RL_IV);
    apple_record_set_direction(&rl, APPLE_DIR_DECRYPT, G25_RL_KEY, G25_RL_IV);
    apple_record_destroy(&rl);

    // Every key/IV byte must be zero after destroy.
    for (int i = 0; i < 16; i++) {
        RFB_CHECK_EQ_UINT(rl.wrap_key[i], 0u);
        RFB_CHECK_EQ_UINT(rl.next_wrap_key[i], 0u);
        RFB_CHECK_EQ_UINT(rl.decrypt.content_key[i], 0u);
        RFB_CHECK_EQ_UINT(rl.decrypt.iv[i], 0u);
        RFB_CHECK_EQ_UINT(rl.encrypt.content_key[i], 0u);
        RFB_CHECK_EQ_UINT(rl.encrypt.iv[i], 0u);
    }
    RFB_CHECK(!rl.initialized);
}

// --- One 64-byte decrypt result -----------------------------------------

RFB_TEST(security_record, decrypt__64_byte_output_not_larger_than_ciphertext) {
    apple_record_layer rl;
    apple_record_init(&rl, G25_RL_WRAP);
    apple_record_set_direction(&rl, APPLE_DIR_DECRYPT, G25_RL_KEY, G25_RL_IV);
    apple_record_set_direction(&rl, APPLE_DIR_ENCRYPT, G25_RL_KEY, G25_RL_IV);

    uint8_t pt[64]; memset(pt, 0x77, sizeof pt);
    uint8_t ct[64]; size_t ct_len = 0;
    RFB_CHECK_EQ_INT(apple_record_encrypt(&rl, pt, 64, ct, sizeof ct, &ct_len), RFB_OK);
    uint8_t out[64]; size_t out_len = 0;
    RFB_CHECK_EQ_INT(apple_record_decrypt(&rl, ct, ct_len, out, sizeof out, &out_len), RFB_OK);
    RFB_CHECK(out_len <= ct_len);
    apple_record_destroy(&rl);
}
