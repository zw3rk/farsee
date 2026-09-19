// SPDX-License-Identifier: Apache-2.0
//
// Modern Apple post-authentication AES-CBC wire framing tests.

#include "rfb_test.h"
#include "farsee/apple_wire_record.h"
#include "farsee/apple_record.h"
#include "farsee/apple_crypto.h"
#include "farsee/memory_budget.h"

#include <stdlib.h>
#include <string.h>

static const uint8_t k_wire_wrap[16] = {
    0xAAu, 0xBBu, 0xCCu, 0xDDu, 0xEEu, 0xFFu, 0x00u, 0x11u,
    0x22u, 0x33u, 0x44u, 0x55u, 0x66u, 0x77u, 0x88u, 0x99u
};
static const uint8_t k_wire_key[16] = {
    0x00u, 0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u, 0x07u,
    0x08u, 0x09u, 0x0au, 0x0bu, 0x0cu, 0x0du, 0x0eu, 0x0fu
};
static const uint8_t k_wire_iv[16] = {
    0x10u, 0x11u, 0x12u, 0x13u, 0x14u, 0x15u, 0x16u, 0x17u,
    0x18u, 0x19u, 0x1au, 0x1bu, 0x1cu, 0x1du, 0x1eu, 0x1fu
};

typedef struct wire_alloc_spy {
    size_t calls;
    size_t fail_call;
    size_t frees;
} wire_alloc_spy;

static void *wire_spy_alloc(rfb_allocator *allocator, size_t size)
{
    wire_alloc_spy *spy = (wire_alloc_spy *)allocator->user;
    spy->calls++;
    if (spy->calls == spy->fail_call) {
        return NULL;
    }
    return malloc(size);
}

static void wire_spy_free(rfb_allocator *allocator, void *allocation)
{
    wire_alloc_spy *spy = (wire_alloc_spy *)allocator->user;
    spy->frees++;
    free(allocation);
}

static void wire_enable_direct_pair(apple_record_layer *enc,
                                    apple_record_layer *dec)
{
    apple_record_init(enc, k_wire_wrap);
    apple_record_init(dec, k_wire_wrap);
    RFB_CHECK(apple_record_set_direction(enc, APPLE_DIR_ENCRYPT, k_wire_key,
                                         k_wire_iv));
    RFB_CHECK(apple_record_set_direction(dec, APPLE_DIR_DECRYPT, k_wire_key,
                                         k_wire_iv));
}

static void wire_encrypt_raw_body(apple_record_layer *enc, uint16_t mlen,
                                  uint8_t ciphertext[32])
{
    uint8_t plaintext[32] = {0};
    uint8_t sha_input[4u + 12u] = {0};
    uint8_t digest[APPLE_WIRE_SHA1_LEN];
    const uint32_t seq = (uint32_t)enc->encrypt.sequence;
    plaintext[0] = (uint8_t)(mlen >> 8);
    plaintext[1] = (uint8_t)(mlen & 0xffu);
    sha_input[0] = (uint8_t)(seq >> 24);
    sha_input[1] = (uint8_t)(seq >> 16);
    sha_input[2] = (uint8_t)(seq >> 8);
    sha_input[3] = (uint8_t)seq;
    memcpy(sha_input + 4u, plaintext, 12u);
    RFB_CHECK(rfb_crypto_sha1(sha_input, sizeof sha_input, digest));
    memcpy(plaintext + 12u, digest, sizeof digest);
    size_t ciphertext_len = 0u;
    RFB_CHECK_EQ_INT(apple_record_encrypt(enc, plaintext, sizeof plaintext,
                                          ciphertext, 32u, &ciphertext_len),
                     RFB_OK);
    RFB_CHECK_EQ_UINT(ciphertext_len, 32u);
}

static void wire_ecb_enc_block(const uint8_t key[16], const uint8_t in[16],
                               uint8_t out[16])
{
    rfb_crypto_cbc_ctx *enc = rfb_crypto_cbc_new();
    static const uint8_t ziv[16] = { 0 };
    size_t outl = 0;
    RFB_CHECK(enc != NULL);
    RFB_CHECK(rfb_crypto_cbc_init(enc, true, key, ziv));
    RFB_CHECK(rfb_crypto_cbc_update(enc, in, 16, out, 16, &outl));
    rfb_crypto_cbc_free(enc);
}

RFB_TEST(apple_wire, fixtures__modern_post_si_len)
{
    RFB_CHECK_EQ_UINT(sizeof apple_wire_modern_post_si,
                      APPLE_WIRE_MODERN_POST_SI_LEN);
    RFB_CHECK_EQ_UINT(apple_wire_modern_post_si[0], 0x21u);
    // The SetEncodings list offers private encoding 0x0450.
    RFB_CHECK_EQ_UINT(apple_wire_modern_post_si[106], 0x00u);
    RFB_CHECK_EQ_UINT(apple_wire_modern_post_si[107], 0x00u);
    RFB_CHECK_EQ_UINT(apple_wire_modern_post_si[108], 0x04u);
    RFB_CHECK_EQ_UINT(apple_wire_modern_post_si[109], 0x50u);
    RFB_CHECK_EQ_UINT(apple_wire_msg12_ack[0], 0x12u);
    RFB_CHECK_EQ_UINT(apple_wire_msg14[0], 0x14u);
}

RFB_TEST(apple_wire, setup_consume__incomplete__zero)
{
    const uint8_t *pay = (const uint8_t *)0x1;
    uint8_t partial[20] = { 0 };
    RFB_CHECK_EQ_UINT(apple_wire_setup_consume_len(partial, 10u, &pay), 0u);
}

RFB_TEST(apple_wire, setup_consume__with_and_without_msg14)
{
    uint8_t wrapped_key[16], wrapped_iv[16];
    wire_ecb_enc_block(k_wire_wrap, k_wire_key, wrapped_key);
    wire_ecb_enc_block(k_wire_wrap, k_wire_iv, wrapped_iv);

    uint8_t setup[52];
    memset(setup, 0, sizeof setup);
    setup[3] = 0x01u; // u32 1
    setup[14] = 0x04u;
    setup[15] = 0x4fu; // type 0x044f
    setup[19] = 0x01u; // u32 1
    memcpy(setup + 20, wrapped_key, 16);
    memcpy(setup + 36, wrapped_iv, 16);

    const uint8_t *pay = NULL;
    size_t n = apple_wire_setup_consume_len(setup, sizeof setup, &pay);
    RFB_CHECK_EQ_UINT(n, 52u);
    RFB_CHECK(pay == setup + 20);

    uint8_t with14[8 + 52];
    memcpy(with14, apple_wire_msg14, 8);
    memcpy(with14 + 8, setup, 52);
    pay = NULL;
    n = apple_wire_setup_consume_len(with14, sizeof with14, &pay);
    RFB_CHECK_EQ_UINT(n, 60u);
    RFB_CHECK(pay == with14 + 8 + 20);
}

RFB_TEST(apple_wire, setup_consume__wrong_magic__reject)
{
    uint8_t junk[52];
    memset(junk, 0xABu, sizeof junk);
    const uint8_t *pay = NULL;
    size_t n = apple_wire_setup_consume_len(junk, sizeof junk, &pay);
    RFB_CHECK(n == (size_t)-1);
    RFB_CHECK(pay == NULL);
}

// Valid 0x044f setup52 envelope with wrapped key material.
RFB_TEST(apple_wire, setup_consume__server_setup52)
{
    static const uint8_t setup52[52] = {
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x04, 0x4f, 0x00, 0x00, 0x00, 0x01, 0x88, 0xee, 0xf5, 0x22,
        0x0d, 0x88, 0xcc, 0x44, 0x22, 0x03, 0xe5, 0x00, 0xed, 0xa0, 0x19, 0xba,
        0x78, 0xc5, 0xc7, 0x70, 0x63, 0xc1, 0x60, 0x1b, 0xd6, 0x5d, 0xc1, 0x18,
        0x83, 0x26, 0x3f, 0x90
    };
    const uint8_t *pay = NULL;
    size_t n = apple_wire_setup_consume_len(setup52, sizeof setup52, &pay);
    RFB_CHECK_EQ_UINT(n, 52u);
    RFB_CHECK(pay == setup52 + 20);
    RFB_CHECK_EQ_UINT(pay[0], 0x88u);
    RFB_CHECK_EQ_UINT(pay[31], 0x90u);

    // Leading cleartext msg14 + setup.
    uint8_t with14[8 + 52];
    memcpy(with14, apple_wire_msg14, 8);
    memcpy(with14 + 8, setup52, 52);
    pay = NULL;
    n = apple_wire_setup_consume_len(with14, sizeof with14, &pay);
    RFB_CHECK_EQ_UINT(n, 60u);
    RFB_CHECK(pay == with14 + 8 + 20);
}

// --- setup52 envelope inspection -----------------------------------------
//
// The setup envelope is `u32be 1|0|0|type|method || payload32`. The supported
// suite has type=0x044f and method=1 (AES-128-CBC). Inspection recognizes the
// envelope first, then decides whether the suite is supported.

// Build a setup52 with an arbitrary type/method (test helper only).
static void wire_make_setup52(uint8_t out[52], uint32_t type, uint32_t method)
{
    memset(out, 0, 52);
    out[3] = 0x01u;
    out[12] = (uint8_t)((type >> 24) & 0xffu);
    out[13] = (uint8_t)((type >> 16) & 0xffu);
    out[14] = (uint8_t)((type >> 8) & 0xffu);
    out[15] = (uint8_t)(type & 0xffu);
    out[16] = (uint8_t)((method >> 24) & 0xffu);
    out[17] = (uint8_t)((method >> 16) & 0xffu);
    out[18] = (uint8_t)((method >> 8) & 0xffu);
    out[19] = (uint8_t)(method & 0xffu);
    for (size_t i = 0; i < 32u; i++) {
        out[20 + i] = (uint8_t)(0xa0u + i);
    }
}

RFB_TEST(apple_wire, setup_inspect__supported_suite__accepted)
{
    // +: the supported suite uses type 0x044f and method 1.
    uint8_t setup[52];
    wire_make_setup52(setup, APPLE_WIRE_TYPE_ENABLE,
                      APPLE_WIRE_SETUP_METHOD_AES_CBC);
    apple_wire_setup_info info;
    const size_t n = apple_wire_setup_inspect(setup, sizeof setup, &info);
    RFB_CHECK_EQ_UINT(n, 52u);
    RFB_CHECK_EQ_UINT(info.consume, 52u);
    RFB_CHECK_EQ_UINT(info.type, APPLE_WIRE_TYPE_ENABLE);
    RFB_CHECK_EQ_UINT(info.method, APPLE_WIRE_SETUP_METHOD_AES_CBC);
    RFB_CHECK(info.supported);
    RFB_CHECK(info.payload32 == setup + 20);

    // + same, behind the optional cleartext msg14 tick.
    uint8_t with14[8 + 52];
    memcpy(with14, apple_wire_msg14, 8);
    memcpy(with14 + 8, setup, 52);
    RFB_CHECK_EQ_UINT(apple_wire_setup_inspect(with14, sizeof with14, &info),
                      60u);
    RFB_CHECK(info.supported);
    RFB_CHECK(info.payload32 == with14 + 8 + 20);
}

RFB_TEST(apple_wire, setup_inspect__unknown_suite__recognised_not_supported)
{
    // −: a well-formed envelope carrying an unsupported suite must be
    // *recognised* (so the operator learns type/method) and *rejected*
    // (fail closed — we have no key schedule for it).
    apple_wire_setup_info info;
    uint8_t other_type[52];
    wire_make_setup52(other_type, 0x0460u, APPLE_WIRE_SETUP_METHOD_AES_CBC);
    RFB_CHECK_EQ_UINT(
        apple_wire_setup_inspect(other_type, sizeof other_type, &info), 52u);
    RFB_CHECK_EQ_UINT(info.type, 0x0460u);
    RFB_CHECK_EQ_UINT(info.method, 1u);
    RFB_CHECK(!info.supported);
    RFB_CHECK(info.payload32 == other_type + 20);

    uint8_t other_method[52];
    wire_make_setup52(other_method, APPLE_WIRE_TYPE_ENABLE, 2u);
    RFB_CHECK_EQ_UINT(
        apple_wire_setup_inspect(other_method, sizeof other_method, &info),
        52u);
    RFB_CHECK_EQ_UINT(info.type, APPLE_WIRE_TYPE_ENABLE);
    RFB_CHECK_EQ_UINT(info.method, 2u);
    RFB_CHECK(!info.supported);

    // The legacy consume helper still refuses both (unchanged contract).
    const uint8_t *pay = NULL;
    RFB_CHECK(apple_wire_setup_consume_len(other_type, sizeof other_type,
                                           &pay) == (size_t)-1);
    RFB_CHECK(pay == NULL);
    RFB_CHECK(apple_wire_setup_consume_len(other_method, sizeof other_method,
                                           &pay) == (size_t)-1);
}

RFB_TEST(apple_wire, setup_inspect__not_an_envelope__rejected)
{
    // −: wrong marker words are not a setup envelope at all.
    apple_wire_setup_info info;
    uint8_t bad[52];
    wire_make_setup52(bad, APPLE_WIRE_TYPE_ENABLE,
                      APPLE_WIRE_SETUP_METHOD_AES_CBC);
    bad[3] = 0x02u; // marker must be u32be 1
    RFB_CHECK(apple_wire_setup_inspect(bad, sizeof bad, &info) == (size_t)-1);
    RFB_CHECK(info.payload32 == NULL);
    RFB_CHECK(!info.supported);

    wire_make_setup52(bad, APPLE_WIRE_TYPE_ENABLE,
                      APPLE_WIRE_SETUP_METHOD_AES_CBC);
    bad[7] = 0x01u; // second word must be zero
    RFB_CHECK(apple_wire_setup_inspect(bad, sizeof bad, &info) == (size_t)-1);

    wire_make_setup52(bad, APPLE_WIRE_TYPE_ENABLE,
                      APPLE_WIRE_SETUP_METHOD_AES_CBC);
    bad[11] = 0x01u; // third word must be zero
    RFB_CHECK(apple_wire_setup_inspect(bad, sizeof bad, &info) == (size_t)-1);

    // − incomplete input reports "need more", not a decision.
    wire_make_setup52(bad, APPLE_WIRE_TYPE_ENABLE,
                      APPLE_WIRE_SETUP_METHOD_AES_CBC);
    RFB_CHECK_EQ_UINT(apple_wire_setup_inspect(bad, 51u, &info), 0u);
    RFB_CHECK(info.payload32 == NULL);

    // − NULL inputs fail closed.
    RFB_CHECK_EQ_UINT(apple_wire_setup_inspect(NULL, 52u, &info), 0u);
    RFB_CHECK(apple_wire_setup_inspect(bad, sizeof bad, NULL) == (size_t)-1);
}

// setup52 with method 1 must inspect as the supported AES-CBC suite.
RFB_TEST(apple_wire, setup_inspect__aes_cbc_method1)
{
    static const uint8_t setup52[52] = {
        0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x04, 0x4f, 0x00, 0x00, 0x00, 0x01, 0x88, 0xee, 0xf5, 0x22,
        0x0d, 0x88, 0xcc, 0x44, 0x22, 0x03, 0xe5, 0x00, 0xed, 0xa0, 0x19, 0xba,
        0x78, 0xc5, 0xc7, 0x70, 0x63, 0xc1, 0x60, 0x1b, 0xd6, 0x5d, 0xc1, 0x18,
        0x83, 0x26, 0x3f, 0x90
    };
    apple_wire_setup_info info;
    RFB_CHECK_EQ_UINT(apple_wire_setup_inspect(setup52, sizeof setup52, &info),
                      52u);
    RFB_CHECK_EQ_UINT(info.type, 0x044fu);
    RFB_CHECK_EQ_UINT(info.method, 1u);
    RFB_CHECK(info.supported);
}

// Deterministic KAT: fixed key/iv/seq=0 msg14 → fixed ciphertext (openssl AES-CBC).
RFB_TEST(apple_wire, seal__msg14_seq0__known_ciphertext_vector)
{
    static const uint8_t key[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    static const uint8_t iv[16] = {
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    // wire = u16be(32) || CBC(pt), using the required seal layout.
    static const uint8_t expect_wire[2 + 32] = {
        0x00, 0x20,
        0x64, 0xee, 0x27, 0x6a, 0xac, 0xbd, 0x92, 0xb9, 0x5b, 0x00, 0x01, 0x68,
        0x74, 0x21, 0x73, 0xb3, 0xcc, 0xec, 0x3a, 0xf5, 0x8d, 0xf7, 0xa7, 0xbd,
        0xc3, 0x99, 0x36, 0xd6, 0x6b, 0x67, 0x30, 0xc0
    };

    apple_record_layer rl;
    apple_record_init(&rl, key); // wrap unused when set_direction
    RFB_CHECK(apple_record_set_direction(&rl, APPLE_DIR_ENCRYPT, key, iv));

    uint8_t wire[64];
    size_t n = 0u;
    RFB_CHECK_EQ_INT(
        apple_wire_record_seal(&rl, apple_wire_msg14, APPLE_WIRE_MSG14_LEN,
                               wire, sizeof wire, &n),
        RFB_OK);
    RFB_CHECK_EQ_UINT(n, sizeof expect_wire);
    RFB_CHECK_MEM_EQ(wire, expect_wire, sizeof expect_wire);
    apple_record_destroy(&rl);
}

RFB_TEST(apple_wire, seal_budget_failure_does_not_advance_record_state)
{
    apple_record_layer rl;
    apple_record_init(&rl, k_wire_wrap);
    RFB_CHECK(apple_record_set_direction(&rl, APPLE_DIR_ENCRYPT, k_wire_key,
                                         k_wire_iv));
    farsee_memory_budget budget;
    RFB_CHECK(farsee_memory_budget_init(&budget, rfb_default_allocator(),
                                        67u));
    uint8_t wire[64] = {0};
    size_t wire_len = 99u;
    RFB_CHECK_EQ_INT(
        apple_wire_record_seal_with_allocator(
            &rl, apple_wire_msg14, APPLE_WIRE_MSG14_LEN, wire, sizeof wire,
            &wire_len, farsee_memory_budget_allocator(&budget)),
        RFB_ERR_NOMEM);
    RFB_CHECK_EQ_UINT(wire_len, 0u);
    RFB_CHECK_EQ_UINT(rl.encrypt.sequence, 0u);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&budget), 0u);
    apple_record_destroy(&rl);
}

RFB_TEST(apple_wire, seal_budget_exact_fit_preserves_known_wire_bytes)
{
    static const uint8_t expected[34] = {
        0x00, 0x20, 0x64, 0xee, 0x27, 0x6a, 0xac, 0xbd, 0x92, 0xb9,
        0x5b, 0x00, 0x01, 0x68, 0x74, 0x21, 0x73, 0xb3, 0xcc, 0xec,
        0x3a, 0xf5, 0x8d, 0xf7, 0xa7, 0xbd, 0xc3, 0x99, 0x36, 0xd6,
        0x6b, 0x67, 0x30, 0xc0,
    };
    apple_record_layer rl;
    apple_record_init(&rl, k_wire_wrap);
    RFB_CHECK(apple_record_set_direction(&rl, APPLE_DIR_ENCRYPT, k_wire_key,
                                         k_wire_iv));
    farsee_memory_budget budget;
    RFB_CHECK(farsee_memory_budget_init(&budget, rfb_default_allocator(),
                                        68u));
    uint8_t wire[64] = {0};
    size_t wire_len = 0u;
    RFB_CHECK_EQ_INT(
        apple_wire_record_seal_with_allocator(
            &rl, apple_wire_msg14, APPLE_WIRE_MSG14_LEN, wire, sizeof wire,
            &wire_len, farsee_memory_budget_allocator(&budget)),
        RFB_OK);
    RFB_CHECK_EQ_UINT(wire_len, sizeof expected);
    RFB_CHECK_MEM_EQ(wire, expected, sizeof expected);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&budget), 0u);
    apple_record_destroy(&rl);
}

RFB_TEST(apple_wire, open_budget_failure_is_transactional_then_exact_fit_opens)
{
    apple_record_layer enc;
    apple_record_layer dec;
    apple_record_init(&enc, k_wire_wrap);
    apple_record_init(&dec, k_wire_wrap);
    RFB_CHECK(apple_record_set_direction(&enc, APPLE_DIR_ENCRYPT, k_wire_key,
                                         k_wire_iv));
    RFB_CHECK(apple_record_set_direction(&dec, APPLE_DIR_DECRYPT, k_wire_key,
                                         k_wire_iv));
    uint8_t wire[64] = {0};
    size_t wire_len = 0u;
    RFB_CHECK_EQ_INT(
        apple_wire_record_seal(&enc, apple_wire_msg14,
                               APPLE_WIRE_MSG14_LEN, wire, sizeof wire,
                               &wire_len),
        RFB_OK);

    farsee_memory_budget too_small;
    RFB_CHECK(farsee_memory_budget_init(&too_small, rfb_default_allocator(),
                                        15u));
    uint8_t message[64] = {0};
    size_t message_len = 0u;
    RFB_CHECK_EQ_INT(
        apple_wire_record_open_with_allocator(
            &dec, wire + 2u, wire_len - 2u, message, sizeof message,
            &message_len, farsee_memory_budget_allocator(&too_small)),
        RFB_ERR_NOMEM);
    RFB_CHECK_EQ_UINT(dec.decrypt.sequence, 0u);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&too_small), 0u);

    farsee_memory_budget exact;
    RFB_CHECK(farsee_memory_budget_init(&exact, rfb_default_allocator(), 16u));
    RFB_CHECK_EQ_INT(
        apple_wire_record_open_with_allocator(
            &dec, wire + 2u, wire_len - 2u, message, sizeof message,
            &message_len, farsee_memory_budget_allocator(&exact)),
        RFB_OK);
    RFB_CHECK_EQ_UINT(message_len, APPLE_WIRE_MSG14_LEN);
    RFB_CHECK_MEM_EQ(message, apple_wire_msg14, APPLE_WIRE_MSG14_LEN);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&exact), 0u);

    apple_record_destroy(&enc);
    apple_record_destroy(&dec);
}

// Product policy: post-enable silence vs sealed FBUR (never imply msg14-first).
RFB_TEST(apple_wire, product_post_enable__silence_or_fbur_only)
{
    RFB_CHECK(apple_wire_product_wants_sealed_fbur(false) == true);
    RFB_CHECK(apple_wire_product_wants_sealed_fbur(true) == false);
}

// Plaintext message taxonomy.
RFB_TEST(apple_wire, classify_msg__kinds)
{
    uint32_t code = 0u;
    RFB_CHECK_EQ_INT(apple_wire_classify_msg(NULL, 0, &code),
                     APPLE_WIRE_KIND_EMPTY);
    RFB_CHECK(strcmp(apple_wire_msg_kind_name(APPLE_WIRE_KIND_FBUR), "fbur") ==
              0);

    RFB_CHECK_EQ_INT(
        apple_wire_classify_msg(apple_wire_msg14, APPLE_WIRE_MSG14_LEN, &code),
        APPLE_WIRE_KIND_MSG14);
    RFB_CHECK_EQ_UINT(code, 0x14u);

    static const uint8_t fbur[10] = {0x03u, 0x00u, 0x00u, 0x00u, 0x00u,
                                     0x00u, 0x04u, 0x00u, 0x03u, 0x00u};
    RFB_CHECK_EQ_INT(apple_wire_classify_msg(fbur, sizeof fbur, &code),
                     APPLE_WIRE_KIND_FBUR);
    RFB_CHECK_EQ_UINT(code, 0x03u);

    static const uint8_t se[4] = {0x02u, 0x00u, 0x00u, 0x01u};
    RFB_CHECK_EQ_INT(apple_wire_classify_msg(se, sizeof se, &code),
                     APPLE_WIRE_KIND_SET_ENCODINGS);

    RFB_CHECK_EQ_INT(
        apple_wire_classify_msg(apple_wire_msg12_ack, APPLE_WIRE_MSG12_ACK_LEN,
                                &code),
        APPLE_WIRE_KIND_MSG12);

    uint8_t typed[16];
    memset(typed, 0, sizeof typed);
    typed[3] = 0x01u;
    typed[14] = 0x04u;
    typed[15] = 0x51u;
    RFB_CHECK_EQ_INT(apple_wire_classify_msg(typed, sizeof typed, &code),
                     APPLE_WIRE_KIND_TYPED);
    RFB_CHECK_EQ_UINT(code, 0x0451u);

    static const uint8_t unk[1] = {0xAAu};
    RFB_CHECK_EQ_INT(apple_wire_classify_msg(unk, 1u, &code),
                     APPLE_WIRE_KIND_UNKNOWN);
    RFB_CHECK_EQ_UINT(code, 0xAAu);
}

RFB_TEST(apple_wire, seal_open__roundtrip_and_msg14_classify)
{
    uint8_t wrapped_key[16], wrapped_iv[16];
    wire_ecb_enc_block(k_wire_wrap, k_wire_key, wrapped_key);
    wire_ecb_enc_block(k_wire_wrap, k_wire_iv, wrapped_iv);

    apple_record_layer enc_rl, dec_rl;
    apple_record_init(&enc_rl, k_wire_wrap);
    apple_record_init(&dec_rl, k_wire_wrap);
    RFB_CHECK(apple_record_enable_wrapped(&enc_rl, APPLE_DIR_ENCRYPT,
                                          wrapped_key, wrapped_iv));
    RFB_CHECK(apple_record_enable_wrapped(&dec_rl, APPLE_DIR_DECRYPT,
                                          wrapped_key, wrapped_iv));

    // Classic KeyEvent-shaped 8 B message.
    static const uint8_t key_msg[8] = {
        0x04u, 0x01u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x20u
    };
    uint8_t wire[64];
    size_t wire_len = 0u;
    RFB_CHECK_EQ_INT(
        apple_wire_record_seal(&enc_rl, key_msg, sizeof key_msg, wire,
                               sizeof wire, &wire_len),
        RFB_OK);
    // Small msgs pad to APPLE_WIRE_RECORD_MIN_BODY (32), not 16.
    RFB_CHECK_EQ_UINT(wire_len, 2u + APPLE_WIRE_RECORD_MIN_BODY);
    RFB_CHECK_EQ_UINT(wire_len, apple_wire_cipher_record_len(
                                    wire, wire_len, APPLE_RECORD_MAX_BODY));

    const uint16_t ct_len =
        (uint16_t)(((uint16_t)wire[0] << 8) | (uint16_t)wire[1]);
    RFB_CHECK_EQ_UINT(ct_len, APPLE_WIRE_RECORD_MIN_BODY);
    uint8_t got[64];
    size_t got_len = 0u;
    RFB_CHECK_EQ_INT(
        apple_wire_record_open(&dec_rl, wire + 2, ct_len, got, sizeof got,
                               &got_len),
        RFB_OK);
    RFB_CHECK_EQ_UINT(got_len, sizeof key_msg);
    RFB_CHECK_MEM_EQ(got, key_msg, sizeof key_msg);

    // msg14 seals to L=32, the minimum server tick record size.
    uint8_t w14[64];
    size_t n14 = 0u;
    RFB_CHECK_EQ_INT(
        apple_wire_record_seal(&enc_rl, apple_wire_msg14, APPLE_WIRE_MSG14_LEN,
                               w14, sizeof w14, &n14),
        RFB_OK);
    RFB_CHECK_EQ_UINT(n14, 2u + 32u);
    RFB_CHECK_EQ_UINT((unsigned)w14[0], 0u);
    RFB_CHECK_EQ_UINT((unsigned)w14[1], 32u);

    // Classify both eight-byte 0x14 test vectors as msg14.
    RFB_CHECK(apple_wire_msg_is_msg14(apple_wire_msg14, 8u));
    static const uint8_t msg14_live[8] = {
        0x14u, 0x00u, 0x00u, 0x04u, 0x00u, 0x01u, 0x00u, 0x04u
    };
    RFB_CHECK(apple_wire_msg_is_msg14(msg14_live, 8u));
    RFB_CHECK(!apple_wire_msg_is_msg14(key_msg, 8u));
    {
        uint32_t c14 = 0u;
        RFB_CHECK_EQ_INT(apple_wire_classify_msg(msg14_live, 8u, &c14),
                         APPLE_WIRE_KIND_MSG14);
        RFB_CHECK_EQ_UINT(c14, 0x14u);
    }

    // typed classify
    uint8_t typed[20];
    memset(typed, 0, sizeof typed);
    typed[3] = 0x01u;
    typed[14] = 0x04u;
    typed[15] = 0x51u;
    uint32_t t = 0u;
    RFB_CHECK(apple_wire_msg_is_typed(typed, sizeof typed, &t));
    RFB_CHECK_EQ_UINT(t, 0x0451u);

    apple_record_destroy(&enc_rl);
    apple_record_destroy(&dec_rl);
}

// Positive: SHA-1 checksum over be32(seq)||body matches the seal layout.
// Negative: modifying ciphertext makes checksum validation fail closed.
RFB_TEST(apple_wire, seal_open__sha1_mac_seq_and_tamper)
{
    uint8_t wrapped_key[16], wrapped_iv[16];
    wire_ecb_enc_block(k_wire_wrap, k_wire_key, wrapped_key);
    wire_ecb_enc_block(k_wire_wrap, k_wire_iv, wrapped_iv);

    apple_record_layer enc_rl, dec_rl;
    apple_record_init(&enc_rl, k_wire_wrap);
    apple_record_init(&dec_rl, k_wire_wrap);
    RFB_CHECK(apple_record_enable_wrapped(&enc_rl, APPLE_DIR_ENCRYPT,
                                          wrapped_key, wrapped_iv));
    RFB_CHECK(apple_record_enable_wrapped(&dec_rl, APPLE_DIR_DECRYPT,
                                          wrapped_key, wrapped_iv));

    // Decrypt a sealed body and check checksum = SHA1(be32(0)||body).
    uint8_t wire[64];
    size_t wire_len = 0u;
    RFB_CHECK_EQ_INT(
        apple_wire_record_seal(&enc_rl, apple_wire_msg14, APPLE_WIRE_MSG14_LEN,
                               wire, sizeof wire, &wire_len),
        RFB_OK);
    RFB_CHECK_EQ_UINT(wire_len, 2u + 32u);

    // Raw decrypt bypasses open so the plaintext checksum can be inspected.
    apple_record_layer peek;
    apple_record_init(&peek, k_wire_wrap);
    RFB_CHECK(apple_record_enable_wrapped(&peek, APPLE_DIR_DECRYPT,
                                          wrapped_key, wrapped_iv));
    uint8_t pt[64];
    size_t pt_len = 0u;
    RFB_CHECK_EQ_INT(
        apple_record_decrypt(&peek, wire + 2, 32u, pt, sizeof pt, &pt_len),
        RFB_OK);
    RFB_CHECK_EQ_UINT(pt_len, 32u);
    uint8_t expect[20];
    uint8_t sha_in[4 + 12];
    sha_in[0] = sha_in[1] = sha_in[2] = 0u;
    sha_in[3] = 0u; // seq 0
    memcpy(sha_in + 4, pt, 12);
    RFB_CHECK(rfb_crypto_sha1(sha_in, 16u, expect));
    RFB_CHECK_MEM_EQ(pt + 12, expect, 20u);
    apple_record_destroy(&peek);

    // Build a ciphertext corruption case for open.
    uint8_t bad[64];
    memcpy(bad, wire, wire_len);
    // Need re-decrypt path: open after encrypt seq already advanced.
    // Fresh pair for clean seq.
    apple_record_destroy(&enc_rl);
    apple_record_destroy(&dec_rl);
    apple_record_init(&enc_rl, k_wire_wrap);
    apple_record_init(&dec_rl, k_wire_wrap);
    RFB_CHECK(apple_record_enable_wrapped(&enc_rl, APPLE_DIR_ENCRYPT,
                                          wrapped_key, wrapped_iv));
    RFB_CHECK(apple_record_enable_wrapped(&dec_rl, APPLE_DIR_DECRYPT,
                                          wrapped_key, wrapped_iv));
    RFB_CHECK_EQ_INT(
        apple_wire_record_seal(&enc_rl, apple_wire_msg14, APPLE_WIRE_MSG14_LEN,
                               wire, sizeof wire, &wire_len),
        RFB_OK);

    bad[2 + 31] ^= 0x01u;
    memcpy(bad, wire, wire_len);
    bad[2 + 16] ^= 0x5au; // flip mid-body
    uint8_t got[64];
    size_t gl = 0u;
    RFB_CHECK(apple_wire_record_open(&dec_rl, bad + 2, 32u, got, sizeof got,
                                     &gl) != RFB_OK);

    apple_record_destroy(&enc_rl);
    apple_record_destroy(&dec_rl);
}

RFB_TEST(apple_wire, seal_open__chained_two_records)
{
    uint8_t wrapped_key[16], wrapped_iv[16];
    wire_ecb_enc_block(k_wire_wrap, k_wire_key, wrapped_key);
    wire_ecb_enc_block(k_wire_wrap, k_wire_iv, wrapped_iv);

    apple_record_layer enc_rl, dec_rl;
    apple_record_init(&enc_rl, k_wire_wrap);
    apple_record_init(&dec_rl, k_wire_wrap);
    RFB_CHECK(apple_record_enable_wrapped(&enc_rl, APPLE_DIR_ENCRYPT,
                                          wrapped_key, wrapped_iv));
    RFB_CHECK(apple_record_enable_wrapped(&dec_rl, APPLE_DIR_DECRYPT,
                                          wrapped_key, wrapped_iv));

    static const uint8_t m0[6] = { 0x05u, 0x00u, 0x00u, 0x10u, 0x00u, 0x20u };
    static const uint8_t m1[8] = {
        0x14u, 0x00u, 0x00u, 0x04u, 0x00u, 0x01u, 0x00u, 0x0cu
    };

    uint8_t w0[64], w1[64];
    size_t n0 = 0u, n1 = 0u;
    RFB_CHECK_EQ_INT(
        apple_wire_record_seal(&enc_rl, m0, sizeof m0, w0, sizeof w0, &n0),
        RFB_OK);
    RFB_CHECK_EQ_INT(
        apple_wire_record_seal(&enc_rl, m1, sizeof m1, w1, sizeof w1, &n1),
        RFB_OK);

    uint8_t g0[64], g1[64];
    size_t gl0 = 0u, gl1 = 0u;
    uint16_t c0 = (uint16_t)(((uint16_t)w0[0] << 8) | w0[1]);
    uint16_t c1 = (uint16_t)(((uint16_t)w1[0] << 8) | w1[1]);
    RFB_CHECK_EQ_INT(
        apple_wire_record_open(&dec_rl, w0 + 2, c0, g0, sizeof g0, &gl0),
        RFB_OK);
    RFB_CHECK_EQ_INT(
        apple_wire_record_open(&dec_rl, w1 + 2, c1, g1, sizeof g1, &gl1),
        RFB_OK);
    RFB_CHECK_EQ_UINT(gl0, sizeof m0);
    RFB_CHECK_MEM_EQ(g0, m0, sizeof m0);
    RFB_CHECK_EQ_UINT(gl1, sizeof m1);
    RFB_CHECK_MEM_EQ(g1, m1, sizeof m1);
    RFB_CHECK(apple_wire_msg_is_msg14(g1, gl1));

    apple_record_destroy(&enc_rl);
    apple_record_destroy(&dec_rl);
}

RFB_TEST(apple_wire, setup_and_taxonomy_helpers_cover_boundary_contracts)
{
    static const char *const names[] = {
        "empty", "msg14", "msg12", "cfg21", "set_encodings", "fbur",
        "fbu", "key", "pointer", "cut_text", "typed", "classic",
        "unknown",
    };
    for (size_t i = 0u; i < sizeof names / sizeof names[0]; i++) {
        RFB_CHECK(strcmp(apple_wire_msg_kind_name((apple_wire_msg_kind)i),
                         names[i]) == 0);
    }
    RFB_CHECK(strcmp(apple_wire_msg_kind_name((apple_wire_msg_kind)99),
                     "unknown") == 0);

    uint8_t setup[APPLE_WIRE_SETUP_LEN];
    wire_make_setup52(setup, APPLE_WIRE_TYPE_ENABLE,
                      APPLE_WIRE_SETUP_METHOD_AES_CBC);
    RFB_CHECK_EQ_UINT(apple_wire_setup_consume_len(setup, sizeof setup, NULL),
                      sizeof setup);
    RFB_CHECK_EQ_UINT(apple_wire_setup_consume_len(setup, 7u, NULL), 0u);
    RFB_CHECK_EQ_UINT(apple_wire_setup_consume_len(
                          apple_wire_msg14, APPLE_WIRE_MSG14_LEN, NULL),
                      0u);

    uint8_t typed[16] = {0};
    typed[3] = 1u;
    typed[15] = 9u;
    uint32_t type = 77u;
    RFB_CHECK(!apple_wire_msg_is_typed(NULL, sizeof typed, &type));
    RFB_CHECK_EQ_UINT(type, 0u);
    RFB_CHECK(!apple_wire_msg_is_typed(typed, 15u, NULL));
    RFB_CHECK(apple_wire_msg_is_typed(typed, sizeof typed, NULL));
    typed[3] = 2u;
    RFB_CHECK(!apple_wire_msg_is_typed(typed, sizeof typed, &type));
    typed[3] = 1u;
    typed[7] = 1u;
    RFB_CHECK(!apple_wire_msg_is_typed(typed, sizeof typed, &type));
    typed[7] = 0u;
    typed[11] = 1u;
    RFB_CHECK(!apple_wire_msg_is_typed(typed, sizeof typed, &type));

    RFB_CHECK(!apple_wire_msg_is_msg14(NULL, APPLE_WIRE_MSG14_LEN));
    RFB_CHECK(!apple_wire_msg_is_msg14(apple_wire_msg14, 7u));
    static const uint8_t not_msg14[APPLE_WIRE_MSG14_LEN] = {0x13u};
    RFB_CHECK(!apple_wire_msg_is_msg14(not_msg14, sizeof not_msg14));
}

RFB_TEST(apple_wire, classify_msg_covers_every_plaintext_kind)
{
    static const uint8_t cfg21[] = {0x21u};
    static const uint8_t msg12[] = {0x12u};
    static const uint8_t short_set_encodings[] = {0x02u};
    static const uint8_t set_encodings[] = {0x02u, 0u, 0u, 0u};
    static const uint8_t classic[] = {0x01u};
    static const uint8_t fbu[] = {0x00u};
    static const uint8_t fbur[] = {0x03u};
    static const uint8_t key[] = {0x04u};
    static const uint8_t pointer[] = {0x05u};
    static const uint8_t cut_text[] = {0x06u};
    static const uint8_t unknown[] = {0x07u};
    uint32_t code = 99u;

    RFB_CHECK_EQ_INT(apple_wire_classify_msg(cfg21, 0u, &code),
                     APPLE_WIRE_KIND_EMPTY);
    RFB_CHECK_EQ_UINT(code, 0u);
    RFB_CHECK_EQ_INT(apple_wire_classify_msg(cfg21, sizeof cfg21, NULL),
                     APPLE_WIRE_KIND_CFG21);
    RFB_CHECK_EQ_INT(apple_wire_classify_msg(cfg21, sizeof cfg21, &code),
                     APPLE_WIRE_KIND_CFG21);
    RFB_CHECK_EQ_UINT(code, 0x21u);
    RFB_CHECK_EQ_INT(apple_wire_classify_msg(msg12, sizeof msg12, &code),
                     APPLE_WIRE_KIND_MSG12);
    RFB_CHECK_EQ_INT(apple_wire_classify_msg(fbu, sizeof fbu, &code),
                     APPLE_WIRE_KIND_FBU);
    RFB_CHECK_EQ_INT(apple_wire_classify_msg(short_set_encodings,
                                             sizeof short_set_encodings,
                                             &code),
                     APPLE_WIRE_KIND_CLASSIC);
    RFB_CHECK_EQ_INT(apple_wire_classify_msg(set_encodings,
                                             sizeof set_encodings, &code),
                     APPLE_WIRE_KIND_SET_ENCODINGS);
    RFB_CHECK_EQ_INT(apple_wire_classify_msg(fbur, sizeof fbur, &code),
                     APPLE_WIRE_KIND_FBUR);
    RFB_CHECK_EQ_INT(apple_wire_classify_msg(key, sizeof key, &code),
                     APPLE_WIRE_KIND_KEY);
    RFB_CHECK_EQ_INT(apple_wire_classify_msg(pointer, sizeof pointer, &code),
                     APPLE_WIRE_KIND_POINTER);
    RFB_CHECK_EQ_INT(apple_wire_classify_msg(cut_text, sizeof cut_text, &code),
                     APPLE_WIRE_KIND_CUT_TEXT);
    RFB_CHECK_EQ_INT(apple_wire_classify_msg(classic, sizeof classic, &code),
                     APPLE_WIRE_KIND_CLASSIC);
    RFB_CHECK_EQ_INT(apple_wire_classify_msg(unknown, sizeof unknown, &code),
                     APPLE_WIRE_KIND_UNKNOWN);
}

RFB_TEST(apple_wire, cipher_record_len_rejects_bad_and_incomplete_prefixes)
{
    static const uint8_t short_input[] = {0u};
    static const uint8_t too_small[] = {0u, 16u};
    static const uint8_t unaligned[] = {0u, 33u};
    static const uint8_t complete[34] = {0u, 32u};

    RFB_CHECK_EQ_UINT(apple_wire_cipher_record_len(NULL, 34u, 32u), 0u);
    RFB_CHECK_EQ_UINT(apple_wire_cipher_record_len(
                          short_input, sizeof short_input, 32u),
                      0u);
    RFB_CHECK(apple_wire_cipher_record_len(too_small, sizeof too_small, 32u) ==
              (size_t)-1);
    RFB_CHECK(apple_wire_cipher_record_len(unaligned, sizeof unaligned, 64u) ==
              (size_t)-1);
    RFB_CHECK(apple_wire_cipher_record_len(complete, sizeof complete, 31u) ==
              (size_t)-1);
    RFB_CHECK_EQ_UINT(apple_wire_cipher_record_len(complete, 33u, 32u), 0u);
    RFB_CHECK_EQ_UINT(apple_wire_cipher_record_len(
                          complete, sizeof complete, 32u),
                      sizeof complete);
}

RFB_TEST(apple_wire, seal_rejects_arguments_limits_and_allocator_failures)
{
    uint8_t byte = 0x04u;
    uint8_t out[64] = {0};
    size_t out_len = 99u;
    apple_record_layer layer;
    memset(&layer, 0, sizeof layer);

    RFB_CHECK_EQ_INT(apple_wire_record_seal(NULL, &byte, 1u, out, sizeof out,
                                            &out_len),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(apple_wire_record_seal(&layer, NULL, 1u, out, sizeof out,
                                            &out_len),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(apple_wire_record_seal(&layer, &byte, 1u, NULL, sizeof out,
                                            &out_len),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(apple_wire_record_seal(&layer, &byte, 1u, out, sizeof out,
                                            NULL),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(apple_wire_record_seal(&layer, &byte, 0u, out, sizeof out,
                                            &out_len),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(apple_wire_record_seal(&layer, &byte, 0x10000u, out,
                                            sizeof out, &out_len),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(apple_wire_record_seal(&layer, &byte, 1u, out, sizeof out,
                                            &out_len),
                     RFB_ERR_STATE);

    apple_record_init(&layer, k_wire_wrap);
    RFB_CHECK(apple_record_set_direction(&layer, APPLE_DIR_ENCRYPT, k_wire_key,
                                         k_wire_iv));
    RFB_CHECK_EQ_INT(apple_wire_record_seal(&layer, &byte, 1u, out, 0u,
                                            &out_len),
                     RFB_ERR_LIMIT);

    rfb_allocator invalid = *rfb_default_allocator();
    invalid.alloc = NULL;
    RFB_CHECK_EQ_INT(apple_wire_record_seal_with_allocator(
                         &layer, &byte, 1u, out, sizeof out, &out_len, &invalid),
                     RFB_ERR_INTERNAL);
    invalid = *rfb_default_allocator();
    invalid.free = NULL;
    RFB_CHECK_EQ_INT(apple_wire_record_seal_with_allocator(
                         &layer, &byte, 1u, out, sizeof out, &out_len, &invalid),
                     RFB_ERR_INTERNAL);

    wire_alloc_spy spy = {.calls = 0u, .fail_call = 1u, .frees = 0u};
    rfb_allocator fault = {
        .alloc = wire_spy_alloc,
        .free = wire_spy_free,
        .user = &spy,
    };
    RFB_CHECK_EQ_INT(apple_wire_record_seal_with_allocator(
                         &layer, &byte, 1u, out, sizeof out, &out_len, &fault),
                     RFB_ERR_NOMEM);
    RFB_CHECK_EQ_UINT(spy.calls, 2u);
    RFB_CHECK_EQ_UINT(spy.frees, 1u);
    RFB_CHECK_EQ_UINT(layer.encrypt.sequence, 0u);

    uint8_t *large_msg = (uint8_t *)malloc(65520u);
    uint8_t *large_out = (uint8_t *)malloc(65554u);
    RFB_CHECK(large_msg != NULL && large_out != NULL);
    if (large_msg != NULL && large_out != NULL) {
        RFB_CHECK_EQ_INT(apple_wire_record_seal(
                             &layer, large_msg, 65520u, large_out, 65554u,
                             &out_len),
                         RFB_ERR_LIMIT);
    }
    free(large_out);
    free(large_msg);
    apple_record_destroy(&layer);

    memset(&layer, 0, sizeof layer);
    layer.encrypt.active = true;
    RFB_CHECK_EQ_INT(apple_wire_record_seal(&layer, &byte, 1u, out, sizeof out,
                                            &out_len),
                     RFB_ERR_STATE);
}

RFB_TEST(apple_wire, seal_exact_body_and_open_empty_or_bad_length)
{
    static const uint8_t exact_body_message[10] = {
        0x04u, 1u, 2u, 3u, 4u, 5u, 6u, 7u, 8u, 9u,
    };
    apple_record_layer enc;
    apple_record_layer dec;
    wire_enable_direct_pair(&enc, &dec);
    uint8_t wire[34];
    size_t wire_len = 0u;
    RFB_CHECK_EQ_INT(apple_wire_record_seal(
                         &enc, exact_body_message, sizeof exact_body_message,
                         wire, sizeof wire, &wire_len),
                     RFB_OK);
    RFB_CHECK_EQ_UINT(wire_len, sizeof wire);
    apple_record_destroy(&enc);
    apple_record_destroy(&dec);

    wire_enable_direct_pair(&enc, &dec);
    uint8_t ciphertext[32];
    wire_encrypt_raw_body(&enc, 13u, ciphertext);
    uint8_t opened[32];
    size_t opened_len = 77u;
    RFB_CHECK_EQ_INT(apple_wire_record_open(&dec, ciphertext,
                                            sizeof ciphertext, opened,
                                            sizeof opened, &opened_len),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_UINT(opened_len, 0u);
    apple_record_destroy(&enc);
    apple_record_destroy(&dec);

    wire_enable_direct_pair(&enc, &dec);
    wire_encrypt_raw_body(&enc, 0u, ciphertext);
    RFB_CHECK_EQ_INT(apple_wire_record_open(&dec, ciphertext,
                                            sizeof ciphertext, opened,
                                            sizeof opened, &opened_len),
                     RFB_OK);
    RFB_CHECK_EQ_UINT(opened_len, 0u);
    apple_record_destroy(&enc);
    apple_record_destroy(&dec);
}

RFB_TEST(apple_wire, open_rejects_arguments_limits_and_allocator_failures)
{
    uint8_t ciphertext[32] = {0};
    uint8_t opened[32] = {0};
    size_t opened_len = 99u;
    apple_record_layer layer;
    memset(&layer, 0, sizeof layer);

    RFB_CHECK_EQ_INT(apple_wire_record_open(NULL, ciphertext,
                                            sizeof ciphertext, opened,
                                            sizeof opened, &opened_len),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(apple_wire_record_open(&layer, NULL, sizeof ciphertext,
                                            opened, sizeof opened,
                                            &opened_len),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(apple_wire_record_open(&layer, ciphertext,
                                            sizeof ciphertext, NULL,
                                            sizeof opened, &opened_len),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(apple_wire_record_open(&layer, ciphertext,
                                            sizeof ciphertext, opened,
                                            sizeof opened, NULL),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(apple_wire_record_open(&layer, ciphertext, 0u, opened,
                                            sizeof opened, &opened_len),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(apple_wire_record_open(&layer, ciphertext, 31u, opened,
                                            sizeof opened, &opened_len),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(apple_wire_record_open(&layer, ciphertext, 16u, opened,
                                            sizeof opened, &opened_len),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(apple_wire_record_open(
                         &layer, ciphertext,
                         (size_t)APPLE_RECORD_MAX_BODY + APPLE_BLOCK_SIZE,
                         opened, sizeof opened, &opened_len),
                     RFB_ERR_LIMIT);
    RFB_CHECK_EQ_INT(apple_wire_record_open(&layer, ciphertext,
                                            sizeof ciphertext, opened, 31u,
                                            &opened_len),
                     RFB_ERR_LIMIT);
    RFB_CHECK_EQ_INT(apple_wire_record_open(&layer, ciphertext,
                                            sizeof ciphertext, opened,
                                            sizeof opened, &opened_len),
                     RFB_ERR_STATE);

    apple_record_init(&layer, k_wire_wrap);
    RFB_CHECK(apple_record_set_direction(&layer, APPLE_DIR_DECRYPT, k_wire_key,
                                         k_wire_iv));
    rfb_allocator invalid = *rfb_default_allocator();
    invalid.alloc = NULL;
    RFB_CHECK_EQ_INT(apple_wire_record_open_with_allocator(
                         &layer, ciphertext, sizeof ciphertext, opened,
                         sizeof opened, &opened_len, &invalid),
                     RFB_ERR_INTERNAL);
    invalid = *rfb_default_allocator();
    invalid.free = NULL;
    RFB_CHECK_EQ_INT(apple_wire_record_open_with_allocator(
                         &layer, ciphertext, sizeof ciphertext, opened,
                         sizeof opened, &opened_len, &invalid),
                     RFB_ERR_INTERNAL);

    uint8_t *large = (uint8_t *)malloc(65568u);
    RFB_CHECK(large != NULL);
    if (large != NULL) {
        RFB_CHECK_EQ_INT(apple_wire_record_open(
                             &layer, large, 65568u, large, 65568u,
                             &opened_len),
                         RFB_ERR_LIMIT);
    }
    free(large);
    apple_record_destroy(&layer);

    memset(&layer, 0, sizeof layer);
    layer.decrypt.active = true;
    RFB_CHECK_EQ_INT(apple_wire_record_open(&layer, ciphertext,
                                            sizeof ciphertext, opened,
                                            sizeof opened, &opened_len),
                     RFB_ERR_STATE);
}
