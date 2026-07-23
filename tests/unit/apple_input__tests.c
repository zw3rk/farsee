// SPDX-License-Identifier: Apache-2.0
//
// G21 — Apple session input message tests (goals.md G21). TDD RED first.
//
// Verifies that standard RFB input messages (KeyEvent/PointerEvent/
// ClientCutText) are serialized correctly and wrapped inside G17 records,
// since apple-wire-spec.md has no captured Apple-specific input messages.

#include "rfb_test.h"
#include "farsee/apple_input.h"
#include "farsee/apple_record.h"
#include "farsee/normalized_input.h"
#include "farsee/bytes.h"
#include "farsee/input.h"

#include <string.h>

// Synthetic wrap key for the deterministic record layer (16 bytes, AES-128).
static const uint8_t k_wrap[16] = {
    0x00u, 0x11u, 0x22u, 0x33u, 0x44u, 0x55u, 0x66u, 0x77u,
    0x88u, 0x99u, 0xAAu, 0xBBu, 0xCCu, 0xDDu, 0xEEu, 0xFFu,
};

// Set up a record layer with a known content key/IV for both directions so
// we can round-trip encrypt→decrypt. The content key is derived from the
// wrap key by the caller in production; here we set a fixed one.
static void setup_rl(apple_record_layer *rl, const uint8_t content_key[16],
                     const uint8_t iv[16])
{
    static const uint8_t zero_key[16] = { 0u };
    static const uint8_t zero_iv[16] = { 0u };
    const uint8_t *ck = (content_key != NULL) ? content_key : zero_key;
    const uint8_t *v  = (iv != NULL) ? iv : zero_iv;
    apple_record_init(rl, k_wrap);
    (void)apple_record_set_direction(rl, APPLE_DIR_ENCRYPT, ck, v);
    (void)apple_record_set_direction(rl, APPLE_DIR_DECRYPT, ck, v);
}

// ===========================================================================
// Serialize standard RFB input messages (plaintext)
// ===========================================================================

RFB_TEST(apple_in, serialize_key__press_a__exact_bytes) {
    rfb_norm_key k = { 0 };
    k.keysym = 0x0061u;
    k.down = true;
    uint8_t out[8] = { 0 };
    size_t n = 0;
    RFB_CHECK_EQ_INT(apple_input_serialize_key(&k, out, sizeof out, &n), RFB_OK);
    RFB_CHECK_EQ_UINT(n, 8u);
    RFB_CHECK_EQ_UINT(out[0], 4u);       // type = KeyEvent
    RFB_CHECK_EQ_UINT(out[1], 1u);       // down
    RFB_CHECK_EQ_UINT(out[6], 0x00u);    // keysym 0x00000061 BE
    RFB_CHECK_EQ_UINT(out[7], 0x61u);
}

RFB_TEST(apple_in, serialize_key__release_return__down_zero) {
    rfb_norm_key k = { 0 };
    k.keysym = XK_Return;  // 0xFF0D
    k.down = false;
    uint8_t out[8] = { 0 };
    size_t n = 0;
    RFB_CHECK_EQ_INT(apple_input_serialize_key(&k, out, sizeof out, &n), RFB_OK);
    RFB_CHECK_EQ_UINT(out[1], 0u);       // down = 0
    // keysym 0x0000FF0D big-endian: out[4..7] = 00 00 FF 0D
    RFB_CHECK_EQ_UINT(out[4], 0x00u);
    RFB_CHECK_EQ_UINT(out[5], 0x00u);
    RFB_CHECK_EQ_UINT(out[6], 0xFFu);
    RFB_CHECK_EQ_UINT(out[7], 0x0Du);
}

RFB_TEST(apple_in, serialize_key__buffer_too_small__limit) {
    rfb_norm_key k = { 0 };
    k.keysym = 0x0061u;
    uint8_t out[7] = { 0 };
    size_t n = 0;
    RFB_CHECK_EQ_INT(apple_input_serialize_key(&k, out, sizeof out, &n),
                     RFB_ERR_LIMIT);
}

RFB_TEST(apple_in, serialize_key__null__internal) {
    size_t n = 0;
    RFB_CHECK_EQ_INT(apple_input_serialize_key(NULL, NULL, 0, &n),
                     RFB_ERR_INTERNAL);
}

RFB_TEST(apple_in, serialize_pointer__left_button__exact_bytes) {
    uint8_t out[6] = { 0 };
    size_t n = 0;
    RFB_CHECK_EQ_INT(apple_input_serialize_pointer(RFB_PTR_BUTTON_LEFT,
                                                   100, 200, out, sizeof out, &n),
                     RFB_OK);
    RFB_CHECK_EQ_UINT(n, 6u);
    RFB_CHECK_EQ_UINT(out[0], 5u);                 // type = PointerEvent
    RFB_CHECK_EQ_UINT(out[1], RFB_PTR_BUTTON_LEFT);
    RFB_CHECK_EQ_UINT(out[3], 100u);               // x BE
    RFB_CHECK_EQ_UINT(out[5], 200u);               // y BE
}

RFB_TEST(apple_in, serialize_pointer__release_all__mask_zero) {
    uint8_t out[6] = { 0 };
    size_t n = 0;
    RFB_CHECK_EQ_INT(apple_input_serialize_pointer(0, 0, 0, out, sizeof out, &n),
                     RFB_OK);
    RFB_CHECK_EQ_UINT(out[1], 0u);
}

RFB_TEST(apple_in, serialize_clipboard__short_text__exact_bytes) {
    static const uint8_t text[] = "hi";
    uint8_t out[32] = { 0 };
    size_t n = 0;
    RFB_CHECK_EQ_INT(apple_input_serialize_clipboard(text, 2, out, sizeof out, &n),
                     RFB_OK);
    RFB_CHECK_EQ_UINT(n, 10u);   // 8 header + 2 text
    RFB_CHECK_EQ_UINT(out[0], 6u);   // type = ClientCutText
    RFB_CHECK_EQ_UINT(out[7], 2u);   // length BE
    RFB_CHECK_EQ_UINT(out[8], 'h');
    RFB_CHECK_EQ_UINT(out[9], 'i');
}

RFB_TEST(apple_in, serialize_clipboard__empty__header_only) {
    uint8_t out[8] = { 0 };
    size_t n = 0;
    RFB_CHECK_EQ_INT(apple_input_serialize_clipboard(NULL, 0, out, sizeof out, &n),
                     RFB_OK);
    RFB_CHECK_EQ_UINT(n, 8u);
}

// ===========================================================================
// Encrypt into a G17 record and round-trip decrypt
// ===========================================================================

RFB_TEST(apple_in, encrypt__round_trip_key_event_preserves_bytes) {
    apple_record_layer rl;
    static const uint8_t ck[16] = {
        0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u, 0x07u, 0x08u,
        0x09u, 0x0Au, 0x0Bu, 0x0Cu, 0x0Du, 0x0Eu, 0x0Fu, 0x10u,
    };
    setup_rl(&rl, ck, NULL);

    // Plaintext KeyEvent for 'a' press.
    uint8_t pt[8] = { 4u, 1u, 0u, 0u, 0u, 0u, 0u, 0x61u };
    uint8_t ct[64] = { 0 };
    size_t ct_len = 0;
    RFB_CHECK_EQ_INT(apple_input_encrypt(&rl, pt, sizeof pt, ct, sizeof ct, &ct_len),
                     RFB_OK);
    // Ciphertext must be a multiple of 16 and at least 16.
    RFB_CHECK(ct_len >= 16u);
    RFB_CHECK_EQ_UINT(ct_len % 16u, 0u);

    // Round-trip: decrypt and compare the first 8 bytes (the message).
    uint8_t back[64] = { 0 };
    size_t back_len = 0;
    RFB_CHECK_EQ_INT(apple_record_decrypt(&rl, ct, ct_len, back, sizeof back,
                                          &back_len), RFB_OK);
    RFB_CHECK(back_len >= 8u);
    RFB_CHECK_MEM_EQ(back, pt, 8u);

    apple_record_destroy(&rl);
}

RFB_TEST(apple_in, send_key__one_shot_encrypts_key_event) {
    apple_record_layer rl;
    setup_rl(&rl, NULL, NULL);
    rfb_norm_key k = { 0 };
    k.keysym = XK_Tab;
    k.down = true;
    uint8_t ct[64] = { 0 };
    size_t ct_len = 0;
    RFB_CHECK_EQ_INT(apple_input_send_key(&rl, &k, ct, sizeof ct, &ct_len),
                     RFB_OK);
    RFB_CHECK(ct_len >= 16u);
    // Decrypt and verify it is a KeyEvent for Tab.
    uint8_t back[64] = { 0 };
    size_t back_len = 0;
    RFB_CHECK_EQ_INT(apple_record_decrypt(&rl, ct, ct_len, back, sizeof back,
                                          &back_len), RFB_OK);
    RFB_CHECK_EQ_UINT(back[0], 4u);            // KeyEvent type
    RFB_CHECK_EQ_UINT(back[1], 1u);            // down
    // keysym 0x0000FF09 (Tab) big-endian: back[6]=0xFF back[7]=0x09
    RFB_CHECK_EQ_UINT(back[6], 0xFFu);
    RFB_CHECK_EQ_UINT(back[7], 0x09u);
    apple_record_destroy(&rl);
}

RFB_TEST(apple_in, encrypt__null_args__internal) {
    size_t ct_len = 0;
    RFB_CHECK_EQ_INT(apple_input_encrypt(NULL, NULL, 0, NULL, 0, &ct_len),
                     RFB_ERR_INTERNAL);
}

// ===========================================================================
// Apple session input is byte-identical to classic RFB inside the record.
// This test proves the G21 contract: standard messages inside G17 records.
// ===========================================================================

RFB_TEST(apple_in, classic_and_apple_produce_same_plaintext_message) {
    // The classic rfb_format_key_event and apple_input_serialize_key must
    // produce identical plaintext (the only difference is the record wrap).
    rfb_norm_key k = { 0 };
    k.keysym = XK_Return;
    k.down = true;
    uint8_t apple_pt[8] = { 0 };
    size_t an = 0;
    RFB_CHECK_EQ_INT(apple_input_serialize_key(&k, apple_pt, sizeof apple_pt, &an),
                     RFB_OK);

    // Classic encoder via the normalized→classic adapter.
    uint8_t classic_pt[8] = { 0 };
    rfb_writer w = rfb_writer_make(classic_pt, sizeof classic_pt);
    RFB_CHECK_EQ_INT(rfb_format_key_event(&w, true, XK_Return), RFB_OK);
    RFB_CHECK_MEM_EQ(apple_pt, classic_pt, 8u);
}
