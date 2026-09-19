// SPDX-License-Identifier: Apache-2.0
//
// Record-layer staging and MAC comparison contracts. Staging is heap-allocated
// and fails closed on allocation errors. The MAC comparison is constant-time.
// These tests cover a large round trip and corruption in the MAC region.

#include "rfb_test.h"
#include "farsee/apple_wire_record.h"
#include "farsee/apple_record.h"
#include "farsee/apple_crypto.h"

#include <stdlib.h>
#include <string.h>

static const uint8_t record_stack_wrap[16] = {
    0xAAu, 0xBBu, 0xCCu, 0xDDu, 0xEEu, 0xFFu, 0x00u, 0x11u,
    0x22u, 0x33u, 0x44u, 0x55u, 0x66u, 0x77u, 0x88u, 0x99u
};
static const uint8_t record_stack_key[16] = {
    0x00u, 0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u, 0x07u,
    0x08u, 0x09u, 0x0au, 0x0bu, 0x0cu, 0x0du, 0x0eu, 0x0fu
};
static const uint8_t record_stack_iv[16] = {
    0x10u, 0x11u, 0x12u, 0x13u, 0x14u, 0x15u, 0x16u, 0x17u,
    0x18u, 0x19u, 0x1au, 0x1bu, 0x1cu, 0x1du, 0x1eu, 0x1fu
};

static void record_stack_enable_pair(apple_record_layer *enc,
                                apple_record_layer *dec)
{
    uint8_t wrapped_key[16], wrapped_iv[16];
    rfb_crypto_cbc_ctx *ec = rfb_crypto_cbc_new();
    static const uint8_t ziv[16] = { 0 };
    size_t outl = 0;
    RFB_CHECK(ec != NULL);
    RFB_CHECK(rfb_crypto_cbc_init(ec, true, record_stack_wrap, ziv));
    RFB_CHECK(rfb_crypto_cbc_update(ec, record_stack_key, 16, wrapped_key, 16,
                                    &outl));
    RFB_CHECK(rfb_crypto_cbc_update(ec, record_stack_iv, 16, wrapped_iv, 16,
                                    &outl));
    rfb_crypto_cbc_free(ec);

    apple_record_init(enc, record_stack_wrap);
    apple_record_init(dec, record_stack_wrap);
    RFB_CHECK(apple_record_enable_wrapped(enc, APPLE_DIR_ENCRYPT,
                                          wrapped_key, wrapped_iv));
    RFB_CHECK(apple_record_enable_wrapped(dec, APPLE_DIR_DECRYPT,
                                          wrapped_key, wrapped_iv));
}

// Large message (60,000 B > 32 KiB, padded to 60,032 B): exercises the
// heap staging in both seal and open and round-trips byte-exact.
RFB_TEST(apple_wire_record_stack, seal_open__large_message__roundtrips)
{
    apple_record_layer enc, dec;
    record_stack_enable_pair(&enc, &dec);

    const size_t msg_len = 60000u;
    uint8_t *msg = (uint8_t *)malloc(msg_len);
    RFB_CHECK(msg != NULL);
    for (size_t i = 0; i < msg_len; i++) {
        msg[i] = (uint8_t)(i * 7u + 3u);
    }

    // padded = ceil16(60000 + 2 + 20) = 60032; wire adds the u16 length.
    uint8_t *wire = (uint8_t *)malloc(2u + 60032u);
    RFB_CHECK(wire != NULL);
    size_t wire_len = 0u;
    RFB_CHECK_EQ_INT(
        apple_wire_record_seal(&enc, msg, msg_len, wire, 2u + 60032u,
                               &wire_len),
        RFB_OK);
    RFB_CHECK_EQ_UINT(wire_len, 2u + 60032u);

    uint8_t *got = (uint8_t *)malloc(60032u);
    RFB_CHECK(got != NULL);
    size_t got_len = 0u;
    RFB_CHECK_EQ_INT(
        apple_wire_record_open(&dec, wire + 2, wire_len - 2u, got, 60032u,
                               &got_len),
        RFB_OK);
    RFB_CHECK_EQ_UINT(got_len, msg_len);
    RFB_CHECK_MEM_EQ(got, msg, msg_len);

    free(got);
    free(wire);
    free(msg);
    apple_record_destroy(&enc);
    apple_record_destroy(&dec);
}

// Corrupt exactly one byte in the LAST ciphertext block (decrypts into the
// trailing 20-byte MAC region): open must fail closed. Pins the
// constant-time MAC comparison (rfb_crypto_ct_eq) against regressions.
RFB_TEST(apple_wire_record_stack, open__mac_region_corrupted__fails_closed)
{
    apple_record_layer enc, dec;
    record_stack_enable_pair(&enc, &dec);

    uint8_t wire[2 + 32];
    size_t wire_len = 0u;
    RFB_CHECK_EQ_INT(
        apple_wire_record_seal(&enc, apple_wire_msg14, APPLE_WIRE_MSG14_LEN,
                               wire, sizeof wire, &wire_len),
        RFB_OK);
    RFB_CHECK_EQ_UINT(wire_len, 2u + 32u);

    apple_record_layer enc_bad, dec_bad;
    record_stack_enable_pair(&enc_bad, &dec_bad);

    uint8_t bad[2 + 32];
    memcpy(bad, wire, wire_len);
    bad[2u + 31u] ^= 0x40u;  // last ciphertext block → MAC bytes

    uint8_t got[32];
    size_t got_len = 0u;
    RFB_CHECK(apple_wire_record_open(&dec_bad, bad + 2, 32u, got, sizeof got,
                                     &got_len) != RFB_OK);

    apple_record_destroy(&dec_bad);
    apple_record_destroy(&enc_bad);
    apple_record_destroy(&dec);
    apple_record_destroy(&enc);
}
