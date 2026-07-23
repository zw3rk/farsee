// SPDX-License-Identifier: Apache-2.0
//
// farsee — Apple session input messages (goals.md G21).
//
// Serializes STANDARD RFC 6143 input messages (KeyEvent/PointerEvent/
// ClientCutText) and wraps them inside G17 encrypted records. See the
// header for the field-classification rationale: apple-wire-spec.md has no
// captured Apple-specific input messages, so the G21 contract mandates
// verified standard messages inside G17 records.
//
// The plaintext byte layout is byte-identical to the classic rfb/input.c
// encoders (RFC 6143 §7.5.4-6). The only difference is the record wrap.

#include "farsee/apple_input.h"
#include "farsee/bytes.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Big-endian writers (local, to keep this module self-contained and avoid a
// hard dependency on rfb/input.c's public encoders — they produce the same
// bytes, verified by the classic_and_apple_produce_same_plaintext_message
// test).
static bool put_u8(rfb_writer *w, uint8_t v)
{
    return rfb_write_u8(w, v);
}

static bool put_u16be(rfb_writer *w, uint16_t v)
{
    return rfb_write_u16(w, v);
}

static bool put_u32be(rfb_writer *w, uint32_t v)
{
    return rfb_write_u32(w, v);
}

rfb_error apple_input_serialize_key(const rfb_norm_key *k,
                                    uint8_t *out, size_t out_cap,
                                    size_t *out_len)
{
    if (out_len != NULL) *out_len = 0u;
    if (k == NULL || out == NULL || out_len == NULL) {
        return RFB_ERR_INTERNAL;
    }
    rfb_writer w = rfb_writer_make(out, out_cap);
    // u8 type=4, u8 down, u16 pad, u32 keysym (big-endian).
    if (!put_u8(&w, 4u)) return RFB_ERR_LIMIT;
    if (!put_u8(&w, k->down ? 1u : 0u)) return RFB_ERR_LIMIT;
    if (!put_u8(&w, 0u)) return RFB_ERR_LIMIT;
    if (!put_u8(&w, 0u)) return RFB_ERR_LIMIT;
    if (!put_u32be(&w, k->keysym)) return RFB_ERR_LIMIT;
    *out_len = w.length;
    return RFB_OK;
}

rfb_error apple_input_serialize_pointer(uint8_t button_mask,
                                        uint16_t x, uint16_t y,
                                        uint8_t *out, size_t out_cap,
                                        size_t *out_len)
{
    if (out_len != NULL) *out_len = 0u;
    if (out == NULL || out_len == NULL) {
        return RFB_ERR_INTERNAL;
    }
    rfb_writer w = rfb_writer_make(out, out_cap);
    // u8 type=5, u8 button_mask, u16 x, u16 y (big-endian).
    if (!put_u8(&w, 5u)) return RFB_ERR_LIMIT;
    if (!put_u8(&w, button_mask)) return RFB_ERR_LIMIT;
    if (!put_u16be(&w, x)) return RFB_ERR_LIMIT;
    if (!put_u16be(&w, y)) return RFB_ERR_LIMIT;
    *out_len = w.length;
    return RFB_OK;
}

rfb_error apple_input_serialize_clipboard(const uint8_t *text, uint32_t length,
                                          uint8_t *out, size_t out_cap,
                                          size_t *out_len)
{
    if (out_len != NULL) *out_len = 0u;
    if (out == NULL || out_len == NULL) {
        return RFB_ERR_INTERNAL;
    }
    if (length > 0u && text == NULL) {
        return RFB_ERR_INTERNAL;
    }
    rfb_writer w = rfb_writer_make(out, out_cap);
    // u8 type=6, u8 pad[3], u32 length, byte[length] text.
    if (!put_u8(&w, 6u)) return RFB_ERR_LIMIT;
    if (!put_u8(&w, 0u)) return RFB_ERR_LIMIT;
    if (!put_u8(&w, 0u)) return RFB_ERR_LIMIT;
    if (!put_u8(&w, 0u)) return RFB_ERR_LIMIT;
    if (!put_u32be(&w, length)) return RFB_ERR_LIMIT;
    if (length > 0u) {
        if (!rfb_write_bytes(&w, text, (size_t)length)) return RFB_ERR_LIMIT;
    }
    *out_len = w.length;
    return RFB_OK;
}

rfb_error apple_input_encrypt(apple_record_layer *rl,
                              const uint8_t *plaintext, size_t pt_len,
                              uint8_t *ciphertext, size_t ct_cap,
                              size_t *ct_len)
{
    if (ct_len != NULL) *ct_len = 0u;
    if (rl == NULL || plaintext == NULL || ciphertext == NULL || ct_len == NULL) {
        return RFB_ERR_INTERNAL;
    }
    if (pt_len == 0u) {
        return RFB_ERR_INTERNAL;
    }
    // The G17 record layer requires 16-byte-aligned plaintext. Compute the
    // padded length and zero-pad a local staging buffer (zero-padding is
    // safe: the standard RFB message is self-delimited by its type/length
    // fields, so trailing padding is ignored on decrypt).
    size_t padded = ((pt_len + 15u) / 16u) * 16u;
    uint8_t pad[256];  // bounded staging; input messages are small (≤ ~8+text)
    if (padded > sizeof pad) {
        return RFB_ERR_LIMIT;
    }
    for (size_t i = 0u; i < padded; i++) {
        pad[i] = (i < pt_len) ? plaintext[i] : 0u;
    }
    return apple_record_encrypt(rl, pad, padded, ciphertext, ct_cap, ct_len);
}

rfb_error apple_input_send_key(apple_record_layer *rl,
                               const rfb_norm_key *k,
                               uint8_t *ciphertext, size_t ct_cap,
                               size_t *ct_len)
{
    if (ct_len != NULL) *ct_len = 0u;
    if (rl == NULL || k == NULL || ciphertext == NULL || ct_len == NULL) {
        return RFB_ERR_INTERNAL;
    }
    uint8_t pt[8];
    size_t pt_len = 0u;
    rfb_error e = apple_input_serialize_key(k, pt, sizeof pt, &pt_len);
    if (e != RFB_OK) {
        return e;
    }
    return apple_input_encrypt(rl, pt, pt_len, ciphertext, ct_cap, ct_len);
}
