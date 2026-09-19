// SPDX-License-Identifier: Apache-2.0
//
// farsee — client input message encoders (plan.md §G6, RFC 6143 §7.5).

#include "farsee/input.h"

rfb_error rfb_format_framebuffer_update_request(rfb_writer *w,
                                                bool incremental,
                                                uint16_t x, uint16_t y,
                                                uint16_t width, uint16_t height)
{
    if (w == NULL) {
        return RFB_ERR_INTERNAL;
    }
    // 10-byte message; reject without partial write if room is short.
    if (w->capacity - w->length < 10u) {
        return RFB_ERR_LIMIT;
    }
    if (!rfb_write_u8(w, 3)) return RFB_ERR_LIMIT;  // type
    if (!rfb_write_u8(w, incremental ? 1u : 0u)) return RFB_ERR_LIMIT;
    if (!rfb_write_u16(w, x)) return RFB_ERR_LIMIT;
    if (!rfb_write_u16(w, y)) return RFB_ERR_LIMIT;
    if (!rfb_write_u16(w, width)) return RFB_ERR_LIMIT;
    if (!rfb_write_u16(w, height)) return RFB_ERR_LIMIT;
    return RFB_OK;
}

rfb_error rfb_format_key_event(rfb_writer *w, bool down, uint32_t keysym)
{
    if (w == NULL) {
        return RFB_ERR_INTERNAL;
    }
    if (!rfb_write_u8(w, 4)) return RFB_ERR_LIMIT;            // type
    if (!rfb_write_u8(w, down ? 1u : 0u)) return RFB_ERR_LIMIT; // down-flag
    if (!rfb_write_u8(w, 0)) return RFB_ERR_LIMIT;            // pad
    if (!rfb_write_u8(w, 0)) return RFB_ERR_LIMIT;            // pad
    if (!rfb_write_u32(w, keysym)) return RFB_ERR_LIMIT;      // keysym (BE)
    return RFB_OK;
}

rfb_error rfb_format_pointer_event(rfb_writer *w,
                                   uint8_t button_mask,
                                   uint16_t x, uint16_t y)
{
    if (w == NULL) {
        return RFB_ERR_INTERNAL;
    }
    if (!rfb_write_u8(w, 5)) return RFB_ERR_LIMIT;            // type
    if (!rfb_write_u8(w, button_mask)) return RFB_ERR_LIMIT;  // button-mask
    if (!rfb_write_u16(w, x)) return RFB_ERR_LIMIT;           // x (BE)
    if (!rfb_write_u16(w, y)) return RFB_ERR_LIMIT;           // y (BE)
    return RFB_OK;
}

rfb_error rfb_format_client_cut_text(rfb_writer *w,
                                     const uint8_t *text, uint32_t length)
{
    if (w == NULL) {
        return RFB_ERR_INTERNAL;
    }
    if (length > 0 && text == NULL) {
        return RFB_ERR_INTERNAL;
    }
    if (!rfb_write_u8(w, 6)) return RFB_ERR_LIMIT;            // type
    if (!rfb_write_u8(w, 0)) return RFB_ERR_LIMIT;            // pad
    if (!rfb_write_u8(w, 0)) return RFB_ERR_LIMIT;            // pad
    if (!rfb_write_u8(w, 0)) return RFB_ERR_LIMIT;            // pad
    if (!rfb_write_u32(w, length)) return RFB_ERR_LIMIT;      // length (BE)
    if (length > 0) {
        if (!rfb_write_bytes(w, text, length)) return RFB_ERR_LIMIT;
    }
    return RFB_OK;
}
