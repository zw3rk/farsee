// SPDX-License-Identifier: Apache-2.0
//
// G6 — input message encoder tests (plan.md §G6, RFC 6143 §7.5.4-6). RED.

#include "rfb_test.h"
#include "farsee/input.h"
#include "farsee/bytes.h"

#include <string.h>

// --- KeyEvent (RFC 6143 §7.5.4) -----------------------------------------
// u8 type=4, u8 down, u16 pad, u32 keysym (big-endian).

RFB_TEST(input, key_event__press_a__exact_bytes) {
    uint8_t out[8] = { 0 };
    rfb_writer w = rfb_writer_make(out, sizeof out);
    // 'a' keysym = 0x61 (X11 keysym for lowercase a).
    RFB_CHECK_EQ_INT(rfb_format_key_event(&w, true, 0x61), RFB_OK);
    RFB_CHECK_EQ_UINT(out[0], 4u);     // message-type
    RFB_CHECK_EQ_UINT(out[1], 1u);     // down=1
    RFB_CHECK_EQ_UINT(out[2], 0u);     // pad
    RFB_CHECK_EQ_UINT(out[3], 0u);
    // keysym big-endian: 0x00000061
    RFB_CHECK_EQ_UINT(out[4], 0x00u);
    RFB_CHECK_EQ_UINT(out[5], 0x00u);
    RFB_CHECK_EQ_UINT(out[6], 0x00u);
    RFB_CHECK_EQ_UINT(out[7], 0x61u);
    RFB_CHECK_EQ_UINT(w.length, 8u);
}

RFB_TEST(input, key_event__release__down_flag_zero) {
    uint8_t out[8] = { 0 };
    rfb_writer w = rfb_writer_make(out, sizeof out);
    RFB_CHECK_EQ_INT(rfb_format_key_event(&w, false, 0xFF0D), RFB_OK);
    RFB_CHECK_EQ_UINT(out[1], 0u);  // down=0
    // keysym 0x0000FF0D (Return)
    RFB_CHECK_EQ_UINT(out[5], 0x00u);
    RFB_CHECK_EQ_UINT(out[6], 0xFFu);
    RFB_CHECK_EQ_UINT(out[7], 0x0Du);
}

RFB_TEST(input, key_event__modifier_shift__exact_keysym) {
    uint8_t out[8] = { 0 };
    rfb_writer w = rfb_writer_make(out, sizeof out);
    // Shift_L = 0xFFE1 → big-endian u32 = 00 00 FF E1
    RFB_CHECK_EQ_INT(rfb_format_key_event(&w, true, 0xFFE1), RFB_OK);
    RFB_CHECK_EQ_UINT(out[4], 0x00u);
    RFB_CHECK_EQ_UINT(out[5], 0x00u);
    RFB_CHECK_EQ_UINT(out[6], 0xFFu);
    RFB_CHECK_EQ_UINT(out[7], 0xE1u);
}

RFB_TEST(input, key_event__buffer_too_small__fails_limit) {
    uint8_t out[7] = { 0 };
    rfb_writer w = rfb_writer_make(out, sizeof out);
    RFB_CHECK_EQ_INT(rfb_format_key_event(&w, true, 0x61), RFB_ERR_LIMIT);
}

// --- PointerEvent (RFC 6143 §7.5.5) -------------------------------------
// u8 type=5, u8 mask, u16 x, u16 y.

RFB_TEST(input, pointer_event__left_button_at_100_200__exact_bytes) {
    uint8_t out[6] = { 0 };
    rfb_writer w = rfb_writer_make(out, sizeof out);
    RFB_CHECK_EQ_INT(rfb_format_pointer_event(&w, RFB_BUTTON_LEFT, 100, 200), RFB_OK);
    RFB_CHECK_EQ_UINT(out[0], 5u);           // type
    RFB_CHECK_EQ_UINT(out[1], RFB_BUTTON_LEFT);  // mask
    RFB_CHECK_EQ_UINT(out[2], 0u); RFB_CHECK_EQ_UINT(out[3], 100u);  // x BE
    RFB_CHECK_EQ_UINT(out[4], 0u); RFB_CHECK_EQ_UINT(out[5], 200u);  // y BE
}

RFB_TEST(input, pointer_event__release_all__mask_zero) {
    uint8_t out[6] = { 0 };
    rfb_writer w = rfb_writer_make(out, sizeof out);
    RFB_CHECK_EQ_INT(rfb_format_pointer_event(&w, 0, 0, 0), RFB_OK);
    RFB_CHECK_EQ_UINT(out[1], 0u);
}

RFB_TEST(input, pointer_event__wheel_up__exact_mask) {
    uint8_t out[6] = { 0 };
    rfb_writer w = rfb_writer_make(out, sizeof out);
    RFB_CHECK_EQ_INT(rfb_format_pointer_event(&w, RFB_BUTTON_WHEEL_UP, 50, 50), RFB_OK);
    RFB_CHECK_EQ_UINT(out[1], RFB_BUTTON_WHEEL_UP);
}

// --- ClientCutText (RFC 6143 §7.5.6) ------------------------------------
// u8 type=6, u8 pad[3], u32 length, then bytes.

RFB_TEST(input, client_cut_text__short_text__exact_bytes) {
    uint8_t out[32] = { 0 };
    rfb_writer w = rfb_writer_make(out, sizeof out);
    static const uint8_t text[] = "hi";
    RFB_CHECK_EQ_INT(rfb_format_client_cut_text(&w, text, 2), RFB_OK);
    RFB_CHECK_EQ_UINT(out[0], 6u);   // type
    RFB_CHECK_EQ_UINT(out[1], 0u);   // pad
    RFB_CHECK_EQ_UINT(out[2], 0u);
    RFB_CHECK_EQ_UINT(out[3], 0u);
    // length big-endian = 2
    RFB_CHECK_EQ_UINT(out[7], 2u);
    // text bytes
    RFB_CHECK_EQ_UINT(out[8], 'h');
    RFB_CHECK_EQ_UINT(out[9], 'i');
    RFB_CHECK_EQ_UINT(w.length, 10u);
}

RFB_TEST(input, client_cut_text__empty_text__header_only) {
    uint8_t out[8] = { 0 };
    rfb_writer w = rfb_writer_make(out, sizeof out);
    RFB_CHECK_EQ_INT(rfb_format_client_cut_text(&w, NULL, 0), RFB_OK);
    RFB_CHECK_EQ_UINT(w.length, 8u);  // header only, no text bytes
    RFB_CHECK_EQ_UINT(out[7], 0u);    // length = 0
}

RFB_TEST(input, client_cut_text__buffer_too_small__fails_limit) {
    uint8_t out[9] = { 0 };
    rfb_writer w = rfb_writer_make(out, sizeof out);
    static const uint8_t text[] = "hello";
    // header(8) + 5 text = 13 > 9
    RFB_CHECK_EQ_INT(rfb_format_client_cut_text(&w, text, 5), RFB_ERR_LIMIT);
}
