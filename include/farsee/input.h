// SPDX-License-Identifier: Apache-2.0
//
// farsee — client input message encoders (plan.md §G6, RFC 6143 §7.5).
//
// KeyEvent (§7.5.4), PointerEvent (§7.5.5), ClientCutText (§7.5.6).
// Each encoder appends exact wire bytes to a writer.

#ifndef FARSEE_INCLUDE_FARSEE_INPUT_H
#define FARSEE_INCLUDE_FARSEE_INPUT_H

#include "farsee/bytes.h"
#include "farsee/error.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Pointer button bitmask (RFC 6143 §7.5.5 bits 0–4). Bits 5–6 are
// farsee mappings for horizontal-wheel buttons 6–7.
#define RFB_BUTTON_LEFT        0x01u
#define RFB_BUTTON_MIDDLE      0x02u
#define RFB_BUTTON_RIGHT       0x04u
#define RFB_BUTTON_WHEEL_UP    0x08u  /* button 4 */
#define RFB_BUTTON_WHEEL_DN    0x10u  /* button 5 */
#define RFB_BUTTON_WHEEL_LEFT  0x20u  /* button 6 — horizontal left */
#define RFB_BUTTON_WHEEL_RIGHT 0x40u  /* button 7 — horizontal right */
// "Release all" is button-mask 0.

// Encode a FramebufferUpdateRequest (message-type 3, RFC 6143 §7.5.3):
//   u8 type=3, u8 incremental, u16 x, u16 y, u16 w, u16 h (big-endian).
// `incremental` false requests a full refresh of the region; true asks for
// only changes since the last update (server policy).
rfb_error rfb_format_framebuffer_update_request(rfb_writer *w,
                                                bool incremental,
                                                uint16_t x, uint16_t y,
                                                uint16_t width, uint16_t height);

// Encode a KeyEvent (message-type 4):
//   u8 type=4, u8 down-flag, u16 pad, u32 keysym.
rfb_error rfb_format_key_event(rfb_writer *w,
                               bool down, uint32_t keysym);

// Encode a PointerEvent (message-type 5):
//   u8 type=5, u8 button-mask, u16 x, u16 y.
rfb_error rfb_format_pointer_event(rfb_writer *w,
                                   uint8_t button_mask,
                                   uint16_t x, uint16_t y);

// Encode a ClientCutText (message-type 6):
//   u8 type=6, u8 pad[3], u32 length, then `length` bytes of text.
//   `length` is the byte count; this function copies the bytes unchanged.
rfb_error rfb_format_client_cut_text(rfb_writer *w,
                                     const uint8_t *text, uint32_t length);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_INPUT_H
