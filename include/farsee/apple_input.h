// SPDX-License-Identifier: Apache-2.0
//
// farsee — Apple session input messages (goals.md G21).
//
// FIELD CLASSIFICATION (goals.md §14, apple-wire-spec.md):
//   docs/apple/apple-wire-spec.md contains NO project-owned capture of any
//   Apple-specific client→server input/keyboard/pointer message. Per the G21
//   contract: "For Apple sessions, implement only input/keyboard-source
//   messages established by project-owned captures; otherwise use verified
//   standard messages inside G17 records."
//
//   Therefore this module serializes STANDARD RFC 6143 input messages
//   (KeyEvent type=4, PointerEvent type=5, ClientCutText type=6) — the same
//   byte layout used by the classic path — and wraps them inside a G17
//   encrypted record (apple_record_encrypt). The standard message layout is
//   CAPTURED (RFC 6143 §7.5.4-6). The record framing is the G17 layer.
//
//   apple-wire-spec.md confirms: "The classic RFB client→server message
//   types (0=SetPixelFormat, 2=SetEncodings, 3=FramebufferUpdateRequest,
//   4=KeyEvent, 5=PointerEvent, 6=ClientCutText) are reused inside
//   encrypted records where the captured evidence supports them."
//
// DIVERGENCE NOTE: the G17 record layer uses AES-128-CBC; the captured wire
// uses ChaCha20-Poly1305. For the deterministic fake-server path both sides
// use the G17 layer. Real macOS requires the captured AEAD cipher.
//
// Pure and bounded: no sockets, no global state. The serialize functions
// write plaintext RFB message bytes into a caller buffer; the encrypt
// function wraps them in one G17 record.

#ifndef FARSEE_INCLUDE_FARSEE_APPLE_INPUT_H
#define FARSEE_INCLUDE_FARSEE_APPLE_INPUT_H

#include "farsee/apple_record.h"
#include "farsee/error.h"
#include "farsee/normalized_input.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// ---------------------------------------------------------------------------
// Serialize a normalized key event as a standard RFB KeyEvent (type=4) into
// a plaintext buffer. The caller encrypts the buffer via apple_input_encrypt.
//   u8 type=4, u8 down, u16 pad, u32 keysym (big-endian)
// *out_len is set to 8 on success. Returns RFB_OK or RFB_ERR_LIMIT/RFB_ERR_INTERNAL.
// ---------------------------------------------------------------------------
rfb_error apple_input_serialize_key(const rfb_norm_key *k,
                                    uint8_t *out, size_t out_cap,
                                    size_t *out_len);

// ---------------------------------------------------------------------------
// Serialize a pointer event as a standard RFB PointerEvent (type=5) into a
// plaintext buffer.
//   u8 type=5, u8 button_mask, u16 x, u16 y (big-endian)
// `button_mask` is the logical button mask OR'd with any wheel bits. x/y are
// framebuffer pixel coordinates (the caller maps viewport→fb via
// rfb_norm_geom_map). *out_len = 6 on success.
// ---------------------------------------------------------------------------
rfb_error apple_input_serialize_pointer(uint8_t button_mask,
                                        uint16_t x, uint16_t y,
                                        uint8_t *out, size_t out_cap,
                                        size_t *out_len);

// ---------------------------------------------------------------------------
// Serialize clipboard text as a standard RFB ClientCutText (type=6) into a
// plaintext buffer.
//   u8 type=6, u8 pad[3], u32 length, byte[length] text
// The caller is responsible for applying clipboard policy (size cap,
// sanitization) before calling. *out_len = 8 + length on success.
// ---------------------------------------------------------------------------
rfb_error apple_input_serialize_clipboard(const uint8_t *text, uint32_t length,
                                          uint8_t *out, size_t out_cap,
                                          size_t *out_len);

// ---------------------------------------------------------------------------
// Encrypt a plaintext input message buffer into a G17 record.
//
// Wraps apple_record_encrypt: pads the plaintext to a 16-byte boundary,
// encrypts under the client→server direction, and writes the ciphertext
// record. The plaintext is caller-owned (may be the output of one of the
// serialize functions above, or a concatenation of several messages).
//
// `rl` must have its encrypt direction initialized. Returns RFB_OK or the
// record-layer error. *ct_len is the ciphertext length (multiple of 16).
// ---------------------------------------------------------------------------
rfb_error apple_input_encrypt(apple_record_layer *rl,
                              const uint8_t *plaintext, size_t pt_len,
                              uint8_t *ciphertext, size_t ct_cap,
                              size_t *ct_len);

// ---------------------------------------------------------------------------
// One-shot convenience: serialize a key event and encrypt it into a record.
// `tmp` is a caller scratch buffer for the plaintext (>= 8 bytes). This is
// the typical call from the event loop.
// ---------------------------------------------------------------------------
rfb_error apple_input_send_key(apple_record_layer *rl,
                               const rfb_norm_key *k,
                               uint8_t *ciphertext, size_t ct_cap,
                               size_t *ct_len);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_APPLE_INPUT_H
