// SPDX-License-Identifier: Apache-2.0
//
// farsee — Base64 encoders for Kitty graphics payloads.
//
// The whole-buffer encoder serves Kitty direct-transfer image bytes and
// shared-memory names. The streaming encoder accepts input in chunks,
// retains up to two pending bytes between calls, and emits standard '='
// padding when flushed.

#ifndef FARSEE_INCLUDE_FARSEE_BASE64_H
#define FARSEE_INCLUDE_FARSEE_BASE64_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Compute the padded Base64 length for input_len.
// The caller must ensure input_len + 2 and the final multiply fit size_t.
static inline size_t rfb_base64_encoded_len(size_t input_len)
{
    return ((input_len + 2u) / 3u) * 4u;
}

// Encode input_len bytes into output, whose capacity is out_cap. For nonempty
// input, input and output must be valid and encoded-length arithmetic must fit
// size_t. Returns a multiple-of-four byte count, or 0 for empty input or
// insufficient capacity. The output is not NUL-terminated.
size_t rfb_base64_encode(const uint8_t *input, size_t input_len,
                         char *output, size_t out_cap);

// Streaming encoder state. Complete three-byte input groups produce four
// output bytes. Up to two input bytes remain pending until a later chunk
// or flush.
typedef struct rfb_base64_stream {
    uint8_t pending[2];
    uint8_t pending_count;  // 0, 1, or 2
} rfb_base64_stream;

void rfb_base64_stream_init(rfb_base64_stream *s);

// Encode a chunk at output + *out_pos; update *out_pos only on success.
// State, output, and out_pos must be non-NULL. Input can be NULL only for an
// empty chunk. Keep *out_pos <= out_cap and addition by 4 representable.
// Insufficient capacity can return false after consuming pending state bytes.
bool rfb_base64_stream_encode(rfb_base64_stream *s,
                              const uint8_t *input, size_t input_len,
                              char *output, size_t out_cap, size_t *out_pos);

// Flush pending bytes with '=' padding. Keep *out_pos <= out_cap and addition
// by 4 representable; invalid arguments or insufficient capacity return false.
bool rfb_base64_stream_flush(rfb_base64_stream *s,
                             char *output, size_t out_cap, size_t *out_pos);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_BASE64_H
