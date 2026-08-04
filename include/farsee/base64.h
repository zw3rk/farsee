// SPDX-License-Identifier: Apache-2.0
//
// farsee — base64 streaming encoder (plan.md §G7, RFC 4648).
//
// Used by the Kitty direct-transfer presenter to encode RGB/RGBA pixel
// data into the Kitty graphics protocol's base64 payload. The encoder is
// streaming: it accepts arbitrary input lengths and produces output in
// 4/3-ratio chunks with standard '=' padding on the final triple.

#ifndef FARSEE_INCLUDE_FARSEE_BASE64_H
#define FARSEE_INCLUDE_FARSEE_BASE64_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Compute the exact base64-encoded length for `input_len` bytes
// (including padding). Used to size output buffers.
static inline size_t rfb_base64_encoded_len(size_t input_len)
{
    return ((input_len + 2u) / 3u) * 4u;
}

// Encode `input_len` bytes of `input` into `output`. `output` must have
// at least `out_cap` bytes of capacity. Returns the number of bytes
// written (always a multiple of 4), or 0 if out_cap is insufficient.
// The output is NOT null-terminated (Kitty payloads are binary, not C strings).
size_t rfb_base64_encode(const uint8_t *input, size_t input_len,
                         char *output, size_t out_cap);

// Streaming encoder state. Allows encoding a large buffer in multiple
// calls without re-scanning earlier output. Used by the Kitty presenter's
// chunked transfer. Up to 2 bytes can be pending between calls.
typedef struct rfb_base64_stream {
    uint8_t pending[2];
    uint8_t pending_count;  // 0, 1, or 2
} rfb_base64_stream;

void rfb_base64_stream_init(rfb_base64_stream *s);

// Encode a chunk of input, appending to `*output`. `*out_pos` is updated
// to point past the bytes written. Handles leftover bytes across calls.
// `out_cap` is the total capacity of the output buffer; returns false on
// overflow.
bool rfb_base64_stream_encode(rfb_base64_stream *s,
                              const uint8_t *input, size_t input_len,
                              char *output, size_t out_cap, size_t *out_pos);

// Flush any remaining leftover bytes (emit '=' padding). Call once at the
// end of the stream. Returns false on overflow.
bool rfb_base64_stream_flush(rfb_base64_stream *s,
                             char *output, size_t out_cap, size_t *out_pos);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_BASE64_H
