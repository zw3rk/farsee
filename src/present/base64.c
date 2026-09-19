// SPDX-License-Identifier: Apache-2.0
//
// farsee — Base64 encoder implementation.

#include "farsee/base64.h"

#include <stdbool.h>

static const char B64_ALPHABET[65] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// Encode one 3-byte triple into 4 output chars. `n_in` is 1..3.
static size_t encode_triple(const uint8_t *in, size_t n_in, char *out)
{
    uint32_t v = 0;
    v |= (uint32_t)in[0] << 16;
    if (n_in >= 2) v |= (uint32_t)in[1] << 8;
    if (n_in >= 3) v |= (uint32_t)in[2];
    out[0] = B64_ALPHABET[(v >> 18) & 0x3F];
    out[1] = B64_ALPHABET[(v >> 12) & 0x3F];
    out[2] = (n_in >= 2) ? B64_ALPHABET[(v >> 6) & 0x3F] : '=';
    out[3] = (n_in >= 3) ? B64_ALPHABET[v & 0x3F] : '=';
    return 4u;
}

size_t rfb_base64_encode(const uint8_t *input, size_t input_len,
                         char *output, size_t out_cap)
{
    size_t needed = rfb_base64_encoded_len(input_len);
    if (needed > out_cap) {
        return 0;  // insufficient capacity
    }
    size_t out_pos = 0;
    size_t i = 0;
    while (i + 3 <= input_len) {
        out_pos += encode_triple(input + i, 3, output + out_pos);
        i += 3;
    }
    size_t rem = input_len - i;
    if (rem > 0) {
        out_pos += encode_triple(input + i, rem, output + out_pos);
    }
    return out_pos;
}

void rfb_base64_stream_init(rfb_base64_stream *s)
{
    if (s != NULL) {
        s->pending[0] = 0;
        s->pending[1] = 0;
        s->pending_count = 0;
    }
}

bool rfb_base64_stream_encode(rfb_base64_stream *s,
                              const uint8_t *input, size_t input_len,
                              char *output, size_t out_cap, size_t *out_pos)
{
    if (s == NULL || output == NULL || out_pos == NULL ||
        (input == NULL && input_len > 0)) {
        return false;
    }
    size_t pos = *out_pos;

    // Combine pending bytes with new input, processing in groups of 3.
    size_t i = 0;
    while (s->pending_count + (input_len - i) >= 3) {
        uint8_t group[3];
        size_t gl = 0;
        while (s->pending_count > 0 && gl < 3) {
            group[gl++] = s->pending[0];
            if (s->pending_count == 2) s->pending[0] = s->pending[1];
            s->pending_count--;
        }
        while (gl < 3 && i < input_len) {
            group[gl++] = input[i++];
        }
        if (gl < 3) break;  // Unreachable for valid stream state.
        if (pos + 4 > out_cap) return false;
        encode_triple(group, 3, output + pos);
        pos += 4;
    }

    // Stash remaining input bytes as pending (0, 1, or 2).
    while (i < input_len) {
        if (s->pending_count >= 2) return false;  // Reject invalid state.
        s->pending[s->pending_count++] = input[i++];
    }

    *out_pos = pos;
    return true;
}

bool rfb_base64_stream_flush(rfb_base64_stream *s,
                             char *output, size_t out_cap, size_t *out_pos)
{
    if (s == NULL || output == NULL || out_pos == NULL) {
        return false;
    }
    if (s->pending_count == 0) {
        return true;  // nothing to flush
    }
    if (*out_pos + 4 > out_cap) {
        return false;
    }
    uint8_t group[3] = { 0, 0, 0 };
    for (size_t i = 0; i < s->pending_count; i++) {
        group[i] = s->pending[i];
    }
    encode_triple(group, s->pending_count, output + *out_pos);
    *out_pos += 4;
    s->pending_count = 0;
    return true;
}
