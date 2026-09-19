// SPDX-License-Identifier: Apache-2.0
//
// Base64 encoder tests, including known-answer vectors.

#include "rfb_test.h"
#include "farsee/base64.h"

#include <string.h>

// Known-answer vectors.
RFB_TEST(base64, base64__empty__empty_output) {
    char out[8];
    size_t n = rfb_base64_encode((const uint8_t *)"", 0, out, sizeof out);
    RFB_CHECK_EQ_UINT(n, 0u);
}

RFB_TEST(base64, base64__f__bg) {
    char out[8] = { 0 };
    size_t n = rfb_base64_encode((const uint8_t *)"f", 1, out, sizeof out);
    RFB_CHECK_EQ_UINT(n, 4u);
    RFB_CHECK(strncmp(out, "Zg==", 4) == 0);
}

RFB_TEST(base64, base64__fo__Zm8) {
    char out[8] = { 0 };
    size_t n = rfb_base64_encode((const uint8_t *)"fo", 2, out, sizeof out);
    RFB_CHECK_EQ_UINT(n, 4u);
    RFB_CHECK(strncmp(out, "Zm8=", 4) == 0);
}

RFB_TEST(base64, base64__foo__Zm9v) {
    char out[8] = { 0 };
    size_t n = rfb_base64_encode((const uint8_t *)"foo", 3, out, sizeof out);
    RFB_CHECK_EQ_UINT(n, 4u);
    RFB_CHECK(strncmp(out, "Zm9v", 4) == 0);
}

RFB_TEST(base64, base64__foob__Zm9vYg) {
    char out[8] = { 0 };
    size_t n = rfb_base64_encode((const uint8_t *)"foob", 4, out, sizeof out);
    RFB_CHECK_EQ_UINT(n, 8u);
    RFB_CHECK(strncmp(out, "Zm9vYg==", 8) == 0);
}

RFB_TEST(base64, base64__fooba__Zm9vYmE) {
    char out[8] = { 0 };
    size_t n = rfb_base64_encode((const uint8_t *)"fooba", 5, out, sizeof out);
    RFB_CHECK_EQ_UINT(n, 8u);
    RFB_CHECK(strncmp(out, "Zm9vYmE=", 8) == 0);
}

RFB_TEST(base64, base64__foobar__Zm9vYmFy) {
    char out[8] = { 0 };
    size_t n = rfb_base64_encode((const uint8_t *)"foobar", 6, out, sizeof out);
    RFB_CHECK_EQ_UINT(n, 8u);
    RFB_CHECK(strncmp(out, "Zm9vYmFy", 8) == 0);
}

RFB_TEST(base64, base64__encoded_len__matches_formula) {
    RFB_CHECK_EQ_UINT(rfb_base64_encoded_len(0), 0u);
    RFB_CHECK_EQ_UINT(rfb_base64_encoded_len(1), 4u);
    RFB_CHECK_EQ_UINT(rfb_base64_encoded_len(2), 4u);
    RFB_CHECK_EQ_UINT(rfb_base64_encoded_len(3), 4u);
    RFB_CHECK_EQ_UINT(rfb_base64_encoded_len(4), 8u);
    RFB_CHECK_EQ_UINT(rfb_base64_encoded_len(6), 8u);
    RFB_CHECK_EQ_UINT(rfb_base64_encoded_len(300), 400u);  // 100 triples
}

// --- all 256 byte values produce the expected length and alphabet ----------
// This case checks output length and Base64 alphabet membership. It does not
// decode the result.

static bool is_b64_char(char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=';
}

RFB_TEST(base64, base64__all_byte_values__valid_alphabet) {
    uint8_t in[256];
    for (int i = 0; i < 256; i++) in[i] = (uint8_t)i;
    char out[512];
    size_t n = rfb_base64_encode(in, 256, out, sizeof out);
    RFB_CHECK_EQ_UINT(n, 344u);  // ceil(256/3)*4 = 86*4
    for (size_t i = 0; i < n; i++) {
        RFB_CHECK(is_b64_char(out[i]));
    }
}

// --- streaming encoder: split "foobar" into three 2-byte chunks ----------
RFB_TEST(base64, base64_stream__foobar_in_three_chunks__matches_whole) {
    char whole[16];
    size_t wn = rfb_base64_encode((const uint8_t *)"foobar", 6, whole, sizeof whole);

    rfb_base64_stream s;
    rfb_base64_stream_init(&s);
    char streamed[16] = { 0 };
    size_t pos = 0;
    RFB_CHECK(rfb_base64_stream_encode(&s, (const uint8_t *)"fo", 2, streamed, sizeof streamed, &pos));
    RFB_CHECK(rfb_base64_stream_encode(&s, (const uint8_t *)"ob", 2, streamed, sizeof streamed, &pos));
    RFB_CHECK(rfb_base64_stream_encode(&s, (const uint8_t *)"ar", 2, streamed, sizeof streamed, &pos));
    RFB_CHECK(rfb_base64_stream_flush(&s, streamed, sizeof streamed, &pos));
    RFB_CHECK_EQ_UINT(pos, wn);
    RFB_CHECK_MEM_EQ(streamed, whole, wn);
}

// --- streaming: single-byte-at-a-time -----------------------------------
RFB_TEST(base64, base64_stream__foobar_one_byte_at_a_time__matches_whole) {
    char whole[16];
    size_t wn = rfb_base64_encode((const uint8_t *)"foobar", 6, whole, sizeof whole);

    rfb_base64_stream s;
    rfb_base64_stream_init(&s);
    char streamed[16] = { 0 };
    size_t pos = 0;
    for (int i = 0; i < 6; i++) {
        RFB_CHECK(rfb_base64_stream_encode(&s, (const uint8_t *)"foobar" + i, 1,
                                           streamed, sizeof streamed, &pos));
    }
    RFB_CHECK(rfb_base64_stream_flush(&s, streamed, sizeof streamed, &pos));
    RFB_CHECK_EQ_UINT(pos, wn);
    RFB_CHECK_MEM_EQ(streamed, whole, wn);
}

// --- streaming: leftover flush emits padding -----------------------------
RFB_TEST(base64, base64_stream__single_byte_f__flush_emits_padding) {
    rfb_base64_stream s;
    rfb_base64_stream_init(&s);
    char out[8] = { 0 };
    size_t pos = 0;
    RFB_CHECK(rfb_base64_stream_encode(&s, (const uint8_t *)"f", 1, out, sizeof out, &pos));
    // 1 leftover byte → no output yet (need at least 3 for a group).
    RFB_CHECK_EQ_UINT(pos, 0u);
    RFB_CHECK(rfb_base64_stream_flush(&s, out, sizeof out, &pos));
    RFB_CHECK_EQ_UINT(pos, 4u);
    RFB_CHECK(strncmp(out, "Zg==", 4) == 0);
}

// --- streaming: insufficient capacity returns false ----------------------
RFB_TEST(base64, base64_stream__overflow__returns_false) {
    rfb_base64_stream s;
    rfb_base64_stream_init(&s);
    char out[2];  // tiny
    size_t pos = 0;
    RFB_CHECK(!rfb_base64_stream_encode(&s, (const uint8_t *)"foobar", 6, out, sizeof out, &pos));
}
