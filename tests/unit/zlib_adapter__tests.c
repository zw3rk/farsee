// SPDX-License-Identifier: Apache-2.0
//
// G8 — zlib adapter tests (plan.md §G8). RED step.
//
// Tests the zlib inflate wrapper: round-trip (compress→decompress),
// persistent stream across calls, output-cap enforcement, and reset.

#include "rfb_test.h"
#include "farsee/zlib_adapter.h"

#include <zlib.h>
#include <string.h>

// Helper: compress data with zlib so we have something to inflate.
static size_t compress_data(const uint8_t *src, size_t src_len,
                            uint8_t *dst, size_t dst_cap)
{
    uLongf out_len = dst_cap;
    if (compress2(dst, &out_len, src, src_len, Z_DEFAULT_COMPRESSION) != Z_OK) {
        return 0;
    }
    return (size_t)out_len;
}

RFB_TEST(zlib, zlib__create_destroy__no_leak) {
    rfb_zlib_stream *s = rfb_zlib_create();
    RFB_CHECK(s != NULL);
    rfb_zlib_destroy(s);
    rfb_zlib_destroy(NULL);  // safe
}

RFB_TEST(zlib, zlib__round_trip_short__matches_original) {
    static const uint8_t input[] = "Hello, ZRLE world! This is test data.";
    uint8_t compressed[256];
    size_t comp_len = compress_data(input, sizeof input - 1, compressed, sizeof compressed);
    RFB_CHECK(comp_len > 0);

    rfb_zlib_stream *s = rfb_zlib_create();
    RFB_CHECK(s != NULL);
    uint8_t output[256] = { 0 };
    size_t out_len = 0;
    RFB_CHECK_EQ_INT(
        rfb_zlib_inflate(s, compressed, comp_len, output, sizeof output, &out_len),
        RFB_OK);
    RFB_CHECK_EQ_UINT(out_len, sizeof input - 1);
    RFB_CHECK_MEM_EQ(output, input, sizeof input - 1);
    rfb_zlib_destroy(s);
}

RFB_TEST(zlib, zlib__output_cap_too_small__returns_limit) {
    static const uint8_t input[] = "This is longer than the output cap.";
    uint8_t compressed[256];
    size_t comp_len = compress_data(input, sizeof input - 1, compressed, sizeof compressed);
    RFB_CHECK(comp_len > 0);

    rfb_zlib_stream *s = rfb_zlib_create();
    uint8_t output[8] = { 0 };  // too small
    size_t out_len = 0;
    RFB_CHECK_EQ_INT(
        rfb_zlib_inflate(s, compressed, comp_len, output, sizeof output, &out_len),
        RFB_ERR_LIMIT);
    rfb_zlib_destroy(s);
}

RFB_TEST(zlib, zlib__persistent_stream__two_inflate_calls_share_context) {
    // ZRLE uses one persistent zlib stream across rectangles. Compress
    // two chunks separately (as flush-blocks) and inflate them through
    // the same stream; the result must be the concatenation.
    static const uint8_t chunk_a[] = "AAAAAAAABBBBBBBB";
    static const uint8_t chunk_b[] = "CCCCCCCCDDDDDDDD";

    // Compress both into one stream using Z_SYNC_FLUSH between them.
    z_stream zs;
    memset(&zs, 0, sizeof zs);
    deflateInit(&zs, Z_DEFAULT_COMPRESSION);
    uint8_t comp[256];
    zs.next_out = comp;
    zs.avail_out = sizeof comp;
    zs.next_in = (Bytef *)(uintptr_t)chunk_a;
    zs.avail_in = sizeof chunk_a - 1;
    deflate(&zs, Z_SYNC_FLUSH);
    zs.next_in = (Bytef *)(uintptr_t)chunk_b;
    zs.avail_in = sizeof chunk_b - 1;
    deflate(&zs, Z_FINISH);
    size_t comp_len = zs.total_out;
    deflateEnd(&zs);

    rfb_zlib_stream *s = rfb_zlib_create();
    uint8_t output[256] = { 0 };
    size_t out_len = 0;
    RFB_CHECK_EQ_INT(
        rfb_zlib_inflate(s, comp, comp_len, output, sizeof output, &out_len),
        RFB_OK);
    // Expected: concatenation of both chunks.
    RFB_CHECK_EQ_UINT(out_len, (sizeof chunk_a - 1) + (sizeof chunk_b - 1));
    RFB_CHECK_MEM_EQ(output, chunk_a, sizeof chunk_a - 1);
    RFB_CHECK_MEM_EQ(output + (sizeof chunk_a - 1), chunk_b, sizeof chunk_b - 1);
    rfb_zlib_destroy(s);
}

RFB_TEST(zlib, zlib__reset__starts_fresh) {
    static const uint8_t input[] = "reset test";
    uint8_t compressed[128];
    size_t comp_len = compress_data(input, sizeof input - 1, compressed, sizeof compressed);
    RFB_CHECK(comp_len > 0);

    rfb_zlib_stream *s = rfb_zlib_create();
    uint8_t output[128] = { 0 };
    size_t out_len = 0;
    // First inflate works.
    RFB_CHECK_EQ_INT(
        rfb_zlib_inflate(s, compressed, comp_len, output, sizeof output, &out_len),
        RFB_OK);
    RFB_CHECK_EQ_UINT(out_len, sizeof input - 1);
    // Reset, then inflate the same compressed data again.
    RFB_CHECK_EQ_INT(rfb_zlib_reset(s), RFB_OK);
    out_len = 0;
    memset(output, 0, sizeof output);
    RFB_CHECK_EQ_INT(
        rfb_zlib_inflate(s, compressed, comp_len, output, sizeof output, &out_len),
        RFB_OK);
    RFB_CHECK_EQ_UINT(out_len, sizeof input - 1);
    RFB_CHECK_MEM_EQ(output, input, sizeof input - 1);
    rfb_zlib_destroy(s);
}

RFB_TEST(zlib, zlib__corrupt_input__returns_protocol_error) {
    rfb_zlib_stream *s = rfb_zlib_create();
    static const uint8_t garbage[16] = { 0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0 };
    uint8_t output[64] = { 0 };
    size_t out_len = 0;
    RFB_CHECK_EQ_INT(
        rfb_zlib_inflate(s, garbage, sizeof garbage, output, sizeof output, &out_len),
        RFB_ERR_PROTOCOL);
    rfb_zlib_destroy(s);
}
