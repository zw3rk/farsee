// SPDX-License-Identifier: Apache-2.0

#include "rfb_test.h"

#include "farsee/encoding_apple_0450.h"
#include "farsee/pixel_format.h"

#include <string.h>
#include <zlib.h>

// Independent zlib stream for five bytes, terminated with Z_SYNC_FLUSH.
static const uint8_t k_one_pixel[] = {
    0x00, 0x00, 0x03, 0xe8, // envelope parameter 1000
    0x00, 0x00, 0x00, 0x0d, // compressed length 13
    0x78, 0xda, 0x62, 0x64, 0x64, 0x64, 0x60,
    0x07, 0x00, 0x00, 0x00, 0xff, 0xff,
};

static const uint8_t k_one_pixel_plus_extra[] = {
    0x00, 0x00, 0x03, 0xe8,
    0x00, 0x00, 0x00, 0x0e,
    0x78, 0xda, 0x62, 0x64, 0x64, 0x64, 0x60,
    0xe7, 0x04, 0x00, 0x00, 0x00, 0xff, 0xff,
};

static size_t make_payload(const uint8_t *expanded, size_t expanded_len,
                           uint8_t *out, size_t out_capacity)
{
    if (expanded == NULL || expanded_len == 0u || out == NULL ||
        out_capacity <= 8u) {
        return 0u;
    }
    z_stream stream;
    memset(&stream, 0, sizeof stream);
    if (deflateInit(&stream, Z_BEST_COMPRESSION) != Z_OK) {
        return 0u;
    }
    stream.next_in = (Bytef *)(uintptr_t)expanded;
    stream.avail_in = (uInt)expanded_len;
    stream.next_out = out + 8u;
    stream.avail_out = (uInt)(out_capacity - 8u);
    const int result = deflate(&stream, Z_SYNC_FLUSH);
    const size_t compressed_len =
        out_capacity - 8u - (size_t)stream.avail_out;
    (void)deflateEnd(&stream);
    if (result != Z_OK || compressed_len == 0u ||
        compressed_len > UINT32_MAX) {
        return 0u;
    }
    out[0] = 0u;
    out[1] = 0u;
    out[2] = 3u;
    out[3] = 0xe8u;
    out[4] = (uint8_t)(compressed_len >> 24u);
    out[5] = (uint8_t)(compressed_len >> 16u);
    out[6] = (uint8_t)(compressed_len >> 8u);
    out[7] = (uint8_t)compressed_len;
    return 8u + compressed_len;
}

RFB_TEST(encoding_apple_0450, transparent_cursor_decodes_without_damage)
{
    static const uint8_t expanded[] = {0u, 0u, 0u, 0u, 0u};
    uint8_t payload[64];
    const size_t payload_len =
        make_payload(expanded, sizeof expanded, payload, sizeof payload);
    RFB_CHECK(payload_len > 0u);
    const rfb_rect_header rh = {
        3u, 4u, 1u, 1u, RFB_ENCODING_APPLE_0450};
    const rfb_pixel_format pf = rfb_pixel_format_canonical_request();
    rfb_cursor cursor;
    memset(&cursor, 0, sizeof cursor);
    RFB_CHECK_EQ_INT(rfb_decode_apple_0450(
                         &cursor, &pf, &rh, payload, payload_len,
                         1024u, rfb_default_allocator()),
                     RFB_OK);
    RFB_CHECK(cursor.valid);
    RFB_CHECK_EQ_UINT(cursor.hotspot_x, 3u);
    RFB_CHECK_EQ_UINT(cursor.hotspot_y, 4u);
    RFB_CHECK_EQ_UINT(cursor.width, 1u);
    RFB_CHECK_EQ_UINT(cursor.height, 1u);
    static const uint8_t transparent[] = {0u, 0u, 0u, 0u};
    RFB_CHECK_MEM_EQ(cursor.rgba, transparent, sizeof transparent);
    rfb_cursor_destroy(&cursor, rfb_default_allocator());
}

RFB_TEST(encoding_apple_0450,
         premultiplied_bgrx_plus_alpha_decodes_to_straight_rgba)
{
    // Two packed canonical wire pixels followed by the separate alpha plane.
    // Pixel 0 is premultiplied BGRX (32,64,128,0) at alpha 128. Pixel 1 is
    // fully transparent. This is the five-byte-per-pixel organization seen
    // on the live Apple cursor path; it is not five interleaved components.
    static const uint8_t expanded[] = {
        32u, 64u, 128u, 0u,
        0u, 0u, 0u, 0u,
        128u, 0u,
    };
    uint8_t payload[64];
    const size_t payload_len =
        make_payload(expanded, sizeof expanded, payload, sizeof payload);
    RFB_CHECK(payload_len > 0u);
    const rfb_rect_header rh = {
        5u, 6u, 2u, 1u, RFB_ENCODING_APPLE_0450};
    const rfb_pixel_format pf = rfb_pixel_format_canonical_request();
    rfb_cursor cursor;
    memset(&cursor, 0, sizeof cursor);
    RFB_CHECK_EQ_INT(rfb_decode_apple_0450(
                         &cursor, &pf, &rh, payload, payload_len, 1024u,
                         rfb_default_allocator()),
                     RFB_OK);
    static const uint8_t expected[] = {
        255u, 128u, 64u, 128u,
        0u, 0u, 0u, 0u,
    };
    RFB_CHECK_MEM_EQ(cursor.rgba, expected, sizeof expected);
    RFB_CHECK_EQ_UINT(cursor.hotspot_x, 5u);
    RFB_CHECK_EQ_UINT(cursor.hotspot_y, 6u);
    rfb_cursor_destroy(&cursor, rfb_default_allocator());
}

RFB_TEST(encoding_apple_0450, malformed_envelopes_fail_closed)
{
    const rfb_rect_header rh = {
        0u, 0u, 1u, 1u, RFB_ENCODING_APPLE_0450};
    const rfb_pixel_format pf = rfb_pixel_format_canonical_request();
    rfb_cursor cursor;
    memset(&cursor, 0, sizeof cursor);
    uint8_t payload[sizeof k_one_pixel + 1u];

    memcpy(payload, k_one_pixel, sizeof k_one_pixel);
    payload[3] = 0xe7u; // parameter 999 is invalid
    RFB_CHECK_EQ_INT(rfb_decode_apple_0450(
                         &cursor, &pf, &rh, payload, sizeof k_one_pixel,
                         1024u, rfb_default_allocator()),
                     RFB_ERR_PROTOCOL);

    memcpy(payload, k_one_pixel, sizeof k_one_pixel);
    payload[7] = 0x0eu; // claims one compressed byte beyond the payload
    RFB_CHECK_EQ_INT(rfb_decode_apple_0450(
                         &cursor, &pf, &rh, payload, sizeof k_one_pixel,
                         1024u, rfb_default_allocator()),
                     RFB_ERR_PROTOCOL);

    memcpy(payload, k_one_pixel, sizeof k_one_pixel);
    payload[sizeof k_one_pixel] = 0u; // unframed trailing data
    RFB_CHECK_EQ_INT(rfb_decode_apple_0450(
                         &cursor, &pf, &rh, payload, sizeof payload, 1024u,
                         rfb_default_allocator()),
                     RFB_ERR_PROTOCOL);

    memcpy(payload, k_one_pixel, sizeof k_one_pixel);
    payload[8] = 0u; // corrupt zlib header
    RFB_CHECK_EQ_INT(rfb_decode_apple_0450(
                         &cursor, &pf, &rh, payload, sizeof k_one_pixel,
                         1024u, rfb_default_allocator()),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK(!cursor.valid);
}

RFB_TEST(encoding_apple_0450, expanded_size_must_match_five_bytes_per_pixel)
{
    const rfb_rect_header too_large = {
        0u, 0u, 2u, 1u, RFB_ENCODING_APPLE_0450};
    const rfb_pixel_format pf = rfb_pixel_format_canonical_request();
    rfb_cursor cursor;
    memset(&cursor, 0, sizeof cursor);
    RFB_CHECK_EQ_INT(rfb_decode_apple_0450(
                         &cursor, &pf, &too_large, k_one_pixel,
                         sizeof k_one_pixel, 1024u, rfb_default_allocator()),
                     RFB_ERR_PROTOCOL);

    const rfb_rect_header one_pixel = {
        0u, 0u, 1u, 1u, RFB_ENCODING_APPLE_0450};
    RFB_CHECK_EQ_INT(rfb_decode_apple_0450(
                         &cursor, &pf, &one_pixel, k_one_pixel,
                         sizeof k_one_pixel, 4u, rfb_default_allocator()),
                     RFB_ERR_LIMIT);

    // The same 1x1 geometry must reject a legal stream that expands to six
    // bytes; exact output size is part of the structural envelope.
    RFB_CHECK_EQ_INT(rfb_decode_apple_0450(
                         &cursor, &pf, &one_pixel, k_one_pixel_plus_extra,
                         sizeof k_one_pixel_plus_extra, 1024u,
                         rfb_default_allocator()),
                     RFB_ERR_PROTOCOL);
}

RFB_TEST(encoding_apple_0450, nonpremultiplied_component_fails_closed)
{
    static const uint8_t expanded[] = {0u, 0u, 129u, 0u, 128u};
    uint8_t payload[64];
    const size_t payload_len =
        make_payload(expanded, sizeof expanded, payload, sizeof payload);
    const rfb_rect_header rh = {
        0u, 0u, 1u, 1u, RFB_ENCODING_APPLE_0450};
    const rfb_pixel_format pf = rfb_pixel_format_canonical_request();
    rfb_cursor cursor;
    memset(&cursor, 0, sizeof cursor);
    RFB_CHECK_EQ_INT(rfb_decode_apple_0450(
                         &cursor, &pf, &rh, payload, payload_len, 1024u,
                         rfb_default_allocator()),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK(!cursor.valid);
    RFB_CHECK(cursor.rgba == NULL);
}

RFB_TEST(encoding_apple_0450, nonzero_packed_padding_fails_closed)
{
    static const uint8_t expanded[] = {0u, 0u, 0u, 1u, 0u};
    uint8_t payload[64];
    const size_t payload_len =
        make_payload(expanded, sizeof expanded, payload, sizeof payload);
    const rfb_rect_header rh = {
        0u, 0u, 1u, 1u, RFB_ENCODING_APPLE_0450};
    const rfb_pixel_format pf = rfb_pixel_format_canonical_request();
    rfb_cursor cursor;
    memset(&cursor, 0, sizeof cursor);
    RFB_CHECK_EQ_INT(rfb_decode_apple_0450(
                         &cursor, &pf, &rh, payload, payload_len, 1024u,
                         rfb_default_allocator()),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK(!cursor.valid);
    RFB_CHECK(cursor.rgba == NULL);
}

RFB_TEST(encoding_apple_0450, rejects_wrong_encoding_and_null_arguments)
{
    rfb_rect_header rh = {0u, 0u, 1u, 1u, RFB_ENCODING_APPLE_0450};
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();
    rfb_cursor cursor;
    memset(&cursor, 0, sizeof cursor);
    RFB_CHECK_EQ_INT(rfb_decode_apple_0450(
                         &cursor, &pf, NULL, k_one_pixel, sizeof k_one_pixel,
                         1024u, rfb_default_allocator()),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(rfb_decode_apple_0450(
                         NULL, &pf, &rh, k_one_pixel, sizeof k_one_pixel,
                         1024u, rfb_default_allocator()),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(rfb_decode_apple_0450(
                         &cursor, NULL, &rh, k_one_pixel, sizeof k_one_pixel,
                         1024u, rfb_default_allocator()),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(rfb_decode_apple_0450(
                         &cursor, &pf, &rh, k_one_pixel, sizeof k_one_pixel,
                         1024u, NULL),
                     RFB_ERR_INTERNAL);

    rfb_allocator missing_alloc = *rfb_default_allocator();
    missing_alloc.alloc = NULL;
    RFB_CHECK_EQ_INT(rfb_decode_apple_0450(
                         &cursor, &pf, &rh, k_one_pixel, sizeof k_one_pixel,
                         1024u, &missing_alloc),
                     RFB_ERR_INTERNAL);
    rfb_allocator missing_free = *rfb_default_allocator();
    missing_free.free = NULL;
    RFB_CHECK_EQ_INT(rfb_decode_apple_0450(
                         &cursor, &pf, &rh, k_one_pixel, sizeof k_one_pixel,
                         1024u, &missing_free),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(rfb_decode_apple_0450(
                         &cursor, &pf, &rh, NULL, 1u, 1024u,
                         rfb_default_allocator()),
                     RFB_ERR_INTERNAL);

    rh.width = 0u;
    RFB_CHECK_EQ_INT(rfb_decode_apple_0450(
                         &cursor, &pf, &rh, k_one_pixel, sizeof k_one_pixel,
                         1024u, rfb_default_allocator()),
                     RFB_ERR_PROTOCOL);
    rh.width = 1u;
    rh.height = 0u;
    RFB_CHECK_EQ_INT(rfb_decode_apple_0450(
                         &cursor, &pf, &rh, k_one_pixel, sizeof k_one_pixel,
                         1024u, rfb_default_allocator()),
                     RFB_ERR_PROTOCOL);
    rh.height = 1u;
    RFB_CHECK_EQ_INT(rfb_decode_apple_0450(
                         &cursor, &pf, &rh, NULL, 0u, 1024u,
                         rfb_default_allocator()),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(rfb_decode_apple_0450(
                         &cursor, &pf, &rh, k_one_pixel, 7u, 1024u,
                         rfb_default_allocator()),
                     RFB_ERR_PROTOCOL);

    rh.encoding = 0;
    RFB_CHECK_EQ_INT(rfb_decode_apple_0450(
                         &cursor, &pf, &rh, k_one_pixel, sizeof k_one_pixel,
                         1024u, rfb_default_allocator()),
                     RFB_ERR_UNSUPPORTED);

    rh.encoding = RFB_ENCODING_APPLE_0450;
    pf.bits_per_pixel = 16u;
    pf.depth = 16u;
    pf.red_max = 31u;
    pf.green_max = 63u;
    pf.blue_max = 31u;
    pf.red_shift = 11u;
    pf.green_shift = 5u;
    pf.blue_shift = 0u;
    RFB_CHECK_EQ_INT(rfb_decode_apple_0450(
                         &cursor, &pf, &rh, k_one_pixel, sizeof k_one_pixel,
                         1024u, rfb_default_allocator()),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK(!cursor.valid);
    RFB_CHECK(cursor.rgba == NULL);
}
