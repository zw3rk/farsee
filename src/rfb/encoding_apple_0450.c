// SPDX-License-Identifier: Apache-2.0
//
// Apple private 0x0450 alpha-cursor decoder.

#include "farsee/encoding_apple_0450.h"

#include "farsee/checked.h"
#include "farsee/pixel_convert.h"
#include "farsee/zlib_adapter.h"

#include <string.h>

static uint32_t be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static uint8_t unpremultiply(uint8_t component, uint8_t alpha)
{
    if (alpha == 0u) {
        return 0u;
    }
    const uint32_t value =
        ((uint32_t)component * 255u + (uint32_t)alpha / 2u) /
        (uint32_t)alpha;
    return (uint8_t)value;
}

rfb_error rfb_decode_apple_0450(rfb_cursor *cursor,
                                const rfb_pixel_format *pf,
                                const rfb_rect_header *rh,
                                const uint8_t *payload, size_t payload_len,
                                size_t byte_limit, rfb_allocator *alloc)
{
    if (cursor == NULL || pf == NULL || rh == NULL || alloc == NULL ||
        alloc->alloc == NULL || alloc->free == NULL ||
        (payload == NULL && payload_len != 0u)) {
        return RFB_ERR_INTERNAL;
    }
    memset(cursor, 0, sizeof *cursor);
    if (rh->encoding != (int32_t)RFB_ENCODING_APPLE_0450) {
        return RFB_ERR_UNSUPPORTED;
    }
    if (rh->width == 0u || rh->height == 0u || payload == NULL ||
        payload_len < 8u || !rfb_pixel_format_is_canonical(pf)) {
        return RFB_ERR_PROTOCOL;
    }

    // The supported profile requires 1000 in the first field. Accepting any
    // other value would assert an unsupported envelope variant.
    if (be32(payload) != APPLE_0450_PROFILE_PARAMETER) {
        return RFB_ERR_PROTOCOL;
    }
    const uint32_t compressed_len = be32(payload + 4u);
    if ((size_t)compressed_len != payload_len - 8u || compressed_len == 0u) {
        return RFB_ERR_PROTOCOL;
    }
    if ((size_t)compressed_len > byte_limit) {
        return RFB_ERR_LIMIT;
    }
    // Each body is an independent Z_SYNC_FLUSH record without a zlib EOF
    // marker. Requiring the flush tail rejects an incomplete next block
    // hidden after otherwise valid output.
    if (compressed_len < 4u ||
        memcmp(payload + payload_len - 4u, "\x00\x00\xff\xff", 4u) != 0) {
        return RFB_ERR_PROTOCOL;
    }

    size_t pixel_count = 0u;
    if (!rfb_checked_mul_size((size_t)rh->width, (size_t)rh->height,
                              &pixel_count)) {
        return RFB_ERR_LIMIT;
    }
    size_t expected = 0u;
    if (!rfb_checked_mul_size(pixel_count,
                              APPLE_0450_EXPANDED_BYTES_PER_PIXEL,
                              &expected)) {
        return RFB_ERR_LIMIT;
    }
    if (expected > byte_limit) {
        return RFB_ERR_LIMIT;
    }

    uint8_t *expanded = (uint8_t *)alloc->alloc(alloc, expected);
    if (expanded == NULL) {
        return RFB_ERR_NOMEM;
    }
    // A fresh stream is required because each body has its own zlib header and
    // must not alter the connection's persistent ZRLE dictionary.
    rfb_error result = rfb_zlib_inflate_independent_exact_output(
        payload + 8u, (size_t)compressed_len, expanded, expected);
    if (result != RFB_OK) {
        alloc->free(alloc, expanded);
        return result;
    }

    size_t rgba_bytes = 0u;
    if (!rfb_checked_mul_size(pixel_count, RFB_BPP_CANONICAL, &rgba_bytes)) {
        alloc->free(alloc, expanded);
        return RFB_ERR_LIMIT;
    }
    uint8_t *rgba = (uint8_t *)alloc->alloc(alloc, rgba_bytes);
    if (rgba == NULL) {
        alloc->free(alloc, expanded);
        return RFB_ERR_NOMEM;
    }

    const uint8_t *alpha = expanded + rgba_bytes;
    for (size_t i = 0u; i < pixel_count; i++) {
        uint8_t converted[4] = {0u, 0u, 0u, 0u};
        rfb_pixel_to_rgba8(pf, expanded + i * 4u, converted);
        const uint8_t a = alpha[i];
        if (expanded[i * 4u + 3u] != 0u || converted[0] > a ||
            converted[1] > a || converted[2] > a) {
            result = RFB_ERR_PROTOCOL;
            break;
        }
        rgba[i * 4u] = unpremultiply(converted[0], a);
        rgba[i * 4u + 1u] = unpremultiply(converted[1], a);
        rgba[i * 4u + 2u] = unpremultiply(converted[2], a);
        rgba[i * 4u + 3u] = a;
    }
    alloc->free(alloc, expanded);
    if (result != RFB_OK) {
        alloc->free(alloc, rgba);
        return result;
    }

    cursor->hotspot_x = rh->x;
    cursor->hotspot_y = rh->y;
    cursor->width = rh->width;
    cursor->height = rh->height;
    cursor->rgba = rgba;
    cursor->valid = true;
    return RFB_OK;
}
