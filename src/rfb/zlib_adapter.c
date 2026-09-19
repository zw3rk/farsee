// SPDX-License-Identifier: Apache-2.0
//
// farsee — zlib adapter for ZRLE (plan.md §G8, RFC 6143 §7.7.6).
//
// Wraps zlib's inflate API behind the rfb_zlib_stream interface so the
// protocol core never calls zlib directly. The stream persists across
// ZRLE rectangles within a single RFB connection.

#include "farsee/zlib_adapter.h"

#include <zlib.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct rfb_zlib_stream {
    rfb_allocator *allocator;
    z_stream zs;
    bool initialized;
    // Grow-only inflate scratch for ZRLE.
    // Avoids per-rect 256 MiB malloc against the hard byte_limit.
    uint8_t *scratch;
    size_t scratch_cap;
};

rfb_zlib_stream *rfb_zlib_create(void)
{
    return rfb_zlib_create_with_allocator(rfb_default_allocator());
}

rfb_zlib_stream *rfb_zlib_create_with_allocator(rfb_allocator *allocator)
{
    if (allocator == NULL || allocator->alloc == NULL ||
        allocator->free == NULL) {
        return NULL;
    }
    rfb_zlib_stream *s =
        (rfb_zlib_stream *)allocator->alloc(allocator, sizeof *s);
    if (s == NULL) {
        return NULL;
    }
    memset(s, 0, sizeof *s);
    s->allocator = allocator;
    // Initialize for inflation (decompression).
    if (inflateInit(&s->zs) != Z_OK) {
        allocator->free(allocator, s);
        return NULL;
    }
    s->initialized = true;
    return s;
}

void rfb_zlib_destroy(rfb_zlib_stream *s)
{
    if (s == NULL) {
        return;
    }
    if (s->initialized) {
        inflateEnd(&s->zs);
    }
    if (s->scratch != NULL) {
        s->allocator->free(s->allocator, s->scratch);
    }
    s->scratch = NULL;
    s->scratch_cap = 0;
    s->allocator->free(s->allocator, s);
}

uint8_t *rfb_zlib_ensure_scratch(rfb_zlib_stream *s, size_t need)
{
    if (s == NULL || need == 0u) {
        return NULL;
    }
    if (s->scratch != NULL && s->scratch_cap >= need) {
        return s->scratch;
    }
    // Grow geometrically; never shrink (reuse across rectangles).
    size_t cap = s->scratch_cap > 0u ? s->scratch_cap : 4096u;
    while (cap < need) {
        if (cap > (SIZE_MAX / 2u)) {
            cap = need;
            break;
        }
        cap *= 2u;
    }
    if (cap < need) {
        cap = need;
    }
    uint8_t *nbuf = (uint8_t *)rfb_allocator_realloc(
        s->allocator, s->scratch, s->scratch_cap, cap);
    if (nbuf == NULL) {
        return NULL;
    }
    s->scratch = nbuf;
    s->scratch_cap = cap;
    return s->scratch;
}

size_t rfb_zlib_scratch_cap(const rfb_zlib_stream *s)
{
    return s != NULL ? s->scratch_cap : 0u;
}

rfb_error rfb_zlib_inflate(rfb_zlib_stream *s,
                           const uint8_t *in, size_t in_len,
                           uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (s == NULL || in == NULL || out == NULL || out_len == NULL) {
        return RFB_ERR_INTERNAL;
    }
    if (!s->initialized) {
        return RFB_ERR_INTERNAL;
    }
    *out_len = 0;
    s->zs.next_in = (Bytef *)(uintptr_t)in;  // zlib wants non-const; we don't write to it
    s->zs.avail_in = (uInt)in_len;
    s->zs.next_out = (Bytef *)out;
    s->zs.avail_out = (uInt)out_cap;

    // Use Z_SYNC_FLUSH for intermediate rectangles and Z_FINISH for the
    // final one. Since we don't know if this is the last rectangle, use
    // Z_SYNC_FLUSH; if the compressed data was created with Z_FINISH,
    // inflate returns Z_STREAM_END and we auto-reset for the next rect.
    int rc = inflate(&s->zs, Z_SYNC_FLUSH);
    *out_len = (size_t)(out_cap - s->zs.avail_out);

    if (rc == Z_OK) {
        // More data may follow in this stream.
        if (*out_len == 0 && s->zs.avail_in > 0) {
            // Didn't produce output but have input left → need Z_FINISH.
            rc = inflate(&s->zs, Z_FINISH);
            *out_len = (size_t)(out_cap - s->zs.avail_out);
        }
    }

    if (rc == Z_OK || rc == Z_STREAM_END) {
        // If the output buffer was completely filled and there's still
        // input remaining, the output was truncated → LIMIT.
        if (s->zs.avail_out == 0 && s->zs.avail_in > 0) {
            if (rc == Z_STREAM_END) {
                inflateReset(&s->zs);
            }
            return RFB_ERR_LIMIT;
        }
        if (rc == Z_STREAM_END) {
            inflateReset(&s->zs);
        }
        return RFB_OK;
    }
    if (rc == Z_BUF_ERROR && *out_len == out_cap) {
        // Output buffer was exactly filled but stream isn't done → need more space.
        return RFB_ERR_LIMIT;
    }
    if (rc == Z_BUF_ERROR) {
        // No progress possible (input consumed, no output expected).
        return RFB_ERR_PROTOCOL;
    }
    // Z_DATA_ERROR, Z_MEM_ERROR, etc.
    return RFB_ERR_PROTOCOL;
}

rfb_error rfb_zlib_reset(rfb_zlib_stream *s)
{
    if (s == NULL || !s->initialized) {
        return RFB_ERR_INTERNAL;
    }
    if (inflateReset(&s->zs) != Z_OK) {
        return RFB_ERR_INTERNAL;
    }
    return RFB_OK;
}

static rfb_error inflate_independent_exact(const uint8_t *in, size_t in_len,
                                           uint8_t *out,
                                           size_t expected_out_len)
{
    if (in == NULL || in_len == 0u || expected_out_len == 0u) {
        return RFB_ERR_INTERNAL;
    }
    if (in_len > UINT_MAX) {
        return RFB_ERR_LIMIT;
    }

    z_stream zs;
    memset(&zs, 0, sizeof zs);
    if (inflateInit(&zs) != Z_OK) {
        return RFB_ERR_INTERNAL;
    }
    zs.next_in = (Bytef *)(uintptr_t)in;
    zs.avail_in = (uInt)in_len;

    uint8_t scratch[4096];
    size_t produced_total = 0u;
    rfb_error result = RFB_ERR_PROTOCOL;
    for (;;) {
        zs.next_out = scratch;
        zs.avail_out = (uInt)sizeof scratch;
        const uInt before_in = zs.avail_in;
        const int rc = inflate(&zs, Z_SYNC_FLUSH);
        const size_t produced = sizeof scratch - (size_t)zs.avail_out;
        if (produced > SIZE_MAX - produced_total) {
            result = RFB_ERR_LIMIT;
            break;
        }
        produced_total += produced;
        if (produced_total > expected_out_len) {
            result = RFB_ERR_PROTOCOL;
            break;
        }
        if (out != NULL && produced > 0u) {
            memcpy(out + produced_total - produced, scratch, produced);
        }

        if (rc == Z_STREAM_END) {
            result = (zs.avail_in == 0u && produced_total == expected_out_len)
                         ? RFB_OK
                         : RFB_ERR_PROTOCOL;
            break;
        }
        if (rc == Z_OK) {
            if (zs.avail_in == 0u && zs.avail_out != 0u) {
                result = (produced_total == expected_out_len)
                             ? RFB_OK
                             : RFB_ERR_PROTOCOL;
                break;
            }
            if (produced == 0u && zs.avail_in == before_in) {
                result = RFB_ERR_PROTOCOL;
                break;
            }
            continue;
        }
        if (rc == Z_BUF_ERROR && zs.avail_in == 0u) {
            result = (produced_total == expected_out_len)
                         ? RFB_OK
                         : RFB_ERR_PROTOCOL;
            break;
        }
        result = RFB_ERR_PROTOCOL;
        break;
    }

    (void)inflateEnd(&zs);
    return result;
}

rfb_error rfb_zlib_validate_independent_exact_output(
    const uint8_t *in, size_t in_len, size_t expected_out_len)
{
    return inflate_independent_exact(in, in_len, NULL, expected_out_len);
}

rfb_error rfb_zlib_inflate_independent_exact_output(
    const uint8_t *in, size_t in_len, uint8_t *out, size_t out_len)
{
    if (out == NULL) {
        return RFB_ERR_INTERNAL;
    }
    return inflate_independent_exact(in, in_len, out, out_len);
}
