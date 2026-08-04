// SPDX-License-Identifier: Apache-2.0
//
// farsee — zlib adapter for ZRLE (plan.md §G8).
//
// Wraps the zlib inflate API behind a clean interface so the RFB protocol
// core never calls zlib directly. ZRLE requires one persistent zlib stream
// per RFB connection (RFC 6143 §7.7.6); the adapter manages that stream's
// lifecycle and exposes inflate + reset operations.
//
// zlib is licensed under the zlib license (plan.md §5.4 allowlist).
// See THIRD_PARTY_NOTICES.md.

#ifndef FARSEE_INCLUDE_FARSEE_ZLIB_ADAPTER_H
#define FARSEE_INCLUDE_FARSEE_ZLIB_ADAPTER_H

#include "farsee/error.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Opaque zlib stream state.
typedef struct rfb_zlib_stream rfb_zlib_stream;

// Allocate a new zlib inflate stream. Returns NULL on failure.
// The stream is persistent across ZRLE rectangles (RFC 6143 §7.7.6).
rfb_zlib_stream *rfb_zlib_create(void);

// Release the stream and its resources. Safe on NULL.
void rfb_zlib_destroy(rfb_zlib_stream *s);

// Inflate (decompress) `in_len` bytes of `in` into `out` (capacity
// `out_cap`). Sets `*out_len` to the number of decompressed bytes.
// The stream state persists across calls, so multi-rectangle ZRLE
// streams share compression context.
// Returns RFB_OK on success, RFB_ERR_PROTOCOL on a zlib error, RFB_ERR_LIMIT
// if the output would exceed `out_cap`.
rfb_error rfb_zlib_inflate(rfb_zlib_stream *s,
                           const uint8_t *in, size_t in_len,
                           uint8_t *out, size_t out_cap, size_t *out_len);

// Reset the stream (e.g. on session reset). The next inflate starts fresh.
rfb_error rfb_zlib_reset(rfb_zlib_stream *s);

// Grow-only scratch buffer owned by the stream (multi-review 2026-08-03 T1).
// Ensures capacity >= need (never shrinks). Returns pointer or NULL on OOM.
// Lifetime: until rfb_zlib_destroy. Used by ZRLE so each rect does not
// malloc the full policy byte_limit (often 256 MiB).
uint8_t *rfb_zlib_ensure_scratch(rfb_zlib_stream *s, size_t need);

// Current scratch capacity (0 if none). Test / diagnostic seam.
size_t rfb_zlib_scratch_cap(const rfb_zlib_stream *s);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_ZLIB_ADAPTER_H
