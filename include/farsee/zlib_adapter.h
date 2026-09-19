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

#include "farsee/allocator.h"
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

// Allocator-aware form. The allocator is borrowed and must outlive the
// stream. It owns the wrapper object and first-party scratch storage.
rfb_zlib_stream *rfb_zlib_create_with_allocator(rfb_allocator *allocator);

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

// Validate the exact output size of one independent zlib stream without
// retaining dictionary state or exposing its output. This proves full input
// consumption and expansion size, but not the caller's framing endpoint: a
// format using Z_SYNC_FLUSH must validate its own flush boundary separately.
rfb_error rfb_zlib_validate_independent_exact_output(
    const uint8_t *in, size_t in_len, size_t expected_out_len);

// Inflate one independent stream into an exact caller-owned destination.
// Full input consumption and exact output size are required. No dictionary
// state is retained. The caller validates any format-specific stream suffix.
rfb_error rfb_zlib_inflate_independent_exact_output(
    const uint8_t *in, size_t in_len, uint8_t *out, size_t out_len);

// Grow-only scratch buffer owned by the stream.
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
