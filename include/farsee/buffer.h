// SPDX-License-Identifier: Apache-2.0
//
// farsee — growable byte buffer with a hard limit (plan.md §G1, §6.3).
//
// The buffer is the substrate for the input and output queues. It grows
// geometrically up to a configured hard limit; beyond that, appends fail
// with RFB_ERR_LIMIT (never silently grow unboundedly). The allocator is
// injectable so allocation-failure tests (plan.md §14.6) can drive every
// growth path.

#ifndef FARSEE_INCLUDE_FARSEE_BUFFER_H
#define FARSEE_INCLUDE_FARSEE_BUFFER_H

#include "farsee/allocator.h"
#include "farsee/error.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rfb_buffer {
    rfb_allocator *alloc;
    uint8_t *data;
    size_t length;     // bytes currently in use
    size_t capacity;   // allocated bytes
    size_t hard_limit; // never grow beyond this; appends fail with RFB_ERR_LIMIT
} rfb_buffer;

// Initialize an empty buffer with the given allocator and hard limit.
// Does not allocate; the first append allocates the initial capacity.
void rfb_buffer_init(rfb_buffer *b, rfb_allocator *alloc, size_t hard_limit);

// Release the backing storage. Safe to call on a zero-initialized buffer
// or after a failed init. After destroy, the buffer is safe to re-init.
void rfb_buffer_destroy(rfb_buffer *b);

// Append n bytes. Returns RFB_ERR_LIMIT if the result would exceed the
// hard limit, RFB_ERR_NOMEM on allocation failure (the buffer's prior
// contents are preserved on either failure). Returns RFB_OK on success.
rfb_error rfb_buffer_append(rfb_buffer *b, const void *data, size_t n);

// Insert n bytes at the front (multi-review deferred D2: home CSI before
// APC in one buffer). Same limit/OOM contract as append.
rfb_error rfb_buffer_prepend(rfb_buffer *b, const void *data, size_t n);

// Drop the first n bytes (consume from the front). If n >= length, the
// buffer becomes empty (storage is retained for reuse).
void rfb_buffer_consume(rfb_buffer *b, size_t n);

// Clear the buffer to length zero without releasing storage.
void rfb_buffer_clear(rfb_buffer *b);

// Shrink length to n (no free). No-op if n >= length. For encode rollback
// to a pre-append mark without wiping prior residual (loop 61434470 r5).
void rfb_buffer_truncate(rfb_buffer *b, size_t n);

// Reserve at least cap bytes of capacity. Returns RFB_ERR_LIMIT/RFB_ERR_NOMEM
// without modifying the buffer on failure.
rfb_error rfb_buffer_reserve(rfb_buffer *b, size_t cap);

// Number of bytes currently stored.
static inline size_t rfb_buffer_length(const rfb_buffer *b)
{
    return b != NULL ? b->length : 0;
}

// Const pointer to the front of the stored bytes (NULL if empty).
static inline const uint8_t *rfb_buffer_data(const rfb_buffer *b)
{
    return b != NULL ? b->data : NULL;
}

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_BUFFER_H
