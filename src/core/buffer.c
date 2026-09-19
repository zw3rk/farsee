// SPDX-License-Identifier: Apache-2.0
//
// farsee — growable byte buffer with a hard limit.
//
// Growth is geometric (next-capacity = capacity * 2, with a small initial
// floor) and never exceeds the configured hard limit. Allocation failure
// during growth is transactional: the old buffer and its contents survive.

#include "farsee/buffer.h"

#include <stdlib.h>
#include <string.h>

// The initial allocation when the first byte is appended. Small enough
// to be cheap for small messages; the geometric growth takes over for
// larger transfers.
#define RFB_BUFFER_INITIAL_CAPACITY 256u

void rfb_buffer_init(rfb_buffer *b, rfb_allocator *alloc, size_t hard_limit)
{
    if (b == NULL) {
        return;
    }
    b->alloc       = alloc;
    b->data        = NULL;
    b->length      = 0;
    b->capacity    = 0;
    b->hard_limit  = hard_limit;
}

void rfb_buffer_destroy(rfb_buffer *b)
{
    if (b == NULL) {
        return;
    }
    if (b->alloc != NULL && b->alloc->free != NULL && b->data != NULL) {
        b->alloc->free(b->alloc, b->data);
    }
    b->data     = NULL;
    b->length   = 0;
    b->capacity = 0;
}

// Compute the next capacity >= needed, bounded by hard_limit. Returns
// false if needed > hard_limit (caller turns that into RFB_ERR_LIMIT).
static bool next_capacity(size_t current, size_t needed, size_t hard_limit,
                          size_t *out)
{
    if (needed > hard_limit) {
        return false;
    }
    size_t cap = current;
    if (cap < RFB_BUFFER_INITIAL_CAPACITY) {
        cap = RFB_BUFFER_INITIAL_CAPACITY;
    }
    while (cap < needed) {
        // Geometric growth, guarded against overflow.
        if (cap > hard_limit / 2) {
            cap = hard_limit;  // can't double within limit; use the limit
            break;
        }
        cap *= 2;
    }
    if (cap > hard_limit) {
        cap = hard_limit;
    }
    if (cap < needed) {
        return false;  // shouldn't happen (needed <= hard_limit) but be safe
    }
    *out = cap;
    return true;
}

rfb_error rfb_buffer_reserve(rfb_buffer *b, size_t cap)
{
    if (b == NULL) {
        return RFB_ERR_INTERNAL;
    }
    if (cap <= b->capacity) {
        return RFB_OK;  // already have it
    }
    if (cap > b->hard_limit) {
        return RFB_ERR_LIMIT;
    }
    if (b->alloc == NULL || b->alloc->alloc == NULL) {
        return RFB_ERR_INTERNAL;
    }
    // Grow via alloc+copy+free so the injectable allocator sees every
    // growth as a single allocation.
    uint8_t *p = (uint8_t *)b->alloc->alloc(b->alloc, cap);
    if (p == NULL) {
        return RFB_ERR_NOMEM;  // old buffer intact
    }
    if (b->data != NULL && b->length > 0) {
        memcpy(p, b->data, b->length);
    }
    if (b->data != NULL && b->alloc->free != NULL) {
        b->alloc->free(b->alloc, b->data);
    }
    b->data     = p;
    b->capacity = cap;
    return RFB_OK;
}

rfb_error rfb_buffer_append(rfb_buffer *b, const void *data, size_t n)
{
    if (b == NULL) {
        return RFB_ERR_INTERNAL;
    }
    if (n == 0) {
        return RFB_OK;
    }
    if (data == NULL) {
        return RFB_ERR_PROTOCOL;  // non-zero append from NULL is a bug
    }
    // Hard-limit check FIRST, before any allocation: the boundary tests
    // rely on RFB_ERR_LIMIT at limit+1 even when growth hasn't happened.
    if (n > b->hard_limit - b->length) {
        return RFB_ERR_LIMIT;
    }
    if (b->length + n > b->capacity) {
        size_t cap;
        if (!next_capacity(b->capacity, b->length + n, b->hard_limit, &cap)) {
            return RFB_ERR_LIMIT;
        }
        rfb_error e = rfb_buffer_reserve(b, cap);
        if (e != RFB_OK) {
            return e;  // RFB_ERR_NOMEM; old contents preserved
        }
    }
    memcpy(b->data + b->length, data, n);
    b->length += n;
    return RFB_OK;
}

rfb_error rfb_buffer_prepend(rfb_buffer *b, const void *data, size_t n)
{
    if (b == NULL) {
        return RFB_ERR_INTERNAL;
    }
    if (n == 0) {
        return RFB_OK;
    }
    if (data == NULL) {
        return RFB_ERR_PROTOCOL;
    }
    if (n > b->hard_limit - b->length) {
        return RFB_ERR_LIMIT;
    }
    if (b->length + n > b->capacity) {
        size_t cap;
        if (!next_capacity(b->capacity, b->length + n, b->hard_limit, &cap)) {
            return RFB_ERR_LIMIT;
        }
        rfb_error e = rfb_buffer_reserve(b, cap);
        if (e != RFB_OK) {
            return e;
        }
    }
    if (b->length > 0u) {
        memmove(b->data + n, b->data, b->length);
    }
    memcpy(b->data, data, n);
    b->length += n;
    return RFB_OK;
}

void rfb_buffer_consume(rfb_buffer *b, size_t n)
{
    if (b == NULL) {
        return;
    }
    if (n >= b->length) {
        b->length = 0;
        return;
    }
    // Guard against inconsistent state (data==NULL with length>0).
    if (b->data == NULL) {
        b->length = 0;
        return;
    }
    // Shift remaining bytes to the front so data always starts at offset 0.
    memmove(b->data, b->data + n, b->length - n);
    b->length -= n;
}

void rfb_buffer_clear(rfb_buffer *b)
{
    if (b != NULL) {
        b->length = 0;
    }
}

void rfb_buffer_truncate(rfb_buffer *b, size_t n)
{
    if (b != NULL && n < b->length) {
        b->length = n;
    }
}
