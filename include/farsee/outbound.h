// SPDX-License-Identifier: Apache-2.0
//
// farsee — bounded outbound queue (plan.md §G5, §6.3, §6.4).
//
// The outbound queue holds bytes the client wants to send to the server
// (handshake, SetPixelFormat, KeyEvent, PointerEvent, etc.). It is
// bounded by a hard byte limit (plan.md §6.4: "queued outbound bytes: 8
// MiB"). Callers remove only bytes reported written; unconsumed bytes
// remain queued in order after a short write.

#ifndef FARSEE_INCLUDE_FARSEE_OUTBOUND_H
#define FARSEE_INCLUDE_FARSEE_OUTBOUND_H

#include "farsee/buffer.h"
#include "farsee/error.h"

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rfb_outbound {
    rfb_buffer buf;   // the queued bytes
    size_t hard_limit;
} rfb_outbound;

void rfb_outbound_init(rfb_outbound *q, rfb_allocator *alloc, size_t hard_limit);
void rfb_outbound_destroy(rfb_outbound *q);

// Append bytes to the queue. Returns RFB_ERR_LIMIT if the result would
// exceed the hard limit (the queue is unchanged).
rfb_error rfb_outbound_append(rfb_outbound *q, const void *data, size_t n);

// Number of bytes currently queued.
static inline size_t rfb_outbound_length(const rfb_outbound *q)
{
    return q != NULL ? rfb_buffer_length(&q->buf) : 0;
}

// Pointer to the front of the queued bytes (NULL if empty).
static inline const uint8_t *rfb_outbound_data(const rfb_outbound *q)
{
    return q != NULL ? rfb_buffer_data(&q->buf) : NULL;
}

// Drop the first n bytes after a (possibly short) write. If n >= length,
// the queue becomes empty.
void rfb_outbound_consume(rfb_outbound *q, size_t n);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_OUTBOUND_H
