// SPDX-License-Identifier: Apache-2.0
//
// farsee — bounded outbound queue (plan.md §G5, §6.4).

#include "farsee/outbound.h"

void rfb_outbound_init(rfb_outbound *q, rfb_allocator *alloc, size_t hard_limit)
{
    if (q == NULL) {
        return;
    }
    rfb_buffer_init(&q->buf, alloc, hard_limit);
    q->hard_limit = hard_limit;
}

void rfb_outbound_destroy(rfb_outbound *q)
{
    if (q == NULL) {
        return;
    }
    rfb_buffer_destroy(&q->buf);
    q->hard_limit = 0;
}

rfb_error rfb_outbound_append(rfb_outbound *q, const void *data, size_t n)
{
    if (q == NULL) {
        return RFB_ERR_INTERNAL;
    }
    return rfb_buffer_append(&q->buf, data, n);
}

void rfb_outbound_consume(rfb_outbound *q, size_t n)
{
    if (q == NULL) {
        return;
    }
    rfb_buffer_consume(&q->buf, n);
}
