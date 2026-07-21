// SPDX-License-Identifier: Apache-2.0
//
// farsee — fake I/O adapter implementation (test-only).

#include "fake_io.h"

#include <string.h>

void fake_io_init(fake_io *f, rfb_allocator *alloc)
{
    memset(f, 0, sizeof *f);
    rfb_buffer_init(&f->inbox, alloc, 1u << 20);
    rfb_buffer_init(&f->outbox, alloc, 1u << 20);
    f->wmode = FAKE_W_NORMAL;
    f->short_n = 1;
    f->eof_on_empty_read = true;
    f->connected = true;
}

void fake_io_destroy(fake_io *f)
{
    if (f == NULL) {
        return;
    }
    rfb_buffer_destroy(&f->inbox);
    rfb_buffer_destroy(&f->outbox);
}

void fake_io_seed_inbox(fake_io *f, const void *data, size_t n)
{
    (void)rfb_buffer_append(&f->inbox, data, n);
}

const uint8_t *fake_io_outbox_data(const fake_io *f)
{
    return rfb_buffer_data(&f->outbox);
}

size_t fake_io_outbox_len(const fake_io *f)
{
    return rfb_buffer_length(&f->outbox);
}

static rfb_io_result fake_connect(void *ctx, const rfb_io_candidate *c)
{
    fake_io *f = (fake_io *)ctx;
    (void)c;
    f->connected = true;
    return RFB_IO_OK;
}

static rfb_io_result fake_read(void *ctx, uint8_t *buf, size_t n, size_t *out_n)
{
    fake_io *f = (fake_io *)ctx;
    size_t avail = rfb_buffer_length(&f->inbox);
    if (avail == 0) {
        *out_n = 0;
        return f->eof_on_empty_read ? RFB_IO_EOF : RFB_IO_BLOCK;
    }
    size_t take = n < avail ? n : avail;
    memcpy(buf, rfb_buffer_data(&f->inbox), take);
    rfb_buffer_consume(&f->inbox, take);
    *out_n = take;
    return RFB_IO_OK;
}

static rfb_io_result fake_write(void *ctx, const uint8_t *buf, size_t n, size_t *out_n)
{
    fake_io *f = (fake_io *)ctx;
    switch (f->wmode) {
    case FAKE_W_EAGAIN:
        *out_n = 0;
        return RFB_IO_BLOCK;
    case FAKE_W_ERROR:
        *out_n = 0;
        return RFB_IO_ERROR;
    case FAKE_W_SHORT: {
        size_t w = f->short_n < n ? f->short_n : n;
        rfb_error e = rfb_buffer_append(&f->outbox, buf, w);
        if (e != RFB_OK) {
            *out_n = 0;
            return RFB_IO_ERROR;
        }
        *out_n = w;
        return RFB_IO_OK;
    }
    case FAKE_W_NORMAL:
    default: {
        rfb_error e = rfb_buffer_append(&f->outbox, buf, n);
        if (e != RFB_OK) {
            *out_n = 0;
            return RFB_IO_ERROR;
        }
        *out_n = n;
        return RFB_IO_OK;
    }
    }
}

static void fake_close(void *ctx)
{
    fake_io *f = (fake_io *)ctx;
    f->connected = false;
}

rfb_io_adapter fake_io_adapter_make(fake_io *f)
{
    rfb_io_adapter a;
    a.ctx = f;
    a.connect = fake_connect;
    a.read = fake_read;
    a.write = fake_write;
    a.close = fake_close;
    return a;
}
