// SPDX-License-Identifier: Apache-2.0
//
// Test-local outbound queue and fake-adapter drain tests (plan.md §14.5).
//
// They cover normal and short writes, blocking with no progress, hard errors,
// and fake-adapter reads. They do not call rfb_io_drain_out or a session loop.

#include "rfb_test.h"
#include "farsee/outbound.h"
#include "farsee/io_adapter.h"
#include "farsee/allocator.h"
#include "fake_io.h"

// Test-local drain helper for rfb_outbound and fake I/O.

// Drain the outbound queue through the adapter. Returns RFB_IO_OK when the
// queue is empty, RFB_IO_BLOCK on EAGAIN (queue advanced by any partial
// write this call), RFB_IO_ERROR on hard error.
static rfb_io_result drain_once(rfb_io_adapter *io, rfb_outbound *q)
{
    while (rfb_outbound_length(q) > 0) {
        size_t n = rfb_outbound_length(q);
        const uint8_t *p = rfb_outbound_data(q);
        size_t wrote = 0;
        rfb_io_result r = io->write(io->ctx, p, n, &wrote);
        if (wrote > 0) {
            rfb_outbound_consume(q, wrote);
        }
        if (r == RFB_IO_BLOCK) {
            return RFB_IO_BLOCK;  // come back later
        }
        if (r == RFB_IO_ERROR) {
            return RFB_IO_ERROR;
        }
        // A successful zero-byte write is treated as blocked to end the loop.
        if (wrote == 0 && r == RFB_IO_OK) {
            return RFB_IO_BLOCK;
        }
    }
    return RFB_IO_OK;
}

// --- normal write: drain 10 bytes in one call ----------------------------

RFB_TEST(io_drain, drain__normal__empties_queue) {
    fake_io f;
    fake_io_init(&f, rfb_default_allocator());
    rfb_io_adapter io = fake_io_adapter_make(&f);
    rfb_outbound q;
    rfb_outbound_init(&q, rfb_default_allocator(), 1024);
    static const uint8_t data[10] = { 1,2,3,4,5,6,7,8,9,10 };
    rfb_outbound_append(&q, data, sizeof data);
    RFB_CHECK_EQ_INT(drain_once(&io, &q), RFB_IO_OK);
    RFB_CHECK_EQ_UINT(rfb_outbound_length(&q), 0u);
    RFB_CHECK_EQ_UINT(fake_io_outbox_len(&f), 10u);
    RFB_CHECK_MEM_EQ(fake_io_outbox_data(&f), data, 10);
    rfb_outbound_destroy(&q);
    fake_io_destroy(&f);
}

// --- one-byte short writes: one drain call loops until empty -------------

RFB_TEST(io_drain, drain__short_write_one_byte__eventually_empties) {
    fake_io f;
    fake_io_init(&f, rfb_default_allocator());
    f.wmode = FAKE_W_SHORT;
    f.short_n = 1;
    rfb_io_adapter io = fake_io_adapter_make(&f);
    rfb_outbound q;
    rfb_outbound_init(&q, rfb_default_allocator(), 1024);
    static const uint8_t data[5] = { 10,20,30,40,50 };
    rfb_outbound_append(&q, data, sizeof data);
    // drain_once performs repeated one-byte writes and returns once empty.
    for (int i = 0; i < 10; i++) {
        rfb_io_result r = drain_once(&io, &q);
        if (r == RFB_IO_OK) break;
        RFB_CHECK(r == RFB_IO_OK);  // no errors expected
    }
    RFB_CHECK_EQ_UINT(rfb_outbound_length(&q), 0u);
    RFB_CHECK_EQ_UINT(fake_io_outbox_len(&f), 5u);
    RFB_CHECK_MEM_EQ(fake_io_outbox_data(&f), data, 5);
    rfb_outbound_destroy(&q);
    fake_io_destroy(&f);
}

// --- EAGAIN mid-drain: queue preserves unconsumed bytes -----------------

RFB_TEST(io_drain, drain__eagain__preserves_queue) {
    fake_io f;
    fake_io_init(&f, rfb_default_allocator());
    f.wmode = FAKE_W_EAGAIN;
    rfb_io_adapter io = fake_io_adapter_make(&f);
    rfb_outbound q;
    rfb_outbound_init(&q, rfb_default_allocator(), 1024);
    static const uint8_t data[4] = { 7,7,7,7 };
    rfb_outbound_append(&q, data, sizeof data);
    RFB_CHECK_EQ_INT(drain_once(&io, &q), RFB_IO_BLOCK);
    RFB_CHECK_EQ_UINT(rfb_outbound_length(&q), 4u);  // nothing consumed
    RFB_CHECK_EQ_UINT(fake_io_outbox_len(&f), 0u);
    // Now switch to normal and drain the rest.
    f.wmode = FAKE_W_NORMAL;
    RFB_CHECK_EQ_INT(drain_once(&io, &q), RFB_IO_OK);
    RFB_CHECK_EQ_UINT(fake_io_outbox_len(&f), 4u);
    rfb_outbound_destroy(&q);
    fake_io_destroy(&f);
}

// --- fixed two-byte short writes drain in one call -----------------------

RFB_TEST(io_drain, drain__two_byte_short_writes__drain_in_one_call) {
    fake_io f;
    fake_io_init(&f, rfb_default_allocator());
    // Each fake write accepts at most two bytes.
    f.wmode = FAKE_W_SHORT;
    f.short_n = 2;
    rfb_io_adapter io = fake_io_adapter_make(&f);
    rfb_outbound q;
    rfb_outbound_init(&q, rfb_default_allocator(), 1024);
    static const uint8_t data[6] = { 1,2,3,4,5,6 };
    rfb_outbound_append(&q, data, sizeof data);
    // drain_once loops over three two-byte writes and empties the six-byte queue.
    // This fake cannot switch to EAGAIN between writes, so this case does not
    // exercise partial progress followed by blocking.
    RFB_CHECK_EQ_INT(drain_once(&io, &q), RFB_IO_OK);
    RFB_CHECK_EQ_UINT(fake_io_outbox_len(&f), 6u);
    rfb_outbound_destroy(&q);
    fake_io_destroy(&f);
}

// --- hard write error ---------------------------------------------------

RFB_TEST(io_drain, drain__hard_error__returns_error) {
    fake_io f;
    fake_io_init(&f, rfb_default_allocator());
    f.wmode = FAKE_W_ERROR;
    rfb_io_adapter io = fake_io_adapter_make(&f);
    rfb_outbound q;
    rfb_outbound_init(&q, rfb_default_allocator(), 1024);
    static const uint8_t data[3] = { 1,2,3 };
    rfb_outbound_append(&q, data, sizeof data);
    RFB_CHECK_EQ_INT(drain_once(&io, &q), RFB_IO_ERROR);
    RFB_CHECK_EQ_UINT(rfb_outbound_length(&q), 3u);  // nothing consumed
    rfb_outbound_destroy(&q);
    fake_io_destroy(&f);
}

// --- read with EOF -------------------------------------------------------

RFB_TEST(io_drain, read__empty_inbox_eof__returns_eof) {
    fake_io f;
    fake_io_init(&f, rfb_default_allocator());
    rfb_io_adapter io = fake_io_adapter_make(&f);
    uint8_t buf[16];
    size_t n = 99;
    RFB_CHECK_EQ_INT(io.read(io.ctx, buf, sizeof buf, &n), RFB_IO_EOF);
    RFB_CHECK_EQ_UINT(n, 0u);
    fake_io_destroy(&f);
}

// --- read with data ------------------------------------------------------

RFB_TEST(io_drain, read__seeded_inbox__returns_bytes) {
    fake_io f;
    fake_io_init(&f, rfb_default_allocator());
    static const uint8_t msg[4] = { 0xAA, 0xBB, 0xCC, 0xDD };
    fake_io_seed_inbox(&f, msg, sizeof msg);
    rfb_io_adapter io = fake_io_adapter_make(&f);
    uint8_t buf[16] = { 0 };
    size_t n = 0;
    RFB_CHECK_EQ_INT(io.read(io.ctx, buf, sizeof buf, &n), RFB_IO_OK);
    RFB_CHECK_EQ_UINT(n, 4u);
    RFB_CHECK_MEM_EQ(buf, msg, 4);
    fake_io_destroy(&f);
}
