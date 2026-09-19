// SPDX-License-Identifier: Apache-2.0
//
// Deadline tests for RFB I/O pump receive loops.
// A pipe with no readable data exercises RFB_ERR_TIMEOUT handling.

#include "rfb_test.h"
#include "farsee/rfb_io_pump.h"
#include "farsee/buffer.h"
#include "farsee/allocator.h"
#include "farsee/error.h"
#include "farsee/server_init.h"
#include "fake_io.h"

#include <string.h>
#include <unistd.h>

// Build a pump whose poll fd is an empty pipe and whose fake adapter blocks.
// Past and short-future deadlines return TIMEOUT before the iteration cap.

static void make_silent_pump(fake_io *f, rfb_io_adapter *io, rfb_buffer *in,
                             rfb_buffer *out, rfb_io_pump *p, int pipe_rd,
                             uint64_t deadline_mono_ms)
{
    fake_io_init(f, rfb_default_allocator());
    f->eof_on_empty_read = false; // BLOCK, not EOF, when empty
    *io = fake_io_adapter_make(f);
    rfb_buffer_init(in, rfb_default_allocator(), 4096);
    rfb_buffer_init(out, rfb_default_allocator(), 4096);
    memset(p, 0, sizeof *p);
    p->io = io;
    p->fd = pipe_rd;
    p->in = in;
    p->out = out;
    p->deadline_mono_ms = deadline_mono_ms;
}

RFB_TEST(io_deadline, recv_exact__past_deadline__timeout)
{
    int fds[2];
    RFB_CHECK(pipe(fds) == 0);

    fake_io f;
    rfb_io_adapter io;
    rfb_buffer in, out;
    rfb_io_pump p;
    // Already expired.
    make_silent_pump(&f, &io, &in, &out, &p, fds[0], rfb_io_mono_ms());

    uint8_t buf[12];
    uint64_t t0 = rfb_io_mono_ms();
    rfb_error e = rfb_io_recv_exact(&p, buf, sizeof buf);
    uint64_t elapsed = rfb_io_mono_ms() - t0;
    RFB_CHECK_EQ_INT(e, RFB_ERR_TIMEOUT);
    // The past deadline returns before the long iteration loop.
    RFB_CHECK(elapsed < 2000u);

    close(fds[0]);
    close(fds[1]);
    rfb_buffer_destroy(&in);
    rfb_buffer_destroy(&out);
    fake_io_destroy(&f);
}

RFB_TEST(io_deadline, recv_exact__short_future_deadline__waits_then_times_out)
{
    int fds[2];
    RFB_CHECK(pipe(fds) == 0);

    fake_io f;
    rfb_io_adapter io;
    rfb_buffer in, out;
    rfb_io_pump p;
    const uint64_t budget_ms = 150u;
    make_silent_pump(&f, &io, &in, &out, &p, fds[0],
                     rfb_io_mono_ms() + budget_ms);

    uint8_t buf[12];
    uint64_t t0 = rfb_io_mono_ms();
    rfb_error e = rfb_io_recv_exact(&p, buf, sizeof buf);
    uint64_t elapsed = rfb_io_mono_ms() - t0;
    RFB_CHECK_EQ_INT(e, RFB_ERR_TIMEOUT);
    // Require a wait near the budget, with a generous scheduling upper bound.
    RFB_CHECK(elapsed < 3000u);
    RFB_CHECK(elapsed + 50u >= budget_ms); // allow timer granularity

    close(fds[0]);
    close(fds[1]);
    rfb_buffer_destroy(&in);
    rfb_buffer_destroy(&out);
    fake_io_destroy(&f);
}

RFB_TEST(io_deadline, read_server_init__past_deadline__timeout)
{
    int fds[2];
    RFB_CHECK(pipe(fds) == 0);

    fake_io f;
    rfb_io_adapter io;
    rfb_buffer in, out;
    rfb_io_pump p;
    make_silent_pump(&f, &io, &in, &out, &p, fds[0], rfb_io_mono_ms());

    rfb_server_init si;
    memset(&si, 0, sizeof si);
    uint64_t t0 = rfb_io_mono_ms();
    rfb_error e = rfb_io_read_server_init(&p, &si);
    uint64_t elapsed = rfb_io_mono_ms() - t0;
    RFB_CHECK_EQ_INT(e, RFB_ERR_TIMEOUT);
    RFB_CHECK(elapsed < 2000u);
    rfb_server_init_destroy(&si);

    close(fds[0]);
    close(fds[1]);
    rfb_buffer_destroy(&in);
    rfb_buffer_destroy(&out);
    fake_io_destroy(&f);
}

RFB_TEST(io_deadline, read_server_init__short_future_deadline__timeout)
{
    int fds[2];
    RFB_CHECK(pipe(fds) == 0);

    fake_io f;
    rfb_io_adapter io;
    rfb_buffer in, out;
    rfb_io_pump p;
    const uint64_t budget_ms = 120u;
    make_silent_pump(&f, &io, &in, &out, &p, fds[0],
                     rfb_io_mono_ms() + budget_ms);

    rfb_server_init si;
    memset(&si, 0, sizeof si);
    uint64_t t0 = rfb_io_mono_ms();
    rfb_error e = rfb_io_read_server_init(&p, &si);
    uint64_t elapsed = rfb_io_mono_ms() - t0;
    RFB_CHECK_EQ_INT(e, RFB_ERR_TIMEOUT);
    RFB_CHECK(elapsed < 3000u);
    rfb_server_init_destroy(&si);

    close(fds[0]);
    close(fds[1]);
    rfb_buffer_destroy(&in);
    rfb_buffer_destroy(&out);
    fake_io_destroy(&f);
}

// Positive: deadline far away + full ServerInit in buffer → OK without wait.
RFB_TEST(io_deadline, read_server_init__data_ready_with_deadline__ok)
{
    fake_io f;
    fake_io_init(&f, rfb_default_allocator());
    rfb_io_adapter io = fake_io_adapter_make(&f);
    rfb_buffer in, out;
    rfb_buffer_init(&in, rfb_default_allocator(), 4096);
    rfb_buffer_init(&out, rfb_default_allocator(), 4096);

    // ServerInit: width/height + valid 32bpp true-color PF + name_len=0.
    uint8_t hdr[24];
    memset(hdr, 0, sizeof hdr);
    hdr[0] = 0; hdr[1] = 100; // width 100
    hdr[2] = 0; hdr[3] = 50;  // height 50
    hdr[4] = 32; // bits-per-pixel
    hdr[5] = 24; // depth
    hdr[6] = 0;  // big-endian
    hdr[7] = 1;  // true-color
    hdr[8] = 0; hdr[9] = 255;   // red-max
    hdr[10] = 0; hdr[11] = 255; // green-max
    hdr[12] = 0; hdr[13] = 255; // blue-max
    hdr[14] = 16; // red-shift
    hdr[15] = 8;  // green-shift
    hdr[16] = 0;  // blue-shift
    // 17..19 pad, 20..23 name_len=0
    RFB_CHECK(rfb_buffer_append(&in, hdr, sizeof hdr) == RFB_OK);

    rfb_io_pump p;
    memset(&p, 0, sizeof p);
    p.io = &io;
    p.fd = -1;
    p.in = &in;
    p.out = &out;
    p.deadline_mono_ms = rfb_io_mono_ms() + 60000u;

    rfb_server_init si;
    memset(&si, 0, sizeof si);
    rfb_error e = rfb_io_read_server_init(&p, &si);
    RFB_CHECK_EQ_INT(e, RFB_OK);
    RFB_CHECK_EQ_UINT(si.width, 100u);
    RFB_CHECK_EQ_UINT(si.height, 50u);
    rfb_server_init_destroy(&si);
    rfb_buffer_destroy(&in);
    rfb_buffer_destroy(&out);
    fake_io_destroy(&f);
}
