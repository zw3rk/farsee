// SPDX-License-Identifier: Apache-2.0
//
// RFB I/O pump.
// Outbound waits use POLLOUT; inbound waits use POLLIN plus a residual delay.

#include "farsee/rfb_io_pump.h"

#include "farsee/limits.h"

#include <errno.h>
#include <poll.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>

static void set_err(rfb_io_pump *p, rfb_error e)
{
    if (p != NULL && p->last_error != NULL) {
        *p->last_error = e;
    }
}

uint64_t rfb_io_mono_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

bool rfb_io_stop_requested(const rfb_io_pump *p)
{
    if (p == NULL) {
        return false;
    }
    return farsee_atomic_int_load_nonzero(p->stop_flag);
}

// Wait in bounded poll(NULL) calls until the monotonic deadline is reached.
static void sleep_until_ms(uint64_t deadline_ms)
{
    for (;;) {
        const uint64_t now = rfb_io_mono_ms();
        if (now >= deadline_ms) {
            return;
        }
        uint64_t left = deadline_ms - now;
        if (left > 1000u) {
            left = 1000u;  // cap single poll sleep; re-check deadline
        }
        (void)poll(NULL, 0, (int)left);
    }
}

rfb_error rfb_io_drain_out(rfb_io_pump *p, int timeout_ms)
{
    if (p == NULL || p->io == NULL || p->out == NULL) {
        return RFB_ERR_INTERNAL;
    }

    // Bound the POLLOUT wait by timeout_ms and cap ready-but-blocked retries.
    const uint64_t t0 = rfb_io_mono_ms();
    const uint64_t deadline =
        (timeout_ms > 0) ? t0 + (uint64_t)timeout_ms : t0;
    unsigned spins = 0;

    while (rfb_buffer_length(p->out) > 0) {
        size_t n = rfb_buffer_length(p->out);
        size_t wrote = 0;
        rfb_io_result r = p->io->write(p->io->ctx, rfb_buffer_data(p->out),
                                       n, &wrote);
        if (r == RFB_IO_BLOCK) {
            if (timeout_ms <= 0) {
                return RFB_OK;  // non-blocking try only
            }
            const uint64_t now = rfb_io_mono_ms();
            if (now >= deadline) {
                return RFB_OK;
            }
            const int rem = (int)(deadline - now);
            struct pollfd pfd;
            pfd.fd = p->fd;
            pfd.events = POLLOUT;
            pfd.revents = 0;
            int pr = poll(&pfd, 1, rem);
            if (pr < 0) {
                if (errno == EINTR) {
                    continue;
                }
                set_err(p, RFB_ERR_IO);
                return RFB_ERR_IO;
            }
            if (pr == 0) {
                return RFB_OK;  // still blocked; caller retries later
            }
            if ((pfd.revents & (POLLNVAL | POLLERR)) != 0) {
                set_err(p, RFB_ERR_IO);
                return RFB_ERR_IO;
            }
            // Writable according to poll — retry write. If write keeps
            // returning BLOCK despite POLLOUT, do not spin forever.
            if (++spins > 64u) {
                return RFB_OK;
            }
            continue;
        }
        if (r == RFB_IO_ERROR || r == RFB_IO_EOF) {
            set_err(p, RFB_ERR_IO);
            return RFB_ERR_IO;
        }
        if (wrote > 0) {
            rfb_buffer_consume(p->out, wrote);
            spins = 0;
        } else {
            return RFB_OK;
        }
    }
    return RFB_OK;
}

rfb_error rfb_io_queue_bytes(rfb_io_pump *p, const uint8_t *data, size_t n)
{
    if (p == NULL || p->out == NULL) {
        return RFB_ERR_INTERNAL;
    }
    rfb_error e = rfb_buffer_append(p->out, data, n);
    if (e != RFB_OK) {
        set_err(p, e);
        return e;
    }
    return rfb_io_drain_out(p, 1000);
}

static rfb_error read_some_impl(rfb_io_pump *p, int timeout_ms,
                                bool drain_out)
{
    if (p == NULL || p->io == NULL || p->in == NULL || p->out == NULL) {
        return RFB_ERR_INTERNAL;
    }

    // Outbound draining and inbound waiting use separate polls. This poll watches
    // only POLLIN. If it appends no input and timeout_ms is positive, the
    // residual path below waits until the call's deadline.
    const size_t in0 = rfb_buffer_length(p->in);
    const uint64_t t0 = rfb_io_mono_ms();
    const uint64_t deadline =
        (timeout_ms > 0) ? t0 + (uint64_t)timeout_ms : t0;
    rfb_error result = RFB_OK;

    if (drain_out && rfb_buffer_length(p->out) > 0u) {
        rfb_error e = rfb_io_drain_out(p, timeout_ms);
        if (e != RFB_OK) {
            return e;
        }
    }

    int rem = timeout_ms;
    if (timeout_ms > 0) {
        const uint64_t now = rfb_io_mono_ms();
        if (now >= deadline) {
            rem = 0;
        } else {
            rem = (int)(deadline - now);
        }
    }

    struct pollfd pfd;
    pfd.fd = p->fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    int pr = poll(&pfd, 1, rem);
    if (pr < 0) {
        if (errno == EINTR) {
            // Fall through to residual floor.
            result = RFB_OK;
            goto floor_sleep;
        }
        set_err(p, RFB_ERR_IO);
        return RFB_ERR_IO;
    }
    if (pr == 0) {
        return RFB_OK;  // full (remaining) timeout slept inside poll
    }

    const short rev = pfd.revents;
    if ((rev & POLLNVAL) != 0) {
        set_err(p, RFB_ERR_IO);
        return RFB_ERR_IO;
    }
    if ((rev & POLLERR) != 0) {
        set_err(p, RFB_ERR_IO);
        return RFB_ERR_IO;
    }

    const bool hung_up = (rev & POLLHUP) != 0;
    const bool readable = (rev & POLLIN) != 0;
    if (!readable && !hung_up) {
        goto floor_sleep;
    }

    // Prefer FIONREAD when only HUP is present. A stream FIN can appear as
    // POLLIN with no queued bytes and no POLLHUP, so let the adapter read in
    // every readable case. That read distinguishes EOF from a transient block.
    int avail = 0;
    const int ioctl_ok = (ioctl(p->fd, FIONREAD, &avail) == 0);
    if (ioctl_ok && avail <= 0 && !readable) {
        set_err(p, RFB_ERR_EOF);
        return RFB_ERR_EOF;
    }

    uint8_t chunk[RFB_IO_PUMP_READ_CHUNK];
    size_t got = 0;
    rfb_io_result r = p->io->read(p->io->ctx, chunk, sizeof chunk, &got);
    if (r == RFB_IO_BLOCK) {
        if (hung_up) {
            set_err(p, RFB_ERR_EOF);
            return RFB_ERR_EOF;
        }
        goto floor_sleep;
    }
    if (r == RFB_IO_EOF) {
        set_err(p, RFB_ERR_EOF);
        return RFB_ERR_EOF;
    }
    if (r == RFB_IO_ERROR) {
        set_err(p, RFB_ERR_IO);
        return RFB_ERR_IO;
    }
    if (got > 0) {
        rfb_error e = rfb_buffer_append(p->in, chunk, got);
        if (e != RFB_OK) {
            set_err(p, e);
            return e;
        }
        return RFB_OK;  // progress — no residual sleep
    }
    if (hung_up) {
        set_err(p, RFB_ERR_EOF);
        return RFB_ERR_EOF;
    }

floor_sleep:
    // No input was appended; wait through the remaining positive timeout budget.
    if (timeout_ms > 0 && rfb_buffer_length(p->in) == in0) {
        sleep_until_ms(deadline);
    }
    return result;
}

rfb_error rfb_io_read_some(rfb_io_pump *p, int timeout_ms)
{
    return read_some_impl(p, timeout_ms, true);
}

rfb_error rfb_io_read_some_no_drain(rfb_io_pump *p, int timeout_ms)
{
    return read_some_impl(p, timeout_ms, false);
}

rfb_error rfb_io_recv_exact(rfb_io_pump *p, uint8_t *data, size_t n)
{
    if (p == NULL || p->in == NULL || data == NULL) {
        return RFB_ERR_INTERNAL;
    }

    size_t got = 0;
    for (int i = 0; i < 10000 && got < n; i++) {
        if (rfb_io_stop_requested(p)) {
            set_err(p, RFB_ERR_CANCELLED);
            return RFB_ERR_CANCELLED;
        }
        if (p->deadline_mono_ms != 0u &&
            rfb_io_mono_ms() >= p->deadline_mono_ms) {
            set_err(p, RFB_ERR_TIMEOUT);
            return RFB_ERR_TIMEOUT;
        }
        size_t avail = rfb_buffer_length(p->in);
        if (avail > 0) {
            size_t take = avail < (n - got) ? avail : (n - got);
            memcpy(data + got, rfb_buffer_data(p->in), take);
            rfb_buffer_consume(p->in, take);
            got += take;
            continue;
        }
        int poll_ms = 2000;
        if (p->deadline_mono_ms != 0u) {
            uint64_t now = rfb_io_mono_ms();
            if (now >= p->deadline_mono_ms) {
                set_err(p, RFB_ERR_TIMEOUT);
                return RFB_ERR_TIMEOUT;
            }
            uint64_t left = p->deadline_mono_ms - now;
            if (left < 2000u) {
                poll_ms = (int)left;
                if (poll_ms < 1) {
                    poll_ms = 1;
                }
            }
        }
        rfb_error e = rfb_io_read_some(p, poll_ms);
        if (e != RFB_OK) {
            return e;
        }
        if (rfb_buffer_length(p->in) == 0) {
            // No data in this iteration; recheck the deadline and iteration cap.
            continue;
        }
    }
    if (got < n) {
        set_err(p, RFB_ERR_TIMEOUT);
        return RFB_ERR_TIMEOUT;
    }
    return RFB_OK;
}

rfb_error rfb_io_read_server_init(rfb_io_pump *p, rfb_server_init *si)
{
    if (p == NULL || p->in == NULL || si == NULL) {
        return RFB_ERR_INTERNAL;
    }

    // Need at least 24 bytes header; name length may require more.
    for (int i = 0; i < 1000; i++) {
        if (rfb_io_stop_requested(p)) {
            set_err(p, RFB_ERR_CANCELLED);
            return RFB_ERR_CANCELLED;
        }
        if (p->deadline_mono_ms != 0u &&
            rfb_io_mono_ms() >= p->deadline_mono_ms) {
            set_err(p, RFB_ERR_TIMEOUT);
            return RFB_ERR_TIMEOUT;
        }
        size_t len = rfb_buffer_length(p->in);
        if (len >= 24u) {
            const uint8_t *d = rfb_buffer_data(p->in);
            uint32_t name_len =
                ((uint32_t)d[20] << 24) | ((uint32_t)d[21] << 16) |
                ((uint32_t)d[22] << 8) | (uint32_t)d[23];
            if (name_len > RFB_LIMIT_DESKTOP_NAME_BYTES) {
                set_err(p, RFB_ERR_LIMIT);
                return RFB_ERR_LIMIT;
            }
            size_t need = 24u + (size_t)name_len;
            if (len >= need) {
                rfb_error e = rfb_parse_server_init_with_allocator(
                    d, len, si, RFB_LIMIT_DESKTOP_NAME_BYTES,
                    p->alloc != NULL ? p->alloc : rfb_default_allocator());
                if (e != RFB_OK) {
                    set_err(p, e);
                    return e;
                }
                rfb_buffer_consume(p->in, need);
                return RFB_OK;
            }
        }
        int poll_ms = 2000;
        if (p->deadline_mono_ms != 0u) {
            uint64_t now = rfb_io_mono_ms();
            if (now >= p->deadline_mono_ms) {
                set_err(p, RFB_ERR_TIMEOUT);
                return RFB_ERR_TIMEOUT;
            }
            uint64_t left = p->deadline_mono_ms - now;
            if (left < 2000u) {
                poll_ms = (int)left;
                if (poll_ms < 1) {
                    poll_ms = 1;
                }
            }
        }
        rfb_error e = rfb_io_drain_out(p, poll_ms > 1000 ? 1000 : poll_ms);
        if (e != RFB_OK) {
            return e;
        }
        e = rfb_io_read_some(p, poll_ms);
        if (e != RFB_OK) {
            return e;
        }
    }
    set_err(p, RFB_ERR_TIMEOUT);
    return RFB_ERR_TIMEOUT;
}
