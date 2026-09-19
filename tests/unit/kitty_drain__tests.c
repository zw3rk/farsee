// SPDX-License-Identifier: Apache-2.0
//
// Shared Kitty stdout drain.
//
// Positive: full drain clears buffer; partial write consumes only written.
// Negative: NULL/empty no-op; invalid fd leaves buffer intact.

#include "rfb_test.h"
#include "farsee/allocator.h"
#include "farsee/buffer.h"
#include "farsee/farsee_thread.h"
#include "farsee/kitty_drain.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

static void fill_buffer(rfb_buffer *b, const uint8_t *data, size_t n)
{
    rfb_buffer_clear(b);
    RFB_CHECK(rfb_buffer_append(b, data, n) == RFB_OK);
}

RFB_TEST(kitty_drain, drain__null_out__noop)
{
    farsee_drain_kitty_out(NULL, STDOUT_FILENO, NULL);
}

RFB_TEST(kitty_drain, drain__empty_buffer__noop)
{
    rfb_buffer b;
    rfb_buffer_init(&b, rfb_default_allocator(), 4096);
    farsee_drain_kitty_out(&b, STDOUT_FILENO, NULL);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&b), 0u);
    rfb_buffer_destroy(&b);
}

RFB_TEST(kitty_drain, drain__full_write_to_pipe__clears_buffer)
{
    int fds[2];
    RFB_CHECK(pipe(fds) == 0);

    rfb_buffer b;
    rfb_buffer_init(&b, rfb_default_allocator(), 4096);
    static const uint8_t payload[] = "\033_Ga=T,f=32;\033\\";
    fill_buffer(&b, payload, sizeof(payload) - 1u);

    farsee_drain_kitty_out(&b, fds[1], NULL);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&b), 0u);

    uint8_t got[64];
    ssize_t n = read(fds[0], got, sizeof got);
    RFB_CHECK(n == (ssize_t)(sizeof(payload) - 1u));
    RFB_CHECK_MEM_EQ(got, payload, (size_t)n);

    (void)close(fds[0]);
    (void)close(fds[1]);
    rfb_buffer_destroy(&b);
}

RFB_TEST(kitty_drain, drain__invalid_fd__preserves_buffer)
{
    rfb_buffer b;
    rfb_buffer_init(&b, rfb_default_allocator(), 4096);
    static const uint8_t payload[] = { 0x01, 0x02, 0x03, 0x04 };
    fill_buffer(&b, payload, sizeof payload);

    farsee_drain_kitty_out(&b, -1, NULL);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&b), sizeof payload);
    RFB_CHECK_MEM_EQ(rfb_buffer_data(&b), payload, sizeof payload);

    rfb_buffer_destroy(&b);
}

RFB_TEST(kitty_drain, drain__nonblocking_full_pipe__partial_or_preserve)
{
    int fds[2];
    RFB_CHECK(pipe(fds) == 0);

    int flags = fcntl(fds[1], F_GETFL);
    RFB_CHECK(flags >= 0);
    RFB_CHECK(fcntl(fds[1], F_SETFL, flags | O_NONBLOCK) == 0);

    /* Fill the pipe until write would block so the next drain hits EAGAIN. */
    uint8_t junk[4096];
    memset(junk, 0xAB, sizeof junk);
    for (;;) {
        ssize_t w = write(fds[1], junk, sizeof junk);
        if (w < 0) {
            RFB_CHECK(errno == EAGAIN || errno == EWOULDBLOCK);
            break;
        }
        if (w == 0) {
            break;
        }
    }

    rfb_buffer b;
    rfb_buffer_init(&b, rfb_default_allocator(), 65536);
    static const uint8_t payload[] = "KITTY-PARTIAL-DRAIN-TEST";
    fill_buffer(&b, payload, sizeof(payload) - 1u);
    const size_t before = rfb_buffer_length(&b);

    farsee_drain_kitty_out(&b, fds[1], NULL);

    /* Pipe full: either no progress (EAGAIN immediately) or a short write
       that consumes only the written prefix. Never drop unwritten bytes. */
    const size_t after = rfb_buffer_length(&b);
    RFB_CHECK(after <= before);
    if (after == before) {
        RFB_CHECK_MEM_EQ(rfb_buffer_data(&b), payload, before);
    } else {
        /* Remainder must equal the unwritten suffix. */
        RFB_CHECK_MEM_EQ(rfb_buffer_data(&b), payload + (before - after), after);
    }

    (void)close(fds[0]);
    (void)close(fds[1]);
    rfb_buffer_destroy(&b);
}

RFB_TEST(kitty_drain, drain__two_calls_after_partial__eventually_clears)
{
    int fds[2];
    RFB_CHECK(pipe(fds) == 0);

    int flags = fcntl(fds[1], F_GETFL);
    RFB_CHECK(flags >= 0);
    RFB_CHECK(fcntl(fds[1], F_SETFL, flags | O_NONBLOCK) == 0);

    /* Make room for only a few bytes by filling almost-full then reading a
       small window — but keep it simple: write payload, read it all on the
       second drain after first full success path already covered. Here we
       just confirm repeated drains on a writable pipe empty the buffer. */
    rfb_buffer b;
    rfb_buffer_init(&b, rfb_default_allocator(), 4096);
    static const uint8_t payload[] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h' };
    fill_buffer(&b, payload, sizeof payload);

    farsee_drain_kitty_out(&b, fds[1], NULL);
    if (rfb_buffer_length(&b) > 0u) {
        /* Drain reader side so the remainder can land. */
        uint8_t tmp[64];
        while (read(fds[0], tmp, sizeof tmp) > 0) {
        }
        farsee_drain_kitty_out(&b, fds[1], NULL);
    }
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&b), 0u);

    (void)close(fds[0]);
    (void)close(fds[1]);
    rfb_buffer_destroy(&b);
}

// The optional write mutex protects buffer mutation (smoke test: no hang).
RFB_TEST(kitty_drain, drain__with_write_mu__serializes)
{
    int fds[2];
    RFB_CHECK(pipe(fds) == 0);
    farsee_mutex *mu = farsee_mutex_create();
    RFB_CHECK(mu != NULL);

    rfb_buffer b;
    rfb_buffer_init(&b, rfb_default_allocator(), 4096);
    static const uint8_t payload[] = "mutex-write";
    fill_buffer(&b, payload, sizeof(payload) - 1u);

    farsee_drain_kitty_out(&b, fds[1], mu);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&b), 0u);

    farsee_mutex_destroy(&mu);
    (void)close(fds[0]);
    (void)close(fds[1]);
    rfb_buffer_destroy(&b);
}

// A multi-chunk payload drains fully with write_mu (lock not required
// across entire write for correctness; buffer empties when done).
RFB_TEST(kitty_drain, drain__large_payload_with_mu__clears)
{
    int fds[2];
    RFB_CHECK(pipe(fds) == 0);
    farsee_mutex *mu = farsee_mutex_create();
    RFB_CHECK(mu != NULL);

    rfb_buffer b;
    rfb_buffer_init(&b, rfb_default_allocator(), 64u * 1024u);
    // > 8192 chunk size so the unlocked write loop iterates.
    uint8_t payload[10000];
    for (size_t i = 0; i < sizeof payload; i++) {
        payload[i] = (uint8_t)(i & 0xffu);
    }
    fill_buffer(&b, payload, sizeof payload);
    RFB_CHECK(farsee_drain_kitty_out(&b, fds[1], mu));
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&b), 0u);

    uint8_t got[sizeof payload];
    size_t total = 0u;
    while (total < sizeof payload) {
        ssize_t n = read(fds[0], got + total, sizeof payload - total);
        RFB_CHECK(n > 0);
        total += (size_t)n;
    }
    RFB_CHECK(memcmp(got, payload, sizeof payload) == 0);

    farsee_mutex_destroy(&mu);
    (void)close(fds[0]);
    (void)close(fds[1]);
    rfb_buffer_destroy(&b);
}

// The prefix (home CSI) precedes the APC payload in one drain.
RFB_TEST(kitty_drain, drain_with_prefix__home_before_apc)
{
    int fds[2];
    RFB_CHECK(pipe(fds) == 0);

    rfb_buffer b;
    rfb_buffer_init(&b, rfb_default_allocator(), 4096);
    static const uint8_t payload[] = "\033_Ga=T,f=32;\033\\";
    fill_buffer(&b, payload, sizeof(payload) - 1u);

    static const char home[] = "\033[H";
    RFB_CHECK(farsee_drain_kitty_out_with_prefix(&b, fds[1], NULL, home,
                                                 sizeof(home) - 1u));
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&b), 0u);

    uint8_t got[64];
    ssize_t n = read(fds[0], got, sizeof got);
    RFB_CHECK(n == (ssize_t)((sizeof(home) - 1u) + (sizeof(payload) - 1u)));
    RFB_CHECK_MEM_EQ(got, home, sizeof(home) - 1u);
    RFB_CHECK_MEM_EQ(got + (sizeof(home) - 1u), payload, sizeof(payload) - 1u);

    (void)close(fds[0]);
    (void)close(fds[1]);
    rfb_buffer_destroy(&b);
}

// An empty buffer must not write the prefix (no idle CSI storm).
RFB_TEST(kitty_drain, drain_with_prefix__empty__no_write)
{
    int fds[2];
    RFB_CHECK(pipe(fds) == 0);
    rfb_buffer b;
    rfb_buffer_init(&b, rfb_default_allocator(), 4096);
    static const char home[] = "\033[H";
    RFB_CHECK(farsee_drain_kitty_out_with_prefix(&b, fds[1], NULL, home,
                                                 sizeof(home) - 1u));
    int flags = fcntl(fds[0], F_GETFL);
    RFB_CHECK(fcntl(fds[0], F_SETFL, flags | O_NONBLOCK) == 0);
    uint8_t got[8];
    RFB_CHECK(read(fds[0], got, sizeof got) < 0);
    RFB_CHECK(errno == EAGAIN || errno == EWOULDBLOCK);
    (void)close(fds[0]);
    (void)close(fds[1]);
    rfb_buffer_destroy(&b);
}

// A mid-APC remainder without a leading ESC must not get another home.
RFB_TEST(kitty_drain, drain_with_prefix__mid_apc_remainder__no_second_home)
{
    int fds[2];
    RFB_CHECK(pipe(fds) == 0);

    rfb_buffer b;
    rfb_buffer_init(&b, rfb_default_allocator(), 4096);
    // Simulate remainder after partial drain: base64 body, not ESC-led.
    static const uint8_t mid[] = "AAAA-mid-apc-body";
    fill_buffer(&b, mid, sizeof(mid) - 1u);

    static const char home[] = "\033[H";
    RFB_CHECK(farsee_drain_kitty_out_with_prefix(&b, fds[1], NULL, home,
                                                 sizeof(home) - 1u));
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&b), 0u);

    uint8_t got[64];
    ssize_t n = read(fds[0], got, sizeof got);
    RFB_CHECK(n == (ssize_t)(sizeof(mid) - 1u));
    // Must be body only — no leading ESC[H.
    RFB_CHECK(got[0] == 'A');
    RFB_CHECK_MEM_EQ(got, mid, sizeof(mid) - 1u);

    (void)close(fds[0]);
    (void)close(fds[1]);
    rfb_buffer_destroy(&b);
}

// An ESC\ terminator remnant must not be treated as an open APC.
RFB_TEST(kitty_drain, drain_with_prefix__esc_backslash_terminator__no_home)
{
    int fds[2];
    RFB_CHECK(pipe(fds) == 0);
    rfb_buffer b;
    rfb_buffer_init(&b, rfb_default_allocator(), 4096);
    static const uint8_t term[] = "\033\\trailing";
    fill_buffer(&b, term, sizeof(term) - 1u);
    static const char home[] = "\033[H";
    RFB_CHECK(farsee_drain_kitty_out_with_prefix(&b, fds[1], NULL, home,
                                                 sizeof(home) - 1u));
    uint8_t got[32];
    ssize_t n = read(fds[0], got, sizeof got);
    RFB_CHECK(n == (ssize_t)(sizeof(term) - 1u));
    RFB_CHECK(got[0] == 0x1b && got[1] == '\\');
    (void)close(fds[0]);
    (void)close(fds[1]);
    rfb_buffer_destroy(&b);
}
