// SPDX-License-Identifier: Apache-2.0
//
// G18A — TCP_NODELAY on the socket adapter (RSA1-UNBLOCK.md §3).
//
// The Apple type-33 RSA1 compatibility path requires TCP_NODELAY so the
// selector + first RSA1 envelope reach the server in one segment, not
// coalesced and split by Nagle's algorithm.
//
// Tests use socketpair(2) (AF_UNIX, SOCK_STREAM) — no network needed.

#include "rfb_test.h"
#include "farsee/socket_posix.h"
#include "farsee/io_adapter.h"
#include "farsee/farsee_atomic.h"
#include "farsee/farsee_thread.h"
#include "farsee/rfb_session.h"
#include "farsee/error.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

// Check whether TCP_NODELAY is currently enabled on a socket fd.
static bool nodelay_is_set(int fd)
{
    int val = 0;
    socklen_t sl = (socklen_t)sizeof val;
    if (getsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &val, &sl) != 0) {
        return false;
    }
    return val != 0;
}

RFB_TEST(g18a_nodelay, set_nodelay__enables_on_connected_socket) {
    int fds[2];
    RFB_CHECK_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);

    // socketpair does not use TCP, but we can still test the setsockopt
    // path on a TCP socket. Create a real TCP socket (unconnected is fine
    // for testing the setsockopt call itself).
    int tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
    RFB_CHECK(tcp_fd >= 0);

    // Before: TCP_NODELAY should be off (default).
    RFB_CHECK(!nodelay_is_set(tcp_fd));

    // Use the socket adapter function.
    rfb_socket_ctx s;
    s.fd = tcp_fd;
    s.nonblocking = false;
    RFB_CHECK(rfb_socket_set_nodelay(&s));

    // After: TCP_NODELAY is enabled.
    RFB_CHECK(nodelay_is_set(tcp_fd));

    close(tcp_fd);
    close(fds[0]);
    close(fds[1]);
}

RFB_TEST(g18a_nodelay, set_nodelay__null_ctx__returns_false) {
    RFB_CHECK(!rfb_socket_set_nodelay(NULL));
}

RFB_TEST(g18a_nodelay, set_nodelay__invalid_fd__returns_false) {
    rfb_socket_ctx s;
    s.fd = -1;
    s.nonblocking = false;
    RFB_CHECK(!rfb_socket_set_nodelay(&s));
}

// multi-review T2: invalid fd → empty mask (no fabricated fields).
RFB_TEST(socket_posix, tcp_stats__invalid_fd__returns_zero_mask)
{
    uint32_t rtt = 99u;
    uint64_t rx = 99u;
    uint64_t tx = 99u;
    const uint32_t m = farsee_socket_tcp_stats(-1, &rtt, &rx, &tx);
    RFB_CHECK_EQ_UINT(m, 0u);
    // Out-params must be left unchanged when nothing is filled.
    RFB_CHECK_EQ_UINT(rtt, 99u);
    RFB_CHECK_EQ_UINT(rx, 99u);
    RFB_CHECK_EQ_UINT(tx, 99u);
}

// multi-review T2: RTT-only platforms must not claim RX via mask.
// On Darwin, TCP_CONNECTION_INFO usually fills RTT+RX; on Linux RTT only.
// Assert: if RX bit unset, out_rx was not written (sentinel preserved).
RFB_TEST(socket_posix, tcp_stats__partial_fill__preserves_unfilled)
{
    int tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
    RFB_CHECK(tcp_fd >= 0);
    uint32_t rtt = 0xDeadBeefu;
    uint64_t rx = 0xCafeBabeull;
    const uint32_t m = farsee_socket_tcp_stats(tcp_fd, &rtt, &rx, NULL);
    if ((m & FARSEE_TCP_STAT_RX) == 0u) {
        RFB_CHECK_EQ_UINT(rx, 0xCafeBabeull);
    }
    if ((m & FARSEE_TCP_STAT_RTT) == 0u) {
        RFB_CHECK_EQ_UINT(rtt, 0xDeadBeefu);
    }
    close(tcp_fd);
}

// loop r1 T3: unconnected SOCK_STREAM must not claim RTT (ESTABLISHED gate).
RFB_TEST(socket_posix, tcp_stats__unconnected_socket__no_rtt_bit)
{
    int tcp_fd = socket(AF_INET, SOCK_STREAM, 0);
    RFB_CHECK(tcp_fd >= 0);
    uint32_t rtt = 0xDeadBeefu;
    uint64_t rx = 0xCafeBabeull;
    uint64_t tx = 0xFeedFaceull;
    const uint32_t m = farsee_socket_tcp_stats(tcp_fd, &rtt, &rx, &tx);
    RFB_CHECK_EQ_UINT(m & FARSEE_TCP_STAT_RTT, 0u);
    RFB_CHECK_EQ_UINT(rtt, 0xDeadBeefu); // out-param unchanged
    // Unconnected: full mask should be empty (no fabricated zeros).
    RFB_CHECK_EQ_UINT(m, 0u);
    close(tcp_fd);
}

// loop r2 T5: pure sample throttle.
RFB_TEST(socket_posix, link_sample_due__window_and_clock_backwards)
{
    uint64_t next = 0u;
    RFB_CHECK(farsee_link_sample_due(1000u, &next, 250u));
    RFB_CHECK_EQ_UINT(next, 1250u);
    RFB_CHECK(!farsee_link_sample_due(1100u, &next, 250u));
    RFB_CHECK(farsee_link_sample_due(1250u, &next, 250u));
    RFB_CHECK_EQ_UINT(next, 1500u);
    // Clock jump back far behind next → re-arm, do not wedge.
    next = 5000u;
    RFB_CHECK(farsee_link_sample_due(100u, &next, 250u));
    RFB_CHECK_EQ_UINT(next, 350u);
    // zero window → default 250
    next = 0u;
    RFB_CHECK(farsee_link_sample_due(0u, &next, 0u));
    RFB_CHECK_EQ_UINT(next, (uint64_t)FARSEE_LINK_RATE_WINDOW_MS);
    RFB_CHECK(!farsee_link_sample_due(10u, NULL, 250u));
}

// loop r1 T6: link_meta pack/unpack round-trip + zero claims nothing.
RFB_TEST(socket_posix, link_meta__pack_unpack_roundtrip)
{
    const uint32_t rtts[] = {0u, 1u, 14u, UINT32_MAX};
    for (size_t i = 0; i < sizeof rtts / sizeof rtts[0]; i++) {
        for (int hr = 0; hr < 2; hr++) {
            for (int hx = 0; hx < 2; hx++) {
                const uint64_t m = farsee_link_meta_pack(
                    rtts[i], hr != 0, hx != 0);
                uint32_t out_rtt = 99u;
                bool out_hr = false;
                bool out_hx = false;
                farsee_link_meta_unpack(m, &out_rtt, &out_hr, &out_hx);
                RFB_CHECK(out_hr == (hr != 0));
                RFB_CHECK(out_hx == (hx != 0));
                if (hr != 0) {
                    RFB_CHECK_EQ_UINT(out_rtt, rtts[i]);
                }
            }
        }
    }
    uint32_t zr = 7u;
    bool zhr = true;
    bool zhx = true;
    farsee_link_meta_unpack(0u, &zr, &zhr, &zhx);
    RFB_CHECK(!zhr);
    RFB_CHECK(!zhx);
}

// multi-review 2026-08-03 T4: make() safe on garbage stack ctx.
RFB_TEST(socket_posix, adapter_make__uninit_ctx__zeroes_fields)
{
    rfb_socket_ctx sc;
    memset(&sc, 0xAB, sizeof sc); // poison
    rfb_io_adapter a = rfb_socket_adapter_make(&sc);
    RFB_CHECK(a.ctx == &sc);
    RFB_CHECK_EQ_INT(sc.fd, -1);
    RFB_CHECK(sc.connect_stop == NULL);
    RFB_CHECK_EQ_UINT(sc.connect_deadline_mono_ms, 0u);
    RFB_CHECK(!sc.nonblocking);
    RFB_CHECK_EQ_UINT(farsee_atomic_u64_load(&sc.rx_bytes), 0u);
}

// T4 (+): set connected fd after make (contract).
RFB_TEST(socket_posix, adapter_make__then_attach_fd)
{
    int sp[2];
    RFB_CHECK_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, sp), 0);
    rfb_socket_ctx sc;
    rfb_io_adapter a = rfb_socket_adapter_make(&sc);
    sc.fd = sp[0];
    sc.nonblocking = true;
    size_t wn = 0;
    uint8_t b = 0x5a;
    RFB_CHECK(a.write(a.ctx, &b, 1, &wn) == RFB_IO_OK);
    RFB_CHECK_EQ_UINT(wn, 1u);
    close(sp[0]);
    close(sp[1]);
}

// multi-review 2026-07-31 T4: short connect_deadline against non-completing
// peer (TEST-NET-1) must fail well under the old 15s hard-coded poll.
RFB_TEST(socket_posix, sock_connect__short_deadline__blackhole_fast_fail)
{
    rfb_io_candidate cands[8];
    size_t nc = 8;
    // 192.0.2.1 is TEST-NET-1 (RFC 5737): not routed; connect hangs.
    RFB_CHECK_EQ_INT(rfb_resolve_candidates("192.0.2.1", 9, cands, &nc), RFB_OK);
    RFB_CHECK(nc >= 1u);

    rfb_socket_ctx sc;
    rfb_io_adapter a = rfb_socket_adapter_make(&sc);
    // Budget set *after* make (make zeroes the ctx — T4).
    {
        struct timespec ts;
        RFB_CHECK(clock_gettime(CLOCK_MONOTONIC, &ts) == 0);
        sc.connect_deadline_mono_ms =
            (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u +
            350u;
    }
    sc.connect_stop = NULL;

    struct timespec t0, t1;
    RFB_CHECK(clock_gettime(CLOCK_MONOTONIC, &t0) == 0);
    rfb_io_result r = a.connect(a.ctx, &cands[0]);
    RFB_CHECK(clock_gettime(CLOCK_MONOTONIC, &t1) == 0);
    RFB_CHECK(r == RFB_IO_ERROR);
    const int64_t ms =
        ((int64_t)t1.tv_sec - (int64_t)t0.tv_sec) * 1000 +
        ((int64_t)t1.tv_nsec - (int64_t)t0.tv_nsec) / 1000000;
    // Old code: poll(15000) once → ~15s. New: must finish near budget.
    // Note: ENETUNREACH hosts may fail instantly; still must not burn 15s.
    RFB_CHECK(ms < 2500);
    if (sc.fd >= 0) {
        close(sc.fd);
        sc.fd = -1;
    }
}

// T4: connect_stop mid-poll aborts before long deadline.
static void *stop_after_ms(void *arg)
{
    farsee_atomic_int *stop = (farsee_atomic_int *)arg;
    { struct timespec ts = {0, 80 * 1000 * 1000}; (void)nanosleep(&ts, NULL); } // 80 ms
    farsee_atomic_int_store(stop, 1);
    return NULL;
}

RFB_TEST(socket_posix, sock_connect__stop_flag__aborts_before_deadline)
{
    rfb_io_candidate cands[8];
    size_t nc = 8;
    RFB_CHECK_EQ_INT(rfb_resolve_candidates("192.0.2.1", 9, cands, &nc), RFB_OK);
    RFB_CHECK(nc >= 1u);

    farsee_atomic_int stop;
    farsee_atomic_int_store(&stop, 0);

    rfb_socket_ctx sc;
    rfb_io_adapter a = rfb_socket_adapter_make(&sc);
    {
        struct timespec ts;
        RFB_CHECK(clock_gettime(CLOCK_MONOTONIC, &ts) == 0);
        // Long deadline — stop must win.
        sc.connect_deadline_mono_ms =
            (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u +
            15000u;
    }
    sc.connect_stop = &stop;

    farsee_thread *th = farsee_thread_create(stop_after_ms, &stop);
    RFB_CHECK(th != NULL);

    struct timespec t0, t1;
    RFB_CHECK(clock_gettime(CLOCK_MONOTONIC, &t0) == 0);
    rfb_io_result r = a.connect(a.ctx, &cands[0]);
    RFB_CHECK(clock_gettime(CLOCK_MONOTONIC, &t1) == 0);
    farsee_thread_join(&th, NULL);

    RFB_CHECK(r == RFB_IO_ERROR);
    RFB_CHECK(farsee_atomic_int_load_nonzero(&stop));
    const int64_t ms =
        ((int64_t)t1.tv_sec - (int64_t)t0.tv_sec) * 1000 +
        ((int64_t)t1.tv_nsec - (int64_t)t0.tv_nsec) / 1000000;
    // Must not burn the 15s deadline; stop at ~80–400 ms.
    RFB_CHECK(ms < 2000);
    if (sc.fd >= 0) {
        close(sc.fd);
    }
}

// Session-level: short connect_timeout against blackhole → TIMEOUT/IO fast.
RFB_TEST(socket_posix, session_connect__blackhole_short_timeout__fast)
{
    unsigned char storage[8192];
    RFB_CHECK(rfb_session_size() <= sizeof storage);
    rfb_session *s = (rfb_session *)(void *)storage;
    rfb_session_clear(s);
    rfb_session_config cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.host = "192.0.2.1";
    cfg.port = 9;
    cfg.connect_timeout_ms = 400u;
    cfg.auth_mode = FARSEE_AUTH_MODE_VNC;
    cfg.allow_none_auth = true;

    struct timespec t0, t1;
    RFB_CHECK(clock_gettime(CLOCK_MONOTONIC, &t0) == 0);
    rfb_error e = rfb_session_connect_classic(s, &cfg);
    RFB_CHECK(clock_gettime(CLOCK_MONOTONIC, &t1) == 0);
    RFB_CHECK(e == RFB_ERR_TIMEOUT || e == RFB_ERR_IO);
    const int64_t ms =
        ((int64_t)t1.tv_sec - (int64_t)t0.tv_sec) * 1000 +
        ((int64_t)t1.tv_nsec - (int64_t)t0.tv_nsec) / 1000000;
    RFB_CHECK(ms < 2500);
    rfb_session_destroy(s);
}

// full2 T3: write after peer close returns error (no SIGPIPE process death).
RFB_TEST(socket_posix, sock_write__peer_closed__returns_io_error)
{
    int fds[2];
    RFB_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
    close(fds[0]); // peer closed

    rfb_socket_ctx sc;
    memset(&sc, 0, sizeof sc);
    sc.fd = fds[1];
    sc.nonblocking = false;
    rfb_io_adapter a = rfb_socket_adapter_make(&sc);
    uint8_t buf[16];
    memset(buf, 0xab, sizeof buf);
    size_t n = 0;
    rfb_io_result r = a.write(a.ctx, buf, sizeof buf, &n);
    // EPIPE / connection reset → ERROR (not process kill).
    RFB_CHECK(r == RFB_IO_ERROR || r == RFB_IO_BLOCK);
    close(fds[1]);
}
