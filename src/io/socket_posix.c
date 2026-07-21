// SPDX-License-Identifier: Apache-2.0
//
// farsee — POSIX nonblocking socket I/O adapter (plan.md §G5).
//
// Production implementation of rfb_io_adapter over a nonblocking TCP
// socket. The session loop drives it through the abstract interface; the
// fake_io test double exercises the same contract without a socket.
//
// All operations are nonblocking. A read/write may return RFB_IO_BLOCK
// (EAGAIN/EWOULDBLOCK); the caller polls and retries.

// Linux: struct tcp_info (netinet/tcp.h) needs _DEFAULT_SOURCE / __USE_MISC
// under -std=c11 -D_POSIX_C_SOURCE=200809L (multi-review T1).
#if defined(__linux__) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE 1
#endif

#include "farsee/socket_posix.h"
#include "farsee/io_adapter.h"
#include "farsee/error.h"
#include "farsee/farsee_atomic.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

// Monotonic ms for connect budget (matches rfb_io_mono_ms contract).
static uint64_t sock_mono_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#if defined(__APPLE__)
#include <netinet/tcp_fsm.h> // TCPS_ESTABLISHED
#endif
#include <netdb.h>
#include <arpa/inet.h>

static int set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

// Enable TCP_NODELAY on a connected socket (RSA1-UNBLOCK.md §3).
// Disables Nagle's algorithm so the selector + first RSA1 envelope reach
// the server in one segment rather than being coalesced and split.
bool rfb_socket_set_nodelay(rfb_socket_ctx *s)
{
    if (s == NULL || s->fd < 0) {
        return false;
    }
    int one = 1;
    return setsockopt(s->fd, IPPROTO_TCP, TCP_NODELAY, &one,
                      (socklen_t)sizeof one) == 0;
}

uint32_t farsee_socket_tcp_stats(int fd, uint32_t *out_rtt_ms,
                                 uint64_t *out_rx_bytes,
                                 uint64_t *out_tx_bytes)
{
    if (fd < 0) {
        return 0u;
    }
    uint32_t mask = 0u;
#if defined(__APPLE__)
    struct tcp_connection_info info;
    socklen_t len = (socklen_t)sizeof info;
    memset(&info, 0, sizeof info);
    if (getsockopt(fd, IPPROTO_TCP, TCP_CONNECTION_INFO, &info, &len) != 0) {
        return 0u;
    }
    // Fail closed: unconnected / half-open must not claim authoritative stats.
    if (info.tcpi_state != TCPS_ESTABLISHED) {
        return 0u;
    }
    if (out_rtt_ms != NULL) {
        // Prefer smoothed RTT; fall back to last sample (ms on Darwin).
        uint32_t rtt = info.tcpi_srtt;
        if (rtt == 0u) {
            rtt = info.tcpi_rttcur;
        }
        // Zero sample is "no measurement yet", not a healthy 0 ms link.
        if (rtt > 0u) {
            *out_rtt_ms = rtt;
            mask |= FARSEE_TCP_STAT_RTT;
        }
    }
    if (out_rx_bytes != NULL) {
        *out_rx_bytes = info.tcpi_rxbytes;
        mask |= FARSEE_TCP_STAT_RX;
    }
    if (out_tx_bytes != NULL) {
        *out_tx_bytes = info.tcpi_txbytes;
        mask |= FARSEE_TCP_STAT_TX;
    }
#elif defined(__linux__)
    struct tcp_info info;
    socklen_t len = (socklen_t)sizeof info;
    memset(&info, 0, sizeof info);
    if (getsockopt(fd, IPPROTO_TCP, TCP_INFO, &info, &len) != 0) {
        return 0u;
    }
    // TCP_ESTABLISHED is 1 on Linux (netinet/tcp.h / linux/tcp.h).
    if (info.tcpi_state != TCP_ESTABLISHED) {
        return 0u;
    }
    if (out_rtt_ms != NULL) {
        // Linux tcpi_rtt is microseconds. Ceil to whole ms so sub-ms LAN
        // never displays as "0ms" (which reads as broken instrumentation).
        if (info.tcpi_rtt > 0u) {
            // Ceil µs → ms: any non-zero RTT is at least 1 ms.
            *out_rtt_ms = (uint32_t)((info.tcpi_rtt + 999u) / 1000u);
            mask |= FARSEE_TCP_STAT_RTT;
        }
    }
    // Kernel rx/tx totals: not reliably available under all headers —
    // caller should use app-level sock.rx_bytes (T2).
    (void)out_rx_bytes;
    (void)out_tx_bytes;
#else
    (void)out_rtt_ms;
    (void)out_rx_bytes;
    (void)out_tx_bytes;
#endif
    return mask;
}

// Connect with a bounded timeout: start nonblocking, poll for writability
// (plan.md §G5 "connect timeout"), verify SO_ERROR, then switch to
// nonblocking for the I/O loop. Returns RFB_IO_OK on success.
static rfb_io_result sock_connect(void *ctx, const rfb_io_candidate *c)
{
    rfb_socket_ctx *s = (rfb_socket_ctx *)ctx;
    if (s == NULL || c == NULL) {
        return RFB_IO_ERROR;
    }
    int fd = socket(c->family, c->socktype, c->protocol);
    if (fd < 0) {
        return RFB_IO_ERROR;
    }
    if (set_nonblocking(fd) != 0) {
        close(fd);
        return RFB_IO_ERROR;
    }
    // Copy into aligned storage: c->addr is uint8_t[] and a direct cast to
    // sockaddr* trips -Wcast-align on Linux Clang (nix package build).
    struct sockaddr_storage ss;
    if (c->addr_len == 0u || c->addr_len > sizeof ss) {
        close(fd);
        return RFB_IO_ERROR;
    }
    memset(&ss, 0, sizeof ss);
    memcpy(&ss, c->addr, c->addr_len);
    int rc = connect(fd, (struct sockaddr *)&ss, (socklen_t)c->addr_len);
    if (rc < 0 && errno != EINPROGRESS) {
        close(fd);
        return RFB_IO_ERROR;
    }
    // Poll for writability with session deadline + stop (T4). Default 15s
    // when no deadline is set (plan.md §6.4). Slice poll so SIGINT/stop and
    // short connect_timeout_ms are observed promptly; EINTR does not restart
    // a full 15s wait.
    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLOUT;
    pfd.revents = 0;
    const uint64_t default_end = sock_mono_ms() + 15000u;
    const uint64_t deadline =
        (s->connect_deadline_mono_ms != 0u) ? s->connect_deadline_mono_ms
                                             : default_end;
    int pr = 0;
    for (;;) {
        if (s->connect_stop != NULL &&
            farsee_atomic_int_load_nonzero(s->connect_stop)) {
            close(fd);
            return RFB_IO_ERROR; // cancelled
        }
        const uint64_t now = sock_mono_ms();
        if (now >= deadline) {
            close(fd);
            return RFB_IO_ERROR; // timeout
        }
        uint64_t left = deadline - now;
        int slice = (left > 100u) ? 100 : (int)left;
        if (slice < 1) {
            slice = 1;
        }
        pr = poll(&pfd, 1, slice);
        if (pr < 0 && errno == EINTR) {
            continue; // re-check deadline/stop
        }
        if (pr < 0) {
            close(fd);
            return RFB_IO_ERROR;
        }
        if (pr > 0) {
            break; // writable or error — check SO_ERROR below
        }
        // pr == 0: slice timeout; loop
    }
    int soerr = 0;
    socklen_t sl = (socklen_t)sizeof soerr;
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl) != 0 || soerr != 0) {
        close(fd);
        return RFB_IO_ERROR;
    }
    // Connected. Leave the socket nonblocking for the I/O loop.
    // Prevent SIGPIPE on send to a closed peer (full2 T3 / H5).
#ifdef __APPLE__
    int nosigpipe = 1;
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &nosigpipe, sizeof nosigpipe);
#endif
    s->fd = fd;
    s->nonblocking = true;
    return RFB_IO_OK;
}

static rfb_io_result sock_read(void *ctx, uint8_t *buf, size_t n, size_t *out_n)
{
    rfb_socket_ctx *s = (rfb_socket_ctx *)ctx;
    if (s == NULL || s->fd < 0 || out_n == NULL) {
        return RFB_IO_ERROR;
    }
    *out_n = 0;
    ssize_t r = recv(s->fd, buf, n, 0);
    if (r < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
            return RFB_IO_BLOCK;
        }
        return RFB_IO_ERROR;
    }
    if (r == 0) {
        return RFB_IO_EOF;  // peer closed
    }
    *out_n = (size_t)r;
    (void)farsee_atomic_u64_fetch_add(&s->rx_bytes, (uint64_t)r);
    return RFB_IO_OK;
}

static rfb_io_result sock_write(void *ctx, const uint8_t *buf, size_t n, size_t *out_n)
{
    rfb_socket_ctx *s = (rfb_socket_ctx *)ctx;
    if (s == NULL || s->fd < 0 || out_n == NULL) {
        return RFB_IO_ERROR;
    }
    *out_n = 0;
    // MSG_NOSIGNAL on Linux so peer close returns EPIPE as RFB_IO_ERROR
    // instead of killing the process (skipping atexit TTY restore).
#if defined(MSG_NOSIGNAL)
    const int send_flags = MSG_NOSIGNAL;
#else
    const int send_flags = 0;
#endif
    ssize_t w = send(s->fd, buf, n, send_flags);
    if (w < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return RFB_IO_BLOCK;
        }
        if (errno == EINTR) {
            return RFB_IO_BLOCK;  // 0 bytes written; caller polls and retries
        }
        return RFB_IO_ERROR;
    }
    *out_n = (size_t)w;
    return RFB_IO_OK;
}

static void sock_close(void *ctx)
{
    rfb_socket_ctx *s = (rfb_socket_ctx *)ctx;
    if (s != NULL && s->fd >= 0) {
        close(s->fd);
        s->fd = -1;
    }
}

rfb_io_adapter rfb_socket_adapter_make(rfb_socket_ctx *s)
{
    rfb_io_adapter a;
    memset(&a, 0, sizeof a);
    a.ctx = s;
    a.connect = sock_connect;
    a.read = sock_read;
    a.write = sock_write;
    a.close = sock_close;
    // Always zero-init the ctx (T4: stack garbage was UB when we read
    // s->fd before init). Callers that need a connected fd or connect
    // budget must set those fields *after* make (attach does this).
    if (s != NULL) {
        memset(s, 0, sizeof *s);
        s->fd = -1;
        s->nonblocking = false;
        s->connect_deadline_mono_ms = 0u;
        s->connect_stop = NULL;
    }
    return a;
}

rfb_error rfb_resolve_candidates(const char *host, uint16_t port,
                                 rfb_io_candidate *out, size_t *inout_count)
{
    if (host == NULL || out == NULL || inout_count == NULL) {
        return RFB_ERR_INTERNAL;
    }
    char port_str[8];
    snprintf(port_str, sizeof port_str, "%u", (unsigned)port);
    struct addrinfo hints;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *res = NULL;
    int rc = getaddrinfo(host, port_str, &hints, &res);
    if (rc != 0) {
        return RFB_ERR_IO;
    }
    size_t count = 0;
    for (struct addrinfo *ai = res; ai != NULL && count < *inout_count; ai = ai->ai_next) {
        size_t alen = (size_t)ai->ai_addrlen;
        if (alen > sizeof out[count].addr) {
            alen = sizeof out[count].addr;
        }
        out[count].family = ai->ai_family;
        out[count].socktype = ai->ai_socktype;
        out[count].protocol = ai->ai_protocol;
        memcpy(out[count].addr, ai->ai_addr, alen);
        out[count].addr_len = alen;
        count++;
    }
    freeaddrinfo(res);
    *inout_count = count;
    return RFB_OK;
}
