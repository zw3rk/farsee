// SPDX-License-Identifier: Apache-2.0
//
// farsee — POSIX socket adapter (plan.md §G5). Production I/O over a
// nonblocking TCP socket.

#ifndef FARSEE_INCLUDE_FARSEE_SOCKET_POSIX_H
#define FARSEE_INCLUDE_FARSEE_SOCKET_POSIX_H

#include "farsee/error.h"
#include "farsee/farsee_atomic.h"
#include "farsee/io_adapter.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rfb_socket_ctx {
    int fd;           // -1 when not connected
    bool nonblocking;
    // Optional connect budget (absolute mono-ms). 0 → default 15s cap.
    // Set by the session before adapter connect.
    uint64_t connect_deadline_mono_ms;
    // Optional cooperative stop during connect poll (SIGINT / quit).
    farsee_atomic_int *connect_stop;
    // App-level cumulative bytes successfully received (always updated on
    // sock_read). Used as a portable downlink counter when kernel TCP stats
    // do not expose rx totals (e.g. Linux under strict feature macros).
    farsee_atomic_u64 rx_bytes;
    // App-level cumulative bytes successfully handed to the transport.
    // Capture-only request timing uses this with an empty outbound buffer to
    // bind the exact queued sealed-record length before starting its deadline.
    farsee_atomic_u64 tx_bytes;
} rfb_socket_ctx;

// Build an adapter backed by a nonblocking TCP socket. The ctx is owned
// by the caller.
rfb_io_adapter rfb_socket_adapter_make(rfb_socket_ctx *s);

// Enable TCP_NODELAY (disable Nagle's algorithm) on the TCP socket in `s`.
// The option reduces Nagle buffering; TCP can still split or combine writes,
// and the socket need not be connected when this setter runs.
// Returns true on success, false if the socket is not connected or
// setsockopt fails.
bool rfb_socket_set_nodelay(rfb_socket_ctx *s);

// Field mask for farsee_socket_tcp_stats (only set bits mean out-params filled).
#define FARSEE_TCP_STAT_RTT 1u
#define FARSEE_TCP_STAT_RX  2u
#define FARSEE_TCP_STAT_TX  4u

// Query kernel TCP stats for an *established* stream socket.
// Returns a bitmask of FARSEE_TCP_STAT_* for fields actually written.
// Unfilled out-params are left unchanged (callers should not treat
// untouched memory as zero traffic). Returns 0 when nothing is available
// (unconnected, half-open, getsockopt failure). RTT is never claimed as
// an authoritative 0 ms from a zero kernel sample — non-zero µs/ms only,
// with Linux sub-ms values ceiled to ≥1 ms so the status band does not
// look broken on LAN/loopback.
uint32_t farsee_socket_tcp_stats(int fd, uint32_t *out_rtt_ms,
                                 uint64_t *out_rx_bytes,
                                 uint64_t *out_tx_bytes);

// Status-band rate/sample window (ms). This is the sole definition.
#define FARSEE_LINK_RATE_WINDOW_MS 250u

// Cross-thread link-meta packing for status band (RFB + RDP).
// Layout: low 32 bits = rtt_ms; bit 32 = have_rtt; bit 33 = have_rx.
#define FARSEE_LINK_META_HAVE_RTT (1ull << 32)
#define FARSEE_LINK_META_HAVE_RX  (1ull << 33)

static inline uint64_t farsee_link_meta_pack(uint32_t rtt_ms, bool have_rtt,
                                            bool have_rx)
{
    uint64_t m = 0u;
    if (have_rtt) {
        m |= (uint64_t)rtt_ms;
        m |= FARSEE_LINK_META_HAVE_RTT;
    }
    if (have_rx) {
        m |= FARSEE_LINK_META_HAVE_RX;
    }
    return m;
}

static inline void farsee_link_meta_unpack(uint64_t meta, uint32_t *out_rtt_ms,
                                           bool *out_have_rtt,
                                           bool *out_have_rx)
{
    if (out_have_rtt != NULL) {
        *out_have_rtt = (meta & FARSEE_LINK_META_HAVE_RTT) != 0u;
    }
    if (out_rtt_ms != NULL) {
        *out_rtt_ms = (uint32_t)(meta & 0xffffffffu);
    }
    if (out_have_rx != NULL) {
        *out_have_rx = (meta & FARSEE_LINK_META_HAVE_RX) != 0u;
    }
}

// Pure throttle: true when a link sample should run. Arms *inout_next_ms to
// now+window (or default window). If *inout_next_ms is more than one window
// ahead of now (monotonic discontinuity), re-arms instead of wedging forever.
static inline bool farsee_link_sample_due(uint64_t now_ms,
                                          uint64_t *inout_next_ms,
                                          uint32_t window_ms)
{
    if (inout_next_ms == NULL) {
        return false;
    }
    if (window_ms == 0u) {
        window_ms = FARSEE_LINK_RATE_WINDOW_MS;
    }
    if (*inout_next_ms != 0u && now_ms < *inout_next_ms) {
        if (*inout_next_ms > now_ms + (uint64_t)window_ms) {
            *inout_next_ms = now_ms + (uint64_t)window_ms;
            return true;
        }
        return false;
    }
    *inout_next_ms = now_ms + (uint64_t)window_ms;
    return true;
}

// Pure rate latch (protocol-thread state; publish via farsee_link_rate_pack).
typedef struct farsee_link_rate {
    uint64_t prev_rx;
    uint64_t prev_ms;
    uint32_t latched_kib_s;
    bool have_prev;
    bool have_rate;
} farsee_link_rate;

static inline void farsee_link_rate_sample(farsee_link_rate *r,
                                           uint64_t rx_bytes, bool have_rx,
                                           uint64_t now_ms, uint32_t window_ms)
{
    if (r == NULL) {
        return;
    }
    if (!have_rx) {
        r->have_rate = false;
        r->have_prev = false;
        return;
    }
    if (window_ms == 0u) {
        window_ms = FARSEE_LINK_RATE_WINDOW_MS;
    }
    if (!r->have_prev) {
        r->prev_rx = rx_bytes;
        r->prev_ms = now_ms;
        r->have_prev = true;
        r->have_rate = false;
        r->latched_kib_s = 0u;
        return;
    }
    if (now_ms < r->prev_ms) {
        r->prev_rx = rx_bytes;
        r->prev_ms = now_ms;
        r->have_rate = false;
        r->latched_kib_s = 0u;
        return;
    }
    const uint64_t dt = now_ms - r->prev_ms;
    if (dt < (uint64_t)window_ms) {
        return;
    }
    if (rx_bytes >= r->prev_rx && dt > 0u) {
        const uint64_t dbytes = rx_bytes - r->prev_rx;
        const uint64_t kib = (dbytes * 1000u) / (dt * 1024u);
        r->latched_kib_s =
            (kib > UINT32_MAX) ? UINT32_MAX : (uint32_t)kib;
        r->have_rate = true;
    } else {
        r->latched_kib_s = 0u;
        r->have_rate = true;
    }
    r->prev_rx = rx_bytes;
    r->prev_ms = now_ms;
}

// Published rate snapshot: low 32 = kib/s, bit 32 = have_rate.
#define FARSEE_LINK_RATE_HAVE (1ull << 32)

static inline uint64_t farsee_link_rate_pack(uint32_t kib_s, bool have_rate)
{
    uint64_t m = (uint64_t)kib_s;
    if (have_rate) {
        m |= FARSEE_LINK_RATE_HAVE;
    }
    return m;
}

static inline void farsee_link_rate_unpack(uint64_t packed, uint32_t *out_kib,
                                           bool *out_have)
{
    if (out_have != NULL) {
        *out_have = (packed & FARSEE_LINK_RATE_HAVE) != 0u;
    }
    if (out_kib != NULL) {
        *out_kib = (uint32_t)(packed & 0xffffffffu);
    }
}

// Sample and pack for protocol publication through a pure test seam.
static inline uint64_t farsee_link_rate_step(farsee_link_rate *r,
                                             uint64_t rx_bytes, bool have_rx,
                                             uint64_t now_ms,
                                             uint32_t window_ms)
{
    if (r == NULL) {
        return 0u;
    }
    farsee_link_rate_sample(r, rx_bytes, have_rx, now_ms, window_ms);
    return farsee_link_rate_pack(r->latched_kib_s, r->have_rate);
}

// Resolve `host:port` into a list of connect candidates (IPv4 + IPv6).
// Writes up to `*inout_count` candidates into `out` (caller-allocated)
// and sets `*inout_count` to the actual number. Returns RFB_OK or an
// error. This wraps getaddrinfo (plan.md §G5).
rfb_error rfb_resolve_candidates(const char *host, uint16_t port,
                                 rfb_io_candidate *out, size_t *inout_count);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_SOCKET_POSIX_H
