// SPDX-License-Identifier: Apache-2.0
//
// farsee — I/O adapter (plan.md §G5, §14.5 "Socket fault tests").
//
// The production implementation wraps a POSIX nonblocking socket. Tests
// inject deterministic short reads, short writes, EINTR, EAGAIN, and
// peer half-close behavior through the abstract operations. Socket tests
// cover connect deadlines separately.
//
// This is the single boundary at which "a single read()/write() must
// complete a message" is NOT assumed (plan.md §14.5).

#ifndef FARSEE_INCLUDE_FARSEE_IO_ADAPTER_H
#define FARSEE_INCLUDE_FARSEE_IO_ADAPTER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Result of a single I/O operation.
typedef enum {
    RFB_IO_OK    = 0,  // read/wrote some bytes (check *out_n)
    RFB_IO_BLOCK = 1,  // EAGAIN/EWOULDBLOCK; come back later
    RFB_IO_EOF   = 2,  // peer closed (read returned 0)
    RFB_IO_ERROR = 3,  // hard error
} rfb_io_result;

// A connect candidate (one resolved address from getaddrinfo). Tests
// inject a list of these to exercise IPv4/IPv6 iteration.
typedef struct rfb_io_candidate {
    int family;      // AF_INET / AF_INET6
    int socktype;    // SOCK_STREAM
    int protocol;    // IPPROTO_TCP or 0
    // sockaddr storage; the candidate owns a copy.
    uint8_t addr[64];
    size_t addr_len;
} rfb_io_candidate;

// The adapter interface. Each function takes the adapter's own context
// pointer. Tests provide a fake implementation; production provides the
// POSIX one.
typedef struct rfb_io_adapter {
    void *ctx;
    // Establish a connection to the chosen candidate. Returns RFB_IO_OK
    // on success or RFB_IO_ERROR on failure.
    rfb_io_result (*connect)(void *ctx, const rfb_io_candidate *c);
    // Read up to n bytes into buf. Sets *out_n to the number read. A
    // peer-close is reported as RFB_IO_EOF (with *out_n=0).
    rfb_io_result (*read)(void *ctx, uint8_t *buf, size_t n, size_t *out_n);
    // Write up to n bytes from buf. Sets *out_n to the number written
    // (may be less than n — short write). EAGAIN/EWOULDBLOCK returns
    // RFB_IO_BLOCK with *out_n reflecting any partial write this call.
    rfb_io_result (*write)(void *ctx, const uint8_t *buf, size_t n, size_t *out_n);
    // Close the underlying resource.
    void (*close)(void *ctx);
} rfb_io_adapter;

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_IO_ADAPTER_H
