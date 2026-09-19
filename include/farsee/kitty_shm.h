// SPDX-License-Identifier: Apache-2.0
//
// farsee — Kitty POSIX shared-memory presenter (ADR-0005).
//
// Kitty `t=s` shared memory is a one-shot transfer object: the terminal
// reads the object and unlinks/closes it. The implementation creates a
// fresh object per transfer, writes the raw pixel bytes, sends the Kitty
// t=s command with only the object name base64-encoded, then waits for
// the terminal to acknowledge before cleaning up.
//
// Key constraints:
//   - unpredictable POSIX shm names beginning with '/';
//   - O_CREAT | O_EXCL, mode 0600;
//   - checked ftruncate, mmap, write, unmap;
//   - base64 only of the shm name, NOT the image bytes;
//   - bounded number of in-flight objects;
//   - no reuse until ack/cleanup resolved;
//   - cleanup on success, error, timeout, cancellation;
//   - deterministic direct fallback on failure.

#ifndef FARSEE_INCLUDE_FARSEE_KITTY_SHM_H
#define FARSEE_INCLUDE_FARSEE_KITTY_SHM_H

#include "farsee/buffer.h"
#include "farsee/error.h"
#include "farsee/kitty_protocol.h"
#include "farsee/kitty_shm_table.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Generate an unpredictable POSIX shm name. The name begins with '/' and
// contains random hex characters. `out` must have room for at least
// `out_cap` bytes; the result is null-terminated. Returns false if the
// cap is too small.
bool rfb_shm_generate_name(char *out, size_t out_cap);

// Platform cleanup operations used by the SHM transfer. The explicit table
// keeps error handling deterministic and provides a fault seam without global
// process state. Production callers use rfb_shm_transfer().
typedef struct rfb_shm_platform_ops {
    void *context;
    int (*unmap_fn)(void *context, void *address, size_t length);
    int (*close_fn)(void *context, int fd);
    int (*unlink_fn)(void *context, const char *name);
} rfb_shm_platform_ops;

// Transfer a framebuffer image via POSIX shared memory + Kitty t=s.
//
// 1. check the in-flight table; if full, return RFB_ERR_IO (caller falls
//    back to direct transfer);
// 2. generate an unpredictable shm name;
// 3. shm_open(O_CREAT|O_EXCL, 0600);
// 4. ftruncate to the image byte count;
// 5. mmap, memcpy the pixel bytes, munmap;
// 6. emit the Kitty t=s command (only the name is base64-encoded);
// 7. close the fd; register in the in-flight table;
// 8. best-effort shm_unlink (tolerates ENOENT — terminal may have unlinked).
//
// On ANY failure at steps 3-6, the shm object is unlinked and the function
// returns RFB_ERR_IO (the caller falls back to direct transfer).
//
// `out` accumulates the Kitty escape sequence. `table` is the bounded
// in-flight tracking table; pass NULL to skip tracking
// (legacy callers).
// `place_cols` / `place_rows`: optional Kitty c/r cell rectangle (0 = omit).
rfb_error rfb_shm_transfer(rfb_buffer *out,
                           const uint8_t *rgba,
                           uint32_t width, uint32_t height,
                           kitty_format fmt,
                           uint32_t image_id,
                           uint32_t placement_id,
                           bool request_ack,
                           rfb_shm_table *table,
                           uint32_t place_cols,
                           uint32_t place_rows);

rfb_error rfb_shm_transfer_with_ops(rfb_buffer *out,
                                    const uint8_t *rgba,
                                    uint32_t width, uint32_t height,
                                    kitty_format fmt,
                                    uint32_t image_id,
                                    uint32_t placement_id,
                                    bool request_ack,
                                    rfb_shm_table *table,
                                    uint32_t place_cols,
                                    uint32_t place_rows,
                                    const rfb_shm_platform_ops *ops);

// The maximum number of in-flight SHM objects.
#define KITTY_SHM_MAX_INFLIGHT 8u

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_KITTY_SHM_H
