// SPDX-License-Identifier: Apache-2.0
//
// Shared Kitty output buffer drain (P2 pure live helper).
// See farsee/kitty_drain.h.

#include "farsee/kitty_drain.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>

// Chunk size for write loops. Keep data in `out` until each chunk is
// written so draw_status (length > 0 under the same mutex) still skips
// CSI mid-APC; only hold write_mu around buffer mutate, not write(2)
// (multi-review r2 F6).
#define FARSEE_KITTY_DRAIN_CHUNK 8192u

bool farsee_drain_kitty_out(rfb_buffer *out, int fd, farsee_mutex *write_mu)
{
    return farsee_drain_kitty_out_with_prefix(out, fd, write_mu, NULL, 0u);
}

bool farsee_drain_kitty_out_with_prefix(rfb_buffer *out, int fd,
                                        farsee_mutex *write_mu,
                                        const char *prefix, size_t prefix_len)
{
    if (out == NULL) {
        return true;
    }

    // Prefer non-blocking I/O so a full TTY cannot freeze the present thread
    // forever. Callers own permanent O_NONBLOCK on shared stdin/stdout
    // (tty_guard restore); we do not F_SETFL here so shell fds are not
    // left nonblocking after exit (T3).
    bool did_prefix = false;
    for (;;) {
        if (write_mu != NULL) {
            farsee_mutex_lock(write_mu);
        }
        if (rfb_buffer_length(out) == 0u) {
            if (write_mu != NULL) {
                farsee_mutex_unlock(write_mu);
            }
            return true;
        }
        if (fd < 0) {
            if (write_mu != NULL) {
                farsee_mutex_unlock(write_mu);
            }
            return false;
        }

        // At APC opener (ESC _ G), prepend placement CSI into the buffer so one
        // drain path handles short writes / EAGAIN — no side-channel prefix.
        if (!did_prefix && prefix != NULL && prefix_len > 0u) {
            const uint8_t *data0 = rfb_buffer_data(out);
            const size_t len0 = rfb_buffer_length(out);
            const bool at_apc_open =
                (data0 != NULL && len0 >= 3u && data0[0] == 0x1Bu &&
                 data0[1] == (uint8_t)'_' && data0[2] == (uint8_t)'G');
            if (at_apc_open) {
                // Caller owns one-home-per-batch latch; at_apc_open rejects
                // residual that already starts with home CSI (ESC[).
                if (rfb_buffer_prepend(out, prefix, prefix_len) != RFB_OK) {
                    // OOM/limit: drain body without home rather than hang.
                }
            }
            did_prefix = true;
        }

        const uint8_t *data = rfb_buffer_data(out);
        const size_t len = rfb_buffer_length(out);
        if (data == NULL || len == 0u) {
            if (write_mu != NULL) {
                farsee_mutex_unlock(write_mu);
            }
            return true;
        }

        // Snapshot a chunk; leave bytes in `out` so concurrent status under
        // the same mutex still sees length > 0 and skips CSI (full2 T6).
        size_t chunk = len;
        if (chunk > FARSEE_KITTY_DRAIN_CHUNK) {
            chunk = FARSEE_KITTY_DRAIN_CHUNK;
        }
        uint8_t tmp[FARSEE_KITTY_DRAIN_CHUNK];
        memcpy(tmp, data, chunk);
        if (write_mu != NULL) {
            farsee_mutex_unlock(write_mu);
        }

        // write(2) without the mutex (r2 F6).
        size_t off = 0u;
        bool hard_err = false;
        bool eagain = false;
        while (off < chunk) {
            ssize_t n = write(fd, tmp + off, chunk - off);
            if (n > 0) {
                off += (size_t)n;
            } else if (n == -1 && errno == EINTR) {
                continue;
            } else if (n == -1 &&
                       (errno == EAGAIN || errno == EWOULDBLOCK)) {
                eagain = true;
                break;
            } else {
                hard_err = true;
                break;
            }
        }

        if (write_mu != NULL) {
            farsee_mutex_lock(write_mu);
        }
        if (hard_err) {
            // Drop remainder so CSI is not wedged (post-t11 T6).
            rfb_buffer_clear(out);
            if (write_mu != NULL) {
                farsee_mutex_unlock(write_mu);
            }
            return true;
        }
        if (off > 0u) {
            // Consume only the written prefix; concurrent present appends
            // only at the end, so front bytes are still our snapshot.
            const size_t cur = rfb_buffer_length(out);
            const size_t take = (off < cur) ? off : cur;
            rfb_buffer_consume(out, take);
        }
        const size_t left = rfb_buffer_length(out);
        if (write_mu != NULL) {
            farsee_mutex_unlock(write_mu);
        }
        if (eagain) {
            return false;
        }
        if (left == 0u) {
            return true;
        }
        // More bytes (rest of snapshot or concurrent append) — next chunk.
    }
}
