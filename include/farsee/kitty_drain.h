// SPDX-License-Identifier: Apache-2.0
//
// farsee — shared Kitty output buffer drain (live present path).
//
// Pure-ish helper used by RFB live and RDP live: write buffered Kitty
// protocol bytes to a file descriptor (typically STDOUT_FILENO), retrying
// EINTR and preserving unwritten bytes on short write / EAGAIN.

#ifndef FARSEE_INCLUDE_FARSEE_KITTY_DRAIN_H
#define FARSEE_INCLUDE_FARSEE_KITTY_DRAIN_H

#include "farsee/buffer.h"
#include "farsee/farsee_thread.h"

#ifdef __cplusplus
extern "C" {
#endif

// Drain `out` to `fd`. Safe for NULL or empty buffer (no-op).
//
// On full write: clears the buffer.
// On partial write: consumes only the written prefix; remainder stays.
// On hard error (including invalid fd) after zero progress: leaves buffer
// unchanged. EINTR is retried. EAGAIN/EWOULDBLOCK stop the loop.
//
// write_mu: optional lock for buffer ownership only (mutate under lock;
// write(2) runs unlocked in chunks). Bytes stay in `out` until written so
// concurrent status (same mutex) still sees length > 0 and skips CSI mid-APC.
// On EAGAIN the remainder stays; callers must not write status CSI while
// rfb_buffer_length(out) > 0. Pass NULL when single-threaded.
//
// Does not permanently mutate fd flags: callers that need O_NONBLOCK on a
// shared stdout must arm/restore via farsee_live_shell_tty_guard.
//
// Returns true if the buffer is fully drained (or was empty); false if a
// remainder remains (EAGAIN / partial). Callers must not emit CSI while
// false (multi-review 2026-08-03 T2).
// On hard write errors (EPIPE/EIO/…, not EAGAIN), the buffer is cleared and
// true is returned so UI is not permanently wedged (post-t11 T6).
bool farsee_drain_kitty_out(rfb_buffer *out, int fd, farsee_mutex *write_mu);

// Same as farsee_drain_kitty_out, but when `out` starts with a Kitty APC
// opener (ESC _ G), prepends `prefix` (e.g. home CSI) into the buffer once
// under write_mu, then drains as one stream (deferred D2). Remainder after
// EAGAIN is mid-buffer (not a fresh APC open) so home is not re-prepended.
// Empty → true, no CSI. prefix may be NULL / prefix_len 0.
bool farsee_drain_kitty_out_with_prefix(rfb_buffer *out, int fd,
                                        farsee_mutex *write_mu,
                                        const char *prefix, size_t prefix_len);

#ifdef __cplusplus
}
#endif

#endif /* FARSEE_INCLUDE_FARSEE_KITTY_DRAIN_H */
