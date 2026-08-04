// SPDX-License-Identifier: Apache-2.0
//
// farsee — compiler-resistant secret zeroization (plan.md §G1, §6.3:
// "best-effort zeroization using a compiler-resistant helper").
//
// Used for the VNC password buffer and the authentication challenge
// response. The helper cannot be elided by the compiler's dead-store
// elimination: it uses a volatile function pointer so the write is
// observable and the compiler must emit it.

#ifndef FARSEE_INCLUDE_FARSEE_SECRET_H
#define FARSEE_INCLUDE_FARSEE_SECRET_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Zero n bytes of buf in a way that resists the compiler's dead-store
// elimination. The pointer-to-volatile indirection forces the store.
void rfb_secret_zero(void *buf, size_t n);

// Classic VNC Authentication uses only the first 8 password bytes (RFC 6143).
// When len > 8, zero the remainder of the allocation [8, buf_cap) and return 8.
// When len <= 8, return len unchanged. Never reads past buf_cap.
// buf may be NULL only when buf_cap == 0.
size_t rfb_secret_trunc_vnc8(void *buf, size_t len, size_t buf_cap);

// Wipe the full allocation then free. NULL-safe. Prefer this over free() for
// any buffer that may have held a password (uses buf_cap, not logical len).
void rfb_secret_wipe_free(void *buf, size_t buf_cap);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_SECRET_H
