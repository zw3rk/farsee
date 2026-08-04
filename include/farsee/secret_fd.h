// SPDX-License-Identifier: Apache-2.0
//
// farsee — shared password-fd reader (P0-N2).
//
// Single implementation for CLI stacks (RDP + RFB). Reads a secret from a
// file descriptor into a heap buffer, strips trailing CR/LF, NUL-terminates.
// Fail-closed on EAGAIN/EWOULDBLOCK (no spin); EINTR is retried.

#ifndef FARSEE_INCLUDE_FARSEE_SECRET_FD_H
#define FARSEE_INCLUDE_FARSEE_SECRET_FD_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Recommended default capacity (bytes including the trailing NUL).
// RDP historically used 1024; RFB used 256 — shared API uses 1024.
// Callers may pass a smaller cap when appropriate.
#define FARSEE_SECRET_FD_DEFAULT_CAP ((size_t)1024u)

// Read up to (cap - 1) bytes from `fd` into a freshly allocated buffer.
//
// On success:
//   - *out is a malloc'd NUL-terminated string (caller frees with free());
//   - trailing '\r' and/or '\n' are stripped;
//   - returns the length excluding the NUL.
//
// On failure:
//   - returns -1;
//   - if out is non-NULL, *out is set to NULL (no partial ownership).
//
// Failures include: out == NULL, cap < 1, fd < 0, allocation failure,
// hard read errors, and EAGAIN/EWOULDBLOCK (nonblocking empty pipe — does
// not spin). EINTR is retried.
long farsee_read_fd_secret(int fd, char **out, size_t cap);

#ifdef __cplusplus
}
#endif

#endif /* FARSEE_INCLUDE_FARSEE_SECRET_FD_H */
