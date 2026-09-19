// SPDX-License-Identifier: Apache-2.0
//
// farsee — shared credential-fd readers.
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

// Default capacity in bytes, including the trailing NUL. Callers may pass a
// smaller capacity when appropriate.
#define FARSEE_SECRET_FD_DEFAULT_CAP ((size_t)1024u)

// Apple RSA1 accepts at most 234 username bytes. The returned allocation has
// one additional byte for a convenience NUL.
#define FARSEE_USERNAME_FD_CAP ((size_t)235u)

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

// Read one exact Apple username from `fd`. Accepted wire forms are raw
// USERNAME, USERNAME LF, or USERNAME CRLF followed by EOF. Logical length is
// 1..234 bytes. NUL, internal/bare/repeated terminators, bytes after the sole
// terminator, truncation, and every read error fail closed. No normalization
// is performed. Success returns the exact logical byte length in a malloc'd
// buffer whose allocation capacity is FARSEE_USERNAME_FD_CAP bytes.
long farsee_read_fd_username(int fd, char **out);

#ifdef __cplusplus
}
#endif

#endif /* FARSEE_INCLUDE_FARSEE_SECRET_FD_H */
