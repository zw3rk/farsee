// SPDX-License-Identifier: Apache-2.0
//
// Secret-buffer zeroization helpers.
//
// rfb_secret_zero writes through a volatile-qualified byte pointer in a
// non-inline helper to resist dead-store elimination.

#ifndef FARSEE_INCLUDE_FARSEE_SECRET_H
#define FARSEE_INCLUDE_FARSEE_SECRET_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Zero n bytes of buf through a volatile-qualified byte pointer to resist
// dead-store elimination.
void rfb_secret_zero(void *buf, size_t n);

// Wipe the full allocation then free. NULL-safe. Prefer this over free() for
// any buffer that may have held a password (uses buf_cap, not logical len).
void rfb_secret_wipe_free(void *buf, size_t buf_cap);

// Maximum accepted private-artifact path storage, including the trailing NUL.
// Writers reject longer or unterminated paths; they never truncate a path.
#define RFB_PRIVATE_FILE_PATH_CAP 4096u

// Callback used by the private artifact writer. The descriptor starts at
// offset zero and names a new, mode-0600 temporary regular file. Return false
// on every formatting or write error.
typedef bool (*rfb_private_file_writer_fn)(int fd, void *context);

// Write all bytes or fail. A zero length succeeds without accessing `data`.
// A NULL data pointer is invalid for a non-zero length. EINTR is retried; a
// zero-byte write before completion is an error.
bool rfb_private_file_write_all(int fd, const void *data, size_t length);

// Atomically replace `path` with the callback output. Existing targets must be
// owner-owned, mode-0600, single-link regular files and must not be symlinks.
// Creation is exclusive and close-on-exec. The original target remains intact
// on callback, close, validation, or rename failure. Parent directories are
// not created.
bool rfb_private_file_write_0600(const char *path,
                                 rfb_private_file_writer_fn writer,
                                 void *context);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_SECRET_H
