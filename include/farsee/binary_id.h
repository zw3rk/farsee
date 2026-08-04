// SPDX-License-Identifier: Apache-2.0
//
// farsee — running binary identity (inode / mtime / git) for stale-rebuild
// detection. When `make` replaces build/dev/bin/farsee, a still-running
// process keeps the old inode mapped; these helpers make that visible.

#ifndef FARSEE_INCLUDE_FARSEE_BINARY_ID_H
#define FARSEE_INCLUDE_FARSEE_BINARY_ID_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Resolve this process's executable path, record inode+mtime, print one
// identity line to stderr. Safe to call once at process start (argv0 may
// be NULL).
void farsee_binary_id_init(const char *argv0);

// Re-stat the on-disk path recorded at init. If the inode or mtime differs
// from what this process started with, print a one-shot WARNING to stderr
// (disk was rebuilt while we were running). Returns true if stale.
bool farsee_binary_id_warn_if_stale(void);

// Accessors for tests / diagnostics (valid after init).
const char *farsee_binary_id_path(void);
const char *farsee_binary_id_git(void);
const char *farsee_binary_id_build_time(void);
unsigned long long farsee_binary_id_inode(void);

#ifdef __cplusplus
}
#endif

#endif /* FARSEE_INCLUDE_FARSEE_BINARY_ID_H */
