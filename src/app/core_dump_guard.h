// SPDX-License-Identifier: Apache-2.0
//
// Internal process core-dump protection. Production callers use
// farsee_core_dump_guard_disable(); the explicit operations table is the
// fault-injection seam for unit tests.

#ifndef FARSEE_SRC_APP_CORE_DUMP_GUARD_H
#define FARSEE_SRC_APP_CORE_DUMP_GUARD_H

#include <stdbool.h>
#include <stdio.h>

typedef struct farsee_core_dump_limits {
    bool soft_is_zero;
    bool hard_is_zero;
} farsee_core_dump_limits;

typedef struct farsee_core_dump_guard_ops {
    void *context;
    bool (*set_limits_zero)(void *context);
    bool (*read_limits)(void *context, farsee_core_dump_limits *out);

    // A reviewed platform can require a supplemental non-dumpable control.
    // Supply both callbacks or neither; an incomplete pair fails closed.
    bool (*set_nondumpable)(void *context);
    bool (*read_nondumpable)(void *context, bool *out);
} farsee_core_dump_guard_ops;

// Disable core dumps and verify the resulting platform state. Any syscall
// failure, incomplete operation table, or state mismatch returns false.
bool farsee_core_dump_guard_disable_with_ops(
    const farsee_core_dump_guard_ops *ops);

// Apply the reviewed production policy for the current supported platform.
bool farsee_core_dump_guard_disable(void);

typedef bool (*farsee_core_dump_guard_fn)(void *context);
typedef int (*farsee_core_dump_guarded_body_fn)(void *context);

// Run the application body only after the supplied guard succeeds. This
// keeps the startup ordering and refusal behavior independently testable.
int farsee_core_dump_guarded_entry(
    farsee_core_dump_guard_fn guard,
    farsee_core_dump_guarded_body_fn body,
    void *context,
    FILE *error_stream);

#endif /* FARSEE_SRC_APP_CORE_DUMP_GUARD_H */
