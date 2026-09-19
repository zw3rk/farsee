// SPDX-License-Identifier: Apache-2.0
//
// Fail-closed process core-dump protection for supported product targets.

#include "app/core_dump_guard.h"

#if !defined(__APPLE__) && !defined(__linux__)
#error "farsee core-dump protection has no reviewed implementation for this target"
#endif

#include <stddef.h>
#include <sys/resource.h>

#ifndef RLIMIT_CORE
#error "farsee requires RLIMIT_CORE to protect process secrets"
#endif

#if defined(__linux__)
#include <sys/prctl.h>
#endif

bool farsee_core_dump_guard_disable_with_ops(
    const farsee_core_dump_guard_ops *ops)
{
    if (ops == NULL || ops->set_limits_zero == NULL ||
        ops->read_limits == NULL ||
        ((ops->set_nondumpable == NULL) !=
         (ops->read_nondumpable == NULL))) {
        return false;
    }

    if (!ops->set_limits_zero(ops->context)) {
        return false;
    }

    farsee_core_dump_limits limits = {
        .soft_is_zero = false,
        .hard_is_zero = false,
    };
    if (!ops->read_limits(ops->context, &limits) || !limits.soft_is_zero ||
        !limits.hard_is_zero) {
        return false;
    }

    if (ops->set_nondumpable != NULL) {
        bool nondumpable = false;
        if (!ops->set_nondumpable(ops->context) ||
            !ops->read_nondumpable(ops->context, &nondumpable) ||
            !nondumpable) {
            return false;
        }
    }

    return true;
}

static bool guard_set_limits_zero(void *context)
{
    (void)context;
    const struct rlimit limits = {
        .rlim_cur = (rlim_t)0,
        .rlim_max = (rlim_t)0,
    };
    return setrlimit(RLIMIT_CORE, &limits) == 0;
}

static bool guard_read_limits(void *context, farsee_core_dump_limits *out)
{
    (void)context;
    if (out == NULL) {
        return false;
    }

    struct rlimit limits;
    if (getrlimit(RLIMIT_CORE, &limits) != 0) {
        return false;
    }
    out->soft_is_zero = limits.rlim_cur == (rlim_t)0;
    out->hard_is_zero = limits.rlim_max == (rlim_t)0;
    return true;
}

#if defined(__linux__)
static bool guard_set_nondumpable(void *context)
{
    (void)context;
    return prctl(PR_SET_DUMPABLE, 0L, 0L, 0L, 0L) == 0;
}

static bool guard_read_nondumpable(void *context, bool *out)
{
    (void)context;
    if (out == NULL) {
        return false;
    }

    const int dumpable = prctl(PR_GET_DUMPABLE, 0L, 0L, 0L, 0L);
    if (dumpable < 0) {
        return false;
    }
    *out = dumpable == 0;
    return true;
}
#endif

bool farsee_core_dump_guard_disable(void)
{
    static const farsee_core_dump_guard_ops ops = {
        .context = NULL,
        .set_limits_zero = guard_set_limits_zero,
        .read_limits = guard_read_limits,
#if defined(__linux__)
        .set_nondumpable = guard_set_nondumpable,
        .read_nondumpable = guard_read_nondumpable,
#else
        .set_nondumpable = NULL,
        .read_nondumpable = NULL,
#endif
    };
    return farsee_core_dump_guard_disable_with_ops(&ops);
}

int farsee_core_dump_guarded_entry(
    farsee_core_dump_guard_fn guard,
    farsee_core_dump_guarded_body_fn body,
    void *context,
    FILE *error_stream)
{
    if (guard == NULL || body == NULL || error_stream == NULL) {
        return 1;
    }
    if (!guard(context)) {
        fputs("farsee: cannot establish core-dump protection; "
              "refusing to start\n", error_stream);
        return 1;
    }
    return body(context);
}
