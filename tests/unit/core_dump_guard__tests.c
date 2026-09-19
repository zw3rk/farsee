// SPDX-License-Identifier: Apache-2.0
//
// Fail-closed process core-dump protection tests.

#include "app/core_dump_guard.h"
#include "tests/test_framework/rfb_test.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__linux__)
#include <sys/prctl.h>
#endif

typedef enum guard_call {
    GUARD_CALL_SET_LIMITS = 1,
    GUARD_CALL_READ_LIMITS = 2,
    GUARD_CALL_SET_NONDUMPABLE = 3,
    GUARD_CALL_READ_NONDUMPABLE = 4,
} guard_call;

typedef struct guard_fake {
    bool set_limits_ok;
    bool read_limits_ok;
    bool soft_is_zero;
    bool hard_is_zero;
    bool set_nondumpable_ok;
    bool read_nondumpable_ok;
    bool nondumpable;
    guard_call calls[4];
    size_t call_count;
} guard_fake;

static void guard_fake_record(guard_fake *fake, guard_call call)
{
    if (fake->call_count < sizeof fake->calls / sizeof fake->calls[0]) {
        fake->calls[fake->call_count] = call;
    }
    fake->call_count += 1u;
}

static bool guard_fake_set_limits(void *context)
{
    guard_fake *fake = (guard_fake *)context;
    guard_fake_record(fake, GUARD_CALL_SET_LIMITS);
    return fake->set_limits_ok;
}

static bool guard_fake_read_limits(void *context,
                                   farsee_core_dump_limits *out)
{
    guard_fake *fake = (guard_fake *)context;
    guard_fake_record(fake, GUARD_CALL_READ_LIMITS);
    if (!fake->read_limits_ok) {
        return false;
    }
    out->soft_is_zero = fake->soft_is_zero;
    out->hard_is_zero = fake->hard_is_zero;
    return true;
}

static bool guard_fake_set_nondumpable(void *context)
{
    guard_fake *fake = (guard_fake *)context;
    guard_fake_record(fake, GUARD_CALL_SET_NONDUMPABLE);
    return fake->set_nondumpable_ok;
}

static bool guard_fake_read_nondumpable(void *context, bool *out)
{
    guard_fake *fake = (guard_fake *)context;
    guard_fake_record(fake, GUARD_CALL_READ_NONDUMPABLE);
    if (!fake->read_nondumpable_ok) {
        return false;
    }
    *out = fake->nondumpable;
    return true;
}

static farsee_core_dump_guard_ops guard_fake_ops(guard_fake *fake,
                                                 bool supplemental)
{
    farsee_core_dump_guard_ops ops = {
        .context = fake,
        .set_limits_zero = guard_fake_set_limits,
        .read_limits = guard_fake_read_limits,
        .set_nondumpable = NULL,
        .read_nondumpable = NULL,
    };
    if (supplemental) {
        ops.set_nondumpable = guard_fake_set_nondumpable;
        ops.read_nondumpable = guard_fake_read_nondumpable;
    }
    return ops;
}

typedef struct guard_case {
    const char *name;
    guard_fake fake;
    bool supplemental;
    bool expected;
    guard_call expected_calls[4];
    size_t expected_call_count;
} guard_case;

RFB_TEST(core_dump_guard, injected_outcomes_are_fail_closed_and_ordered)
{
    guard_case cases[] = {
        {
            .name = "verified limits",
            .fake = {true, true, true, true, true, true, true, {0}, 0u},
            .supplemental = false,
            .expected = true,
            .expected_calls = {GUARD_CALL_SET_LIMITS, GUARD_CALL_READ_LIMITS},
            .expected_call_count = 2u,
        },
        {
            .name = "verified limits and supplemental guard",
            .fake = {true, true, true, true, true, true, true, {0}, 0u},
            .supplemental = true,
            .expected = true,
            .expected_calls = {GUARD_CALL_SET_LIMITS, GUARD_CALL_READ_LIMITS,
                               GUARD_CALL_SET_NONDUMPABLE,
                               GUARD_CALL_READ_NONDUMPABLE},
            .expected_call_count = 4u,
        },
        {
            .name = "limit set failure",
            .fake = {false, true, true, true, true, true, true, {0}, 0u},
            .supplemental = true,
            .expected = false,
            .expected_calls = {GUARD_CALL_SET_LIMITS},
            .expected_call_count = 1u,
        },
        {
            .name = "limit read failure",
            .fake = {true, false, true, true, true, true, true, {0}, 0u},
            .supplemental = true,
            .expected = false,
            .expected_calls = {GUARD_CALL_SET_LIMITS, GUARD_CALL_READ_LIMITS},
            .expected_call_count = 2u,
        },
        {
            .name = "nonzero soft limit",
            .fake = {true, true, false, true, true, true, true, {0}, 0u},
            .supplemental = true,
            .expected = false,
            .expected_calls = {GUARD_CALL_SET_LIMITS, GUARD_CALL_READ_LIMITS},
            .expected_call_count = 2u,
        },
        {
            .name = "nonzero hard limit",
            .fake = {true, true, true, false, true, true, true, {0}, 0u},
            .supplemental = true,
            .expected = false,
            .expected_calls = {GUARD_CALL_SET_LIMITS, GUARD_CALL_READ_LIMITS},
            .expected_call_count = 2u,
        },
        {
            .name = "both limits nonzero",
            .fake = {true, true, false, false, true, true, true, {0}, 0u},
            .supplemental = true,
            .expected = false,
            .expected_calls = {GUARD_CALL_SET_LIMITS, GUARD_CALL_READ_LIMITS},
            .expected_call_count = 2u,
        },
        {
            .name = "supplemental set failure",
            .fake = {true, true, true, true, false, true, true, {0}, 0u},
            .supplemental = true,
            .expected = false,
            .expected_calls = {GUARD_CALL_SET_LIMITS, GUARD_CALL_READ_LIMITS,
                               GUARD_CALL_SET_NONDUMPABLE},
            .expected_call_count = 3u,
        },
        {
            .name = "supplemental read failure",
            .fake = {true, true, true, true, true, false, true, {0}, 0u},
            .supplemental = true,
            .expected = false,
            .expected_calls = {GUARD_CALL_SET_LIMITS, GUARD_CALL_READ_LIMITS,
                               GUARD_CALL_SET_NONDUMPABLE,
                               GUARD_CALL_READ_NONDUMPABLE},
            .expected_call_count = 4u,
        },
        {
            .name = "supplemental guard inactive",
            .fake = {true, true, true, true, true, true, false, {0}, 0u},
            .supplemental = true,
            .expected = false,
            .expected_calls = {GUARD_CALL_SET_LIMITS, GUARD_CALL_READ_LIMITS,
                               GUARD_CALL_SET_NONDUMPABLE,
                               GUARD_CALL_READ_NONDUMPABLE},
            .expected_call_count = 4u,
        },
    };

    for (size_t i = 0u; i < sizeof cases / sizeof cases[0]; ++i) {
        guard_case *test_case = &cases[i];
        const farsee_core_dump_guard_ops ops =
            guard_fake_ops(&test_case->fake, test_case->supplemental);
        RFB_CHECK_MSG(farsee_core_dump_guard_disable_with_ops(&ops) ==
                          test_case->expected,
                      test_case->name);
        RFB_CHECK_MSG(test_case->fake.call_count ==
                          test_case->expected_call_count,
                      test_case->name);
        for (size_t j = 0u; j < test_case->expected_call_count; ++j) {
            RFB_CHECK_MSG(test_case->fake.calls[j] ==
                              test_case->expected_calls[j],
                          test_case->name);
        }
    }
}

RFB_TEST(core_dump_guard, invalid_operation_tables_fail_before_syscalls)
{
    guard_fake fake = {true, true, true, true, true, true, true, {0}, 0u};
    farsee_core_dump_guard_ops ops = guard_fake_ops(&fake, false);

    RFB_CHECK(!farsee_core_dump_guard_disable_with_ops(NULL));

    ops.set_limits_zero = NULL;
    RFB_CHECK(!farsee_core_dump_guard_disable_with_ops(&ops));
    RFB_CHECK_EQ_UINT(fake.call_count, 0u);

    ops = guard_fake_ops(&fake, false);
    ops.read_limits = NULL;
    RFB_CHECK(!farsee_core_dump_guard_disable_with_ops(&ops));
    RFB_CHECK_EQ_UINT(fake.call_count, 0u);

    ops = guard_fake_ops(&fake, false);
    ops.set_nondumpable = guard_fake_set_nondumpable;
    RFB_CHECK(!farsee_core_dump_guard_disable_with_ops(&ops));
    RFB_CHECK_EQ_UINT(fake.call_count, 0u);

    ops = guard_fake_ops(&fake, false);
    ops.read_nondumpable = guard_fake_read_nondumpable;
    RFB_CHECK(!farsee_core_dump_guard_disable_with_ops(&ops));
    RFB_CHECK_EQ_UINT(fake.call_count, 0u);
}

RFB_TEST(core_dump_guard, production_guard_is_verified_in_child)
{
    const pid_t child = fork();
    if (child < 0) {
        RFB_FAIL("fork failed");
        return;
    }
    if (child == 0) {
        struct rlimit limits;
        if (!farsee_core_dump_guard_disable()) {
            _exit(10);
        }
        if (getrlimit(RLIMIT_CORE, &limits) != 0) {
            _exit(11);
        }
        if (limits.rlim_cur != (rlim_t)0 || limits.rlim_max != (rlim_t)0) {
            _exit(12);
        }
#if defined(__linux__)
        if (prctl(PR_GET_DUMPABLE, 0L, 0L, 0L, 0L) != 0) {
            _exit(13);
        }
#endif
        _exit(0);
    }

    int status = 0;
    RFB_CHECK_EQ_INT(waitpid(child, &status, 0), child);
    if (!WIFEXITED(status)) {
        RFB_FAIL("core-dump guard child did not exit normally");
        return;
    }
    RFB_CHECK_EQ_INT(WEXITSTATUS(status), 0);
}

typedef struct guarded_entry_fake {
    bool guard_result;
    unsigned guard_calls;
    unsigned body_calls;
    int body_result;
} guarded_entry_fake;

static bool guarded_entry_fake_guard(void *context)
{
    guarded_entry_fake *fake = (guarded_entry_fake *)context;
    fake->guard_calls += 1u;
    return fake->guard_result;
}

static int guarded_entry_fake_body(void *context)
{
    guarded_entry_fake *fake = (guarded_entry_fake *)context;
    fake->body_calls += 1u;
    return fake->body_result;
}

RFB_TEST(core_dump_guard, guarded_entry_refuses_before_application_body)
{
    guarded_entry_fake fake = {
        .guard_result = false,
        .guard_calls = 0u,
        .body_calls = 0u,
        .body_result = 27,
    };
    FILE *errors = tmpfile();
    RFB_CHECK(errors != NULL);

    RFB_CHECK_EQ_INT(
        farsee_core_dump_guarded_entry(
            guarded_entry_fake_guard, guarded_entry_fake_body, &fake, errors),
        1);
    RFB_CHECK_EQ_UINT(fake.guard_calls, 1u);
    RFB_CHECK_EQ_UINT(fake.body_calls, 0u);

    RFB_CHECK_EQ_INT(fseek(errors, 0L, SEEK_SET), 0);
    char message[128] = {0};
    RFB_CHECK(fread(message, 1u, sizeof message - 1u, errors) > 0u);
    RFB_CHECK(strstr(message, "refusing to start") != NULL);
    RFB_CHECK_EQ_INT(fclose(errors), 0);
}

RFB_TEST(core_dump_guard, guarded_entry_runs_body_only_after_success)
{
    guarded_entry_fake fake = {
        .guard_result = true,
        .guard_calls = 0u,
        .body_calls = 0u,
        .body_result = 27,
    };
    FILE *errors = tmpfile();
    RFB_CHECK(errors != NULL);

    RFB_CHECK_EQ_INT(
        farsee_core_dump_guarded_entry(
            guarded_entry_fake_guard, guarded_entry_fake_body, &fake, errors),
        27);
    RFB_CHECK_EQ_UINT(fake.guard_calls, 1u);
    RFB_CHECK_EQ_UINT(fake.body_calls, 1u);
    RFB_CHECK_EQ_INT(fseek(errors, 0L, SEEK_END), 0);
    RFB_CHECK_EQ_INT(ftell(errors), 0L);
    RFB_CHECK_EQ_INT(fclose(errors), 0);
}

RFB_TEST(core_dump_guard, guarded_entry_rejects_missing_operations)
{
    guarded_entry_fake fake = {
        .guard_result = true,
        .guard_calls = 0u,
        .body_calls = 0u,
        .body_result = 0,
    };
    FILE *errors = tmpfile();
    RFB_CHECK(errors != NULL);

    RFB_CHECK_EQ_INT(
        farsee_core_dump_guarded_entry(
            NULL, guarded_entry_fake_body, &fake, errors),
        1);
    RFB_CHECK_EQ_INT(
        farsee_core_dump_guarded_entry(
            guarded_entry_fake_guard, NULL, &fake, errors),
        1);
    RFB_CHECK_EQ_INT(
        farsee_core_dump_guarded_entry(
            guarded_entry_fake_guard, guarded_entry_fake_body, &fake, NULL),
        1);
    RFB_CHECK_EQ_UINT(fake.guard_calls, 0u);
    RFB_CHECK_EQ_UINT(fake.body_calls, 0u);
    RFB_CHECK_EQ_INT(fclose(errors), 0);
}
