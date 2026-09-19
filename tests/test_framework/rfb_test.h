// SPDX-License-Identifier: Apache-2.0
//
// farsee — project-owned minimal C test harness (plan.md §14).
//
// Registration model:
//   Each RFB_TEST() emits a static function plus a `const rfb_test_entry`
//   record with external linkage. A small helper (tools/gen_test_registry.py)
//   scans the test sources for RFB_TEST() invocations and emits:
//     - an empty compatibility header proving test sources are not included;
//     - the rfb_test__all_entries[] array of pointers to those records.
//   The Makefile regenerates this list whenever the set of test files
//   changes, so adding a test file needs no manual edit.
//
// Why not constructors or linker sections?
//   - __attribute__((constructor)) deadlocks under AddressSanitizer on
//     macOS during dyld initializer execution (observed; never reaches
//     main). The project requires ASan-clean runs (plan.md §15.4, G12).
//   - Linker-section boundary symbols (section$start$/section$stop$) are
//     not emitted reliably by modern Apple ld, even for short section
//     names. ELF works but Mach-O does not.
//   - Independent test objects plus the generated registry are portable,
//     ASan-safe, and avoid one compiler process for the full suite.
//
// Conventions (plan.md §13.4):
//   test name: <module>__<condition>__<expected_result>
//
// Do not introduce sleeps or timing-based assertions (plan.md §13.3).
// Use deterministic fakes for time, I/O, and allocation.

#ifndef FARSEE_TESTS_TEST_FRAMEWORK_RFB_TEST_H
#define FARSEE_TESTS_TEST_FRAMEWORK_RFB_TEST_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// A test function takes no arguments and returns nothing. It records
// failures through the RFB_TEST_* macros below; the runner observes the
// per-test failure flag.
typedef void (*rfb_test_fn)(void);

// A single test record. Each RFB_TEST() emits one of these with external
// linkage so the generated registry can take its address by name.
typedef struct rfb_test_entry {
    const char *suite;     // logical group ("checked", "handshake", ...)
    const char *name;      // full <module>__<condition>__<expected_result>
    rfb_test_fn fn;
} rfb_test_entry;

// The generated registry. Defined in tests/test_framework/registry.generated.c
// which is produced by tools/gen_test_registry.py.
extern const rfb_test_entry *const rfb_test__all_entries[];
extern const size_t rfb_test__all_entries_count;

#define RFB_TEST_CONCAT_(a, b) a##b
#define RFB_TEST_CONCAT(a, b) RFB_TEST_CONCAT_(a, b)

// Register a test. Use it at file scope:
//
//   RFB_TEST(checked, checked_mul__size_t_overflow__returns_false) {
//       ...
//   }
//
// Expands to:
//   - a forward declaration of the (static) test function;
//   - an externally-visible `rfb_test_entry` record holding the suite
//     name, test name, and function pointer; and
//   - the static test function body that follows the macro.
//
// The record's symbol name is `rfb_test_rec__<test_name>`; the generator
// finds it by that exact pattern.
#define RFB_TEST(suite_name, test_name)                                        \
    static void test_name(void);                                               \
    const rfb_test_entry rfb_test_rec__##test_name = {                         \
        .suite = #suite_name,                                                  \
        .name  = #test_name,                                                   \
        .fn    = test_name,                                                    \
    };                                                                         \
    static void test_name(void)

// ---------------------------------------------------------------------------
// Per-test outcome state shared with the runner.
// The runner resets it between tests; assertion and skip macros update it
// while the selected test runs. Tests execute sequentially.
// ---------------------------------------------------------------------------
extern bool     rfb_test__current_failed;
extern bool     rfb_test__current_skipped;   // set by RFB_SKIP()
extern const char *rfb_test__current_name;
extern size_t   rfb_test__current_assert_line;
extern const char *rfb_test__current_assert_file;

// Mark the current test as skipped (e.g. a platform/sanitizer-specific
// gate that cannot run here). A skipped test is counted as neither passed
// nor failed; the runner reports it in the skipped tally. Use sparingly
// and always document why (e.g. an ADR-documented deadlock).
#define RFB_SKIP(reason)                                                       \
    do {                                                                       \
        rfb_test__current_skipped = true;                                      \
        (void)(reason);                                                        \
        return;                                                                \
    } while (0)

#define rfb_test__fail_at(file, line, msg)                                     \
    do {                                                                       \
        rfb_test__current_failed = true;                                       \
        rfb_test__current_assert_file = file;                                  \
        rfb_test__current_assert_line = line;                                  \
        rfb_test__record_failure(file, line, msg);                             \
    } while (0)

#define rfb_test__fail(msg) rfb_test__fail_at(__FILE__, __LINE__, msg)

// --- Core assertions -------------------------------------------------------
#define RFB_CHECK(cond)                                                        \
    do {                                                                       \
        if (!(cond)) {                                                         \
            rfb_test__fail("RFB_CHECK(" #cond ") failed");                     \
        }                                                                      \
    } while (0)

#define RFB_FAIL(msg) rfb_test__fail(msg)

#define RFB_CHECK_MSG(cond, msg)                                               \
    do {                                                                       \
        if (!(cond)) {                                                         \
            rfb_test__fail(msg);                                               \
        }                                                                      \
    } while (0)

// --- Integer equality with signed/unsigned flavors -------------------------
#define RFB_CHECK_EQ_INT(actual, expected)                                     \
    do {                                                                       \
        long long rfb_a__ = (long long)(actual);                               \
        long long rfb_e__ = (long long)(expected);                             \
        if (rfb_a__ != rfb_e__) {                                              \
            rfb_test__fail_fmt(__FILE__, __LINE__,                             \
                "RFB_CHECK_EQ_INT(%s=%lld, %s=%lld)",                          \
                #actual, rfb_a__, #expected, rfb_e__);                         \
        }                                                                      \
    } while (0)

#define RFB_CHECK_EQ_UINT(actual, expected)                                    \
    do {                                                                       \
        unsigned long long rfb_a__ = (unsigned long long)(actual);             \
        unsigned long long rfb_e__ = (unsigned long long)(expected);           \
        if (rfb_a__ != rfb_e__) {                                              \
            rfb_test__fail_fmt(__FILE__, __LINE__,                             \
                "RFB_CHECK_EQ_UINT(%s=%llu, %s=%llu)",                         \
                #actual, rfb_a__, #expected, rfb_e__);                         \
        }                                                                      \
    } while (0)

// --- Memory equality (used heavily by framebuffer tests) -------------------
#define RFB_CHECK_MEM_EQ(actual, expected, n)                                  \
    do {                                                                       \
        const unsigned char *rfb_a__ = (const unsigned char *)(actual);        \
        const unsigned char *rfb_e__ = (const unsigned char *)(expected);      \
        size_t rfb_n__ = (size_t)(n);                                          \
        for (size_t rfb_i__ = 0; rfb_i__ < rfb_n__; rfb_i__++) {               \
            if (rfb_a__[rfb_i__] != rfb_e__[rfb_i__]) {                        \
                rfb_test__fail_fmt(__FILE__, __LINE__,                         \
                    "RFB_CHECK_MEM_EQ mismatch at byte %zu: "                  \
                    "0x%02x != 0x%02x",                                        \
                    rfb_i__, rfb_a__[rfb_i__], rfb_e__[rfb_i__]);              \
                break;                                                         \
            }                                                                  \
        }                                                                      \
    } while (0)

// --- Hex-dump comparison helper (returns true on match) -------------------
bool rfb_test_mem_eq_hex(
    const void *actual, const void *expected, size_t n);

// Internal helpers used by the macros. Not for direct test use.
void rfb_test__record_failure(
    const char *file, size_t line, const char *msg);
void rfb_test__fail_fmt(
    const char *file, size_t line, const char *fmt, ...);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_TESTS_TEST_FRAMEWORK_RFB_TEST_H
