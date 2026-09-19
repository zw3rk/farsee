// SPDX-License-Identifier: Apache-2.0
//
// farsee test harness: runner + assertion helpers.
//
// Design (plan.md §14): test files compile independently and expose one
// constant record per RFB_TEST. The generated registry references those
// records directly, without constructors or linker sections.
//
// The Makefile regenerates both artifacts whenever the set of test
// files changes.

#include "rfb_test.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

// Per-test outcome state shared with assertion and skip macros.
bool        rfb_test__current_failed = false;
bool        rfb_test__current_skipped = false;
const char *rfb_test__current_name = "";
size_t      rfb_test__current_assert_line = 0;
const char *rfb_test__current_assert_file = "";

// --- Failure formatting state ----------------------------------------------
static char   g_last_msg[512];
static char   g_last_file[256];
static size_t g_last_line;

void rfb_test__record_failure(const char *file, size_t line, const char *msg)
{
    // Keep the first failure's message paired with its own location when a
    // test has several failing assertions.
    if (g_last_msg[0] == '\0') {
        snprintf(g_last_msg, sizeof g_last_msg, "%s", msg ? msg : "(no msg)");
        snprintf(g_last_file, sizeof g_last_file, "%s", file ? file : "?");
        g_last_line = line;
    }
}

void rfb_test__fail_fmt(const char *file, size_t line, const char *fmt, ...)
{
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    // fmt is always a literal from our own macros; suppress the
    // -Wformat-nonliteral warning locally without weakening the
    // project-wide -Wformat-security policy.
#if defined(__clang__)
#  pragma clang diagnostic push
#  pragma clang diagnostic ignored "-Wformat-nonliteral"
#endif
    vsnprintf(buf, sizeof buf, fmt, ap);
#if defined(__clang__)
#  pragma clang diagnostic pop
#endif
    va_end(ap);
    rfb_test__fail_at(file, line, buf);
}

bool rfb_test_mem_eq_hex(
    const void *actual, const void *expected, size_t n)
{
    const unsigned char *a = (const unsigned char *)actual;
    const unsigned char *e = (const unsigned char *)expected;
    for (size_t i = 0; i < n; i++) {
        if (a[i] != e[i]) {
            return false;
        }
    }
    return true;
}

// --- Sorting for stable, grouped output -----------------------------------
static int cmp_entry(const rfb_test_entry *a, const rfb_test_entry *b)
{
    int c = strcmp(a->suite, b->suite);
    if (c != 0) return c;
    return strcmp(a->name, b->name);
}

static void reset_test_state(void)
{
    g_last_msg[0] = '\0';
    g_last_file[0] = '\0';
    g_last_line = 0;
    rfb_test__current_failed = false;
    rfb_test__current_skipped = false;
}

// --- Opt-in per-test timeout ------------------------------------------------
// FARSEE_TEST_TIMEOUT_S=N arms alarm() around each test so a hung test
// fails fast instead of hanging `make test` forever (PTY-style hangs are a
// known failure class in this repo). The handler is async-signal-safe: it
// only write()s a line pre-formatted before the test ran, then _exit(1).
// The whole run terminates; that is the documented fail-fast contract.
static unsigned g_timeout_s;
static char   g_timeout_line[192];
static size_t g_timeout_line_len;

static void on_test_timeout(int sig)
{
    (void)sig;
    ssize_t written = write(2, g_timeout_line, g_timeout_line_len);
    (void)written;
    _exit(1);
}

int main(int argc, char **argv)
{
    const char *filter = NULL;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--filter") == 0 && i + 1 < argc) {
            filter = argv[++i];
        } else if (strncmp(argv[i], "--filter=", 9) == 0) {
            filter = argv[i] + 9;
        } else if (strcmp(argv[i], "--list") == 0) {
            for (size_t k = 0; k < rfb_test__all_entries_count; k++) {
                printf("%s::%s\n",
                       rfb_test__all_entries[k]->suite,
                       rfb_test__all_entries[k]->name);
            }
            return 0;
        } else {
            fprintf(stderr, "farsee_tests: unknown arg '%s'\n", argv[i]);
            fprintf(stderr, "usage: %s [--filter SUBSTR] [--list]\n"
                            "  SUBSTR matches the test name or the suite "
                            "name; a filter that matches\n"
                            "  nothing exits non-zero\n",
                    argv[0]);
            return 2;
        }
    }

    // Optional per-test alarm (see on_test_timeout above).
    const char *timeout_env = getenv("FARSEE_TEST_TIMEOUT_S");
    if (timeout_env != NULL && timeout_env[0] != '\0') {
        char *end = NULL;
        unsigned long v = strtoul(timeout_env, &end, 10);
        if (end != timeout_env && *end == '\0' && v > 0u && v <= 3600u) {
            g_timeout_s = (unsigned)v;
            struct sigaction sa_alrm;
            memset(&sa_alrm, 0, sizeof sa_alrm);
            sa_alrm.sa_handler = on_test_timeout;
            sigemptyset(&sa_alrm.sa_mask);
            sa_alrm.sa_flags = 0;  // no SA_RESTART: a timeout must kill us
            (void)sigaction(SIGALRM, &sa_alrm, NULL);
        } else {
            fprintf(stderr,
                    "farsee_tests: bad FARSEE_TEST_TIMEOUT_S '%s' "
                    "(want integer 1..3600); ignoring\n",
                    timeout_env);
        }
    }

    // Sort a shallow copy of the registry for stable, grouped output.
    // The generated array is already sorted, but we re-sort defensively
    // in case the generation order ever changes. We never mutate the
    // records, only reorder pointers to them.
    const rfb_test_entry **sorted = NULL;
    if (rfb_test__all_entries_count > 0) {
        sorted = (const rfb_test_entry **)calloc(
            rfb_test__all_entries_count, sizeof(const rfb_test_entry *));
        if (sorted == NULL) {
            fprintf(stderr, "farsee_tests: out of memory\n");
            return 2;
        }
        for (size_t k = 0; k < rfb_test__all_entries_count; k++) {
            sorted[k] = rfb_test__all_entries[k];
        }
        for (size_t k = 1; k < rfb_test__all_entries_count; k++) {
            const rfb_test_entry *key = sorted[k];
            size_t j = k;
            while (j > 0 && cmp_entry(sorted[j - 1], key) > 0) {
                sorted[j] = sorted[j - 1];
                j--;
            }
            sorted[j] = key;
        }
    }

    size_t total = rfb_test__all_entries_count;
    size_t ran = 0;
    size_t passed = 0;
    size_t failed = 0;
    size_t skipped = 0;
    size_t matched = 0;  // entries selected by --filter (when given)

    char last_suite[128] = "";
    size_t suite_passed = 0;
    size_t suite_failed = 0;

    for (size_t idx = 0; idx < total; idx++) {
        const rfb_test_entry *t = sorted[idx];
        // --filter matches the test name or the suite name.
        if (filter != NULL && strstr(t->name, filter) == NULL
            && strstr(t->suite, filter) == NULL) {
            skipped++;
            continue;
        }
        if (filter != NULL) {
            matched++;
        }
        if (strcmp(t->suite, last_suite) != 0) {
            if (last_suite[0] != '\0') {
                printf("  [%s] %zu passed, %zu failed\n",
                       last_suite, suite_passed, suite_failed);
            }
            snprintf(last_suite, sizeof last_suite, "%s", t->suite);
            suite_passed = 0;
            suite_failed = 0;
            printf("\n== %s ==\n", t->suite);
        }

        ran++;
        reset_test_state();
        rfb_test__current_name = t->name;
        if (g_timeout_s > 0u) {
            int n = snprintf(g_timeout_line, sizeof g_timeout_line,
                             "TIMEOUT after %us: %s::%s\n", g_timeout_s,
                             t->suite, t->name);
            g_timeout_line_len =
                (n > 0 && (size_t)n < sizeof g_timeout_line)
                    ? (size_t)n
                    : (sizeof g_timeout_line - 1u);
            alarm(g_timeout_s);
        }
        t->fn();
        if (g_timeout_s > 0u) {
            alarm(0);
        }
        if (rfb_test__current_skipped) {
            // A self-skipped test: count as skipped (not ran/passed/failed).
            ran--;
            skipped++;
            printf("  SKIP  %s\n", t->name);
        } else if (rfb_test__current_failed) {
            failed++;
            suite_failed++;
            printf("  FAIL  %s\n", t->name);
            if (g_last_file[0]) {
                printf("        %s:%zu: %s\n",
                       g_last_file, g_last_line, g_last_msg);
            }
        } else {
            passed++;
            suite_passed++;
            printf("  ok    %s\n", t->name);
        }
    }
    if (last_suite[0] != '\0') {
        printf("  [%s] %zu passed, %zu failed\n",
               last_suite, suite_passed, suite_failed);
    }

    // A filter that selects nothing is almost certainly a typo and fails.
    if (filter != NULL && matched == 0) {
        fprintf(stderr, "farsee_tests: no tests matched --filter '%s'\n",
                filter);
        free(sorted);
        return 2;
    }

    printf("\n----------------------------------------"
           "----------------------------------------\n");
    printf("TESTS  total=%zu  ran=%zu  passed=%zu  failed=%zu  skipped=%zu\n",
           total, ran, passed, failed, skipped);
    printf("----------------------------------------"
           "----------------------------------------\n");
    free(sorted);
    return failed == 0 ? 0 : 1;
}
