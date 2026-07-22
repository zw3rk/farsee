// SPDX-License-Identifier: Apache-2.0
//
// G18 — Known-hosts trust tests.

#include "rfb_test.h"
#include "farsee/known_hosts.h"
#include "farsee/farsee_thread.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

static const char *kh_path = "/tmp/farsee_known_hosts_test";

static void cleanup(void)
{
    unlink(kh_path);
}

static const uint8_t FP_A[32] = { 0xAA };
static const uint8_t FP_B[32] = { 0xBB };

RFB_TEST(g18_kh, known_hosts__first_use__not_found) {
    cleanup();
    RFB_CHECK_EQ_INT(
        known_hosts_check("host1", 5900, FP_A, kh_path),
        KNOWN_HOSTS_NOT_FOUND);
    cleanup();
}

RFB_TEST(g18_kh, known_hosts__add_then_check__match) {
    cleanup();
    RFB_CHECK(known_hosts_add("host1", 5900, FP_A, kh_path));
    RFB_CHECK_EQ_INT(
        known_hosts_check("host1", 5900, FP_A, kh_path),
        KNOWN_HOSTS_MATCH);
    cleanup();
}

RFB_TEST(g18_kh, known_hosts__changed_key__mismatch) {
    cleanup();
    RFB_CHECK(known_hosts_add("host1", 5900, FP_A, kh_path));
    RFB_CHECK_EQ_INT(
        known_hosts_check("host1", 5900, FP_B, kh_path),
        KNOWN_HOSTS_MISMATCH);
    cleanup();
}

RFB_TEST(g18_kh, known_hosts__file_mode_0600) {
    cleanup();
    RFB_CHECK(known_hosts_add("host1", 5900, FP_A, kh_path));
    struct stat st;
    stat(kh_path, &st);
    RFB_CHECK_EQ_UINT(st.st_mode & 0777, 0600u);
    cleanup();
}

RFB_TEST(g18_kh, known_hosts__different_ports__separate) {
    cleanup();
    RFB_CHECK(known_hosts_add("host1", 5900, FP_A, kh_path));
    RFB_CHECK_EQ_INT(
        known_hosts_check("host1", 5901, FP_A, kh_path),
        KNOWN_HOSTS_NOT_FOUND);
    cleanup();
}

RFB_TEST(g18_kh, known_hosts__add_same_twice__no_duplicate) {
    cleanup();
    RFB_CHECK(known_hosts_add("host1", 5900, FP_A, kh_path));
    RFB_CHECK(known_hosts_add("host1", 5900, FP_A, kh_path));
    // File should have exactly one line.
    FILE *f = fopen(kh_path, "r");
    char buf[1024];
    size_t n = fread(buf, 1, sizeof buf - 1, f);
    fclose(f);
    buf[n] = '\0';
    int newlines = 0;
    for (size_t i = 0; i < n; i++) if (buf[i] == '\n') newlines++;
    RFB_CHECK_EQ_INT(newlines, 1);
    cleanup();
}

RFB_TEST(g18_kh, known_hosts__null_inputs__fail_closed) {
    RFB_CHECK_EQ_INT(known_hosts_check(NULL, 5900, FP_A, kh_path),
                     KNOWN_HOSTS_MISMATCH);
    RFB_CHECK(!known_hosts_add(NULL, 5900, FP_A, kh_path));
}

// Residual T3: known_hosts_add creates parent directory when missing.
RFB_TEST(g18_kh, known_hosts__add_creates_parent_dir)
{
    const char *nested = "/tmp/farsee_kh_parent_test/rdp_known_hosts";
    // Remove nested path and parent dir if present.
    unlink(nested);
    rmdir("/tmp/farsee_kh_parent_test");
    RFB_CHECK(known_hosts_add("h", 3389, FP_A, nested));
    RFB_CHECK_EQ_INT(known_hosts_check("h", 3389, FP_A, nested),
                     KNOWN_HOSTS_MATCH);
    unlink(nested);
    rmdir("/tmp/farsee_kh_parent_test");
}

// full2 T7: whitespace host rejected.
RFB_TEST(g18_kh, known_hosts__whitespace_host__rejected)
{
    const char *path = "/tmp/farsee_kh_ws_test";
    unlink(path);
    RFB_CHECK(!known_hosts_add("bad host", 3389, FP_A, path));
    unlink(path);
}

// loop r2: MISMATCH under add fails closed — no rewrite / last-writer pin.
RFB_TEST(g18_kh, known_hosts__add_mismatch__fails_keeps_original)
{
    const char *path = "/tmp/farsee_kh_repin_test";
    unlink(path);
    RFB_CHECK(known_hosts_add("h", 3389, FP_A, path));
    RFB_CHECK_EQ_INT(known_hosts_check("h", 3389, FP_A, path), KNOWN_HOSTS_MATCH);
    // Second add with different fp must refuse; A remains pinned.
    RFB_CHECK(!known_hosts_add("h", 3389, FP_B, path));
    RFB_CHECK_EQ_INT(known_hosts_check("h", 3389, FP_A, path), KNOWN_HOSTS_MATCH);
    RFB_CHECK_EQ_INT(known_hosts_check("h", 3389, FP_B, path), KNOWN_HOSTS_MISMATCH);
    unlink(path);
    unlink("/tmp/farsee_kh_repin_test.lock");
}

// multi-review 2026-07-31 T8: two threads race known_hosts_add on the same
// host:port with different fingerprints → exactly one line (lock serializes
// check+mutate so we never double-append).
typedef struct {
    const char *path;
    const uint8_t *fp;
    int ok;
} kh_conc_arg;

static void *kh_conc_add(void *arg)
{
    kh_conc_arg *a = (kh_conc_arg *)arg;
    a->ok = known_hosts_add("racehost", 5900, a->fp, a->path) ? 1 : 0;
    return NULL;
}

RFB_TEST(g18_kh, known_hosts__concurrent_add_same_host__single_line)
{
    const char *path = "/tmp/farsee_kh_conc_test";
    unlink(path);
    unlink("/tmp/farsee_kh_conc_test.lock");

    kh_conc_arg a = { .path = path, .fp = FP_A, .ok = 0 };
    kh_conc_arg b = { .path = path, .fp = FP_B, .ok = 0 };

    farsee_thread *ta = farsee_thread_create(kh_conc_add, &a);
    farsee_thread *tb = farsee_thread_create(kh_conc_add, &b);
    RFB_CHECK(ta != NULL && tb != NULL);
    farsee_thread_join(&ta, NULL);
    farsee_thread_join(&tb, NULL);
    // Exactly one add succeeds; the other hits MISMATCH under lock and fails.
    RFB_CHECK((a.ok + b.ok) == 1);

    FILE *f = fopen(path, "r");
    RFB_CHECK(f != NULL);
    int lines = 0;
    int racehost_lines = 0;
    char buf[256];
    while (fgets(buf, (int)sizeof buf, f) != NULL) {
        if (buf[0] == '\0' || buf[0] == '\n') {
            continue;
        }
        lines++;
        if (strncmp(buf, "racehost ", 9) == 0) {
            racehost_lines++;
        }
    }
    fclose(f);
    RFB_CHECK_EQ_INT(lines, 1);
    RFB_CHECK_EQ_INT(racehost_lines, 1);
    // Surviving pin is the first writer under lock (loser fails closed).
    known_hosts_result ra = known_hosts_check("racehost", 5900, FP_A, path);
    known_hosts_result rb = known_hosts_check("racehost", 5900, FP_B, path);
    RFB_CHECK((ra == KNOWN_HOSTS_MATCH && rb == KNOWN_HOSTS_MISMATCH) ||
              (rb == KNOWN_HOSTS_MATCH && ra == KNOWN_HOSTS_MISMATCH));

    unlink(path);
    unlink("/tmp/farsee_kh_conc_test.lock");
}

// loop r1 T5: non-ENOENT fopen failure is MISMATCH (fail-closed), not first-use.
RFB_TEST(g18_kh, known_hosts__unreadable_store__mismatch) {
    cleanup();
    RFB_CHECK(known_hosts_add("host1", 5900, FP_A, kh_path));
    RFB_CHECK_EQ_INT(chmod(kh_path, 0), 0);
    // As non-root, fopen should fail with EACCES → MISMATCH.
    if (geteuid() != 0) {
        RFB_CHECK_EQ_INT(
            known_hosts_check("host1", 5900, FP_A, kh_path),
            KNOWN_HOSTS_MISMATCH);
    }
    (void)chmod(kh_path, 0600);
    cleanup();
}
