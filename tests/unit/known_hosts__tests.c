// SPDX-License-Identifier: Apache-2.0
//
// Known-hosts trust-store tests.

#include "rfb_test.h"
#include "farsee/known_hosts.h"
#include "farsee/farsee_thread.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <dirent.h>
#include <sys/resource.h>
#include <sys/wait.h>
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

static bool write_entry_file(const char *path, const char *host, uint16_t port,
                             const uint8_t fp[32], const char *suffix,
                             mode_t mode)
{
    static const char hex_digits[] = "0123456789abcdef";
    char hex[65];
    for (size_t i = 0u; i < 32u; i++) {
        hex[i * 2u] = hex_digits[(fp[i] >> 4u) & 0x0fu];
        hex[i * 2u + 1u] = hex_digits[fp[i] & 0x0fu];
    }
    hex[64] = '\0';
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (fd < 0) {
        return false;
    }
    char line[512];
    int n = snprintf(line, sizeof line, "%s %u %s%s\n", host,
                     (unsigned)port, hex, suffix != NULL ? suffix : "");
    bool ok = n > 0 && (size_t)n < sizeof line &&
              write(fd, line, (size_t)n) == (ssize_t)n &&
              fchmod(fd, mode) == 0;
    close(fd);
    return ok;
}

static bool write_raw_store(const char *path, const char *text)
{
    if (path == NULL || text == NULL) {
        return false;
    }
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        return false;
    }
    const size_t length = strlen(text);
    const bool ok = write(fd, text, length) == (ssize_t)length &&
                    fchmod(fd, 0600) == 0;
    return close(fd) == 0 && ok;
}

static bool write_large_store(const char *path, size_t block_count)
{
    char hex[65];
    memset(hex, '0', sizeof hex - 1u);
    hex[sizeof hex - 1u] = '\0';
    char line[96];
    const int formatted = snprintf(
        line, sizeof line, "filler 1 %s\n", hex);
    if (formatted <= 0 || (size_t)formatted >= sizeof line) {
        return false;
    }
    const size_t line_length = (size_t)formatted;
    char block[8192];
    size_t block_length = 0u;
    while (block_length + line_length <= sizeof block) {
        memcpy(block + block_length, line, line_length);
        block_length += line_length;
    }

    const int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        return false;
    }
    bool ok = true;
    for (size_t block_index = 0u;
         ok && block_index < block_count;
         block_index++) {
        size_t written = 0u;
        while (written < block_length) {
            const ssize_t count = write(
                fd, block + written, block_length - written);
            if (count < 0 && errno == EINTR) {
                continue;
            }
            if (count <= 0) {
                ok = false;
                break;
            }
            written += (size_t)count;
        }
    }
    if (fchmod(fd, 0600) != 0) {
        ok = false;
    }
    return close(fd) == 0 && ok;
}

typedef enum kh_temp_race_action {
    KH_TEMP_RACE_REMOVE_TEMP = 0,
    KH_TEMP_RACE_REMOVE_TARGET,
} kh_temp_race_action;

typedef struct kh_temp_race {
    const char *directory;
    const char *target;
    int ready_fd;
    kh_temp_race_action action;
    bool acted;
} kh_temp_race;

static void *kh_temp_race_run(void *context)
{
    kh_temp_race *race = (kh_temp_race *)context;
    DIR *directory = opendir(race->directory);
    const uint8_t ready = directory != NULL ? 1u : 0u;
    if (write(race->ready_fd, &ready, sizeof ready) !=
        (ssize_t)sizeof ready) {
        if (directory != NULL) {
            closedir(directory);
        }
        return NULL;
    }
    if (directory == NULL) {
        return NULL;
    }

    const uint64_t deadline = farsee_thread_monotonic_ms() + 5000u;
    while (!race->acted && farsee_thread_monotonic_ms() < deadline) {
        rewinddir(directory);
        struct dirent *entry;
        while ((entry = readdir(directory)) != NULL) {
            if (strncmp(entry->d_name, "known_hosts.tmp.", 16u) != 0) {
                continue;
            }
            if (race->action == KH_TEMP_RACE_REMOVE_TARGET) {
                race->acted = unlink(race->target) == 0;
            } else {
                char temporary[256];
                const int n = snprintf(
                    temporary, sizeof temporary, "%s/%s",
                    race->directory, entry->d_name);
                race->acted = n > 0 && (size_t)n < sizeof temporary &&
                              unlink(temporary) == 0;
            }
            break;
        }
    }
    closedir(directory);
    return NULL;
}

static bool run_known_hosts_temp_race(
    const char *directory, const char *path, kh_temp_race_action action)
{
    int ready_pipe[2];
    if (pipe(ready_pipe) != 0) {
        return false;
    }
    kh_temp_race race = {
        .directory = directory,
        .target = path,
        .ready_fd = ready_pipe[1],
        .action = action,
        .acted = false,
    };
    farsee_thread *thread = farsee_thread_create(kh_temp_race_run, &race);
    if (thread == NULL) {
        close(ready_pipe[0]);
        close(ready_pipe[1]);
        return false;
    }
    uint8_t ready = 0u;
    const bool synchronized =
        read(ready_pipe[0], &ready, sizeof ready) == (ssize_t)sizeof ready &&
        ready == 1u;
    const bool added = synchronized &&
                       known_hosts_add("newhost", 5901, FP_B, path);
    farsee_thread_join(&thread, NULL);
    const bool closed = close(ready_pipe[0]) == 0 &&
                        close(ready_pipe[1]) == 0;
    return synchronized && race.acted && !added && closed;
}

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
    RFB_CHECK_EQ_INT(known_hosts_check("host1", 5900, NULL, kh_path),
                     KNOWN_HOSTS_MISMATCH);
    RFB_CHECK_EQ_INT(known_hosts_check("host1", 5900, FP_A, NULL),
                     KNOWN_HOSTS_MISMATCH);
    RFB_CHECK_EQ_INT(known_hosts_check("", 5900, FP_A, kh_path),
                     KNOWN_HOSTS_MISMATCH);
    RFB_CHECK_EQ_INT(known_hosts_check("host1", 0, FP_A, kh_path),
                     KNOWN_HOSTS_MISMATCH);
    RFB_CHECK(!known_hosts_add(NULL, 5900, FP_A, kh_path));
    RFB_CHECK(!known_hosts_add("host1", 5900, NULL, kh_path));
    RFB_CHECK(!known_hosts_add("host1", 5900, FP_A, NULL));
    RFB_CHECK_EQ_INT(known_hosts_check("host1", 5900, FP_A, ""),
                     KNOWN_HOSTS_MISMATCH);
    RFB_CHECK(!known_hosts_add("host1", 5900, FP_A, ""));
    RFB_CHECK(!known_hosts_add("host1", 0, FP_A, kh_path));
}

RFB_TEST(g18_kh, known_hosts__host_token_boundaries__fail_closed)
{
    char overlong[257];
    memset(overlong, 'h', sizeof overlong - 1u);
    overlong[sizeof overlong - 1u] = '\0';
    RFB_CHECK_EQ_INT(known_hosts_check(overlong, 5900, FP_A, kh_path),
                     KNOWN_HOSTS_MISMATCH);
    RFB_CHECK(!known_hosts_add(overlong, 5900, FP_A, kh_path));
    RFB_CHECK_EQ_INT(known_hosts_check("bad\thost", 5900, FP_A, kh_path),
                     KNOWN_HOSTS_MISMATCH);
    RFB_CHECK_EQ_INT(known_hosts_check("bad\177host", 5900, FP_A, kh_path),
                     KNOWN_HOSTS_MISMATCH);
}

RFB_TEST(g18_kh, known_hosts__malformed_lines__fail_closed)
{
    char path[] = "/tmp/farsee-kh-malformed-XXXXXX";
    int fd = mkstemp(path);
    RFB_CHECK(fd >= 0);
    if (fd < 0) {
        return;
    }
    RFB_CHECK_EQ_INT(close(fd), 0);

    char valid_hex[65];
    memset(valid_hex, '0', sizeof valid_hex - 1u);
    valid_hex[0] = 'a';
    valid_hex[1] = 'a';
    valid_hex[sizeof valid_hex - 1u] = '\0';
    static const struct {
        const char *prefix;
        bool include_hex;
        const char *suffix;
    } malformed_lines[] = {
        {"host 5900 ", true, ""},
        {"host-without-fields\n", false, ""},
        {" 5900 ", true, "\n"},
        {"host 5900\n", false, ""},
        {"host  ", true, "\n"},
        {"host x ", true, "\n"},
        {"host 123456 ", true, "\n"},
        {"host 0 ", true, "\n"},
        {"host 65536 ", true, "\n"},
        {"host 5900 short\n", false, ""},
    };
    char line[512];
    for (size_t i = 0u;
         i < sizeof malformed_lines / sizeof malformed_lines[0];
         i++) {
        const int n = snprintf(
            line, sizeof line, "%s%s%s", malformed_lines[i].prefix,
            malformed_lines[i].include_hex ? valid_hex : "",
            malformed_lines[i].suffix);
        RFB_CHECK(n > 0 && (size_t)n < sizeof line);
        RFB_CHECK(write_raw_store(path, line));
        RFB_CHECK_EQ_INT(known_hosts_check("host", 5900, FP_A, path),
                         KNOWN_HOSTS_MISMATCH);
    }

    char invalid_hex[65];
    memcpy(invalid_hex, valid_hex, sizeof invalid_hex);
    invalid_hex[0] = 'g';
    int n = snprintf(line, sizeof line, "host 5900 %s\n", invalid_hex);
    RFB_CHECK(n > 0 && (size_t)n < sizeof line);
    RFB_CHECK(write_raw_store(path, line));
    RFB_CHECK_EQ_INT(known_hosts_check("host", 5900, FP_A, path),
                     KNOWN_HOSTS_MISMATCH);

    memcpy(invalid_hex, valid_hex, sizeof invalid_hex);
    invalid_hex[1] = 'g';
    n = snprintf(line, sizeof line, "host 5900 %s\n", invalid_hex);
    RFB_CHECK(n > 0 && (size_t)n < sizeof line);
    RFB_CHECK(write_raw_store(path, line));
    RFB_CHECK_EQ_INT(known_hosts_check("host", 5900, FP_A, path),
                     KNOWN_HOSTS_MISMATCH);

    char long_host[257];
    memset(long_host, 'h', sizeof long_host - 1u);
    long_host[sizeof long_host - 1u] = '\0';
    n = snprintf(line, sizeof line, "%s 5900 %s\n", long_host, valid_hex);
    RFB_CHECK(n > 0 && (size_t)n < sizeof line);
    RFB_CHECK(write_raw_store(path, line));
    RFB_CHECK_EQ_INT(known_hosts_check("host", 5900, FP_A, path),
                     KNOWN_HOSTS_MISMATCH);

    RFB_CHECK_EQ_INT(unlink(path), 0);
}

// known_hosts_add creates the parent directory when it is missing.
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

// Host tokens cannot contain whitespace.
RFB_TEST(g18_kh, known_hosts__whitespace_host__rejected)
{
    const char *path = "/tmp/farsee_kh_ws_test";
    unlink(path);
    RFB_CHECK(!known_hosts_add("bad host", 3389, FP_A, path));
    unlink(path);
}

// A mismatched add fails closed without replacing the stored pin.
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

// Two concurrent additions for the same host and port with different
// fingerprints produce exactly one line. The lock serializes check+mutate.
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

// A non-ENOENT open failure is MISMATCH, not first use.
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

RFB_TEST(g18_kh, known_hosts__fingerprint_suffix__mismatch)
{
    const char *path = "/tmp/farsee_kh_suffix_test";
    unlink(path);
    RFB_CHECK(write_entry_file(path, "host1", 5900, FP_A, "garbage", 0600));
    RFB_CHECK_EQ_INT(known_hosts_check("host1", 5900, FP_A, path),
                     KNOWN_HOSTS_MISMATCH);
    unlink(path);
}

RFB_TEST(g18_kh, known_hosts__trailing_token__mismatch)
{
    const char *path = "/tmp/farsee_kh_trailing_test";
    unlink(path);
    RFB_CHECK(write_entry_file(path, "host1", 5900, FP_A, " extra", 0600));
    RFB_CHECK_EQ_INT(known_hosts_check("host1", 5900, FP_A, path),
                     KNOWN_HOSTS_MISMATCH);
    unlink(path);
}

RFB_TEST(g18_kh, known_hosts__duplicate_host_port__mismatch)
{
    const char *path = "/tmp/farsee_kh_duplicate_test";
    unlink(path);
    RFB_CHECK(write_entry_file(path, "host1", 5900, FP_A, NULL, 0600));
    int fd = open(path, O_WRONLY | O_APPEND);
    RFB_CHECK(fd >= 0);
    if (fd >= 0) {
        static const char duplicate[] =
            "host1 5900 aa00000000000000000000000000000000000000000000000000000000000000\n";
        RFB_CHECK(write(fd, duplicate, sizeof duplicate - 1u) ==
                  (ssize_t)(sizeof duplicate - 1u));
        close(fd);
    }
    RFB_CHECK_EQ_INT(known_hosts_check("host1", 5900, FP_A, path),
                     KNOWN_HOSTS_MISMATCH);
    unlink(path);
}

RFB_TEST(g18_kh, known_hosts__symlink_store__fails_closed)
{
    const char *target = "/tmp/farsee_kh_symlink_target";
    const char *path = "/tmp/farsee_kh_symlink_test";
    unlink(path);
    unlink(target);
    RFB_CHECK(write_entry_file(target, "host1", 5900, FP_A, NULL, 0600));
    RFB_CHECK_EQ_INT(symlink(target, path), 0);
    RFB_CHECK_EQ_INT(known_hosts_check("host1", 5900, FP_A, path),
                     KNOWN_HOSTS_MISMATCH);
    RFB_CHECK(!known_hosts_add("host1", 5900, FP_A, path));
    unlink(path);
    unlink(target);
    unlink("/tmp/farsee_kh_symlink_test.lock");
}

RFB_TEST(g18_kh, known_hosts__non_regular_store__fails_closed)
{
    const char *path = "/tmp/farsee_kh_directory_test";
    rmdir(path);
    RFB_CHECK_EQ_INT(mkdir(path, 0700), 0);
    RFB_CHECK_EQ_INT(known_hosts_check("host1", 5900, FP_A, path),
                     KNOWN_HOSTS_MISMATCH);
    RFB_CHECK(!known_hosts_add("host1", 5900, FP_A, path));
    rmdir(path);
    unlink("/tmp/farsee_kh_directory_test.lock");
}

RFB_TEST(g18_kh, known_hosts__unsafe_mode__fails_closed)
{
    const char *path = "/tmp/farsee_kh_mode_test";
    unlink(path);
    RFB_CHECK(write_entry_file(path, "host1", 5900, FP_A, NULL, 0644));
    RFB_CHECK_EQ_INT(known_hosts_check("host1", 5900, FP_A, path),
                     KNOWN_HOSTS_MISMATCH);
    RFB_CHECK(!known_hosts_add("host1", 5900, FP_A, path));
    unlink(path);
    unlink("/tmp/farsee_kh_mode_test.lock");
}

RFB_TEST(g18_kh, known_hosts__hard_link_store__fails_closed)
{
    const char *path = "/tmp/farsee_kh_hard_link_test";
    const char *alias = "/tmp/farsee_kh_hard_link_alias";
    unlink(alias);
    unlink(path);
    RFB_CHECK(write_entry_file(path, "host1", 5900, FP_A, NULL, 0600));
    RFB_CHECK_EQ_INT(link(path, alias), 0);
    RFB_CHECK_EQ_INT(known_hosts_check("host1", 5900, FP_A, path),
                     KNOWN_HOSTS_MISMATCH);
    RFB_CHECK(!known_hosts_add("host1", 5900, FP_A, path));
    unlink(alias);
    unlink(path);
    unlink("/tmp/farsee_kh_hard_link_test.lock");
}

RFB_TEST(g18_kh, known_hosts__overlong_path__add_rejected)
{
    char path[600];
    memset(path, 'a', sizeof path);
    memcpy(path, "/tmp/", 5u);
    path[sizeof path - 1u] = '\0';
    RFB_CHECK(!known_hosts_add("host1", 5900, FP_A, path));
}

RFB_TEST(g18_kh, known_hosts__safe_parent_replacement_preserves_all_entries)
{
    char directory[] = "/tmp/farsee-kh-safe-XXXXXX";
    RFB_CHECK(mkdtemp(directory) != NULL);
    char path[128];
    char lock_path[136];
    const int pn = snprintf(path, sizeof path, "%s/known_hosts", directory);
    const int ln = snprintf(
        lock_path, sizeof lock_path, "%s/known_hosts.lock", directory);
    RFB_CHECK(pn > 0 && (size_t)pn < sizeof path);
    RFB_CHECK(ln > 0 && (size_t)ln < sizeof lock_path);
    RFB_CHECK(known_hosts_add("host1", 5900, FP_A, path));
    struct stat before;
    RFB_CHECK_EQ_INT(stat(path, &before), 0);
    RFB_CHECK(known_hosts_add("host2", 5901, FP_B, path));
    struct stat after;
    RFB_CHECK_EQ_INT(stat(path, &after), 0);
    RFB_CHECK(before.st_dev != after.st_dev || before.st_ino != after.st_ino);
    RFB_CHECK_EQ_INT(
        known_hosts_check("host1", 5900, FP_A, path), KNOWN_HOSTS_MATCH);
    RFB_CHECK_EQ_INT(
        known_hosts_check("host2", 5901, FP_B, path), KNOWN_HOSTS_MATCH);
    RFB_CHECK_EQ_INT(unlink(path), 0);
    RFB_CHECK_EQ_INT(unlink(lock_path), 0);
    RFB_CHECK_EQ_INT(rmdir(directory), 0);
}

RFB_TEST(g18_kh, known_hosts__symlink_parent_is_rejected)
{
    char directory[] = "/tmp/farsee-kh-real-XXXXXX";
    RFB_CHECK(mkdtemp(directory) != NULL);
    char alias[128];
    const int an = snprintf(alias, sizeof alias, "%s.alias", directory);
    RFB_CHECK(an > 0 && (size_t)an < sizeof alias);
    RFB_CHECK_EQ_INT(symlink(directory, alias), 0);
    char path[160];
    const int pn = snprintf(path, sizeof path, "%s/known_hosts", alias);
    RFB_CHECK(pn > 0 && (size_t)pn < sizeof path);
    RFB_CHECK(!known_hosts_add("host1", 5900, FP_A, path));
    RFB_CHECK_EQ_INT(
        known_hosts_check("host1", 5900, FP_A, path), KNOWN_HOSTS_MISMATCH);

    char redirected[160];
    const int rn = snprintf(
        redirected, sizeof redirected, "%s/known_hosts", directory);
    RFB_CHECK(rn > 0 && (size_t)rn < sizeof redirected);
    struct stat status;
    RFB_CHECK(lstat(redirected, &status) != 0 && errno == ENOENT);
    RFB_CHECK_EQ_INT(unlink(alias), 0);
    RFB_CHECK_EQ_INT(rmdir(directory), 0);
}

RFB_TEST(g18_kh, known_hosts__nonsticky_writable_parent_is_rejected)
{
    char directory[] = "/tmp/farsee-kh-mode-XXXXXX";
    RFB_CHECK(mkdtemp(directory) != NULL);
    RFB_CHECK_EQ_INT(chmod(directory, 0777), 0);
    char path[128];
    const int pn = snprintf(path, sizeof path, "%s/known_hosts", directory);
    RFB_CHECK(pn > 0 && (size_t)pn < sizeof path);
    RFB_CHECK(!known_hosts_add("host1", 5900, FP_A, path));
    RFB_CHECK_EQ_INT(
        known_hosts_check("host1", 5900, FP_A, path), KNOWN_HOSTS_MISMATCH);
    struct stat status;
    RFB_CHECK(lstat(path, &status) != 0 && errno == ENOENT);
    RFB_CHECK_EQ_INT(chmod(directory, 0700), 0);
    RFB_CHECK_EQ_INT(rmdir(directory), 0);
}

RFB_TEST(g18_kh, known_hosts__partial_replacement_preserves_old_store)
{
    char directory[] = "/tmp/farsee-kh-partial-XXXXXX";
    RFB_CHECK(mkdtemp(directory) != NULL);
    char path[128];
    char lock_path[136];
    const int pn = snprintf(path, sizeof path, "%s/known_hosts", directory);
    const int ln = snprintf(
        lock_path, sizeof lock_path, "%s/known_hosts.lock", directory);
    RFB_CHECK(pn > 0 && (size_t)pn < sizeof path);
    RFB_CHECK(ln > 0 && (size_t)ln < sizeof lock_path);
    RFB_CHECK(known_hosts_add("host1", 5900, FP_A, path));
    struct stat before;
    RFB_CHECK_EQ_INT(stat(path, &before), 0);

    const pid_t child = fork();
    RFB_CHECK(child >= 0);
    if (child == 0) {
        struct rlimit limit;
        if (getrlimit(RLIMIT_FSIZE, &limit) != 0 ||
            (rlim_t)before.st_size + 5u > limit.rlim_max) {
            _exit(3);
        }
        limit.rlim_cur = (rlim_t)before.st_size + 5u;
        if (setrlimit(RLIMIT_FSIZE, &limit) != 0 ||
            signal(SIGXFSZ, SIG_IGN) == SIG_ERR) {
            _exit(4);
        }
        _exit(known_hosts_add("host2", 5901, FP_B, path) ? 5 : 0);
    }
    int status = 0;
    RFB_CHECK_EQ_INT(waitpid(child, &status, 0), child);
    RFB_CHECK(WIFEXITED(status));
    RFB_CHECK_EQ_INT(WEXITSTATUS(status), 0);

    struct stat after;
    RFB_CHECK_EQ_INT(stat(path, &after), 0);
    RFB_CHECK_EQ_UINT((unsigned long long)after.st_size,
                      (unsigned long long)before.st_size);
    RFB_CHECK_EQ_INT(
        known_hosts_check("host1", 5900, FP_A, path), KNOWN_HOSTS_MATCH);
    RFB_CHECK_EQ_INT(
        known_hosts_check("host2", 5901, FP_B, path), KNOWN_HOSTS_NOT_FOUND);
    RFB_CHECK_EQ_INT(unlink(path), 0);
    RFB_CHECK_EQ_INT(unlink(lock_path), 0);
    RFB_CHECK_EQ_INT(rmdir(directory), 0);
}

RFB_TEST(g18_kh, known_hosts__parser_near_matches_fail_closed)
{
    char path[] = "/tmp/farsee-kh-parser-edge-XXXXXX";
    const int fd = mkstemp(path);
    RFB_CHECK(fd >= 0);
    if (fd < 0) {
        return;
    }
    RFB_CHECK_EQ_INT(close(fd), 0);

    char hex[65];
    memset(hex, '0', sizeof hex - 1u);
    hex[0] = 'a';
    hex[1] = 'a';
    hex[sizeof hex - 1u] = '\0';
    static const char invalid_nibbles[] = {'/', ':', '`', 'A'};
    char line[256];
    for (size_t nibble = 0u; nibble < 2u; nibble++) {
        for (size_t i = 0u; i < sizeof invalid_nibbles; i++) {
            const char saved = hex[nibble];
            hex[nibble] = invalid_nibbles[i];
            const int n = snprintf(
                line, sizeof line, "host 5900 %s\n", hex);
            RFB_CHECK(n > 0 && (size_t)n < sizeof line);
            RFB_CHECK(write_raw_store(path, line));
            RFB_CHECK_EQ_INT(
                known_hosts_check("host", 5900, FP_A, path),
                KNOWN_HOSTS_MISMATCH);
            hex[nibble] = saved;
        }
    }

    int n = snprintf(
        line, sizeof line, "host 5900 %s\nignored", hex);
    RFB_CHECK(n > 0 && (size_t)n < sizeof line);
    RFB_CHECK(write_raw_store(path, line));
    RFB_CHECK_EQ_INT(known_hosts_check("host", 5900, FP_A, path),
                     KNOWN_HOSTS_MISMATCH);

    n = snprintf(line, sizeof line, "host / %s\n", hex);
    RFB_CHECK(n > 0 && (size_t)n < sizeof line);
    RFB_CHECK(write_raw_store(path, line));
    RFB_CHECK_EQ_INT(known_hosts_check("host", 5900, FP_A, path),
                     KNOWN_HOSTS_MISMATCH);

    RFB_CHECK(write_entry_file(path, "host", 65535u, FP_A, NULL, 0600));
    RFB_CHECK_EQ_INT(known_hosts_check("host", 65535u, FP_A, path),
                     KNOWN_HOSTS_MATCH);
    RFB_CHECK_EQ_INT(unlink(path), 0);
}

RFB_TEST(g18_kh, known_hosts__empty_and_missing_parent_are_not_found)
{
    char empty_path[] = "/tmp/farsee-kh-empty-XXXXXX";
    const int fd = mkstemp(empty_path);
    RFB_CHECK(fd >= 0);
    if (fd < 0) {
        return;
    }
    RFB_CHECK_EQ_INT(close(fd), 0);
    RFB_CHECK_EQ_INT(
        known_hosts_check("host", 5900, FP_A, empty_path),
        KNOWN_HOSTS_NOT_FOUND);
    RFB_CHECK_EQ_INT(unlink(empty_path), 0);

    char missing_directory[] = "/tmp/farsee-kh-missing-XXXXXX";
    RFB_CHECK(mkdtemp(missing_directory) != NULL);
    RFB_CHECK_EQ_INT(rmdir(missing_directory), 0);
    char missing_path[160];
    const int n = snprintf(
        missing_path, sizeof missing_path, "%s/known_hosts",
        missing_directory);
    RFB_CHECK(n > 0 && (size_t)n < sizeof missing_path);
    RFB_CHECK_EQ_INT(
        known_hosts_check("host", 5900, FP_A, missing_path),
        KNOWN_HOSTS_NOT_FOUND);
}

RFB_TEST(g18_kh, known_hosts__unsafe_lock_sidecars_fail_closed)
{
    char directory[] = "/tmp/farsee-kh-lock-edge-XXXXXX";
    RFB_CHECK(mkdtemp(directory) != NULL);
    char path[160];
    char lock_path[168];
    char target_path[168];
    const int pn = snprintf(path, sizeof path, "%s/known_hosts", directory);
    const int ln = snprintf(
        lock_path, sizeof lock_path, "%s/known_hosts.lock", directory);
    const int tn = snprintf(
        target_path, sizeof target_path, "%s/lock-target", directory);
    RFB_CHECK(pn > 0 && (size_t)pn < sizeof path);
    RFB_CHECK(ln > 0 && (size_t)ln < sizeof lock_path);
    RFB_CHECK(tn > 0 && (size_t)tn < sizeof target_path);

    RFB_CHECK(write_raw_store(lock_path, ""));
    RFB_CHECK_EQ_INT(chmod(lock_path, 0644), 0);
    RFB_CHECK(!known_hosts_add("host", 5900, FP_A, path));
    RFB_CHECK_EQ_INT(unlink(lock_path), 0);

    RFB_CHECK(write_raw_store(target_path, ""));
    RFB_CHECK_EQ_INT(symlink(target_path, lock_path), 0);
    RFB_CHECK(!known_hosts_add("host", 5900, FP_A, path));
    RFB_CHECK_EQ_INT(unlink(lock_path), 0);
    RFB_CHECK_EQ_INT(unlink(target_path), 0);
    struct stat status;
    RFB_CHECK(lstat(path, &status) != 0 && errno == ENOENT);
    RFB_CHECK_EQ_INT(rmdir(directory), 0);
}

RFB_TEST(g18_kh, known_hosts__unwritable_parent_blocks_replacement)
{
    char directory[] = "/tmp/farsee-kh-nowrite-XXXXXX";
    RFB_CHECK(mkdtemp(directory) != NULL);
    char path[160];
    char lock_path[168];
    const int pn = snprintf(path, sizeof path, "%s/known_hosts", directory);
    const int ln = snprintf(
        lock_path, sizeof lock_path, "%s/known_hosts.lock", directory);
    RFB_CHECK(pn > 0 && (size_t)pn < sizeof path);
    RFB_CHECK(ln > 0 && (size_t)ln < sizeof lock_path);

    RFB_CHECK(write_raw_store(lock_path, ""));
    RFB_CHECK_EQ_INT(chmod(directory, 0500), 0);
    RFB_CHECK(!known_hosts_add("host1", 5900, FP_A, path));

    RFB_CHECK_EQ_INT(chmod(directory, 0700), 0);
    RFB_CHECK(write_entry_file(path, "host1", 5900, FP_A, NULL, 0600));
    RFB_CHECK_EQ_INT(chmod(directory, 0500), 0);
    RFB_CHECK(!known_hosts_add("host2", 5901, FP_B, path));
    RFB_CHECK_EQ_INT(known_hosts_check("host1", 5900, FP_A, path),
                     KNOWN_HOSTS_MATCH);
    RFB_CHECK_EQ_INT(known_hosts_check("host2", 5901, FP_B, path),
                     KNOWN_HOSTS_NOT_FOUND);

    RFB_CHECK_EQ_INT(chmod(directory, 0700), 0);
    RFB_CHECK_EQ_INT(unlink(path), 0);
    RFB_CHECK_EQ_INT(unlink(lock_path), 0);
    RFB_CHECK_EQ_INT(rmdir(directory), 0);
}

RFB_TEST(g18_kh, known_hosts__maximum_host_line_round_trips)
{
    char directory[] = "/tmp/farsee-kh-max-host-XXXXXX";
    RFB_CHECK(mkdtemp(directory) != NULL);
    char path[160];
    char lock_path[168];
    const int pn = snprintf(path, sizeof path, "%s/known_hosts", directory);
    const int ln = snprintf(
        lock_path, sizeof lock_path, "%s/known_hosts.lock", directory);
    RFB_CHECK(pn > 0 && (size_t)pn < sizeof path);
    RFB_CHECK(ln > 0 && (size_t)ln < sizeof lock_path);
    char host[256];
    memset(host, 'h', sizeof host - 1u);
    host[sizeof host - 1u] = '\0';

    RFB_CHECK(known_hosts_add(host, 65535u, FP_A, path));
    RFB_CHECK_EQ_INT(known_hosts_check(host, 65535u, FP_A, path),
                     KNOWN_HOSTS_MATCH);
    RFB_CHECK_EQ_INT(unlink(path), 0);
    RFB_CHECK_EQ_INT(unlink(lock_path), 0);
    RFB_CHECK_EQ_INT(rmdir(directory), 0);
}

static int known_hosts_size_limit_child(const char *path, off_t store_size)
{
    struct rlimit original_limit;
    if (getrlimit(RLIMIT_FSIZE, &original_limit) != 0) {
        return 2;
    }
    struct sigaction ignored_action;
    memset(&ignored_action, 0, sizeof ignored_action);
    ignored_action.sa_handler = SIG_IGN;
    if (sigemptyset(&ignored_action.sa_mask) != 0 ||
        sigaction(SIGXFSZ, &ignored_action, NULL) != 0) {
        return 3;
    }

    struct rlimit limited = original_limit;
    limited.rlim_cur = 5u;
    if (setrlimit(RLIMIT_FSIZE, &limited) != 0 ||
        known_hosts_add("host2", 5901, FP_B, path)) {
        return 4;
    }

    limited = original_limit;
    limited.rlim_cur = (rlim_t)store_size + 5u;
    if (setrlimit(RLIMIT_FSIZE, &limited) != 0 ||
        known_hosts_add("host2", 5901, FP_B, path)) {
        return 5;
    }
    return 0;
}

RFB_TEST(g18_kh, known_hosts__size_limit_preserves_store_during_replace)
{
    char directory[] = "/tmp/farsee-kh-size-limit-XXXXXX";
    RFB_CHECK(mkdtemp(directory) != NULL);
    char path[160];
    char lock_path[168];
    const int pn = snprintf(path, sizeof path, "%s/known_hosts", directory);
    const int ln = snprintf(
        lock_path, sizeof lock_path, "%s/known_hosts.lock", directory);
    RFB_CHECK(pn > 0 && (size_t)pn < sizeof path);
    RFB_CHECK(ln > 0 && (size_t)ln < sizeof lock_path);
    RFB_CHECK(known_hosts_add("host1", 5900, FP_A, path));

    struct stat before;
    RFB_CHECK_EQ_INT(stat(path, &before), 0);
    const pid_t kid = fork();
    RFB_CHECK(kid >= 0);
    if (kid < 0) {
        return;
    }
    if (kid == 0) {
        _exit(known_hosts_size_limit_child(path, before.st_size));
    }
    int kid_status = 0;
    RFB_CHECK_EQ_INT(waitpid(kid, &kid_status, 0), kid);
    RFB_CHECK(WIFEXITED(kid_status));
    RFB_CHECK_EQ_INT(
        WIFEXITED(kid_status) ? WEXITSTATUS(kid_status) : -1, 0);
    RFB_CHECK_EQ_INT(known_hosts_check("host1", 5900, FP_A, path),
                     KNOWN_HOSTS_MATCH);
    RFB_CHECK_EQ_INT(known_hosts_check("host2", 5901, FP_B, path),
                     KNOWN_HOSTS_NOT_FOUND);
    struct stat after;
    RFB_CHECK_EQ_INT(stat(path, &after), 0);
    RFB_CHECK_EQ_UINT((unsigned long long)after.st_size,
                      (unsigned long long)before.st_size);

    RFB_CHECK_EQ_INT(unlink(path), 0);
    RFB_CHECK_EQ_INT(unlink(lock_path), 0);
    RFB_CHECK_EQ_INT(rmdir(directory), 0);
}

RFB_TEST(g18_kh, known_hosts__concurrent_path_changes_abort_replacement)
{
    char directory[] = "/tmp/farsee-kh-path-race-XXXXXX";
    RFB_CHECK(mkdtemp(directory) != NULL);
    char path[160];
    char lock_path[168];
    const int pn = snprintf(path, sizeof path, "%s/known_hosts", directory);
    const int ln = snprintf(
        lock_path, sizeof lock_path, "%s/known_hosts.lock", directory);
    RFB_CHECK(pn > 0 && (size_t)pn < sizeof path);
    RFB_CHECK(ln > 0 && (size_t)ln < sizeof lock_path);

    RFB_CHECK(write_large_store(path, 2048u));
    RFB_CHECK(run_known_hosts_temp_race(
        directory, path, KH_TEMP_RACE_REMOVE_TEMP));
    struct stat status;
    RFB_CHECK_EQ_INT(stat(path, &status), 0);

    RFB_CHECK(run_known_hosts_temp_race(
        directory, path, KH_TEMP_RACE_REMOVE_TARGET));
    RFB_CHECK(lstat(path, &status) != 0 && errno == ENOENT);
    RFB_CHECK_EQ_INT(unlink(lock_path), 0);
    RFB_CHECK_EQ_INT(rmdir(directory), 0);
}
