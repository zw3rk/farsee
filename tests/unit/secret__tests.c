// SPDX-License-Identifier: Apache-2.0
//
// Secret zeroization and private-file tests.
//
// The zeroization cases inspect buffer contents after rfb_secret_zero returns.

#include "rfb_test.h"
#include "core/private_file_internal.h"
#include "farsee/secret.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

RFB_TEST(secret, secret__zero__clears_buffer_contents) {
    uint8_t buf[16];
    memset(buf, 0xAB, sizeof buf);
    rfb_secret_zero(buf, sizeof buf);
    for (size_t i = 0; i < sizeof buf; i++) {
        RFB_CHECK_EQ_UINT(buf[i], 0u);
    }
}

RFB_TEST(secret, secret__zero_partial__clears_only_first_n) {
    uint8_t buf[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    rfb_secret_zero(buf, 3);
    RFB_CHECK_EQ_UINT(buf[0], 0u);
    RFB_CHECK_EQ_UINT(buf[1], 0u);
    RFB_CHECK_EQ_UINT(buf[2], 0u);
    RFB_CHECK_EQ_UINT(buf[3], 4u);  // untouched
    RFB_CHECK_EQ_UINT(buf[7], 8u);
}

RFB_TEST(secret, secret__zero_null_or_zero__is_noop) {
    rfb_secret_zero(NULL, 16);   // must not crash
    uint8_t buf[4] = { 9, 9, 9, 9 };
    rfb_secret_zero(buf, 0);
    RFB_CHECK_EQ_UINT(buf[0], 9u);  // untouched when n==0
}

RFB_TEST(secret, secret__zero_then_volatile_read__observes_zero_bytes) {
    // Read the cleared storage through a volatile-qualified pointer.
    static uint8_t storage[32];
    for (size_t i = 0; i < sizeof storage; i++) storage[i] = 0xCC;
    rfb_secret_zero(storage, sizeof storage);
    volatile const uint8_t *readback = storage;
    for (size_t i = 0; i < sizeof storage; i++) {
        RFB_CHECK_EQ_UINT(readback[i], 0u);
    }
}

RFB_TEST(secret, wipe_free__null_safe)
{
    rfb_secret_wipe_free(NULL, 0u);
    rfb_secret_wipe_free(NULL, 32u);
}

RFB_TEST(secret, wipe_free__live_allocation__returns)
{
    // Allocate, fill, wipe-free; the wipe is tested by trunc + zero suites;
    // here we only assert wipe_free does not crash on a live allocation.
    char *p = (char *)malloc(32u);
    RFB_CHECK(p != NULL);
    memset(p, 0xEE, 32u);
    rfb_secret_wipe_free(p, 32u);
}

RFB_TEST(secret, wipe_free__zero_capacity_allocation__returns)
{
    // A non-null zero-length allocation is valid owned storage. The helper
    // must free it without trying to wipe bytes outside its logical extent.
    void *p = malloc(1u);
    RFB_CHECK(p != NULL);
    rfb_secret_wipe_free(p, 0u);
}

typedef struct private_writer_test_context {
    bool descriptor_was_private;
    bool fail_after_write;
    const char *unlink_before_return;
} private_writer_test_context;

static bool private_writer_test_callback(int fd, void *context)
{
    private_writer_test_context *test =
        (private_writer_test_context *)context;
    struct stat status;
    const int descriptor_flags = fcntl(fd, F_GETFD, 0);
    test->descriptor_was_private =
        descriptor_flags >= 0 && (descriptor_flags & FD_CLOEXEC) != 0 &&
        fstat(fd, &status) == 0 && S_ISREG(status.st_mode) &&
        status.st_uid == geteuid() && (status.st_mode & 0777) == 0600 &&
        status.st_nlink == 1;
    static const uint8_t output[] = {0x71u, 0x72u, 0x73u};
    const bool wrote = rfb_private_file_write_all(fd, output, sizeof output);
    if (test->unlink_before_return != NULL &&
        unlink(test->unlink_before_return) != 0) {
        return false;
    }
    return wrote && !test->fail_after_write;
}

RFB_TEST(secret, private_file__callback_gets_private_cloexec_descriptor)
{
    char path[] = "/tmp/farsee-private-writer-XXXXXX";
    const int fd = mkstemp(path);
    RFB_CHECK(fd >= 0);
    RFB_CHECK_EQ_INT(close(fd), 0);
    RFB_CHECK_EQ_INT(unlink(path), 0);
    private_writer_test_context context = {
        .descriptor_was_private = false,
        .fail_after_write = false,
        .unlink_before_return = NULL,
    };
    RFB_CHECK(rfb_private_file_write_0600(
        path, private_writer_test_callback, &context));
    RFB_CHECK(context.descriptor_was_private);
    struct stat status;
    RFB_CHECK_EQ_INT(stat(path, &status), 0);
    RFB_CHECK_EQ_UINT((unsigned long long)status.st_size, 3ull);
    RFB_CHECK_EQ_INT(unlink(path), 0);
}

RFB_TEST(secret, private_file__callback_failure_preserves_existing_target)
{
    char path[] = "/tmp/farsee-private-preserve-XXXXXX";
    const int fd = mkstemp(path);
    RFB_CHECK(fd >= 0);
    static const uint8_t sentinel[] = {0x21u, 0x22u};
    RFB_CHECK_EQ_INT(write(fd, sentinel, sizeof sentinel),
                     (ssize_t)sizeof sentinel);
    RFB_CHECK_EQ_INT(close(fd), 0);
    private_writer_test_context context = {
        .descriptor_was_private = false,
        .fail_after_write = true,
        .unlink_before_return = NULL,
    };
    RFB_CHECK(!rfb_private_file_write_0600(
        path, private_writer_test_callback, &context));
    RFB_CHECK(context.descriptor_was_private);
    struct stat status;
    RFB_CHECK_EQ_INT(stat(path, &status), 0);
    RFB_CHECK_EQ_UINT((unsigned long long)status.st_size,
                      (unsigned long long)sizeof sentinel);
    RFB_CHECK_EQ_INT(unlink(path), 0);
}

RFB_TEST(secret, private_file__existing_target_is_replaced_atomically)
{
    char path[] = "/tmp/farsee-private-replace-XXXXXX";
    const int fd = mkstemp(path);
    RFB_CHECK(fd >= 0);
    static const uint8_t old_data[] = {0x11u, 0x12u};
    RFB_CHECK_EQ_INT(write(fd, old_data, sizeof old_data),
                     (ssize_t)sizeof old_data);
    struct stat before;
    RFB_CHECK_EQ_INT(fstat(fd, &before), 0);
    RFB_CHECK_EQ_INT(close(fd), 0);

    private_writer_test_context context = {
        .descriptor_was_private = false,
        .fail_after_write = false,
        .unlink_before_return = NULL,
    };
    RFB_CHECK(rfb_private_file_write_0600(
        path, private_writer_test_callback, &context));
    RFB_CHECK(context.descriptor_was_private);
    struct stat after;
    RFB_CHECK_EQ_INT(stat(path, &after), 0);
    RFB_CHECK(before.st_dev != after.st_dev || before.st_ino != after.st_ino);
    RFB_CHECK_EQ_UINT((unsigned long long)after.st_size, 3ull);
    RFB_CHECK_EQ_INT(unlink(path), 0);
}

RFB_TEST(secret, private_file__target_removal_during_write_fails_closed)
{
    char path[] = "/tmp/farsee-private-race-XXXXXX";
    const int fd = mkstemp(path);
    RFB_CHECK(fd >= 0);
    RFB_CHECK_EQ_INT(close(fd), 0);
    private_writer_test_context context = {
        .descriptor_was_private = false,
        .fail_after_write = false,
        .unlink_before_return = path,
    };
    RFB_CHECK(!rfb_private_file_write_0600(
        path, private_writer_test_callback, &context));
    RFB_CHECK(context.descriptor_was_private);
    struct stat status;
    RFB_CHECK(lstat(path, &status) != 0 && errno == ENOENT);
}

RFB_TEST(secret, private_file__unsafe_existing_targets_fail_closed)
{
    char directory[] = "/tmp/farsee-private-targets-XXXXXX";
    RFB_CHECK(mkdtemp(directory) != NULL);
    char path[160];
    char alias[168];
    const int path_length = snprintf(
        path, sizeof path, "%s/output", directory);
    const int alias_length = snprintf(
        alias, sizeof alias, "%s/alias", directory);
    RFB_CHECK(path_length > 0 && (size_t)path_length < sizeof path);
    RFB_CHECK(alias_length > 0 && (size_t)alias_length < sizeof alias);
    private_writer_test_context context = {
        .descriptor_was_private = false,
        .fail_after_write = false,
        .unlink_before_return = NULL,
    };

    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0644);
    RFB_CHECK(fd >= 0);
    RFB_CHECK_EQ_INT(close(fd), 0);
    RFB_CHECK(!rfb_private_file_write_0600(
        path, private_writer_test_callback, &context));
    RFB_CHECK_EQ_INT(chmod(path, 0600), 0);
    RFB_CHECK_EQ_INT(link(path, alias), 0);
    RFB_CHECK(!rfb_private_file_write_0600(
        path, private_writer_test_callback, &context));
    RFB_CHECK_EQ_INT(unlink(alias), 0);
    RFB_CHECK_EQ_INT(unlink(path), 0);

    RFB_CHECK_EQ_INT(mkdir(path, 0700), 0);
    RFB_CHECK(!rfb_private_file_write_0600(
        path, private_writer_test_callback, &context));
    RFB_CHECK_EQ_INT(rmdir(path), 0);
    fd = open(alias, O_WRONLY | O_CREAT | O_EXCL, 0600);
    RFB_CHECK(fd >= 0);
    RFB_CHECK_EQ_INT(close(fd), 0);
    RFB_CHECK_EQ_INT(symlink(alias, path), 0);
    RFB_CHECK(!rfb_private_file_write_0600(
        path, private_writer_test_callback, &context));
    RFB_CHECK_EQ_INT(unlink(path), 0);
    RFB_CHECK_EQ_INT(unlink(alias), 0);
    RFB_CHECK_EQ_INT(rmdir(directory), 0);
}

RFB_TEST(secret, private_file__safe_parent_directory_succeeds)
{
    char directory[] = "/tmp/farsee-private-dir-XXXXXX";
    RFB_CHECK(mkdtemp(directory) != NULL);
    char path[128];
    const int n = snprintf(path, sizeof path, "%s/output", directory);
    RFB_CHECK(n > 0 && (size_t)n < sizeof path);
    private_writer_test_context context = {
        .descriptor_was_private = false,
        .fail_after_write = false,
        .unlink_before_return = NULL,
    };
    RFB_CHECK(rfb_private_file_write_0600(
        path, private_writer_test_callback, &context));
    RFB_CHECK(context.descriptor_was_private);
    RFB_CHECK_EQ_INT(unlink(path), 0);
    RFB_CHECK_EQ_INT(rmdir(directory), 0);
}

RFB_TEST(secret, private_file__symlink_parent_directory_is_rejected)
{
    char directory[] = "/tmp/farsee-private-real-XXXXXX";
    RFB_CHECK(mkdtemp(directory) != NULL);
    char alias[128];
    const int an = snprintf(alias, sizeof alias, "%s.alias", directory);
    RFB_CHECK(an > 0 && (size_t)an < sizeof alias);
    RFB_CHECK_EQ_INT(symlink(directory, alias), 0);
    char path[160];
    const int pn = snprintf(path, sizeof path, "%s/output", alias);
    RFB_CHECK(pn > 0 && (size_t)pn < sizeof path);
    private_writer_test_context context = {
        .descriptor_was_private = false,
        .fail_after_write = false,
        .unlink_before_return = NULL,
    };
    RFB_CHECK(!rfb_private_file_write_0600(
        path, private_writer_test_callback, &context));

    char redirected[160];
    const int rn = snprintf(
        redirected, sizeof redirected, "%s/output", directory);
    RFB_CHECK(rn > 0 && (size_t)rn < sizeof redirected);
    struct stat status;
    RFB_CHECK(lstat(redirected, &status) != 0 && errno == ENOENT);
    RFB_CHECK_EQ_INT(unlink(alias), 0);
    RFB_CHECK_EQ_INT(rmdir(directory), 0);
}

RFB_TEST(secret, private_file__nonsticky_writable_parent_is_rejected)
{
    char directory[] = "/tmp/farsee-private-mode-XXXXXX";
    RFB_CHECK(mkdtemp(directory) != NULL);
    RFB_CHECK_EQ_INT(chmod(directory, 0777), 0);
    char path[128];
    const int n = snprintf(path, sizeof path, "%s/output", directory);
    RFB_CHECK(n > 0 && (size_t)n < sizeof path);
    private_writer_test_context context = {
        .descriptor_was_private = false,
        .fail_after_write = false,
        .unlink_before_return = NULL,
    };
    RFB_CHECK(!rfb_private_file_write_0600(
        path, private_writer_test_callback, &context));
    struct stat status;
    RFB_CHECK(lstat(path, &status) != 0 && errno == ENOENT);
    RFB_CHECK_EQ_INT(chmod(directory, 0700), 0);
    RFB_CHECK_EQ_INT(rmdir(directory), 0);
}

RFB_TEST(secret, private_path__creates_one_private_parent_and_anchors_name)
{
    char root[] = "/tmp/farsee-private-root-XXXXXX";
    RFB_CHECK(mkdtemp(root) != NULL);
    char directory[160];
    char path[192];
    const int directory_length = snprintf(
        directory, sizeof directory, "%s/created", root);
    const int path_length = snprintf(
        path, sizeof path, "%s/output", directory);
    RFB_CHECK(directory_length > 0 &&
              (size_t)directory_length < sizeof directory);
    RFB_CHECK(path_length > 0 && (size_t)path_length < sizeof path);

    rfb_private_path anchored;
    RFB_CHECK_EQ_INT(rfb_private_path_open(&anchored, path, true),
                     RFB_PRIVATE_PATH_OK);
    RFB_CHECK(strcmp(anchored.basename, "output") == 0);
    struct stat status;
    RFB_CHECK_EQ_INT(fstat(anchored.directory_fd, &status), 0);
    RFB_CHECK(S_ISDIR(status.st_mode));
    RFB_CHECK_EQ_UINT((unsigned)(status.st_mode & 0777), 0700u);
    const int descriptor_flags = fcntl(anchored.directory_fd, F_GETFD, 0);
    RFB_CHECK(descriptor_flags >= 0 &&
              (descriptor_flags & FD_CLOEXEC) != 0);

    char too_small[1];
    RFB_CHECK_EQ_INT(rfb_private_temp_open_at(
                         &anchored, too_small, sizeof too_small), -1);
    RFB_CHECK(rfb_private_path_close(&anchored));
    RFB_CHECK_EQ_INT(anchored.directory_fd, -1);
    RFB_CHECK_EQ_UINT((unsigned char)anchored.basename[0], 0u);
    RFB_CHECK_EQ_INT(rmdir(directory), 0);
    RFB_CHECK_EQ_INT(rmdir(root), 0);
}

RFB_TEST(secret, private_path__invalid_and_nested_missing_paths_fail_closed)
{
    rfb_private_path anchored;
    RFB_CHECK_EQ_INT(rfb_private_path_open(NULL, "file", false),
                     RFB_PRIVATE_PATH_INVALID);
    RFB_CHECK_EQ_INT(rfb_private_path_open(&anchored, NULL, false),
                     RFB_PRIVATE_PATH_INVALID);
    RFB_CHECK_EQ_INT(rfb_private_path_open(&anchored, ".", false),
                     RFB_PRIVATE_PATH_INVALID);
    RFB_CHECK_EQ_INT(rfb_private_path_open(&anchored, "..", false),
                     RFB_PRIVATE_PATH_INVALID);
    RFB_CHECK_EQ_INT(rfb_private_path_open(&anchored, "/tmp/", false),
                     RFB_PRIVATE_PATH_INVALID);
    RFB_CHECK(!rfb_private_path_close(NULL));
    anchored.directory_fd = -1;
    anchored.basename[0] = '\0';
    RFB_CHECK(!rfb_private_path_close(&anchored));
    RFB_CHECK_EQ_INT(rfb_private_temp_open_at(NULL, NULL, 0u), -1);
    RFB_CHECK(!rfb_private_directory_sync(-1));
    RFB_CHECK(!rfb_private_file_write_0600("ignored", NULL, NULL));

    char unterminated[RFB_PRIVATE_FILE_PATH_CAP];
    memset(unterminated, 'p', sizeof unterminated);
    RFB_CHECK_EQ_INT(rfb_private_path_open(
                         &anchored, unterminated, false),
                     RFB_PRIVATE_PATH_INVALID);

    RFB_CHECK_EQ_INT(rfb_private_path_open(
                         &anchored, "farsee-private-relative", false),
                     RFB_PRIVATE_PATH_OK);
    char temporary[64];
    rfb_private_path invalid = anchored;
    invalid.directory_fd = -1;
    RFB_CHECK_EQ_INT(rfb_private_temp_open_at(
                         &invalid, temporary, sizeof temporary), -1);
    invalid = anchored;
    invalid.basename[0] = '\0';
    RFB_CHECK_EQ_INT(rfb_private_temp_open_at(
                         &invalid, temporary, sizeof temporary), -1);
    RFB_CHECK_EQ_INT(rfb_private_temp_open_at(
                         &anchored, NULL, sizeof temporary), -1);
    RFB_CHECK_EQ_INT(rfb_private_temp_open_at(
                         &anchored, temporary, 0u), -1);
    RFB_CHECK(rfb_private_path_close(&anchored));

    RFB_CHECK_EQ_INT(rfb_private_path_open(
                         &anchored, "/farsee-private-root-anchor", false),
                     RFB_PRIVATE_PATH_OK);
    RFB_CHECK(rfb_private_path_close(&anchored));

    char root[] = "/tmp/farsee-private-missing-XXXXXX";
    RFB_CHECK(mkdtemp(root) != NULL);
    char missing[192];
    char nested[224];
    const int missing_length = snprintf(
        missing, sizeof missing, "%s/missing/output", root);
    const int nested_length = snprintf(
        nested, sizeof nested, "%s/missing/nested/output", root);
    RFB_CHECK(missing_length > 0 &&
              (size_t)missing_length < sizeof missing);
    RFB_CHECK(nested_length > 0 && (size_t)nested_length < sizeof nested);
    RFB_CHECK_EQ_INT(rfb_private_path_open(&anchored, missing, false),
                     RFB_PRIVATE_PATH_MISSING);
    RFB_CHECK_EQ_INT(anchored.directory_fd, -1);
    RFB_CHECK_EQ_UINT((unsigned char)anchored.basename[0], 0u);
    RFB_CHECK_EQ_INT(rfb_private_path_open(&anchored, nested, true),
                     RFB_PRIVATE_PATH_INVALID);
    RFB_CHECK_EQ_INT(rmdir(root), 0);
}

RFB_TEST(secret, private_file_primitives__validate_status_and_write_contract)
{
    RFB_CHECK(!rfb_private_regular_status_valid(NULL));
    RFB_CHECK(!rfb_private_file_write_all(-1, "x", 1u));
    RFB_CHECK(!rfb_private_file_write_all(1, NULL, 1u));

    char path[] = "/tmp/farsee-private-primitives-XXXXXX";
    const int fd = mkstemp(path);
    RFB_CHECK(fd >= 0);
    struct stat regular;
    RFB_CHECK_EQ_INT(fstat(fd, &regular), 0);
    RFB_CHECK(rfb_private_regular_status_valid(&regular));

    struct stat changed = regular;
    changed.st_mode |= S_IRGRP;
    RFB_CHECK(!rfb_private_regular_status_valid(&changed));
    changed = regular;
    changed.st_uid = geteuid() == 0u ? 1u : 0u;
    RFB_CHECK(!rfb_private_regular_status_valid(&changed));
    changed = regular;
    changed.st_nlink = 2;
    RFB_CHECK(!rfb_private_regular_status_valid(&changed));
    struct stat directory;
    RFB_CHECK_EQ_INT(stat("/tmp", &directory), 0);
    RFB_CHECK(!rfb_private_regular_status_valid(&directory));

    static const uint8_t bytes[] = {0x31u, 0x32u, 0x33u};
    RFB_CHECK(rfb_private_file_write_all(fd, NULL, 0u));
    RFB_CHECK(rfb_private_file_write_all(fd, bytes, sizeof bytes));
    RFB_CHECK_EQ_INT(close(fd), 0);
    const int read_fd = open(path, O_RDONLY);
    RFB_CHECK(read_fd >= 0);
    uint8_t actual[sizeof bytes];
    RFB_CHECK_EQ_INT(read(read_fd, actual, sizeof actual),
                     (ssize_t)sizeof actual);
    RFB_CHECK_MEM_EQ(actual, bytes, sizeof bytes);
    RFB_CHECK_EQ_INT(close(read_fd), 0);
    RFB_CHECK_EQ_INT(unlink(path), 0);
}

RFB_TEST(secret, private_file_write_all__full_nonblocking_pipe_fails)
{
    int pipe_fds[2] = {-1, -1};
    if (pipe(pipe_fds) != 0) {
        RFB_FAIL("pipe creation failed");
        return;
    }
    const int flags = fcntl(pipe_fds[1], F_GETFL);
    if (flags < 0 ||
        fcntl(pipe_fds[1], F_SETFL, flags | O_NONBLOCK) != 0) {
        RFB_FAIL("cannot make pipe writer nonblocking");
        (void)close(pipe_fds[0]);
        (void)close(pipe_fds[1]);
        return;
    }

    uint8_t fill[4096];
    memset(fill, 0xA5, sizeof fill);
    ssize_t count = 0;
    do {
        count = write(pipe_fds[1], fill, sizeof fill);
    } while (count > 0);
    RFB_CHECK_EQ_INT(count, -1);
    RFB_CHECK(errno == EAGAIN || errno == EWOULDBLOCK);

    const uint8_t byte = 0x5Au;
    RFB_CHECK(!rfb_private_file_write_all(pipe_fds[1], &byte, 1u));
    RFB_CHECK_EQ_INT(close(pipe_fds[0]), 0);
    RFB_CHECK_EQ_INT(close(pipe_fds[1]), 0);
}
