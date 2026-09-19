// SPDX-License-Identifier: Apache-2.0
//
// Secret-buffer zeroization and private-file helpers.
//
// rfb_secret_zero writes through a volatile-qualified byte pointer in the
// non-inline zero_impl helper to resist dead-store elimination.

#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif

#include "farsee/secret.h"

#include "core/private_file_internal.h"
#include "farsee/apple_crypto.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

// The sink is non-inline and writes through a volatile-qualified pointer.
static void zero_impl(volatile uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        p[i] = 0;
    }
}

void rfb_secret_zero(void *buf, size_t n)
{
    if (buf == NULL || n == 0) {
        return;
    }
    // Write through a volatile-qualified pointer to resist dead-store
    // elimination.
    zero_impl((volatile uint8_t *)buf, n);
}

void rfb_secret_wipe_free(void *buf, size_t buf_cap)
{
    if (buf == NULL) {
        return;
    }
    if (buf_cap > 0u) {
        rfb_secret_zero(buf, buf_cap);
    }
    free(buf);
}

static bool private_path_length(const char *path, size_t *length)
{
    if (path == NULL || length == NULL) {
        return false;
    }
    for (size_t i = 0u; i < RFB_PRIVATE_FILE_PATH_CAP; i++) {
        if (path[i] == '\0') {
            *length = i;
            return i > 0u;
        }
    }
    return false;
}

bool rfb_private_regular_status_valid(const struct stat *status)
{
    return status != NULL && S_ISREG(status->st_mode) &&
           status->st_uid == geteuid() &&
           (status->st_mode & 0777) == 0600 && status->st_nlink == 1;
}

typedef struct private_target_identity {
    bool exists;
    dev_t device;
    ino_t inode;
} private_target_identity;

static bool private_directory_status_valid(const struct stat *status)
{
    if (status == NULL || !S_ISDIR(status->st_mode) ||
        (status->st_uid != geteuid() && status->st_uid != 0u)) {
        return false;
    }
    const mode_t writable = status->st_mode & (S_IWGRP | S_IWOTH);
    return writable == 0 || (status->st_mode & S_ISVTX) != 0;
}

static bool private_set_cloexec(int fd)
{
    const int flags = fcntl(fd, F_GETFD, 0);
    return flags >= 0 &&
           fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == 0;
}

static rfb_private_path_result private_directory_open_existing(
    const char *directory, int *fd_out)
{
    struct stat path_status;
    if (lstat(directory, &path_status) != 0) {
        return errno == ENOENT ? RFB_PRIVATE_PATH_MISSING
                               : RFB_PRIVATE_PATH_INVALID;
    }
    const bool trusted_root_symlink =
        S_ISLNK(path_status.st_mode) && path_status.st_uid == 0u;
    if (S_ISLNK(path_status.st_mode) && !trusted_root_symlink) {
        return RFB_PRIVATE_PATH_INVALID;
    }
    int flags = O_RDONLY;
#ifdef O_DIRECTORY
    flags |= O_DIRECTORY;
#endif
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    if (!trusted_root_symlink) {
        flags |= O_NOFOLLOW;
    }
#endif
    const int fd = open(directory, flags);
    if (fd < 0) {
        return RFB_PRIVATE_PATH_INVALID;
    }
    struct stat descriptor_status;
    const bool valid = private_set_cloexec(fd) &&
                       fstat(fd, &descriptor_status) == 0 &&
                       private_directory_status_valid(&descriptor_status);
    if (!valid) {
        (void)close(fd);
        return RFB_PRIVATE_PATH_INVALID;
    }
    *fd_out = fd;
    return RFB_PRIVATE_PATH_OK;
}

static bool private_split_path(const char *path, char *directory,
                               size_t directory_capacity, char *basename,
                               size_t basename_capacity)
{
    size_t length = 0u;
    if (!private_path_length(path, &length) || directory == NULL ||
        basename == NULL || directory_capacity == 0u ||
        basename_capacity == 0u) {
        return false;
    }
    size_t slash = length;
    while (slash > 0u && path[slash - 1u] != '/') {
        slash--;
    }
    const size_t basename_offset = slash;
    const size_t basename_length = length - basename_offset;
    if (basename_length == 0u || basename_length >= basename_capacity ||
        (basename_length == 1u && path[basename_offset] == '.') ||
        (basename_length == 2u && path[basename_offset] == '.' &&
         path[basename_offset + 1u] == '.')) {
        return false;
    }
    memcpy(basename, path + basename_offset, basename_length);
    basename[basename_length] = '\0';

    if (slash == 0u) {
        if (directory_capacity < 2u) {
            return false;
        }
        directory[0] = '.';
        directory[1] = '\0';
        return true;
    }
    size_t directory_length = slash - 1u;
    if (directory_length == 0u) {
        directory_length = 1u;
    }
    if (directory_length >= directory_capacity) {
        return false;
    }
    memcpy(directory, path, directory_length);
    directory[directory_length] = '\0';
    return true;
}

bool rfb_private_directory_sync(int directory_fd)
{
    int result;
    do {
        result = fsync(directory_fd);
    } while (result < 0 && errno == EINTR);
    return result == 0;
}

static rfb_private_path_result private_directory_create_one(
    const char *directory, int *fd_out)
{
    char parent[RFB_PRIVATE_FILE_PATH_CAP];
    char child[RFB_PRIVATE_FILE_PATH_CAP];
    if (!private_split_path(directory, parent, sizeof parent,
                            child, sizeof child)) {
        return RFB_PRIVATE_PATH_INVALID;
    }
    int parent_fd = -1;
    if (private_directory_open_existing(parent, &parent_fd) !=
        RFB_PRIVATE_PATH_OK) {
        return RFB_PRIVATE_PATH_INVALID;
    }
    bool ok = true;
    if (mkdirat(parent_fd, child, 0700) != 0 && errno != EEXIST) {
        ok = false;
    }
    int flags = O_RDONLY;
#ifdef O_DIRECTORY
    flags |= O_DIRECTORY;
#endif
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    const int fd = ok ? openat(parent_fd, child, flags) : -1;
    struct stat status;
    if (fd < 0 || !private_set_cloexec(fd) || fstat(fd, &status) != 0 ||
        !private_directory_status_valid(&status) ||
        (status.st_uid == geteuid() &&
         (status.st_mode & (S_IWGRP | S_IWOTH)) != 0) ||
        !rfb_private_directory_sync(parent_fd)) {
        ok = false;
    }
    if (close(parent_fd) != 0) {
        ok = false;
    }
    if (!ok) {
        if (fd >= 0) {
            (void)close(fd);
        }
        return RFB_PRIVATE_PATH_INVALID;
    }
    *fd_out = fd;
    return RFB_PRIVATE_PATH_OK;
}

rfb_private_path_result rfb_private_path_open(rfb_private_path *out,
                                              const char *path,
                                              bool create_parent)
{
    if (out == NULL) {
        return RFB_PRIVATE_PATH_INVALID;
    }
    out->directory_fd = -1;
    out->basename[0] = '\0';
    char directory[RFB_PRIVATE_FILE_PATH_CAP];
    if (!private_split_path(path, directory, sizeof directory,
                            out->basename, sizeof out->basename)) {
        return RFB_PRIVATE_PATH_INVALID;
    }
    rfb_private_path_result result = private_directory_open_existing(
        directory, &out->directory_fd);
    if (result == RFB_PRIVATE_PATH_MISSING && create_parent) {
        result = private_directory_create_one(directory, &out->directory_fd);
    }
    if (result != RFB_PRIVATE_PATH_OK) {
        out->basename[0] = '\0';
    }
    return result;
}

bool rfb_private_path_close(rfb_private_path *path)
{
    if (path == NULL || path->directory_fd < 0) {
        return false;
    }
    const int fd = path->directory_fd;
    path->directory_fd = -1;
    path->basename[0] = '\0';
    return close(fd) == 0;
}

int rfb_private_temp_open_at(const rfb_private_path *path,
                             char *temporary_name,
                             size_t temporary_name_capacity)
{
    if (path == NULL || path->directory_fd < 0 ||
        path->basename[0] == '\0' || temporary_name == NULL ||
        temporary_name_capacity == 0u) {
        return -1;
    }
    static const char hex[] = "0123456789abcdef";
    for (unsigned attempt = 0u; attempt < 32u; attempt++) {
        uint8_t random[8];
        if (!rfb_crypto_random_bytes(random, sizeof random)) {
            return -1;
        }
        char suffix[17];
        for (size_t i = 0u; i < sizeof random; i++) {
            suffix[i * 2u] = hex[random[i] >> 4u];
            suffix[i * 2u + 1u] = hex[random[i] & 0x0fu];
        }
        suffix[16] = '\0';
        const int formatted = snprintf(
            temporary_name, temporary_name_capacity, "%s.tmp.%s",
            path->basename, suffix);
        if (formatted <= 0 ||
            (size_t)formatted >= temporary_name_capacity) {
            return -1;
        }
        int flags = O_WRONLY | O_CREAT | O_EXCL;
#ifdef O_CLOEXEC
        flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
        flags |= O_NOFOLLOW;
#endif
        const int fd = openat(
            path->directory_fd, temporary_name, flags, 0600);
        if (fd >= 0) {
            struct stat status;
            if (!private_set_cloexec(fd) || fchmod(fd, 0600) != 0 ||
                fstat(fd, &status) != 0 ||
                !rfb_private_regular_status_valid(&status)) {
                (void)close(fd);
                (void)unlinkat(path->directory_fd, temporary_name, 0);
                return -1;
            }
            return fd;
        }
        if (errno != EEXIST) {
            return -1;
        }
    }
    return -1;
}

static bool private_target_inspect_at(const rfb_private_path *path,
                                      private_target_identity *identity)
{
    struct stat path_status;
    if (fstatat(path->directory_fd, path->basename, &path_status,
                AT_SYMLINK_NOFOLLOW) != 0) {
        if (errno == ENOENT) {
            identity->exists = false;
            identity->device = 0;
            identity->inode = 0;
            return true;
        }
        return false;
    }
    if (!rfb_private_regular_status_valid(&path_status)) {
        return false;
    }

    int open_flags = O_RDONLY | O_NONBLOCK;
#ifdef O_CLOEXEC
    open_flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    open_flags |= O_NOFOLLOW;
#endif
    const int fd = openat(path->directory_fd, path->basename, open_flags);
    if (fd < 0) {
        return false;
    }
#ifndef O_CLOEXEC
    const int descriptor_flags = fcntl(fd, F_GETFD, 0);
    if (descriptor_flags < 0 ||
        fcntl(fd, F_SETFD, descriptor_flags | FD_CLOEXEC) != 0) {
        (void)close(fd);
        return false;
    }
#endif
    struct stat descriptor_status;
    const bool valid = fstat(fd, &descriptor_status) == 0 &&
                       rfb_private_regular_status_valid(&descriptor_status) &&
                       descriptor_status.st_dev == path_status.st_dev &&
                       descriptor_status.st_ino == path_status.st_ino;
    if (close(fd) != 0 || !valid) {
        return false;
    }
    identity->exists = true;
    identity->device = path_status.st_dev;
    identity->inode = path_status.st_ino;
    return true;
}

static bool private_target_unchanged_at(
    const rfb_private_path *path, const private_target_identity *identity)
{
    struct stat status;
    if (fstatat(path->directory_fd, path->basename, &status,
                AT_SYMLINK_NOFOLLOW) != 0) {
        return !identity->exists && errno == ENOENT;
    }
    return identity->exists && rfb_private_regular_status_valid(&status) &&
           status.st_dev == identity->device && status.st_ino == identity->inode;
}

bool rfb_private_file_write_all(int fd, const void *data, size_t length)
{
    if (fd < 0 || (data == NULL && length > 0u)) {
        return false;
    }
    const uint8_t *bytes = (const uint8_t *)data;
    size_t offset = 0u;
    while (offset < length) {
        const ssize_t count = write(fd, bytes + offset, length - offset);
        if (count > 0) {
            offset += (size_t)count;
            continue;
        }
        if (count < 0 && errno == EINTR) {
            continue;
        }
        return false;
    }
    return true;
}

bool rfb_private_file_write_0600(const char *path,
                                 rfb_private_file_writer_fn writer,
                                 void *context)
{
    if (writer == NULL) {
        return false;
    }

    rfb_private_path anchored;
    if (rfb_private_path_open(&anchored, path, false) !=
        RFB_PRIVATE_PATH_OK) {
        return false;
    }
    private_target_identity target;
    if (!private_target_inspect_at(&anchored, &target)) {
        (void)rfb_private_path_close(&anchored);
        return false;
    }

    char temporary[RFB_PRIVATE_FILE_PATH_CAP];
    const int fd = rfb_private_temp_open_at(
        &anchored, temporary, sizeof temporary);
    if (fd < 0) {
        (void)rfb_private_path_close(&anchored);
        return false;
    }
    bool ok = true;
    if (ok && !writer(fd, context)) {
        ok = false;
    }
    struct stat final_status;
    if (ok && (fstat(fd, &final_status) != 0 ||
               !rfb_private_regular_status_valid(&final_status))) {
        ok = false;
    }
    if (ok) {
        int sync_result;
        do {
            sync_result = fsync(fd);
        } while (sync_result < 0 && errno == EINTR);
        ok = sync_result == 0;
    }
    if (close(fd) != 0) {
        ok = false;
    }
    if (ok && !private_target_unchanged_at(&anchored, &target)) {
        ok = false;
    }
    bool renamed = false;
    if (ok) {
        if (renameat(anchored.directory_fd, temporary,
                     anchored.directory_fd, anchored.basename) == 0) {
            renamed = true;
        } else {
            ok = false;
        }
    }
    if (ok && !rfb_private_directory_sync(anchored.directory_fd)) {
        ok = false;
    }
    if (!renamed && unlinkat(anchored.directory_fd, temporary, 0) != 0 &&
        errno != ENOENT) {
        ok = false;
    }
    if (!rfb_private_path_close(&anchored)) {
        ok = false;
    }
    return ok;
}
