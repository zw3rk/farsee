// SPDX-License-Identifier: Apache-2.0
//
// farsee — Apple known-hosts trust.

#include "farsee/known_hosts.h"

#include "core/private_file_internal.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>

// Format: "host port hex_fingerprint\n" (lowercase hex, 64 chars + newline)
#define KH_LINE_MAX (256 + 1 + 5 + 1 + 64 + 1)

static bool host_token_ok(const char *host);

static void fingerprint_to_hex(const uint8_t fp[32], char out[65])
{
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        out[i * 2]     = hex[(fp[i] >> 4) & 0xF];
        out[i * 2 + 1] = hex[fp[i] & 0xF];
    }
    out[64] = '\0';
}

static bool hex_to_fingerprint(const char *hex, uint8_t out[32])
{
    if (hex == NULL || strlen(hex) != 64u) {
        return false;
    }
    for (int i = 0; i < 32; i++) {
        char c1 = hex[i * 2];
        if (c1 == '\0') {
            return false;
        }
        int hi = -1;
        if (c1 >= '0' && c1 <= '9') hi = c1 - '0';
        else if (c1 >= 'a' && c1 <= 'f') hi = c1 - 'a' + 10;
        if (hi < 0) {
            return false;
        }
        char c2 = hex[i * 2 + 1];
        if (c2 == '\0') {
            return false;
        }
        int lo = -1;
        if (c2 >= '0' && c2 <= '9') lo = c2 - '0';
        else if (c2 >= 'a' && c2 <= 'f') lo = c2 - 'a' + 10;
        if (lo < 0) {
            return false;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

static bool fd_is_private_regular(int fd)
{
    struct stat st;
    return fstat(fd, &st) == 0 && rfb_private_regular_status_valid(&st);
}

static bool parse_port(const char *text, uint16_t *out)
{
    if (text == NULL || out == NULL || text[0] == '\0') {
        return false;
    }
    unsigned value = 0u;
    size_t digits = 0u;
    for (const char *p = text; *p != '\0'; p++) {
        if (*p < '0' || *p > '9' || digits == 5u) {
            return false;
        }
        value = value * 10u + (unsigned)(*p - '0');
        digits++;
    }
    if (value == 0u || value > 65535u) {
        return false;
    }
    *out = (uint16_t)value;
    return true;
}

static bool parse_line(char *line, char **host_out, uint16_t *port_out,
                       uint8_t fingerprint_out[32])
{
    char *newline = strchr(line, '\n');
    if (newline == NULL || newline[1] != '\0') {
        return false;
    }
    *newline = '\0';

    char *first_space = strchr(line, ' ');
    if (first_space == NULL || first_space == line) {
        return false;
    }
    *first_space = '\0';
    char *port_text = first_space + 1;
    char *second_space = strchr(port_text, ' ');
    if (second_space == NULL || second_space == port_text) {
        return false;
    }
    *second_space = '\0';
    char *hex = second_space + 1;
    if (strchr(hex, ' ') != NULL || strlen(line) > 255u ||
        !parse_port(port_text, port_out) ||
        !hex_to_fingerprint(hex, fingerprint_out)) {
        return false;
    }
    *host_out = line;
    return true;
}

static known_hosts_result known_hosts_check_at(
    const char *host, uint16_t port,
    const uint8_t fingerprint[32],
    const rfb_private_path *path)
{
    errno = 0;
    int flags = O_RDONLY | O_CLOEXEC;
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    int fd = openat(path->directory_fd, path->basename, flags);
    if (fd < 0) {
        // Only a missing store is "first use". Unreadable or corrupt paths
        // fail closed.
        return (errno == ENOENT) ? KNOWN_HOSTS_NOT_FOUND : KNOWN_HOSTS_MISMATCH;
    }
    if (!fd_is_private_regular(fd)) {
        close(fd);
        return KNOWN_HOSTS_MISMATCH;
    }
    FILE *f = fdopen(fd, "r");
    if (f == NULL) {
        close(fd);
        return KNOWN_HOSTS_MISMATCH;
    }

    char line[KH_LINE_MAX];
    known_hosts_result result = KNOWN_HOSTS_NOT_FOUND;
    bool found = false;

    while (fgets(line, sizeof line, f) != NULL) {
        char *file_host = NULL;
        uint16_t file_port = 0u;
        uint8_t file_fp[32];
        if (!parse_line(line, &file_host, &file_port, file_fp)) {
            result = KNOWN_HOSTS_MISMATCH;
            break;
        }
        if (strcmp(file_host, host) == 0 && file_port == port) {
            // Duplicate host:port entries make pin selection ambiguous even
            // when their fingerprints happen to agree. Treat the store as
            // corrupt instead of depending on file order.
            if (found) {
                result = KNOWN_HOSTS_MISMATCH;
                break;
            }
            found = true;
            result = memcmp(file_fp, fingerprint, 32) == 0
                   ? KNOWN_HOSTS_MATCH : KNOWN_HOSTS_MISMATCH;
        }
    }
    if (ferror(f)) {
        result = KNOWN_HOSTS_MISMATCH;
    }
    if (fclose(f) != 0) {
        result = KNOWN_HOSTS_MISMATCH;
    }
    return result;
}

known_hosts_result known_hosts_check(
    const char *host, uint16_t port,
    const uint8_t fingerprint[32],
    const char *known_hosts_path)
{
    if (host == NULL || fingerprint == NULL || known_hosts_path == NULL ||
        known_hosts_path[0] == '\0' || !host_token_ok(host) || port == 0u) {
        return KNOWN_HOSTS_MISMATCH;
    }
    rfb_private_path path;
    const rfb_private_path_result opened = rfb_private_path_open(
        &path, known_hosts_path, false);
    if (opened == RFB_PRIVATE_PATH_MISSING) {
        return KNOWN_HOSTS_NOT_FOUND;
    }
    if (opened != RFB_PRIVATE_PATH_OK) {
        return KNOWN_HOSTS_MISMATCH;
    }
    known_hosts_result result = known_hosts_check_at(
        host, port, fingerprint, &path);
    if (!rfb_private_path_close(&path)) {
        result = KNOWN_HOSTS_MISMATCH;
    }
    return result;
}

// Host must be a single token (no whitespace/control) for line-oriented store.
static bool host_token_ok(const char *host)
{
    if (host == NULL || host[0] == '\0') {
        return false;
    }
    size_t length = 0u;
    for (const char *p = host; *p != '\0'; p++) {
        unsigned char c = (unsigned char)*p;
        if (c <= 0x20u || c == 0x7fu || length == 255u) {
            return false;
        }
        length++;
    }
    return true;
}

// Exclusive lock across check+mutate so concurrent writers cannot double-
// append the same host:port. Use a sidecar `.lock` so rename replacement
// of the data file does not drop the lock.
static int known_hosts_lock(const rfb_private_path *path)
{
    char lock_path[RFB_PRIVATE_FILE_PATH_CAP];
    int n = snprintf(lock_path, sizeof lock_path, "%s.lock", path->basename);
    if (n <= 0 || (size_t)n >= sizeof lock_path) {
        return -1;
    }
    int flags = O_RDWR | O_CLOEXEC;
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    bool created = false;
    int fd = openat(path->directory_fd, lock_path,
                    flags | O_CREAT | O_EXCL, 0600);
    if (fd >= 0) {
        created = true;
    } else if (errno == EEXIST) {
        fd = openat(path->directory_fd, lock_path, flags);
    }
    if (fd < 0) {
        return -1;
    }
    if ((created && fchmod(fd, 0600) != 0) || !fd_is_private_regular(fd)) {
        close(fd);
        return -1;
    }
    while (flock(fd, LOCK_EX) != 0) {
        if (errno == EINTR) {
            continue;
        }
        close(fd);
        return -1;
    }
    return fd;
}

static bool known_hosts_unlock(int lock_fd)
{
    if (lock_fd < 0) {
        return false;
    }
    int result;
    do {
        result = flock(lock_fd, LOCK_UN);
    } while (result != 0 && errno == EINTR);
    const bool unlocked = result == 0;
    return close(lock_fd) == 0 && unlocked;
}

typedef struct known_hosts_identity {
    bool exists;
    dev_t device;
    ino_t inode;
} known_hosts_identity;

static int known_hosts_source_open(const rfb_private_path *path,
                                   known_hosts_identity *identity)
{
    int flags = O_RDONLY | O_CLOEXEC;
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    const int fd = openat(path->directory_fd, path->basename, flags);
    if (fd < 0) {
        if (errno == ENOENT) {
            identity->exists = false;
            identity->device = 0;
            identity->inode = 0;
            return -2;
        }
        return -1;
    }
    struct stat status;
    if (fstat(fd, &status) != 0 ||
        !rfb_private_regular_status_valid(&status)) {
        (void)close(fd);
        return -1;
    }
    identity->exists = true;
    identity->device = status.st_dev;
    identity->inode = status.st_ino;
    return fd;
}

static bool known_hosts_target_unchanged(
    const rfb_private_path *path, const known_hosts_identity *identity)
{
    struct stat status;
    if (fstatat(path->directory_fd, path->basename, &status,
                AT_SYMLINK_NOFOLLOW) != 0) {
        return !identity->exists && errno == ENOENT;
    }
    return identity->exists && rfb_private_regular_status_valid(&status) &&
           status.st_dev == identity->device &&
           status.st_ino == identity->inode;
}

static bool known_hosts_copy(int source_fd, int destination_fd)
{
    uint8_t buffer[4096];
    for (;;) {
        ssize_t count;
        do {
            count = read(source_fd, buffer, sizeof buffer);
        } while (count < 0 && errno == EINTR);
        if (count < 0) {
            return false;
        }
        if (count == 0) {
            return true;
        }
        if (!rfb_private_file_write_all(
                destination_fd, buffer, (size_t)count)) {
            return false;
        }
    }
}

static bool known_hosts_replace(const rfb_private_path *path,
                                const char *line, size_t line_length)
{
    known_hosts_identity identity;
    const int source_fd = known_hosts_source_open(path, &identity);
    if (source_fd == -1) {
        return false;
    }
    char temporary[RFB_PRIVATE_FILE_PATH_CAP];
    const int destination_fd = rfb_private_temp_open_at(
        path, temporary, sizeof temporary);
    if (destination_fd < 0) {
        if (source_fd >= 0) {
            (void)close(source_fd);
        }
        return false;
    }

    bool ok = source_fd < 0 || known_hosts_copy(source_fd, destination_fd);
    if (source_fd >= 0 && close(source_fd) != 0) {
        ok = false;
    }
    if (ok && !rfb_private_file_write_all(
                  destination_fd, line, line_length)) {
        ok = false;
    }
    struct stat destination_status;
    if (ok && (fstat(destination_fd, &destination_status) != 0 ||
               !rfb_private_regular_status_valid(&destination_status))) {
        ok = false;
    }
    if (ok) {
        int sync_result;
        do {
            sync_result = fsync(destination_fd);
        } while (sync_result != 0 && errno == EINTR);
        ok = sync_result == 0;
    }
    if (close(destination_fd) != 0) {
        ok = false;
    }
    if (ok && !known_hosts_target_unchanged(path, &identity)) {
        ok = false;
    }
    bool renamed = false;
    if (ok) {
        if (renameat(path->directory_fd, temporary,
                     path->directory_fd, path->basename) == 0) {
            renamed = true;
        } else {
            ok = false;
        }
    }
    if (ok && !rfb_private_directory_sync(path->directory_fd)) {
        ok = false;
    }
    if (!renamed && unlinkat(path->directory_fd, temporary, 0) != 0 &&
        errno != ENOENT) {
        ok = false;
    }
    return ok;
}

bool known_hosts_add(
    const char *host, uint16_t port,
    const uint8_t fingerprint[32],
    const char *known_hosts_path)
{
    if (host == NULL || fingerprint == NULL || known_hosts_path == NULL ||
        known_hosts_path[0] == '\0' || port == 0u)
        return false;
    if (!host_token_ok(host)) {
        return false;
    }

    char hex[65];
    fingerprint_to_hex(fingerprint, hex);

    rfb_private_path path;
    if (rfb_private_path_open(&path, known_hosts_path, true) !=
        RFB_PRIVATE_PATH_OK) {
        return false;
    }

    int lock_fd = known_hosts_lock(&path);
    if (lock_fd < 0) {
        (void)rfb_private_path_close(&path);
        return false;
    }

    // Re-check under the lock (TOCTOU-safe vs concurrent writers).
    known_hosts_result r =
        known_hosts_check_at(host, port, fingerprint, &path);
    if (r == KNOWN_HOSTS_MATCH) {
        const bool unlocked = known_hosts_unlock(lock_fd);
        const bool closed = rfb_private_path_close(&path);
        return unlocked && closed;
    }

    // On MISMATCH under lock, fail closed without rewriting the file.
    // Concurrent FIRST_USE with different certs must not last-writer-wins.
    if (r == KNOWN_HOSTS_MISMATCH) {
        (void)known_hosts_unlock(lock_fd);
        (void)rfb_private_path_close(&path);
        return false;
    }

    char line[KH_LINE_MAX];
    int len = snprintf(line, sizeof line, "%s %u %s\n", host, (unsigned)port, hex);
    bool ok = len > 0 && (size_t)len < sizeof line &&
              known_hosts_replace(&path, line, (size_t)len);
    if (!known_hosts_unlock(lock_fd)) {
        ok = false;
    }
    if (!rfb_private_path_close(&path)) {
        ok = false;
    }
    return ok;
}
