// SPDX-License-Identifier: Apache-2.0
//
// farsee — Apple known-hosts trust (goals.md G18).

#include "farsee/known_hosts.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>

// Format: "host port hex_fingerprint\n" (lowercase hex, 64 chars + newline)
#define KH_LINE_MAX (256 + 1 + 5 + 1 + 64 + 1)

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
    if (hex == NULL) {
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

known_hosts_result known_hosts_check(
    const char *host, uint16_t port,
    const uint8_t fingerprint[32],
    const char *known_hosts_path)
{
    if (host == NULL || fingerprint == NULL || known_hosts_path == NULL)
        return KNOWN_HOSTS_MISMATCH;  // fail closed

    errno = 0;
    FILE *f = fopen(known_hosts_path, "r");
    if (f == NULL) {
        // Only missing store is "first use"; unreadable/corrupt path fail-closed
        // (loop r1 T5 / multi-review).
        return (errno == ENOENT) ? KNOWN_HOSTS_NOT_FOUND : KNOWN_HOSTS_MISMATCH;
    }

    char line[KH_LINE_MAX];
    known_hosts_result result = KNOWN_HOSTS_NOT_FOUND;
    char expected_hex[65];
    fingerprint_to_hex(fingerprint, expected_hex);

    while (fgets(line, sizeof line, f) != NULL) {
        // Parse: "host port hex_fingerprint\n"
        char file_host[256];
        unsigned file_port_u = 0;
        char file_hex[65];
        if (sscanf(line, "%255s %u %64s", file_host, &file_port_u, file_hex) == 3 &&
            file_port_u >= 1 && file_port_u <= 65535 &&
            strcmp(file_host, host) == 0 && (uint16_t)file_port_u == port) {
            uint8_t file_fp[32];
            if (hex_to_fingerprint(file_hex, file_fp)) {
                if (memcmp(file_fp, fingerprint, 32) == 0) {
                    result = KNOWN_HOSTS_MATCH;
                } else {
                    result = KNOWN_HOSTS_MISMATCH;
                }
            } else {
                // Corrupt pin for this host → fail closed (T11), not NOT_FOUND.
                result = KNOWN_HOSTS_MISMATCH;
            }
            break;  // found the host entry
        }
    }
    fclose(f);
    return result;
}

// Ensure parent directory of path exists (mkdir 0700). path must be a file
// path with at least one '/'. Best-effort: ignore EEXIST.
static bool ensure_parent_dir(const char *path)
{
    if (path == NULL || path[0] == '\0') {
        return false;
    }
    char dir[512];
    size_t n = strlen(path);
    if (n == 0u || n >= sizeof dir) {
        return false;
    }
    memcpy(dir, path, n + 1u);
    char *slash = strrchr(dir, '/');
    if (slash == NULL || slash == dir) {
        return true; // no parent or root
    }
    *slash = '\0';
    if (dir[0] == '\0') {
        return true;
    }
    if (mkdir(dir, 0700) == 0 || errno == EEXIST) {
        return true;
    }
    // One more level (e.g. ~/.farsee when path is ~/.farsee/rdp_known_hosts
    // and only ~ exists) — if intermediate missing, fail closed.
    return false;
}

// Host must be a single token (no whitespace/control) for line-oriented store.
static bool host_token_ok(const char *host)
{
    if (host == NULL || host[0] == '\0') {
        return false;
    }
    for (const char *p = host; *p != '\0'; p++) {
        unsigned char c = (unsigned char)*p;
        if (c <= 0x20u || c == 0x7fu) {
            return false;
        }
    }
    return true;
}

// Exclusive lock across check+mutate so concurrent writers cannot double-
// append the same host:port (2026-07-31 T8). Sidecar `.lock` so rename rewrite
// of the data file does not drop the lock.
static int known_hosts_lock(const char *known_hosts_path)
{
    char lock_path[512];
    int n = snprintf(lock_path, sizeof lock_path, "%s.lock", known_hosts_path);
    if (n <= 0 || (size_t)n >= sizeof lock_path) {
        return -1;
    }
    int fd = open(lock_path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (fd < 0) {
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

static void known_hosts_unlock(int lock_fd)
{
    if (lock_fd >= 0) {
        (void)flock(lock_fd, LOCK_UN);
        close(lock_fd);
    }
}

bool known_hosts_add(
    const char *host, uint16_t port,
    const uint8_t fingerprint[32],
    const char *known_hosts_path)
{
    if (host == NULL || fingerprint == NULL || known_hosts_path == NULL)
        return false;
    if (!host_token_ok(host)) {
        return false;
    }

    char hex[65];
    fingerprint_to_hex(fingerprint, hex);

    if (!ensure_parent_dir(known_hosts_path)) {
        return false;
    }

    int lock_fd = known_hosts_lock(known_hosts_path);
    if (lock_fd < 0) {
        return false;
    }

    // Re-check under the lock (TOCTOU-safe vs concurrent writers).
    known_hosts_result r =
        known_hosts_check(host, port, fingerprint, known_hosts_path);
    if (r == KNOWN_HOSTS_MATCH) {
        known_hosts_unlock(lock_fd);
        return true;
    }

    // On MISMATCH under lock: fail closed without rewrite (loop r2).
    // Concurrent FIRST_USE with different certs must not last-writer-wins.
    if (r == KNOWN_HOSTS_MISMATCH) {
        known_hosts_unlock(lock_fd);
        return false;
    }

    // NOT_FOUND: append. Create with 0600 if needed.
    bool ok = false;
    int flags = O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC;
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
    int fd = open(known_hosts_path, flags, 0600);
    if (fd < 0) {
        known_hosts_unlock(lock_fd);
        return false;
    }

    char line[KH_LINE_MAX];
    int len = snprintf(line, sizeof line, "%s %u %s\n", host, (unsigned)port, hex);
    if (len > 0 && (size_t)len < sizeof line) {
        size_t off = 0;
        ok = true;
        while (off < (size_t)len) {
            ssize_t w = write(fd, line + off, (size_t)len - off);
            if (w < 0) {
                if (errno == EINTR) continue;
                ok = false;
                break;
            }
            off += (size_t)w;
        }
        ok = ok && off == (size_t)len;
    }
    close(fd);
    known_hosts_unlock(lock_fd);
    return ok;
}
