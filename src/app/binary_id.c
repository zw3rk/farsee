// SPDX-License-Identifier: Apache-2.0
//
// Running binary identity + stale-rebuild warning.

#include "farsee/binary_id.h"
#include "farsee/version.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif

// From build/obj/*/generated/build_id.h (Makefile gen-build-id).
#if defined(__has_include)
#  if __has_include("build_id.h")
#    include "build_id.h"
#  endif
#endif

#ifndef FARSEE_GIT_REV
#define FARSEE_GIT_REV "unknown"
#endif
#ifndef FARSEE_BUILD_TIME
#define FARSEE_BUILD_TIME "unknown"
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static char g_path[PATH_MAX];
static unsigned long long g_inode;
static time_t g_mtime;
static bool g_ok;
static bool g_warned;

static bool resolve_exe_path(const char *argv0, char *out, size_t out_cap)
{
    if (out == NULL || out_cap < 2u) {
        return false;
    }
    out[0] = '\0';

#ifdef __APPLE__
    {
        uint32_t n = (uint32_t)out_cap;
        if (_NSGetExecutablePath(out, &n) == 0) {
            char real[PATH_MAX];
            if (realpath(out, real) != NULL) {
                (void)snprintf(out, out_cap, "%s", real);
            }
            return out[0] != '\0';
        }
    }
#else
    {
        ssize_t n = readlink("/proc/self/exe", out, out_cap - 1u);
        if (n > 0) {
            out[n] = '\0';
            return true;
        }
    }
#endif

    if (argv0 != NULL && argv0[0] != '\0') {
        char real[PATH_MAX];
        if (realpath(argv0, real) != NULL) {
            (void)snprintf(out, out_cap, "%s", real);
            return true;
        }
        (void)snprintf(out, out_cap, "%s", argv0);
        return true;
    }
    return false;
}

void farsee_binary_id_init(const char *argv0)
{
    g_ok = false;
    g_warned = false;
    g_inode = 0;
    g_mtime = 0;
    g_path[0] = '\0';

    if (!resolve_exe_path(argv0, g_path, sizeof g_path)) {
        fprintf(stderr,
                "farsee: binary %s git=%s built=%s (path unresolved)\n",
                farsee_version_string(), FARSEE_GIT_REV, FARSEE_BUILD_TIME);
        (void)fflush(stderr);
        return;
    }

    struct stat st;
    memset(&st, 0, sizeof(st));
    if (stat(g_path, &st) != 0) {
        fprintf(stderr,
                "farsee: binary %s git=%s built=%s path=%s (stat failed)\n",
                farsee_version_string(), FARSEE_GIT_REV, FARSEE_BUILD_TIME,
                g_path);
        (void)fflush(stderr);
        return;
    }

    g_inode = (unsigned long long)st.st_ino;
    g_mtime = st.st_mtime;
    g_ok = true;

    char mbuf[32];
    struct tm tm;
    memset(&tm, 0, sizeof(tm));
#if defined(__APPLE__) || defined(__unix__)
    if (localtime_r(&g_mtime, &tm) != NULL) {
        (void)strftime(mbuf, sizeof mbuf, "%Y-%m-%dT%H:%M:%S", &tm);
    } else {
        (void)snprintf(mbuf, sizeof mbuf, "%lld", (long long)g_mtime);
    }
#else
    (void)snprintf(mbuf, sizeof mbuf, "%lld", (long long)g_mtime);
#endif

    fprintf(stderr,
            "farsee: binary %s git=%s built=%s\n"
            "farsee:   path=%s\n"
            "farsee:   inode=%llu mtime=%s  (restart after rebuild if these "
            "change on disk)\n",
            farsee_version_string(), FARSEE_GIT_REV, FARSEE_BUILD_TIME, g_path,
            g_inode, mbuf);
    (void)fflush(stderr);
}

bool farsee_binary_id_warn_if_stale(void)
{
    if (!g_ok || g_path[0] == '\0') {
        return false;
    }
    struct stat st;
    memset(&st, 0, sizeof(st));
    if (stat(g_path, &st) != 0) {
        return false;
    }
    const unsigned long long ino = (unsigned long long)st.st_ino;
    if (ino == g_inode && st.st_mtime == g_mtime) {
        return false;
    }
    if (!g_warned) {
        g_warned = true;
        fprintf(stderr,
                "farsee: WARNING: on-disk binary differs from this process "
                "(running inode=%llu mtime_disk_changed; disk inode=%llu). "
                "Quit and restart to pick up the rebuild — you are still "
                "executing the old image.\n",
                g_inode, ino);
        (void)fflush(stderr);
    }
    return true;
}

const char *farsee_binary_id_path(void)
{
    return g_path[0] != '\0' ? g_path : "";
}

const char *farsee_binary_id_git(void)
{
    return FARSEE_GIT_REV;
}

const char *farsee_binary_id_build_time(void)
{
    return FARSEE_BUILD_TIME;
}

unsigned long long farsee_binary_id_inode(void)
{
    return g_inode;
}
