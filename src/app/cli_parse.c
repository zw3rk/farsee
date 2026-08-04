// SPDX-License-Identifier: Apache-2.0
//
// Strict numeric CLI parse helpers (P0-CLI). See farsee/cli_parse.h.

#include "farsee/cli_parse.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>

bool farsee_parse_u32(const char *s, uint32_t *out)
{
    if (s == NULL || out == NULL || s[0] == '\0') {
        return false;
    }
    /* strtoul accepts leading '-'; reject signed input for unsigned. */
    if (s[0] == '-') {
        return false;
    }

    errno = 0;
    char *end = NULL;
    unsigned long v = strtoul(s, &end, 10);
    if (end == s || end == NULL || *end != '\0') {
        return false;
    }
    if (errno == ERANGE || v > (unsigned long)UINT32_MAX) {
        return false;
    }
    *out = (uint32_t)v;
    return true;
}

bool farsee_parse_i32(const char *s, int32_t *out)
{
    if (s == NULL || out == NULL || s[0] == '\0') {
        return false;
    }

    errno = 0;
    char *end = NULL;
    long v = strtol(s, &end, 10);
    if (end == s || end == NULL || *end != '\0') {
        return false;
    }
    if (errno == ERANGE || v < (long)INT32_MIN || v > (long)INT32_MAX) {
        return false;
    }
    *out = (int32_t)v;
    return true;
}

bool farsee_parse_u64(const char *s, uint64_t *out)
{
    if (s == NULL || out == NULL || s[0] == '\0') {
        return false;
    }
    if (s[0] == '-') {
        return false;
    }

    errno = 0;
    char *end = NULL;
    unsigned long long v = strtoull(s, &end, 10);
    if (end == s || end == NULL || *end != '\0') {
        return false;
    }
    if (errno == ERANGE) {
        return false;
    }
    *out = (uint64_t)v;
    return true;
}
