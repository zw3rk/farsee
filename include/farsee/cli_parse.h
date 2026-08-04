// SPDX-License-Identifier: Apache-2.0
//
// farsee — strict numeric CLI parse helpers (P0-CLI).
//
// Full-consumption decimal parsers built on strto* + endptr. Reject empty
// input, trailing garbage, ERANGE, and out-of-range values for the target
// width. On failure *out is left untouched.

#ifndef FARSEE_INCLUDE_FARSEE_CLI_PARSE_H
#define FARSEE_INCLUDE_FARSEE_CLI_PARSE_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Parse a non-negative decimal uint32. Rejects '-', empty, trailing junk,
// and values that do not fit in uint32_t.
bool farsee_parse_u32(const char *s, uint32_t *out);

// Parse a signed decimal int32. Rejects empty, trailing junk, and ERANGE.
bool farsee_parse_i32(const char *s, int32_t *out);

// Parse a non-negative decimal uint64. Rejects '-', empty, trailing junk,
// and ERANGE beyond uint64_t.
bool farsee_parse_u64(const char *s, uint64_t *out);

#ifdef __cplusplus
}
#endif

#endif /* FARSEE_INCLUDE_FARSEE_CLI_PARSE_H */
