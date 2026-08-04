// SPDX-License-Identifier: Apache-2.0
//
// Strict numeric CLI parse helpers (P0-CLI).
//
// Positive: full consumption of a decimal integer.
// Negative: empty, trailing garbage, overflow/ERANGE, null args.

#include "rfb_test.h"
#include "farsee/cli_parse.h"

#include <limits.h>
#include <stdint.h>

// ---- u32 ----------------------------------------------------------------

RFB_TEST(cli_parse, parse_u32__42__ok)
{
    uint32_t v = 0;
    RFB_CHECK(farsee_parse_u32("42", &v));
    RFB_CHECK_EQ_UINT(v, 42u);
}

RFB_TEST(cli_parse, parse_u32__zero__ok)
{
    uint32_t v = 99;
    RFB_CHECK(farsee_parse_u32("0", &v));
    RFB_CHECK_EQ_UINT(v, 0u);
}

RFB_TEST(cli_parse, parse_u32__trailing_garbage__fails)
{
    uint32_t v = 7;
    RFB_CHECK(!farsee_parse_u32("42x", &v));
    RFB_CHECK_EQ_UINT(v, 7u); /* untouched */
}

RFB_TEST(cli_parse, parse_u32__empty__fails)
{
    uint32_t v = 7;
    RFB_CHECK(!farsee_parse_u32("", &v));
    RFB_CHECK_EQ_UINT(v, 7u);
}

RFB_TEST(cli_parse, parse_u32__overflow__fails)
{
    uint32_t v = 7;
    /* Larger than UINT32_MAX (and long enough to trip ERANGE on 64-bit). */
    RFB_CHECK(!farsee_parse_u32("99999999999999999999", &v));
    RFB_CHECK_EQ_UINT(v, 7u);
}

RFB_TEST(cli_parse, parse_u32__null_args__fails)
{
    uint32_t v = 0;
    RFB_CHECK(!farsee_parse_u32(NULL, &v));
    RFB_CHECK(!farsee_parse_u32("1", NULL));
}

RFB_TEST(cli_parse, parse_u32__negative__fails)
{
    uint32_t v = 7;
    RFB_CHECK(!farsee_parse_u32("-1", &v));
    RFB_CHECK_EQ_UINT(v, 7u);
}

// ---- i32 ----------------------------------------------------------------

RFB_TEST(cli_parse, parse_i32__42__ok)
{
    int32_t v = 0;
    RFB_CHECK(farsee_parse_i32("42", &v));
    RFB_CHECK_EQ_INT(v, 42);
}

RFB_TEST(cli_parse, parse_i32__negative__ok)
{
    int32_t v = 0;
    RFB_CHECK(farsee_parse_i32("-7", &v));
    RFB_CHECK_EQ_INT(v, -7);
}

RFB_TEST(cli_parse, parse_i32__trailing_garbage__fails)
{
    int32_t v = 7;
    RFB_CHECK(!farsee_parse_i32("42x", &v));
    RFB_CHECK_EQ_INT(v, 7);
}

RFB_TEST(cli_parse, parse_i32__empty__fails)
{
    int32_t v = 7;
    RFB_CHECK(!farsee_parse_i32("", &v));
    RFB_CHECK_EQ_INT(v, 7);
}

RFB_TEST(cli_parse, parse_i32__overflow__fails)
{
    int32_t v = 7;
    RFB_CHECK(!farsee_parse_i32("99999999999999999999", &v));
    RFB_CHECK_EQ_INT(v, 7);
}

// ---- u64 ----------------------------------------------------------------

RFB_TEST(cli_parse, parse_u64__timeout_ms__ok)
{
    uint64_t v = 0;
    RFB_CHECK(farsee_parse_u64("30000", &v));
    RFB_CHECK(v == 30000ull);
}

RFB_TEST(cli_parse, parse_u64__trailing_garbage__fails)
{
    uint64_t v = 7;
    RFB_CHECK(!farsee_parse_u64("30x", &v));
    RFB_CHECK(v == 7ull);
}

RFB_TEST(cli_parse, parse_u64__empty__fails)
{
    uint64_t v = 7;
    RFB_CHECK(!farsee_parse_u64("", &v));
    RFB_CHECK(v == 7ull);
}

RFB_TEST(cli_parse, parse_u64__overflow__fails)
{
    uint64_t v = 7;
    RFB_CHECK(!farsee_parse_u64(
        "18446744073709551616", /* UINT64_MAX + 1 */
        &v));
    RFB_CHECK(v == 7ull);
}
