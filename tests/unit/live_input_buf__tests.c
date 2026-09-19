// SPDX-License-Identifier: Apache-2.0
//
// Pure live-input fill tests (RDP demux must not drop excess chunk bytes).

#include "rfb_test.h"
#include "farsee/live_input_buf.h"

#include <string.h>

RFB_TEST(live_input_buf, fill__chunk_only__fits)
{
    uint8_t work[16];
    size_t wlen = 0, used = 0;
    const uint8_t data[] = "hello";
    RFB_CHECK(farsee_live_input_fill(work, sizeof work, NULL, 0, data,
                                     sizeof data - 1u, 0, &wlen, &used));
    RFB_CHECK_EQ_UINT(wlen, 5u);
    RFB_CHECK_EQ_UINT(used, 5u);
    RFB_CHECK(memcmp(work, "hello", 5) == 0);
}

RFB_TEST(live_input_buf, fill__residual_plus_chunk)
{
    uint8_t work[16];
    size_t wlen = 0, used = 0;
    const uint8_t res[] = "ab";
    const uint8_t data[] = "cdef";
    RFB_CHECK(farsee_live_input_fill(work, sizeof work, res, 2, data, 4, 0,
                                     &wlen, &used));
    RFB_CHECK_EQ_UINT(wlen, 6u);
    RFB_CHECK_EQ_UINT(used, 4u);
    RFB_CHECK(memcmp(work, "abcdef", 6) == 0);
}

// Negative (bug class): a single fill of a large chunk into a small work
// buffer must report partial use so the caller can loop — never claim the
// whole chunk was accepted when it was not.
RFB_TEST(live_input_buf, fill__oversize_chunk__partial_use_not_silent_drop)
{
    uint8_t work[8];
    size_t wlen = 0, used = 0;
    uint8_t data[32];
    memset(data, 'x', sizeof data);
    RFB_CHECK(farsee_live_input_fill(work, sizeof work, NULL, 0, data,
                                     sizeof data, 0, &wlen, &used));
    RFB_CHECK_EQ_UINT(wlen, 8u);
    RFB_CHECK_EQ_UINT(used, 8u); // only first 8 of 32 — caller must continue
    // Second fill from offset 8 consumes the next 8.
    size_t wlen2 = 0, used2 = 0;
    RFB_CHECK(farsee_live_input_fill(work, sizeof work, NULL, 0, data,
                                     sizeof data, 8, &wlen2, &used2));
    RFB_CHECK_EQ_UINT(used2, 8u);
    // Third fill still has data left.
    size_t wlen3 = 0, used3 = 0;
    RFB_CHECK(farsee_live_input_fill(work, sizeof work, NULL, 0, data,
                                     sizeof data, 16, &wlen3, &used3));
    RFB_CHECK_EQ_UINT(used3, 8u);
    size_t total = used + used2 + used3;
    RFB_CHECK(total < sizeof data); // one more iteration remains
    size_t wlen4 = 0, used4 = 0;
    RFB_CHECK(farsee_live_input_fill(work, sizeof work, NULL, 0, data,
                                     sizeof data, total, &wlen4, &used4));
    RFB_CHECK_EQ_UINT(used + used2 + used3 + used4, sizeof data);
}

RFB_TEST(live_input_buf, fill__null_work__fails)
{
    size_t wlen = 1, used = 1;
    uint8_t data[1] = {0};
    RFB_CHECK(!farsee_live_input_fill(NULL, 8, NULL, 0, data, 1, 0, &wlen,
                                      &used));
}

RFB_TEST(live_input_buf, fill__zero_cap__fails)
{
    uint8_t work[1];
    size_t wlen = 1, used = 1;
    RFB_CHECK(!farsee_live_input_fill(work, 0, NULL, 0, NULL, 0, 0, &wlen,
                                      &used));
}
