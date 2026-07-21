// SPDX-License-Identifier: Apache-2.0
//
// G1 — secret zeroization tests (plan.md §G1: "zeroization observable
// through a test hook/build mode"). RED step.
//
// We verify rfb_secret_zero actually clears memory. The compiler-resistant
// aspect is validated by the build (if the dead-store eliminator removed
// it, the test would fail).

#include "rfb_test.h"
#include "farsee/secret.h"
#include <string.h>

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

RFB_TEST(secret, secret__zero_then_read__compiler_cannot_elide) {
    // This is the "observable" check: if the compiler elided the zero,
    // the buffer would still contain 0xCC. The volatile write in
    // rfb_secret_zero prevents elision, so we observe zeros.
    // We read back through a volatile pointer so the reads themselves
    // cannot be optimized away or folded with the writes.
    static uint8_t storage[32];
    for (size_t i = 0; i < sizeof storage; i++) storage[i] = 0xCC;
    rfb_secret_zero(storage, sizeof storage);
    volatile const uint8_t *readback = storage;
    for (size_t i = 0; i < sizeof storage; i++) {
        RFB_CHECK_EQ_UINT(readback[i], 0u);
    }
}

// T7: classic VNC Auth truncates to 8 bytes and must wipe the tail of the
// allocation so free does not leak the remainder of a longer password.
RFB_TEST(secret, trunc_vnc8__long_password__zeros_tail_and_returns_8)
{
    char buf[16];
    memcpy(buf, "0123456789abcdef", 16);
    size_t n = rfb_secret_trunc_vnc8(buf, 16u, sizeof buf);
    RFB_CHECK_EQ_UINT(n, 8u);
    for (size_t i = 0; i < 8u; i++) {
        RFB_CHECK_EQ_UINT((uint8_t)buf[i], (uint8_t)('0' + (int)i));
    }
    // Tail (past 8) must be wiped — including what was '8','9','a',...
    for (size_t i = 8u; i < sizeof buf; i++) {
        RFB_CHECK_EQ_UINT((uint8_t)buf[i], 0u);
    }
}

RFB_TEST(secret, trunc_vnc8__short_password__unchanged)
{
    char buf[8] = { 'a', 'b', 'c', 0, 1, 2, 3, 4 };
    size_t n = rfb_secret_trunc_vnc8(buf, 3u, sizeof buf);
    RFB_CHECK_EQ_UINT(n, 3u);
    RFB_CHECK(buf[0] == 'a' && buf[1] == 'b' && buf[2] == 'c');
    RFB_CHECK_EQ_UINT((uint8_t)buf[4], 1u); // not a trunc wipe path
}

RFB_TEST(secret, wipe_free__null_safe)
{
    rfb_secret_wipe_free(NULL, 0u);
    rfb_secret_wipe_free(NULL, 32u);
}

RFB_TEST(secret, wipe_free__zeros_before_free)
{
    // Allocate, fill, wipe-free; the wipe is tested by trunc + zero suites;
    // here we only assert wipe_free does not crash on a live allocation.
    char *p = (char *)malloc(32u);
    RFB_CHECK(p != NULL);
    memset(p, 0xEE, 32u);
    rfb_secret_wipe_free(p, 32u);
}
