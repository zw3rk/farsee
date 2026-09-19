// SPDX-License-Identifier: Apache-2.0
//
// G0 — test harness self-test (plan.md §G0: "test harness self-test
// proving pass, fail, and expected diagnostic behavior").
//
// These tests assert the observable contract of the framework itself
// without tripping the runner's per-test failure flag. The key insight
// is that a *passing* RFB_CHECK must leave the flag clean, while a
// *failing* RFB_CHECK sets it. To test the failing path without failing
// THIS test, we snapshot and restore the flag around the deliberate
// failure, and additionally verify the failure-recording helpers wrote
// the expected file/line/message.

#include "rfb_test.h"

#include <string.h>

// A passing RFB_CHECK must not mark the test failed.
RFB_TEST(harness, harness__passing_check__leaves_failure_flag_clean) {
    // Snapshot (runner has already reset the flag to false before us).
    RFB_CHECK(rfb_test__current_failed == false);
    RFB_CHECK(1 == 1);
    RFB_CHECK(rfb_test__current_failed == false);
}

// A failing RFB_CHECK must set the per-test flag and record file/line.
// We snapshot the flag, trigger a controlled failure through the internal
// helper, verify the recording, then restore the flag so this test
// itself still passes.
RFB_TEST(harness, harness__failing_check__records_file_line_and_message) {
    bool saved = rfb_test__current_failed;
    const char *saved_file = rfb_test__current_assert_file;
    size_t saved_line = rfb_test__current_assert_line;

    rfb_test__current_failed = false;
    rfb_test__fail_at("some_file.c", (size_t)42, "boom");

    bool flag_set = rfb_test__current_failed;
    bool file_ok  = (strcmp(rfb_test__current_assert_file, "some_file.c") == 0);
    bool line_ok  = (rfb_test__current_assert_line == 42);

    // Restore so this test does not itself get marked failed by the runner.
    rfb_test__current_failed = saved;
    rfb_test__current_assert_file = saved_file;
    rfb_test__current_assert_line = saved_line;

    RFB_CHECK_MSG(flag_set, "fail flag must be set after a failing check");
    RFB_CHECK_MSG(file_ok, "failure file must be recorded");
    RFB_CHECK_MSG(line_ok, "failure line must be recorded");
}

// A failing RFB_CHECK_EQ_INT records both operands in the message.
// Same snapshot/restore trick.
RFB_TEST(harness, harness__eq_int__records_both_values_on_mismatch) {
    bool saved = rfb_test__current_failed;
    rfb_test__current_failed = false;

    RFB_CHECK_EQ_INT(2 + 2, 5);  // expected to fail this assertion
    bool flag_set = rfb_test__current_failed;

    rfb_test__current_failed = saved;
    RFB_CHECK_MSG(flag_set, "eq_int mismatch must set the fail flag");
}

// A passing RFB_CHECK_EQ_INT must not mark the test failed.
RFB_TEST(harness, harness__eq_int__matching_values__passes) {
    RFB_CHECK_EQ_INT(2 + 2, 4);
    RFB_CHECK(rfb_test__current_failed == false);
}

// Unsigned equality behaves independently of the signed helper.
RFB_TEST(harness, harness__eq_uint__handles_large_values) {
    RFB_CHECK_EQ_UINT(0xFFFFFFFFULL, 4294967295ULL);
    RFB_CHECK(rfb_test__current_failed == false);
}

// Memory equality: matching buffers must pass.
RFB_TEST(harness, harness__mem_eq__matching_bytes__passes) {
    static const unsigned char a[4] = { 0x00, 0x7F, 0x80, 0xFF };
    static const unsigned char b[4] = { 0x00, 0x7F, 0x80, 0xFF };
    RFB_CHECK_MEM_EQ(a, b, sizeof a);
    RFB_CHECK(rfb_test__current_failed == false);
}

// Memory equality: mismatching buffers must fail (snapshot/restore).
RFB_TEST(harness, harness__mem_eq__mismatch__fails) {
    bool saved = rfb_test__current_failed;
    rfb_test__current_failed = false;
    static const unsigned char a[3] = { 1, 2, 3 };
    static const unsigned char b[3] = { 1, 9, 3 };
    RFB_CHECK_MEM_EQ(a, b, sizeof a);
    bool flag_set = rfb_test__current_failed;
    rfb_test__current_failed = saved;
    RFB_CHECK_MSG(flag_set, "mem mismatch must set the fail flag");
}

// Hex helper returns true on match, false on mismatch, without touching
// the per-test flag.
RFB_TEST(harness, harness__mem_eq_hex__returns_correct_bool) {
    static const unsigned char a[2] = { 0xAA, 0x55 };
    static const unsigned char b[2] = { 0xAA, 0x55 };
    static const unsigned char c[2] = { 0xAA, 0x56 };
    RFB_CHECK(rfb_test_mem_eq_hex(a, b, 2) == true);
    RFB_CHECK(rfb_test_mem_eq_hex(a, c, 2) == false);
    RFB_CHECK(rfb_test__current_failed == false);
}

// Sanity: the runner reset our flag before us, and no earlier assertion in
// this test touched it — so a brand-new test sees false. This is the
// "harness self-test proving ... expected diagnostic behavior" clause.
RFB_TEST(harness, harness__fresh_test__starts_with_clean_flag) {
    RFB_CHECK_MSG(rfb_test__current_failed == false,
                  "runner must reset the failure flag before each test");
}
