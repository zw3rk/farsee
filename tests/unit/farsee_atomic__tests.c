// SPDX-License-Identifier: Apache-2.0
//
// P0-N3 — C11 atomic stop / force_repaint helpers.

#include "farsee/farsee_atomic.h"
#include "tests/test_framework/rfb_test.h"

#include <stdatomic.h>

// Positive: store 1, load sees 1.
RFB_TEST(farsee_atomic, stop_store_load__zero_to_one)
{
    farsee_atomic_int flag = 0;
    RFB_CHECK_EQ_INT(farsee_atomic_int_load(&flag), 0);
    farsee_atomic_int_store(&flag, 1);
    RFB_CHECK_EQ_INT(farsee_atomic_int_load(&flag), 1);
    RFB_CHECK(farsee_atomic_int_load_nonzero(&flag));
}

// Positive: stop convenience helpers.
RFB_TEST(farsee_atomic, stop_flag_set_clear__roundtrip)
{
    farsee_stop_flag stop = 0;
    RFB_CHECK(!farsee_stop_flag_is_set(&stop));
    farsee_stop_flag_set(&stop);
    RFB_CHECK(farsee_stop_flag_is_set(&stop));
    farsee_stop_flag_clear(&stop);
    RFB_CHECK(!farsee_stop_flag_is_set(&stop));
}

// Positive: exchange clears force_repaint and returns prior value.
RFB_TEST(farsee_atomic, force_repaint_exchange__clears_and_returns_prior)
{
    farsee_atomic_int force_repaint = 0;
    farsee_atomic_int_store(&force_repaint, 1);
    const int prev = farsee_atomic_int_exchange(&force_repaint, 0);
    RFB_CHECK_EQ_INT(prev, 1);
    RFB_CHECK_EQ_INT(farsee_atomic_int_load(&force_repaint), 0);
    // Second exchange is a no-op clear.
    RFB_CHECK_EQ_INT(farsee_atomic_int_exchange(&force_repaint, 0), 0);
}

// Positive: u64 generation counter store/load.
RFB_TEST(farsee_atomic, u64_store_load__roundtrip)
{
    farsee_atomic_u64 gen = 0;
    farsee_atomic_u64_store(&gen, 42u);
    RFB_CHECK(farsee_atomic_u64_load(&gen) == 42u);
    RFB_CHECK(farsee_atomic_u64_fetch_add(&gen, 8u) == 42u);
    RFB_CHECK(farsee_atomic_u64_load(&gen) == 50u);
}

// Negative: NULL helpers are no-ops / return zero (fail closed).
RFB_TEST(farsee_atomic, null_helpers__no_crash)
{
    RFB_CHECK_EQ_INT(farsee_atomic_int_load(NULL), 0);
    farsee_atomic_int_store(NULL, 1);
    RFB_CHECK_EQ_INT(farsee_atomic_int_exchange(NULL, 1), 0);
    RFB_CHECK(!farsee_atomic_int_load_nonzero(NULL));
    RFB_CHECK(farsee_atomic_u64_load(NULL) == 0u);
    farsee_atomic_u64_store(NULL, 9u);
    farsee_stop_flag_set(NULL);
    RFB_CHECK(!farsee_stop_flag_is_set(NULL));
    farsee_stop_flag_clear(NULL);
}

// Characterization: atomic_int is lock-free on this platform (signal path).
RFB_TEST(farsee_atomic, atomic_int__is_lock_free)
{
    farsee_atomic_int flag = 0;
    RFB_CHECK(atomic_is_lock_free(&flag));
}
