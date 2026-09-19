// SPDX-License-Identifier: Apache-2.0
//
// Wakeup-primitive unit tests.
//
// These tests exercise the POSIX self-pipe primitive directly, without a
// reactor or network. They cover signal/consume, an empty consume, repeated
// signal coalescing, and destroy paths.

#include "farsee/farsee_wakeup.h"
#include "tests/test_framework/rfb_test.h"

RFB_TEST(farsee_wakeup, signal_then_consume__round_trip)
{
    farsee_wakeup *w = farsee_wakeup_create();
    RFB_CHECK(w != NULL);
    // Nothing pending initially.
    RFB_CHECK(farsee_wakeup_consume(w) == false);
    // Signal then consume.
    RFB_CHECK(farsee_wakeup_signal(w));
    RFB_CHECK(farsee_wakeup_consume(w));
    // Consumed; a second consume finds nothing.
    RFB_CHECK(farsee_wakeup_consume(w) == false);
    farsee_wakeup_destroy(&w);
    RFB_CHECK(w == NULL);
}

RFB_TEST(farsee_wakeup, repeated_signals_coalesce)
{
    farsee_wakeup *w = farsee_wakeup_create();
    RFB_CHECK(w != NULL);
    RFB_CHECK(farsee_wakeup_signal(w));
    RFB_CHECK(farsee_wakeup_signal(w));
    RFB_CHECK(farsee_wakeup_signal(w));
    // Coalesced: a single consume clears the wakeup.
    RFB_CHECK(farsee_wakeup_consume(w));
    RFB_CHECK(farsee_wakeup_consume(w) == false);
    farsee_wakeup_destroy(&w);
}

RFB_TEST(farsee_wakeup, destroy_null_is_safe)
{
    farsee_wakeup *w = NULL;
    farsee_wakeup_destroy(&w);
    RFB_CHECK(w == NULL);
}

RFB_TEST(farsee_wakeup, destroy_then_create__fresh_handle_operates)
{
    // Create, signal, and destroy one handle, then exercise a fresh handle.
    farsee_wakeup *a = farsee_wakeup_create();
    RFB_CHECK(farsee_wakeup_signal(a));
    farsee_wakeup_destroy(&a);

    farsee_wakeup *b = farsee_wakeup_create();
    RFB_CHECK(b != NULL);
    RFB_CHECK(farsee_wakeup_consume(b) == false);
    RFB_CHECK(farsee_wakeup_signal(b));
    RFB_CHECK(farsee_wakeup_consume(b));
    farsee_wakeup_destroy(&b);
}
