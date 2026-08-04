// SPDX-License-Identifier: Apache-2.0
//
// F2 — wakeup primitive tests.
// (FARSEE_ARCHITECTURE_IMPROVEMENT_PLAN.md §8.2, §8.3 — F2 gate.)
//
// The wakeup is a self-pipe (POSIX) that lets another thread interrupt a
// reactor blocked in tick(). These tests exercise it against the real
// POSIX reactor in isolation (no network), verifying:
//   - signal/consume round-trip;
//   - consume with nothing pending returns false;
//   - repeated signals coalesce (one consume clears the wakeup);
//   - destroy is safe from any state.

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

RFB_TEST(farsee_wakeup, signal_after_destroy_path_is_safe_via_new_handle)
{
    // Create, signal, destroy, then a fresh handle works independently —
    // verifies the primitive's resources are not shared globally.
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
