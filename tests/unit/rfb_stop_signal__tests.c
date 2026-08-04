// SPDX-License-Identifier: Apache-2.0
//
// P0-N4 — async-signal-safe RFB stop path (updated for P0-N3 atomics).
//
// Contract: the signal handler body is only farsee_rfb_request_stop() →
// farsee_rfb_stop_flag_set(&g_rfb_stop). That helper stores 1 into a
// farsee_atomic_int (lock-free) and does nothing else (no tcsetattr, write,
// isatty, fprintf). TTY restore remains on atexit + post-loop cleanup.

#include "rfb_test.h"
#include "app/rfb_live.h"
#include "farsee/farsee_atomic.h"

// Positive: 0 → 1.
RFB_TEST(rfb_stop_signal, stop_flag_set__zero__stores_one)
{
    farsee_atomic_int flag = 0;
    farsee_rfb_stop_flag_set(&flag);
    RFB_CHECK_EQ_INT(farsee_atomic_int_load(&flag), 1);
}

// Idempotent: already 1 stays 1.
RFB_TEST(rfb_stop_signal, stop_flag_set__already_one__stays_one)
{
    farsee_atomic_int flag = 0;
    farsee_atomic_int_store(&flag, 1);
    farsee_rfb_stop_flag_set(&flag);
    RFB_CHECK_EQ_INT(farsee_atomic_int_load(&flag), 1);
}

// Negative: NULL is a no-op (no crash).
RFB_TEST(rfb_stop_signal, stop_flag_set__null__no_crash)
{
    farsee_rfb_stop_flag_set(NULL);
}

// Characterization: only the pointed-to flag is written.
RFB_TEST(rfb_stop_signal, stop_flag_set__isolated__neighbours_untouched)
{
    farsee_atomic_int before = 0;
    farsee_atomic_int flag = 0;
    farsee_atomic_int after = 0;
    farsee_rfb_stop_flag_set(&flag);
    RFB_CHECK_EQ_INT(farsee_atomic_int_load(&before), 0);
    RFB_CHECK_EQ_INT(farsee_atomic_int_load(&flag), 1);
    RFB_CHECK_EQ_INT(farsee_atomic_int_load(&after), 0);
}

// Handler-equivalent: request_stop is the public set-flag-only API used by
// rfb_on_signal. It must set the session stop flag (observable via the
// pure helper shape: request_stop is implemented as stop_flag_set on the
// process flag). We exercise request_stop for linkage + idempotence; the
// pure-helper tests above pin the "only store 1" contract.
RFB_TEST(rfb_stop_signal, request_stop__callable_and_idempotent)
{
    // request_stop must be linkable and safe to call outside a session
    // (sets the process stop flag; session entry resets it before arming
    // handlers). Calling twice must not crash.
    farsee_rfb_request_stop();
    farsee_rfb_request_stop();
}
