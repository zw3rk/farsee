// SPDX-License-Identifier: Apache-2.0
//
// Stack-owned signal disposition scope for live sessions.

#ifndef FARSEE_SRC_APP_LIVE_SIGNAL_SCOPE_H
#define FARSEE_SRC_APP_LIVE_SIGNAL_SCOPE_H

#include <stdbool.h>
#include <signal.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FARSEE_LIVE_SIGNAL_SCOPE_CAPACITY 4u

typedef void (*farsee_live_signal_handler)(int);

typedef struct farsee_live_signal_scope {
    int signals[FARSEE_LIVE_SIGNAL_SCOPE_CAPACITY];
    struct sigaction previous[FARSEE_LIVE_SIGNAL_SCOPE_CAPACITY];
    size_t armed;
} farsee_live_signal_scope;

void farsee_live_signal_scope_init(farsee_live_signal_scope *scope);

// Install one handler for every signal. The complete owned set is blocked in
// the calling thread during the disposition transaction and while the handler
// runs. The calling thread's signal mask is unchanged on return. A partial
// failure restores all dispositions installed by this call before it returns
// false.
bool farsee_live_signal_scope_arm(
    farsee_live_signal_scope *scope, const int *signals, size_t count,
    farsee_live_signal_handler handler);

// Cooperative live-session stop scope: SIGINT, SIGTERM, and SIGHUP.
bool farsee_live_signal_scope_arm_terminal(
    farsee_live_signal_scope *scope, farsee_live_signal_handler handler);

// Restore prior dispositions while the complete owned set is blocked in the
// calling thread, then restore that thread's signal mask. Safe to call more
// than once.
void farsee_live_signal_scope_restore(farsee_live_signal_scope *scope);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_SRC_APP_LIVE_SIGNAL_SCOPE_H
