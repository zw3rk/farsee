// SPDX-License-Identifier: Apache-2.0
//
// Stack-owned signal disposition scope for live sessions.

#include "app/live_signal_scope.h"

#include <string.h>

static int live_signal_scope_add(sigset_t *set, int signal_number)
{
    // Parentheses select the POSIX function when Darwin also defines a macro
    // whose expansion triggers GCC -Wsign-conversion.
    return (sigaddset)(set, signal_number);
}

static bool live_signal_scope_build_set(sigset_t *set, const int *signals,
                                        size_t count)
{
    if (sigemptyset(set) != 0) {
        return false;
    }
    for (size_t i = 0u; i < count; i++) {
        if (live_signal_scope_add(set, signals[i]) != 0) {
            return false;
        }
    }
    return true;
}

static void live_signal_scope_restore_dispositions(
    farsee_live_signal_scope *scope)
{
    while (scope->armed > 0u) {
        const size_t index = scope->armed - 1u;
        (void)sigaction(
            scope->signals[index], &scope->previous[index], NULL);
        scope->signals[index] = 0;
        memset(&scope->previous[index], 0, sizeof scope->previous[index]);
        scope->armed = index;
    }
}

void farsee_live_signal_scope_init(farsee_live_signal_scope *scope)
{
    if (scope != NULL) {
        memset(scope, 0, sizeof *scope);
    }
}

void farsee_live_signal_scope_restore(farsee_live_signal_scope *scope)
{
    if (scope == NULL) {
        return;
    }

    sigset_t owned_set;
    sigset_t caller_mask;
    const bool blocked = scope->armed > 0u &&
                         live_signal_scope_build_set(
                             &owned_set, scope->signals, scope->armed) &&
                         sigprocmask(SIG_BLOCK, &owned_set, &caller_mask) == 0;
    live_signal_scope_restore_dispositions(scope);
    if (blocked) {
        (void)sigprocmask(SIG_SETMASK, &caller_mask, NULL);
    }
}

bool farsee_live_signal_scope_arm(
    farsee_live_signal_scope *scope, const int *signals, size_t count,
    farsee_live_signal_handler handler)
{
    if (scope == NULL || signals == NULL || count == 0u ||
        count > FARSEE_LIVE_SIGNAL_SCOPE_CAPACITY || handler == SIG_ERR ||
        scope->armed != 0u) {
        return false;
    }

    sigset_t owned_set;
    sigset_t caller_mask;
    if (!live_signal_scope_build_set(&owned_set, signals, count) ||
        sigprocmask(SIG_BLOCK, &owned_set, &caller_mask) != 0) {
        return false;
    }

    struct sigaction action;
    memset(&action, 0, sizeof action);
    action.sa_handler = handler;
    action.sa_mask = owned_set;
    bool installed = true;
    for (size_t i = 0u; i < count; i++) {
        scope->signals[i] = signals[i];
        if (sigaction(signals[i], &action, &scope->previous[i]) != 0) {
            live_signal_scope_restore_dispositions(scope);
            scope->signals[i] = 0;
            memset(&scope->previous[i], 0, sizeof scope->previous[i]);
            installed = false;
            break;
        }
        scope->armed = i + 1u;
    }
    if (sigprocmask(SIG_SETMASK, &caller_mask, NULL) != 0) {
        if (installed) {
            live_signal_scope_restore_dispositions(scope);
        }
        (void)sigprocmask(SIG_SETMASK, &caller_mask, NULL);
        return false;
    }
    return installed;
}

bool farsee_live_signal_scope_arm_terminal(
    farsee_live_signal_scope *scope, farsee_live_signal_handler handler)
{
    static const int signals[] = {SIGINT, SIGTERM, SIGHUP};
    return farsee_live_signal_scope_arm(
        scope, signals, sizeof signals / sizeof signals[0], handler);
}
