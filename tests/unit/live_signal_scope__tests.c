// SPDX-License-Identifier: Apache-2.0
//
// Scoped live-session signal ownership and rollback.

#include "rfb_test.h"
#include "app/live_signal_scope.h"

#include <signal.h>
#include <stddef.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static volatile sig_atomic_t scope_signal_seen;
static volatile sig_atomic_t scope_peer_signal_seen;
static volatile sig_atomic_t scope_peer_signal_nested;

static void scope_test_handler(int sig)
{
    scope_signal_seen = sig;
}

static void scope_prior_handler(int sig)
{
    scope_signal_seen = -sig;
}

static void scope_masking_handler(int sig)
{
    if (sig == SIGUSR1) {
        scope_signal_seen = sig;
        (void)kill(getpid(), SIGUSR2);
        if (scope_peer_signal_seen != 0) {
            scope_peer_signal_nested = 1;
        }
    } else if (sig == SIGUSR2) {
        scope_peer_signal_seen = sig;
    }
}

static int terminal_scope_child(void)
{
    static const int signals[] = {SIGINT, SIGTERM, SIGHUP};
    struct sigaction prior;
    memset(&prior, 0, sizeof prior);
    prior.sa_handler = scope_prior_handler;
    sigemptyset(&prior.sa_mask);
    for (size_t i = 0u; i < sizeof signals / sizeof signals[0]; i++) {
        if (sigaction(signals[i], &prior, NULL) != 0) {
            return 2;
        }
    }

    for (unsigned cycle = 0u; cycle < 2u; cycle++) {
        farsee_live_signal_scope scope;
        farsee_live_signal_scope_init(&scope);
        if (!farsee_live_signal_scope_arm_terminal(
                &scope, scope_test_handler)) {
            return 3;
        }
        for (size_t i = 0u; i < sizeof signals / sizeof signals[0]; i++) {
            scope_signal_seen = 0;
            if (raise(signals[i]) != 0 || scope_signal_seen != signals[i]) {
                return 4;
            }
        }
        farsee_live_signal_scope_restore(&scope);
        farsee_live_signal_scope_restore(&scope);
        for (size_t i = 0u; i < sizeof signals / sizeof signals[0]; i++) {
            struct sigaction current;
            memset(&current, 0, sizeof current);
            if (sigaction(signals[i], NULL, &current) != 0 ||
                current.sa_handler != scope_prior_handler) {
                return 5;
            }
        }
    }
    return 0;
}

RFB_TEST(live_signal_scope,
         terminal_scope__handles_hup_restores_prior_and_rearms)
{
    const pid_t child = fork();
    RFB_CHECK(child >= 0);
    if (child == 0) {
        _exit(terminal_scope_child());
    }
    int status = 0;
    RFB_CHECK(waitpid(child, &status, 0) == child);
    RFB_CHECK(WIFEXITED(status));
    RFB_CHECK_EQ_INT(WIFEXITED(status) ? WEXITSTATUS(status) : -1, 0);
}

static int partial_rollback_child(void)
{
    struct sigaction prior;
    memset(&prior, 0, sizeof prior);
    prior.sa_handler = scope_prior_handler;
    sigemptyset(&prior.sa_mask);
    if (sigaction(SIGUSR1, &prior, NULL) != 0) {
        return 2;
    }
    // SIGKILL is a valid set member but cannot have a disposition. This forces
    // the second sigaction to fail after SIGUSR1 was installed.
    const int signals[] = {SIGUSR1, SIGKILL};
    farsee_live_signal_scope scope;
    farsee_live_signal_scope_init(&scope);
    if (farsee_live_signal_scope_arm(
            &scope, signals, 2u, scope_test_handler)) {
        return 3;
    }
    struct sigaction current;
    memset(&current, 0, sizeof current);
    if (sigaction(SIGUSR1, NULL, &current) != 0 ||
        current.sa_handler != scope_prior_handler) {
        return 4;
    }
    scope_signal_seen = 0;
    if (raise(SIGUSR1) != 0 || scope_signal_seen != -SIGUSR1) {
        return 5;
    }
    return 0;
}

RFB_TEST(live_signal_scope, partial_install__rolls_back_installed_handler)
{
    const pid_t child = fork();
    RFB_CHECK(child >= 0);
    if (child == 0) {
        _exit(partial_rollback_child());
    }
    int status = 0;
    RFB_CHECK(waitpid(child, &status, 0) == child);
    RFB_CHECK(WIFEXITED(status));
    RFB_CHECK_EQ_INT(WIFEXITED(status) ? WEXITSTATUS(status) : -1, 0);
}

static int full_handler_mask_child(void)
{
    const int signals[] = {SIGUSR1, SIGUSR2};
    farsee_live_signal_scope scope;
    farsee_live_signal_scope_init(&scope);
    if (!farsee_live_signal_scope_arm(
            &scope, signals, 2u, scope_masking_handler)) {
        return 2;
    }
    scope_signal_seen = 0;
    scope_peer_signal_seen = 0;
    scope_peer_signal_nested = 0;
    if (raise(SIGUSR1) != 0 || scope_signal_seen != SIGUSR1 ||
        scope_peer_signal_seen != SIGUSR2 || scope_peer_signal_nested != 0) {
        return 3;
    }
    farsee_live_signal_scope_restore(&scope);
    return 0;
}

RFB_TEST(live_signal_scope,
         owned_set__peer_signal_does_not_nest_handler)
{
    const pid_t child = fork();
    RFB_CHECK(child >= 0);
    if (child == 0) {
        _exit(full_handler_mask_child());
    }
    int status = 0;
    RFB_CHECK(waitpid(child, &status, 0) == child);
    RFB_CHECK(WIFEXITED(status));
    RFB_CHECK_EQ_INT(WIFEXITED(status) ? WEXITSTATUS(status) : -1, 0);
}

static int caller_mask_child(void)
{
    struct sigaction prior;
    memset(&prior, 0, sizeof prior);
    prior.sa_handler = scope_prior_handler;
    sigemptyset(&prior.sa_mask);
    if (sigaction(SIGUSR1, &prior, NULL) != 0) {
        return 2;
    }

    sigset_t signal_set;
    sigset_t caller_mask;
    sigemptyset(&signal_set);
    if ((sigaddset)(&signal_set, SIGUSR1) != 0 ||
        sigprocmask(SIG_BLOCK, &signal_set, &caller_mask) != 0) {
        return 3;
    }

    farsee_live_signal_scope scope;
    farsee_live_signal_scope_init(&scope);
    if (!farsee_live_signal_scope_arm(
            &scope, (const int[]){SIGUSR1}, 1u, scope_test_handler)) {
        return 4;
    }
    sigset_t observed_mask;
    if (sigprocmask(SIG_BLOCK, NULL, &observed_mask) != 0 ||
        (sigismember)(&observed_mask, SIGUSR1) != 1) {
        return 5;
    }

    scope_signal_seen = 0;
    if (raise(SIGUSR1) != 0 || scope_signal_seen != 0 ||
        sigprocmask(SIG_SETMASK, &caller_mask, NULL) != 0 ||
        scope_signal_seen != SIGUSR1) {
        return 6;
    }

    if (sigprocmask(SIG_BLOCK, &signal_set, &caller_mask) != 0) {
        return 7;
    }
    scope_signal_seen = 0;
    if (raise(SIGUSR1) != 0) {
        return 8;
    }
    farsee_live_signal_scope_restore(&scope);
    if (scope_signal_seen != 0 ||
        sigprocmask(SIG_BLOCK, NULL, &observed_mask) != 0 ||
        (sigismember)(&observed_mask, SIGUSR1) != 1 ||
        sigprocmask(SIG_SETMASK, &caller_mask, NULL) != 0 ||
        scope_signal_seen != -SIGUSR1) {
        return 9;
    }
    return 0;
}

RFB_TEST(live_signal_scope,
         pending_signal__transitions_preserve_caller_mask)
{
    const pid_t child = fork();
    RFB_CHECK(child >= 0);
    if (child == 0) {
        _exit(caller_mask_child());
    }
    int status = 0;
    RFB_CHECK(waitpid(child, &status, 0) == child);
    RFB_CHECK(WIFEXITED(status));
    RFB_CHECK_EQ_INT(WIFEXITED(status) ? WEXITSTATUS(status) : -1, 0);
}

RFB_TEST(live_signal_scope, scope_invalid_inputs__fail_closed)
{
    const int signal_number = SIGTERM;
    const int invalid_signal = -1;
    const int too_many[FARSEE_LIVE_SIGNAL_SCOPE_CAPACITY + 1u] = {
        SIGINT, SIGTERM, SIGHUP, SIGUSR1, SIGUSR2,
    };
    farsee_live_signal_scope scope;
    farsee_live_signal_scope_init(NULL);
    farsee_live_signal_scope_init(&scope);
    RFB_CHECK(!farsee_live_signal_scope_arm(
        NULL, &signal_number, 1u, scope_test_handler));
    RFB_CHECK(!farsee_live_signal_scope_arm(
        &scope, NULL, 1u, scope_test_handler));
    RFB_CHECK(!farsee_live_signal_scope_arm(
        &scope, &signal_number, 0u, scope_test_handler));
    RFB_CHECK(!farsee_live_signal_scope_arm(
        &scope, &signal_number, 1u, SIG_ERR));
    RFB_CHECK(!farsee_live_signal_scope_arm(
        &scope, &invalid_signal, 1u, scope_test_handler));
    RFB_CHECK(!farsee_live_signal_scope_arm(
        &scope, too_many, FARSEE_LIVE_SIGNAL_SCOPE_CAPACITY + 1u,
        scope_test_handler));

    RFB_CHECK(farsee_live_signal_scope_arm(
        &scope, &signal_number, 1u, scope_test_handler));
    RFB_CHECK(!farsee_live_signal_scope_arm(
        &scope, &signal_number, 1u, scope_test_handler));
    farsee_live_signal_scope_restore(&scope);
    farsee_live_signal_scope_restore(&scope);
    farsee_live_signal_scope_restore(NULL);
}
