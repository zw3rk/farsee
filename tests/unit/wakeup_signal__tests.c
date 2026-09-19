// SPDX-License-Identifier: Apache-2.0
//
// Wakeup signal error handling contracts. A non-EINTR, non-EAGAIN write error
// reports failure and cannot claim that a wakeup was armed.
//
// The EPIPE child exercises that contract deterministically: fds are
// allocated lowest-available, so a probe reveals the wakeup's read end,
// which the child closes behind the primitive's back. The itimer child
// additionally drives interrupted writes (1us repeating SIGALRM, handler
// without SA_RESTART) to pin the retry-on-EINTR behaviour on platforms
// where nonblocking writes do surface it. The full-pipe case pins the
// EAGAIN coalescing contract.

#include "farsee/farsee_wakeup.h"
#include "tests/test_framework/rfb_test.h"

#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <unistd.h>

// Returns the child exit code: 0 = expected behaviour,
// 1 = signal reported armed on a failed write,
// 2 = harness setup failure.
static int wakeup_epipe_child(void)
{
    // SIGPIPE must not kill the child: the write under test fails with
    // EPIPE, and the point is the RETURN VALUE, not the signal.
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        return 2;
    }
    // Discover the fd the wakeup's pipe read end will receive (fds are
    // allocated lowest-available; nothing else opens fds in between).
    int probe = open("/dev/null", O_RDONLY);
    if (probe < 0) {
        return 2;
    }
    (void)close(probe);

    farsee_wakeup *w = farsee_wakeup_create();
    if (w == NULL) {
        return 2;
    }
    // Close the read end behind the primitive's back: the next signal
    // write fails with EPIPE. It must report FAILURE, not success.
    (void)close(probe);
    bool armed = farsee_wakeup_signal(w);
    farsee_wakeup_destroy(&w);
    return armed ? 1 : 0;
}

RFB_TEST(wakeup_signal, wakeup_signal__failed_write__reports_failure)
{
    pid_t pid = fork();
    RFB_CHECK(pid >= 0);
    if (pid == 0) {
        _exit(wakeup_epipe_child());
    }
    int status = 0;
    RFB_CHECK(waitpid(pid, &status, 0) == pid);
    RFB_CHECK_MSG(WIFEXITED(status), "wakeup EPIPE child died abnormally");
    int code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    char msg[64];
    (void)snprintf(msg, sizeof msg,
                   "wakeup EPIPE child exit code %d", code);
    RFB_CHECK_MSG(code == 0, msg);  // failed writes must report false
}

// --- retry on EINTR (interrupted writes) -------------------------------------

static volatile sig_atomic_t g_alarm_runs = 0;

static void on_sigalrm(int sig)
{
    (void)sig;
    g_alarm_runs = 0x5a;
}

// Returns the child exit code: 0 = every signal() report verified,
// 1 = a wakeup was reported armed but no byte landed,
// 2 = harness setup failure, 3 = no signal ever delivered (vacuous).
static int wakeup_eintr_child(void)
{
    struct sigaction sa;
    sa.sa_handler = on_sigalrm;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;  // no SA_RESTART: interrupted writes return EINTR
    if (sigaction(SIGALRM, &sa, NULL) != 0) {
        return 2;
    }
    struct itimerval it;
    it.it_interval.tv_sec = 0;
    it.it_interval.tv_usec = 1;  // fire as fast as the kernel allows
    it.it_value = it.it_interval;
    if (setitimer(ITIMER_REAL, &it, NULL) != 0) {
        return 2;
    }

    farsee_wakeup *w = farsee_wakeup_create();
    if (w == NULL) {
        return 2;
    }
    for (int i = 0; i < 20000; ++i) {
        (void)farsee_wakeup_consume(w);  // drain: EAGAIN cannot occur
        if (!farsee_wakeup_signal(w)) {
            farsee_wakeup_destroy(&w);
            return 1;  // interrupted write must retry, not give up
        }
        if (!farsee_wakeup_consume(w)) {
            farsee_wakeup_destroy(&w);
            return 1;  // reported armed, but no byte landed
        }
    }
    farsee_wakeup_destroy(&w);
    return g_alarm_runs == 0x5a ? 0 : 3;
}

RFB_TEST(wakeup_signal, wakeup_signal__eintr_interrupted_write__still_lands_byte)
{
    pid_t pid = fork();
    RFB_CHECK(pid >= 0);
    if (pid == 0) {
        _exit(wakeup_eintr_child());
    }
    int status = 0;
    RFB_CHECK(waitpid(pid, &status, 0) == pid);
    RFB_CHECK_MSG(WIFEXITED(status), "wakeup EINTR child died abnormally");
    int code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    char msg[64];
    (void)snprintf(msg, sizeof msg,
                   "wakeup EINTR child failed (exit code %d)", code);
    RFB_CHECK_MSG(code == 0, msg);
}

// --- full pipe: EAGAIN means already pending ----------------------------------

RFB_TEST(wakeup_signal, wakeup_signal__full_pipe__coalesced_as_pending)
{
    // Fill the pipe past any platform buffer (Linux 64KiB default):
    // further signals must report success (a wakeup is already pending)
    // and a consume must still observe bytes.
    farsee_wakeup *w = farsee_wakeup_create();
    RFB_CHECK(w != NULL);
    for (int i = 0; i < 70000; ++i) {
        RFB_CHECK(farsee_wakeup_signal(w));
    }
    RFB_CHECK(farsee_wakeup_consume(w));
    farsee_wakeup_destroy(&w);
}
