// SPDX-License-Identifier: Apache-2.0
//
// Wakeup signal error handling contracts. A non-EINTR, non-EAGAIN write error
// reports failure and cannot claim that a wakeup was armed.
//
// The EPIPE child exercises that contract deterministically: fds are
// allocated lowest-available, so a probe reveals the wakeup's read end,
// which the child closes behind the primitive's back. A private writer seam
// deterministically pins retry-on-EINTR behaviour. The full-pipe case pins
// the EAGAIN coalescing contract.

#include "farsee/farsee_wakeup.h"
#include "farsee/farsee_wakeup_internal.h"
#include "tests/test_framework/rfb_test.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/wait.h>
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

typedef struct wakeup_write_script {
    int calls;
    int error_after_eintr;
} wakeup_write_script;

static ssize_t wakeup_eintr_writer(void *context, int fd,
                                   const void *buffer, size_t length)
{
    wakeup_write_script *script = (wakeup_write_script *)context;
    ++script->calls;
    if (script->calls == 1) {
        errno = EINTR;
        return -1;
    }
    if (script->error_after_eintr != 0) {
        errno = script->error_after_eintr;
        return -1;
    }
    return write(fd, buffer, length);
}

RFB_TEST(wakeup_signal, wakeup_signal__eintr_then_write__retries_and_lands_byte)
{
    farsee_wakeup *w = farsee_wakeup_create();
    RFB_CHECK(w != NULL);
    wakeup_write_script script = {0};

    RFB_CHECK(farsee_wakeup_signal_with_writer(
        w, wakeup_eintr_writer, &script));
    RFB_CHECK_EQ_INT(script.calls, 2);
    RFB_CHECK(farsee_wakeup_consume(w));
    farsee_wakeup_destroy(&w);
}

RFB_TEST(wakeup_signal, wakeup_signal__eintr_then_eio__reports_failure)
{
    farsee_wakeup *w = farsee_wakeup_create();
    RFB_CHECK(w != NULL);
    wakeup_write_script script = {
        .calls = 0,
        .error_after_eintr = EIO,
    };

    RFB_CHECK(!farsee_wakeup_signal_with_writer(
        w, wakeup_eintr_writer, &script));
    RFB_CHECK_EQ_INT(script.calls, 2);
    RFB_CHECK(!farsee_wakeup_consume(w));
    farsee_wakeup_destroy(&w);
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
