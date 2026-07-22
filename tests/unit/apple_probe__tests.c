// SPDX-License-Identifier: Apache-2.0
//
// G14 — Apple probe redaction tests. Verifies the redaction verifier
// correctly rejects unredacted canary secrets.

#include "rfb_test.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>

static int run_verify_redaction(const char *content)
{
    // Write content to a temp file, run the verifier, return exit code.
    char path[] = "/tmp/farsee_redact_XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) return -1;
    write(fd, content, strlen(content));
    close(fd);

    pid_t pid = fork();
    if (pid == 0) {
        // Redirect stdout to /dev/null; stderr to a pipe for capture.
        int devnull = open("/dev/null", O_WRONLY);
        dup2(devnull, 1);
        close(devnull);
        execlp("python3", "python3",
               "tools/apple/apple_probe.py",
               "--verify-redaction", path,
               (char *)NULL);
        _exit(127);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    unlink(path);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

#include "rfb_test.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/wait.h>

RFB_TEST(g14_redact, redaction__clean_file__passes) {
    // A file with no canary secrets should pass.
    RFB_CHECK_EQ_INT(
        run_verify_redaction("{\"state\":\"BANNER\",\"bytes\":\"524642203030332e3838390a\"}"),
        0);
}

RFB_TEST(g14_redact, redaction__canary_password_detected) {
    // A file containing the password canary should fail.
    RFB_CHECK_EQ_INT(
        run_verify_redaction("{\"password\":\"__CANARY_PASSWORD__\"}"),
        1);
}

RFB_TEST(g14_redact, redaction__canary_key_detected) {
    // A file containing a key canary should fail.
    RFB_CHECK_EQ_INT(
        run_verify_redaction("{\"key\":\"__CANARY_KEY_0__\"}"),
        1);
}
