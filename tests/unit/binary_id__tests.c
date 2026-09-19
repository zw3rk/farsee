// SPDX-License-Identifier: Apache-2.0
//
// Running-binary identity contracts.

#include "rfb_test.h"
#include "farsee/binary_id.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

typedef struct stderr_capture {
    int saved_fd;
    int read_fd;
} stderr_capture;

static bool stderr_capture_begin(stderr_capture *capture)
{
    int descriptors[2] = {-1, -1};
    if (capture == NULL || pipe(descriptors) != 0) {
        return false;
    }
    capture->saved_fd = -1;
    capture->read_fd = -1;
    (void)fflush(stderr);
    capture->saved_fd = dup(STDERR_FILENO);
    if (capture->saved_fd < 0 ||
        dup2(descriptors[1], STDERR_FILENO) < 0) {
        if (capture->saved_fd >= 0) {
            (void)close(capture->saved_fd);
        }
        (void)close(descriptors[0]);
        (void)close(descriptors[1]);
        return false;
    }
    capture->read_fd = descriptors[0];
    (void)close(descriptors[1]);
    return true;
}

static bool stderr_capture_end(stderr_capture *capture,
                               char *output, size_t output_capacity)
{
    if (capture == NULL || output == NULL || output_capacity == 0u) {
        return false;
    }
    (void)fflush(stderr);
    const bool restored = dup2(capture->saved_fd, STDERR_FILENO) >= 0;
    (void)close(capture->saved_fd);

    size_t used = 0u;
    while (used + 1u < output_capacity) {
        const ssize_t got = read(capture->read_fd, output + used,
                                 output_capacity - used - 1u);
        if (got <= 0) {
            break;
        }
        used += (size_t)got;
    }
    (void)close(capture->read_fd);
    output[used] = '\0';
    return restored;
}

RFB_TEST(binary_id, init__records_running_executable_identity)
{
    stderr_capture capture;
    char diagnostic[1024];

    RFB_CHECK(stderr_capture_begin(&capture));
    farsee_binary_id_init(NULL);
    RFB_CHECK(stderr_capture_end(&capture, diagnostic, sizeof diagnostic));

    RFB_CHECK(farsee_binary_id_path()[0] != '\0');
    RFB_CHECK(farsee_binary_id_inode() != 0u);
    RFB_CHECK(farsee_binary_id_git()[0] != '\0');
    RFB_CHECK(farsee_binary_id_build_time()[0] != '\0');
    RFB_CHECK(strstr(diagnostic, "farsee: binary ") != NULL);
    RFB_CHECK(strstr(diagnostic, "farsee:   path=") != NULL);
    RFB_CHECK(strstr(diagnostic, "inode=") != NULL);
}

RFB_TEST(binary_id, unchanged_executable__is_not_stale)
{
    stderr_capture capture;
    char diagnostic[1024];

    RFB_CHECK(stderr_capture_begin(&capture));
    farsee_binary_id_init(NULL);
    RFB_CHECK(!farsee_binary_id_warn_if_stale());
    RFB_CHECK(!farsee_binary_id_warn_if_stale());
    RFB_CHECK(stderr_capture_end(&capture, diagnostic, sizeof diagnostic));

    RFB_CHECK(strstr(diagnostic, "WARNING") == NULL);
}
