// SPDX-License-Identifier: Apache-2.0
//
// Host pasteboard access boundary tests.

#ifdef FARSEE_WITH_RDP

#include "protocol/rdp/rdp_host_clipboard.h"
#include "tests/test_framework/rfb_test.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

RFB_TEST(rdp_host_clip, invalid_arguments__fail_closed)
{
    RFB_CHECK(rdp_host_clipboard_get_utf8(NULL, 8) == -1);
    char dummy = 'x';
    RFB_CHECK(rdp_host_clipboard_get_utf8(&dummy, 0) == -1);
    RFB_CHECK(!rdp_host_clipboard_set_utf8(NULL, 5));
}

RFB_TEST(rdp_host_clip, inherited_file_override__cannot_read_or_write_path)
{
    char path[] = "/tmp/farsee-clipboard-boundary-XXXXXX";
    int fd = mkstemp(path);
    RFB_CHECK(fd >= 0);
    static const char sentinel[] = "unchanged";
    RFB_CHECK(write(fd, sentinel, sizeof sentinel) == (ssize_t)sizeof sentinel);

    const char *old_path = getenv("PATH");
    char *saved_path = NULL;
    if (old_path != NULL) {
        const size_t path_length = strlen(old_path);
        saved_path = (char *)malloc(path_length + 1u);
        RFB_CHECK(saved_path != NULL);
        memcpy(saved_path, old_path, path_length + 1u);
    }
    RFB_CHECK_EQ_INT(setenv("FARSEE_CLIP_FAKE", path, 1), 0);
    RFB_CHECK_EQ_INT(setenv("PATH", "/nonexistent", 1), 0);
    char buf[32];
    RFB_CHECK(rdp_host_clipboard_get_utf8(buf, sizeof(buf)) == -1);
    RFB_CHECK(!rdp_host_clipboard_set_utf8("overwrite", 9u));

    RFB_CHECK_EQ_INT(unsetenv("FARSEE_CLIP_FAKE"), 0);
    if (saved_path != NULL) {
        RFB_CHECK_EQ_INT(setenv("PATH", saved_path, 1), 0);
    } else {
        RFB_CHECK_EQ_INT(unsetenv("PATH"), 0);
    }
    free(saved_path);

    RFB_CHECK_EQ_INT(lseek(fd, 0, SEEK_SET), 0);
    char actual[sizeof sentinel];
    RFB_CHECK(read(fd, actual, sizeof actual) == (ssize_t)sizeof actual);
    RFB_CHECK_MEM_EQ(actual, sentinel, sizeof sentinel);
    RFB_CHECK_EQ_INT(close(fd), 0);
    RFB_CHECK_EQ_INT(unlink(path), 0);
}

#endif  // FARSEE_WITH_RDP
