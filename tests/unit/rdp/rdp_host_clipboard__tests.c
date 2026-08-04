// SPDX-License-Identifier: Apache-2.0
//
// R6 — host pasteboard access tests (FARSEE_CLIP_FAKE file roundtrip).

#ifdef FARSEE_WITH_RDP

#include "protocol/rdp/rdp_host_clipboard.h"
#include "tests/test_framework/rfb_test.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Build a unique temp path under /tmp for the FAKE pasteboard file.
static void make_fake_path(char *out, size_t cap)
{
    // mkstemp needs the template in a writable buffer; we create then close
    // so the path is reserved and the file exists for later get/set.
    char tmpl[] = "/tmp/farsee-clip-fake-XXXXXX";
    int fd = mkstemp(tmpl);
    RFB_CHECK(fd >= 0);
    if (fd >= 0) {
        close(fd);
    }
    // snprintf into out (tmpl is the final path after mkstemp).
    (void)snprintf(out, cap, "%s", tmpl);
}

RFB_TEST(rdp_host_clip, fake__roundtrip_utf8)
{
    char path[128];
    make_fake_path(path, sizeof(path));
    RFB_CHECK(setenv("FARSEE_CLIP_FAKE", path, 1) == 0);

    const char *payload = "hello clipboard\nworld";
    size_t len = strlen(payload);
    RFB_CHECK(rdp_host_clipboard_set_utf8(payload, len));

    char buf[128];
    long n = rdp_host_clipboard_get_utf8(buf, sizeof(buf));
    RFB_CHECK(n == (long)len);
    RFB_CHECK(strcmp(buf, payload) == 0);

    // Empty write.
    RFB_CHECK(rdp_host_clipboard_set_utf8("", 0));
    n = rdp_host_clipboard_get_utf8(buf, sizeof(buf));
    RFB_CHECK(n == 0);
    RFB_CHECK(buf[0] == '\0');

    unsetenv("FARSEE_CLIP_FAKE");
    (void)unlink(path);
}

RFB_TEST(rdp_host_clip, fake__null_and_cap_safe)
{
    char path[128];
    make_fake_path(path, sizeof(path));
    RFB_CHECK(setenv("FARSEE_CLIP_FAKE", path, 1) == 0);

    RFB_CHECK(rdp_host_clipboard_get_utf8(NULL, 8) == -1);
    {
        char dummy = 'x';
        RFB_CHECK(rdp_host_clipboard_get_utf8(&dummy, 0) == -1);
    }
    RFB_CHECK(rdp_host_clipboard_set_utf8(NULL, 5) == false);

    // Truncation: small cap still NUL-terminates.
    RFB_CHECK(rdp_host_clipboard_set_utf8("abcdef", 6));
    char tiny[4];
    long n = rdp_host_clipboard_get_utf8(tiny, sizeof(tiny));
    RFB_CHECK(n == 3);
    RFB_CHECK(strcmp(tiny, "abc") == 0);

    unsetenv("FARSEE_CLIP_FAKE");
    (void)unlink(path);
}

RFB_TEST(rdp_host_clip, fake__missing_file_returns_minus_one)
{
    RFB_CHECK(setenv("FARSEE_CLIP_FAKE",
                     "/tmp/farsee-clip-fake-does-not-exist-xyz", 1) == 0);
    char buf[32];
    RFB_CHECK(rdp_host_clipboard_get_utf8(buf, sizeof(buf)) == -1);
    unsetenv("FARSEE_CLIP_FAKE");
}

#endif  // FARSEE_WITH_RDP
