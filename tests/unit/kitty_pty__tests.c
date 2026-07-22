// SPDX-License-Identifier: Apache-2.0
//
// G7 — integration test: Kitty direct transfer reconstructed by the
// fake terminal (plan.md §G7). RED step.
//
// Uses a pipe (not a PTY) to feed Kitty graphics commands to the Python
// fake terminal, avoiding the line-discipline blocking that a PTY's
// canonical mode introduces. The byte-level contract is identical; PTY-
// specific behavior (raw mode, suspend/resume) is a G11 manual-acceptance
// item (plan.md §G7).

#include "rfb_test.h"
#include "farsee/kitty_protocol.h"
#include "farsee/buffer.h"
#include "farsee/allocator.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/wait.h>

RFB_TEST(kitty_pty, pty__direct_transfer_2x2_rgba__reconstructed_by_fake_terminal) {
    // Known source image: 2x2 RGBA = 16 bytes.
    static const uint8_t src[16] = {
        0xFF,0x00,0x00,0xFF, 0x00,0xFF,0x00,0xFF,
        0x00,0x00,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,
    };
    rfb_buffer out;
    rfb_buffer_init(&out, rfb_default_allocator(), 1u << 20);
    RFB_CHECK_EQ_INT(
        kitty_encode_direct_framebuffer(&out, src, 2, 2,
                                        KITTY_FMT_RGBA32, 1, 1, false, 0, 0),
        RFB_OK);

    // Create a pipe: parent writes Kitty commands to pipe_in[1], child
    // reads from pipe_in[0]. Child writes reconstructed bytes to
    // pipe_out[1], parent reads from pipe_out[0].
    int pipe_in[2], pipe_out[2];
    if (pipe(pipe_in) != 0 || pipe(pipe_out) != 0) {
        RFB_CHECK(false);
        goto cleanup;
    }

    pid_t pid = fork();
    if (pid < 0) {
        RFB_CHECK(false);
        goto cleanup;
    }
    if (pid == 0) {
        // Child: redirect stdin ← pipe_in[0], stdout → pipe_out[1].
        close(pipe_in[1]);
        close(pipe_out[0]);
        dup2(pipe_in[0], 0);   // the fake terminal reads from fd 0
        dup2(pipe_out[1], 1);  // writes to stdout
        close(pipe_in[0]);
        close(pipe_out[1]);
        char exp_str[16];
        snprintf(exp_str, sizeof exp_str, "%d", 16);
        // The fake terminal reads from fd 0 (stdin) when --pty-fd is 0.
        execlp("python3", "python3",
               "tests/integration/fake_kitty_terminal.py",
               "--pty-fd", "0",
               "--expect-bytes", exp_str,
               (char *)NULL);
        _exit(127);
    }

    // Parent: write Kitty commands, close write end to signal EOF.
    close(pipe_in[0]);
    close(pipe_out[1]);
    size_t off = 0;
    while (off < rfb_buffer_length(&out)) {
        ssize_t w = write(pipe_in[1], rfb_buffer_data(&out) + off,
                          rfb_buffer_length(&out) - off);
        if (w <= 0) break;
        off += (size_t)w;
    }
    close(pipe_in[1]);  // EOF

    // Read the reconstructed bytes.
    uint8_t got[64] = { 0 };
    size_t got_len = 0;
    while (got_len < sizeof got) {
        ssize_t r = read(pipe_out[0], got + got_len, sizeof got - got_len);
        if (r <= 0) break;
        got_len += (size_t)r;
    }
    close(pipe_out[0]);

    int status = 0;
    waitpid(pid, &status, 0);

    RFB_CHECK_EQ_UINT(got_len, 16u);
    if (got_len == 16) {
        RFB_CHECK_MEM_EQ(got, src, 16);
    }

cleanup:
    rfb_buffer_destroy(&out);
}

RFB_TEST(kitty_pty, pty__capability_query__is_valid_apc_sequence) {
    rfb_buffer out;
    rfb_buffer_init(&out, rfb_default_allocator(), 4096);
    RFB_CHECK_EQ_INT(kitty_query_capability(&out), RFB_OK);
    const uint8_t *d = rfb_buffer_data(&out);
    size_t len = rfb_buffer_length(&out);
    RFB_CHECK_EQ_UINT(d[0], 0x1B);
    RFB_CHECK_EQ_UINT(d[1], '_');
    RFB_CHECK_EQ_UINT(d[len - 2], 0x1B);
    RFB_CHECK_EQ_UINT(d[len - 1], '\\');
    bool found = false;
    for (size_t i = 2; i + 4 < len; i++) {
        if (d[i] == 'G' && d[i+1] == 'i' && d[i+2] == '=' &&
            d[i+3] == '3' && d[i+4] == '1') {
            found = true;
            break;
        }
    }
    RFB_CHECK(found);
    rfb_buffer_destroy(&out);
}
