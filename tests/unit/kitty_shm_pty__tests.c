// SPDX-License-Identifier: Apache-2.0
//
// G10 — SHM integration test: Kitty t=s command reconstructed by the
// fake terminal (plan.md §G10). RED step.
//
// Uses a pipe to feed Kitty t=s commands to the Python fake terminal,
// which opens the shm object by name, reads the pixel bytes, and
// outputs them for verification.

#include "rfb_test.h"
#include "farsee/kitty_shm.h"
#include "farsee/kitty_shm_table.h"
#include "farsee/buffer.h"
#include "farsee/allocator.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

RFB_TEST(shm_pty, pty__shm_transfer_2x2_rgba__reconstructed_by_fake_terminal) {
    static const uint8_t src[16] = {
        0xFF,0x00,0x00,0xFF, 0x00,0xFF,0x00,0xFF,
        0x00,0x00,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,
    };
    rfb_buffer out;
    rfb_buffer_init(&out, rfb_default_allocator(), 1u << 20);
    rfb_shm_table table;
    rfb_shm_table_init(&table);
    RFB_CHECK_EQ_INT(
        rfb_shm_transfer(&out, src, 2, 2, KITTY_FMT_RGBA32, 1, 1, false, &table, 0, 0),
        RFB_OK);

    int pipe_in[2], pipe_out[2];
    if (pipe(pipe_in) != 0 || pipe(pipe_out) != 0) {
        RFB_CHECK(false); goto cleanup;
    }
    pid_t pid = fork();
    if (pid < 0) { RFB_CHECK(false); goto cleanup; }
    if (pid == 0) {
        close(pipe_in[1]); close(pipe_out[0]);
        dup2(pipe_in[0], 0);
        dup2(pipe_out[1], 1);
        close(pipe_in[0]); close(pipe_out[1]);
        char exp_str[16];
        snprintf(exp_str, sizeof exp_str, "%d", 16);
        execlp("python3", "python3",
               "tests/integration/fake_kitty_terminal.py",
               "--pty-fd", "0",
               "--expect-bytes", exp_str,
               (char *)NULL);
        _exit(127);
    }
    close(pipe_in[0]); close(pipe_out[1]);
    size_t off = 0;
    while (off < rfb_buffer_length(&out)) {
        ssize_t w = write(pipe_in[1], rfb_buffer_data(&out) + off,
                          rfb_buffer_length(&out) - off);
        if (w <= 0) break;
        off += (size_t)w;
    }
    close(pipe_in[1]);
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
    // Clean up the shm object now that the fake terminal has read it.
    // The deferred-unlink model keeps the object alive until the terminal
    // processes the command (plan.md §G10).
    if (table.count > 0) {
        for (size_t i = 0; i < KITTY_SHM_MAX_INFLIGHT; i++) {
            if (table.entries[i].in_use) {
                shm_unlink(table.entries[i].name);
            }
        }
    }
    // The shm object may be page-aligned (larger than 16 bytes); verify
    // the first 16 bytes match the source.
    RFB_CHECK(got_len >= 16u);
    if (got_len >= 16) {
        RFB_CHECK_MEM_EQ(got, src, 16);
    }
cleanup:
    rfb_buffer_destroy(&out);
}
