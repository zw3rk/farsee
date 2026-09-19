// SPDX-License-Identifier: Apache-2.0
//
// Deterministic contracts for the live RDP owner's private drain helpers.

#ifdef FARSEE_WITH_RDP

#include "app/live_shell_tty_guard.h"
#include "app/rdp_live_input.h"
#include "app/rdp_live_internal.h"
#include "farsee/allocator.h"
#include "farsee/buffer.h"
#include "farsee/kitty_tile.h"
#include "tests/test_framework/rfb_test.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

typedef struct stdout_capture {
    int saved_fd;
    int read_fd;
} stdout_capture;

static void stdout_capture_init(stdout_capture *capture)
{
    capture->saved_fd = -1;
    capture->read_fd = -1;
}

static bool stdout_capture_begin(stdout_capture *capture)
{
    int fds[2] = {-1, -1};
    stdout_capture_init(capture);
    if (fflush(stdout) != 0 || pipe(fds) != 0) {
        return false;
    }
    capture->saved_fd = dup(STDOUT_FILENO);
    if (capture->saved_fd < 0) {
        (void)close(fds[0]);
        (void)close(fds[1]);
        return false;
    }
    if (dup2(fds[1], STDOUT_FILENO) < 0) {
        (void)close(capture->saved_fd);
        capture->saved_fd = -1;
        (void)close(fds[0]);
        (void)close(fds[1]);
        return false;
    }
    (void)close(fds[1]);
    capture->read_fd = fds[0];
    return true;
}

static bool stdout_capture_end(stdout_capture *capture, uint8_t *bytes,
                               size_t capacity, size_t *out_length)
{
    bool ok = true;
    size_t used = 0u;

    farsee_live_shell_tty_guard_restore();
    if (fflush(stdout) != 0 || capture->saved_fd < 0 ||
        dup2(capture->saved_fd, STDOUT_FILENO) < 0) {
        ok = false;
    }
    if (capture->saved_fd >= 0) {
        (void)close(capture->saved_fd);
        capture->saved_fd = -1;
    }
    if (!ok) {
        if (capture->read_fd >= 0) {
            (void)close(capture->read_fd);
            capture->read_fd = -1;
        }
        *out_length = 0u;
        return false;
    }

    for (;;) {
        uint8_t chunk[64];
        ssize_t n = read(capture->read_fd, chunk, sizeof chunk);
        if (n > 0) {
            const size_t got = (size_t)n;
            if (got > capacity - used) {
                ok = false;
            } else {
                memcpy(bytes + used, chunk, got);
                used += got;
            }
            continue;
        }
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n < 0) {
            ok = false;
        }
        break;
    }
    (void)close(capture->read_fd);
    capture->read_fd = -1;
    *out_length = used;
    return ok;
}

static bool stdout_backpressure_begin(stdout_capture *capture)
{
    int fds[2] = {-1, -1};
    uint8_t fill[4096];
    memset(fill, 0xa5, sizeof fill);
    stdout_capture_init(capture);
    if (fflush(stdout) != 0 || pipe(fds) != 0) {
        return false;
    }
    const int flags = fcntl(fds[1], F_GETFL, 0);
    if (flags < 0 || fcntl(fds[1], F_SETFL, flags | O_NONBLOCK) != 0) {
        (void)close(fds[0]);
        (void)close(fds[1]);
        return false;
    }
    for (;;) {
        const ssize_t written = write(fds[1], fill, sizeof fill);
        if (written > 0) {
            continue;
        }
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written < 0 &&
            (errno == EAGAIN || errno == EWOULDBLOCK)) {
            break;
        }
        (void)close(fds[0]);
        (void)close(fds[1]);
        return false;
    }
    capture->saved_fd = dup(STDOUT_FILENO);
    if (capture->saved_fd < 0 || dup2(fds[1], STDOUT_FILENO) < 0) {
        if (capture->saved_fd >= 0) {
            (void)close(capture->saved_fd);
        }
        (void)close(fds[0]);
        (void)close(fds[1]);
        stdout_capture_init(capture);
        return false;
    }
    (void)close(fds[1]);
    capture->read_fd = fds[0];
    return true;
}

static bool stdout_backpressure_end(stdout_capture *capture)
{
    farsee_live_shell_tty_guard_restore();
    const bool restored = capture->saved_fd >= 0 &&
                          dup2(capture->saved_fd, STDOUT_FILENO) >= 0;
    if (capture->saved_fd >= 0) {
        (void)close(capture->saved_fd);
    }
    if (capture->read_fd >= 0) {
        (void)close(capture->read_fd);
    }
    stdout_capture_init(capture);
    return restored;
}

RFB_TEST(rdp_live_helpers,
         kitty_pending__tracks_borrowed_buffer_with_optional_lock)
{
    farsee_live_shell shell;
    rfb_kitty_tile tile;
    rfb_buffer output;
    static const uint8_t apc[] = "\033_Gx\033\\";

    farsee_live_shell_init(&shell, NULL, 1u);
    RFB_CHECK(!farsee_live_shell_kitty_pending(NULL));
    RFB_CHECK(!farsee_live_shell_kitty_pending(&shell));

    memset(&tile, 0, sizeof tile);
    shell.kitty = &tile;
    RFB_CHECK(!farsee_live_shell_kitty_pending(&shell));

    rfb_buffer_init(&output, rfb_default_allocator(), 4096u);
    tile.out = &output;
    RFB_CHECK(!farsee_live_shell_kitty_pending(&shell));
    RFB_CHECK(rfb_buffer_append(&output, apc, sizeof apc - 1u) == RFB_OK);
    RFB_CHECK(farsee_live_shell_kitty_pending(&shell));

    shell.io_mu = farsee_mutex_create();
    if (shell.io_mu == NULL) {
        RFB_FAIL("farsee_mutex_create failed");
        rfb_buffer_destroy(&output);
        return;
    }
    RFB_CHECK(farsee_live_shell_kitty_pending(&shell));
    farsee_mutex_lock(shell.io_mu);
    rfb_buffer_clear(&output);
    farsee_mutex_unlock(shell.io_mu);
    RFB_CHECK(!farsee_live_shell_kitty_pending(&shell));

    farsee_mutex_destroy(&shell.io_mu);
    shell.kitty = NULL;
    rfb_buffer_destroy(&output);
}

RFB_TEST(rdp_live_helpers, graphics_drain__null_and_empty_are_safe)
{
    rdp_live_tick tick;
    rfb_buffer output;

    rdp_live_flush_pending_graphics(NULL);
    memset(&tick, 0, sizeof tick);
    farsee_live_shell_init(&tick.shell, NULL, 1u);
    rdp_live_flush_pending_graphics(&tick);
    RFB_CHECK(!tick.need_home);

    rfb_buffer_init(&output, rfb_default_allocator(), 4096u);
    tick.kitty_out = &output;
    rdp_live_flush_pending_graphics(&tick);
    RFB_CHECK(tick.need_home);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&output), 0u);

    tick.need_home = false;
    tick.shell.io_mu = farsee_mutex_create();
    if (tick.shell.io_mu == NULL) {
        RFB_FAIL("farsee_mutex_create failed");
        rfb_buffer_destroy(&output);
        return;
    }
    rdp_live_flush_pending_graphics(&tick);
    RFB_CHECK(tick.need_home);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&output), 0u);

    farsee_mutex_destroy(&tick.shell.io_mu);
    rfb_buffer_destroy(&output);
}

RFB_TEST(rdp_live_helpers,
         graphics_drain__homes_apc_and_publishes_desktop)
{
    static const uint8_t apc[] = "\033_Gf=32;AA\033\\";
    static const uint8_t homed_apc[] = "\033[H\033_Gf=32;AA\033\\";
    rdp_live_tick tick;
    rdp_display_sink sink;
    rfb_buffer output;
    stdout_capture capture;
    uint8_t output_bytes[64];
    size_t output_length = 0u;

    memset(&tick, 0, sizeof tick);
    farsee_live_shell_init(&tick.shell, NULL, 1u);
    rdp_display_sink_init(&sink);
    rfb_buffer_init(&output, rfb_default_allocator(), 4096u);
    tick.kitty_out = &output;
    tick.sink = &sink;
    tick.need_home = true;
    farsee_atomic_u64_store(&sink.last_desk_size,
                            rdp_desk_size_pack(1024u, 768u));
    RFB_CHECK(rfb_buffer_append(&output, apc, sizeof apc - 1u) == RFB_OK);

    if (!stdout_capture_begin(&capture)) {
        RFB_FAIL("stdout capture setup failed");
        rfb_buffer_destroy(&output);
        return;
    }
    rdp_live_flush_pending_graphics(&tick);
    RFB_CHECK(stdout_capture_end(&capture, output_bytes, sizeof output_bytes,
                                 &output_length));
    RFB_CHECK_EQ_UINT(output_length, sizeof homed_apc - 1u);
    RFB_CHECK_MEM_EQ(output_bytes, homed_apc, sizeof homed_apc - 1u);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&output), 0u);
    RFB_CHECK(tick.need_home);
    RFB_CHECK(farsee_live_shell_apply_pending_desk(&tick.shell, false));
    RFB_CHECK_EQ_UINT(tick.shell.desk_w, 1024u);
    RFB_CHECK_EQ_UINT(tick.shell.desk_h, 768u);

    tick.need_home = false;
    tick.shell.layout_active = true;
    tick.shell.io_mu = farsee_mutex_create();
    if (tick.shell.io_mu == NULL) {
        RFB_FAIL("farsee_mutex_create failed");
        rfb_buffer_destroy(&output);
        return;
    }
    farsee_atomic_u64_store(&sink.last_desk_size,
                            rdp_desk_size_pack(1024u, 0u));
    RFB_CHECK(rfb_buffer_append(&output, apc, sizeof apc - 1u) == RFB_OK);
    if (!stdout_capture_begin(&capture)) {
        RFB_FAIL("stdout capture setup failed");
        farsee_mutex_destroy(&tick.shell.io_mu);
        rfb_buffer_destroy(&output);
        return;
    }
    rdp_live_flush_pending_graphics(&tick);
    RFB_CHECK(stdout_capture_end(&capture, output_bytes, sizeof output_bytes,
                                 &output_length));
    RFB_CHECK_EQ_UINT(output_length, sizeof apc - 1u);
    RFB_CHECK_MEM_EQ(output_bytes, apc, sizeof apc - 1u);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&output), 0u);
    RFB_CHECK(tick.need_home);
    RFB_CHECK(!farsee_live_shell_apply_pending_desk(&tick.shell, false));

    farsee_mutex_destroy(&tick.shell.io_mu);
    rfb_buffer_destroy(&output);
}

RFB_TEST(rdp_live_helpers,
         graphics_backpressure__keeps_one_home_prefix_on_residual)
{
    static const uint8_t apc[] = "\033_Gf=32;AA\033\\";
    static const uint8_t homed_apc[] = "\033[H\033_Gf=32;AA\033\\";
    rdp_live_tick tick;
    rfb_buffer output;
    stdout_capture capture;
    uint8_t written_bytes[64];
    size_t written_length = 0u;

    memset(&tick, 0, sizeof tick);
    farsee_live_shell_init(&tick.shell, NULL, 1u);
    tick.shell.layout_active = true;
    tick.need_home = true;
    rfb_buffer_init(&output, rfb_default_allocator(), 4096u);
    tick.kitty_out = &output;
    RFB_CHECK(rfb_buffer_append(&output, apc, sizeof apc - 1u) == RFB_OK);

    if (!stdout_backpressure_begin(&capture)) {
        RFB_FAIL("stdout backpressure setup failed");
        rfb_buffer_destroy(&output);
        return;
    }
    rdp_live_flush_pending_graphics(&tick);
    RFB_CHECK(stdout_backpressure_end(&capture));
    RFB_CHECK(!tick.need_home);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&output), sizeof homed_apc - 1u);
    RFB_CHECK_MEM_EQ(rfb_buffer_data(&output), homed_apc,
                     sizeof homed_apc - 1u);

    tick.shell.layout_active = false;
    if (!stdout_capture_begin(&capture)) {
        RFB_FAIL("stdout capture setup failed");
        rfb_buffer_destroy(&output);
        return;
    }
    rdp_live_flush_pending_graphics(&tick);
    RFB_CHECK(stdout_capture_end(&capture, written_bytes, sizeof written_bytes,
                                 &written_length));
    RFB_CHECK_EQ_UINT(written_length, sizeof homed_apc - 1u);
    RFB_CHECK_MEM_EQ(written_bytes, homed_apc, sizeof homed_apc - 1u);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&output), 0u);
    RFB_CHECK(tick.need_home);

    rfb_buffer_destroy(&output);
}

RFB_TEST(rdp_live_helpers,
         tty_response_drain__consumes_available_bytes_without_owning_fd)
{
    static const uint8_t responses[] = "response-one-response-two";
    int fds[2] = {-1, -1};
    uint8_t byte = 0u;

    rdp_live_discard_tty_responses(-1);
    if (pipe(fds) != 0) {
        RFB_FAIL("pipe failed");
        return;
    }
    RFB_CHECK(write(fds[1], responses, sizeof responses - 1u) ==
              (ssize_t)(sizeof responses - 1u));
    (void)close(fds[1]);
    fds[1] = -1;
    rdp_live_discard_tty_responses(fds[0]);
    RFB_CHECK(read(fds[0], &byte, 1u) == 0);
    (void)close(fds[0]);

    if (pipe(fds) != 0) {
        RFB_FAIL("second pipe failed");
        return;
    }
    const int flags = fcntl(fds[0], F_GETFL, 0);
    if (flags < 0 || fcntl(fds[0], F_SETFL, flags | O_NONBLOCK) != 0) {
        RFB_FAIL("could not make pipe nonblocking");
        (void)close(fds[0]);
        (void)close(fds[1]);
        return;
    }
    rdp_live_discard_tty_responses(fds[0]);
    byte = 0x5au;
    RFB_CHECK(write(fds[1], &byte, 1u) == 1);
    byte = 0u;
    RFB_CHECK(read(fds[0], &byte, 1u) == 1);
    RFB_CHECK_EQ_UINT(byte, 0x5au);
    (void)close(fds[0]);
    (void)close(fds[1]);
}

#endif  // FARSEE_WITH_RDP
