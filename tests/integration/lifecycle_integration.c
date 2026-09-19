// SPDX-License-Identifier: Apache-2.0
//
// G5 — integration test: connect through the POSIX nonblocking adapter,
// run the handshake SM + read ServerInit, and confirm the loop drives the
// state machine to DONE and parses the framebuffer geometry. Uses the
// scripted Python server over real loopback TCP.
//
// Build: wired into the Makefile integration target.
// Run:   ./build/<build>/bin/lifecycle_integration <port> <password> [<vnc|none>]

#include "farsee/handshake.h"
#include "farsee/server_init.h"
#include "farsee/socket_posix.h"
#include "farsee/outbound.h"
#include "farsee/buffer.h"
#include "farsee/allocator.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s <port> <password> [vnc|none]\n", argv[0]);
        return 2;
    }
    int port = atoi(argv[1]);
    const char *password = argv[2];
    bool allow_none = (argc >= 4 && strcmp(argv[3], "none") == 0);

    // Connect via the POSIX adapter (the G5 path under test).
    rfb_socket_ctx sctx;
    rfb_io_adapter io = rfb_socket_adapter_make(&sctx);
    // Build a loopback candidate directly (avoid getaddrinfo flakiness in CI).
    rfb_io_candidate cand;
    memset(&cand, 0, sizeof cand);
    cand.family = AF_INET;
    cand.socktype = SOCK_STREAM;
    cand.protocol = 0;
    struct sockaddr_in *sa = (struct sockaddr_in *)cand.addr;
    sa->sin_family = AF_INET;
    sa->sin_port = htons((unsigned short)port);
    inet_pton(AF_INET, "127.0.0.1", &sa->sin_addr);
    cand.addr_len = sizeof *sa;
    if (io.connect(io.ctx, &cand) != RFB_IO_OK) {
        printf("{\"result\":\"fail\",\"stage\":\"connect\"}\n");
        return 1;
    }

    rfb_handshake_policy pol = rfb_handshake_policy_default();
    pol.allow_none_auth = allow_none;
    rfb_handshake h;
    rfb_handshake_init(&h, &pol, rfb_default_allocator());
    {
        size_t pwlen = strlen(password);
        if (pwlen > 8) pwlen = 8;
        rfb_handshake_set_password(&h, (const uint8_t *)password, pwlen);
    }

    rfb_buffer in, out;
    rfb_buffer_init(&in, rfb_default_allocator(), 1u << 20);
    rfb_buffer_init(&out, rfb_default_allocator(), 1u << 20);

    int stage_code = 0;
    const char *stage_name = "handshake";
    for (int i = 0; i < 2000 && !rfb_handshake_finished(&h); i++) {
        // Drain outbound (nonblocking writes; if BLOCK, poll for writability).
        while (rfb_buffer_length(&out) > 0) {
            size_t n = rfb_buffer_length(&out);
            size_t wrote = 0;
            rfb_io_result r = io.write(io.ctx, rfb_buffer_data(&out), n, &wrote);
            if (r == RFB_IO_BLOCK) {
                // Poll briefly for writability, then retry.
                struct pollfd pfd;
                pfd.fd = sctx.fd;
                pfd.events = POLLOUT;
                pfd.revents = 0;
                poll(&pfd, 1, 1000);
                continue;
            }
            if (r == RFB_IO_ERROR) { stage_code = 1; goto done; }
            if (wrote > 0) rfb_buffer_consume(&out, wrote);
        }
        // Poll for readability before reading (avoid EAGAIN spin).
        {
            struct pollfd pfd;
            pfd.fd = sctx.fd;
            pfd.events = POLLIN;
            pfd.revents = 0;
            int pr = poll(&pfd, 1, 2000);
            if (pr <= 0) {
                // Timeout or error; break to avoid infinite loop.
                break;
            }
        }
        // Read available input.
        uint8_t rbuf[4096];
        size_t got = 0;
        rfb_io_result r = io.read(io.ctx, rbuf, sizeof rbuf, &got);
        if (r == RFB_IO_ERROR) { stage_code = 2; stage_name = "read"; goto done; }
        if (r == RFB_IO_EOF) break;
        if (got > 0) rfb_buffer_append(&in, rbuf, got);
        // Step the handshake.
        rfb_error e = rfb_handshake_step(&h, &in, &out);
        if (e != RFB_OK) {
            // Could be a real auth failure (expected for the wrong-pw
            // scenario); the server-script handles that side.
            break;
        }
        // Move the handshake's internal output into our out buffer.
        // (The handshake SM appends to its own `out`; here we pass the
        // same buffer, so nothing extra to do.)
    }
    // Final drain.
    while (rfb_buffer_length(&out) > 0) {
        size_t wrote = 0;
        rfb_io_result r = io.write(io.ctx, rfb_buffer_data(&out), rfb_buffer_length(&out), &wrote);
        if (r != RFB_IO_OK && r != RFB_IO_BLOCK) break;
        if (wrote > 0) rfb_buffer_consume(&out, wrote);
        if (wrote == 0) break;
    }

    if (h.state == RFB_HS_DONE) {
        // Read ServerInit (up to 4 KiB message).
        // Emit ClientInit (shared flag).
        uint8_t ci[1] = { pol.shared_flag ? 1u : 0u };
        size_t wrote = 0;
        io.write(io.ctx, ci, 1, &wrote);
        // Read ServerInit bytes.
        for (int k = 0; k < 100 && rfb_buffer_length(&in) < 24; k++) {
            struct pollfd pfd;
            pfd.fd = sctx.fd;
            pfd.events = POLLIN;
            pfd.revents = 0;
            if (poll(&pfd, 1, 2000) <= 0) break;
            uint8_t rbuf[256];
            size_t got = 0;
            rfb_io_result r = io.read(io.ctx, rbuf, sizeof rbuf, &got);
            if (r == RFB_IO_EOF) break;
            if (got > 0) rfb_buffer_append(&in, rbuf, got);
            else break;
        }
        rfb_server_init si;
        memset(&si, 0xEE, sizeof si);
        rfb_error e = rfb_parse_server_init(rfb_buffer_data(&in),
                                            rfb_buffer_length(&in), &si, 1024);
        if (e == RFB_OK) {
            printf("{\"result\":\"ok\",\"stage\":\"serverinit\","
                   "\"width\":%u,\"height\":%u,\"bpp\":%u}\n",
                   si.width, si.height, si.pixel_format.bits_per_pixel);
            rfb_server_init_destroy(&si);
        } else {
            stage_code = 3; stage_name = "serverinit";
        }
    } else {
        printf("{\"result\":\"fail\",\"stage\":\"%s\",\"state\":%d,\"error\":\"%s\"}\n",
               stage_name, h.state, rfb_strerror(h.last_error));
        stage_code = 4;
    }

done:
    if (stage_code != 0 && stage_code != 4) {
        printf("{\"result\":\"fail\",\"stage\":\"%s\",\"code\":%d}\n", stage_name, stage_code);
    }
    io.close(io.ctx);
    rfb_buffer_destroy(&in);
    rfb_buffer_destroy(&out);
    rfb_handshake_destroy(&h);
    return (stage_code == 0 || stage_code == 4) ? 0 : 1;
}
