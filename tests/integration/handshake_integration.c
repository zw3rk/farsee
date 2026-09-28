// SPDX-License-Identifier: Apache-2.0
//
// G2 — integration test driver: run the handshake SM against the scripted
// Python RFB server over real loopback TCP (plan.md §G2 "Integration test:
// Scripted loopback server validates exact bytes from client").
//
// This is a standalone binary (not part of the unit runner) because it
// uses sockets. It connects to 127.0.0.1:<port> (the harness launches the
// scripted server and passes the port), runs the handshake SM until DONE
// or FAILED, and prints a one-line JSON result that the Python harness
// checks.
//
// Build: wired into the Makefile's integration target (added below).
// Run:   ./build/<build>/bin/handshake_integration <port> <password> [--allow-none]

#include "farsee/handshake.h"
#include "farsee/buffer.h"
#include "farsee/allocator.h"
#include "farsee/bytes.h"

#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: %s <port> <password> [--allow-none]\n", argv[0]);
        return 2;
    }
    int port = atoi(argv[1]);
    const char *password = argv[2];
    bool allow_none = (argc >= 4 && strcmp(argv[3], "--allow-none") == 0);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        printf("{\"result\":\"fail\",\"reason\":\"socket\"}\n");
        return 1;
    }
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)port);
    if (inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) != 1) {
        printf("{\"result\":\"fail\",\"reason\":\"inet_pton\"}\n");
        close(fd);
        return 1;
    }
    if (connect(fd, (struct sockaddr *)&addr, sizeof addr) != 0) {
        printf("{\"result\":\"fail\",\"reason\":\"connect\"}\n");
        close(fd);
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
    rfb_buffer_init(&in, rfb_default_allocator(), 8192);
    rfb_buffer_init(&out, rfb_default_allocator(), 8192);

    rfb_error e = RFB_OK;
    char fail_reason[256] = "";
    for (int i = 0; i < 64 && !rfb_handshake_finished(&h); i++) {
        // Drain output to the socket.
        if (rfb_buffer_length(&out) > 0) {
            size_t n = rfb_buffer_length(&out);
            ssize_t w = send(fd, rfb_buffer_data(&out), n, 0);
            if (w > 0) {
                rfb_buffer_consume(&out, (size_t)w);
            }
        }
        // Try to read some input (non-blocking peek: short timeout).
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        struct timeval tv = { .tv_sec = 2, .tv_usec = 0 };
        int rc = select(fd + 1, &rfds, NULL, NULL, &tv);
        if (rc > 0 && FD_ISSET(fd, &rfds)) {
            uint8_t rbuf[256];
            ssize_t r = recv(fd, rbuf, sizeof rbuf, 0);
            if (r == 0) {
                // peer closed
                break;
            }
            if (r > 0) {
                rfb_buffer_append(&in, rbuf, (size_t)r);
            }
        }
        e = rfb_handshake_step(&h, &in, &out);
        if (e != RFB_OK) {
            break;
        }
    }
    // Final drain.
    while (rfb_buffer_length(&out) > 0) {
        ssize_t w = send(fd, rfb_buffer_data(&out), rfb_buffer_length(&out), 0);
        if (w <= 0) break;
        rfb_buffer_consume(&out, (size_t)w);
    }

    int result_code = 0;
    if (h.state == RFB_HS_DONE) {
        printf("{\"result\":\"ok\",\"security\":%d}\n", (int)h.selected_security);
    } else {
        const char *why = rfb_strerror(h.last_error);
        // Escape the failure reason for JSON (it's server-controlled).
        size_t fr_len = rfb_buffer_length(&h.failure_reason);
        if (fr_len > 0) {
            size_t copy = fr_len < sizeof(fail_reason) - 1 ? fr_len : sizeof(fail_reason) - 1;
            memcpy(fail_reason, rfb_buffer_data(&h.failure_reason), copy);
            fail_reason[copy] = '\0';
        }
        printf("{\"result\":\"fail\",\"reason\":\"%s\",\"detail\":\"%s\"}\n",
               why, fail_reason);
        result_code = 1;
    }

    close(fd);
    rfb_buffer_destroy(&in);
    rfb_buffer_destroy(&out);
    rfb_handshake_destroy(&h);
    return result_code;
}
