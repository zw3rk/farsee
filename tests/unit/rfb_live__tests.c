// SPDX-License-Identifier: Apache-2.0
//
// Classic RFB live orchestration: deterministic outcome policy and a complete
// loopback connection through the product entry point.

#include "rfb_test.h"
#include "app/rfb_live.h"
#include "app/rfb_live_internal.h"

#include "farsee/apple_postauth.h"
#include "farsee/farsee_error.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

typedef struct rfb_live_outcome_case {
    farsee_mt_terminal_kind terminal_kind;
    farsee_error mt_error;
    rfb_error protocol_error;
    uint8_t unexpected_type;
    bool stop_requested;
    uint64_t present_count;
    int expected_code;
    const char *expected_text;
} rfb_live_outcome_case;

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
    const bool restored =
        dup2(capture->saved_fd, STDERR_FILENO) >= 0;
    (void)close(capture->saved_fd);

    size_t used = 0u;
    while (used + 1u < output_capacity) {
        const ssize_t got = read(capture->read_fd, output + used,
                                 output_capacity - used - 1u);
        if (got > 0) {
            used += (size_t)got;
            continue;
        }
        if (got < 0 && errno == EINTR) {
            continue;
        }
        break;
    }
    (void)close(capture->read_fd);
    output[used] = '\0';
    return restored;
}

static bool stream_contains(FILE *stream, const char *needle)
{
    if (stream == NULL || needle == NULL || fflush(stream) != 0 ||
        fseek(stream, 0, SEEK_SET) != 0) {
        return false;
    }
    char output[1024];
    const size_t count = fread(output, 1u, sizeof output - 1u, stream);
    output[count] = '\0';
    return strstr(output, needle) != NULL;
}

static bool stream_is_empty(FILE *stream)
{
    if (stream == NULL || fflush(stream) != 0 ||
        fseek(stream, 0, SEEK_END) != 0) {
        return false;
    }
    return ftell(stream) == 0L;
}

RFB_TEST(rfb_live, report_outcome__terminal_matrix__maps_code_and_diagnostic)
{
    const farsee_error ok = farsee_error_make(
        FARSEE_E_OK, FARSEE_SUB_NONE, FARSEE_PHASE_CLOSED);
    const farsee_error thread_error = farsee_error_make_with_msg(
        FARSEE_ERR_INTERNAL, FARSEE_SUB_CORE, FARSEE_PHASE_ACTIVE,
        "worker creation failed");
    const rfb_live_outcome_case cases[] = {
        {FARSEE_MT_TERMINAL_ALLOCATION_FAILURE, ok, RFB_OK, 0u, false, 0u,
         5, "out of memory"},
        {FARSEE_MT_TERMINAL_PRESENTER_FAILURE, ok, RFB_OK, 0u, false, 0u,
         5, "presenter failed"},
        {FARSEE_MT_TERMINAL_INPUT_FAILURE, ok, RFB_OK, 0u, false, 0u,
         5, "input failed"},
        {FARSEE_MT_TERMINAL_THREAD_CREATION_FAILURE, thread_error, RFB_OK,
         0u, false, 0u, 5, "worker creation failed"},
        {FARSEE_MT_TERMINAL_INTERNAL_FAILURE, thread_error, RFB_OK, 0u, false,
         0u, 5, "worker creation failed"},
        {FARSEE_MT_TERMINAL_PROTOCOL_FAILURE, ok, RFB_ERR_PROTOCOL, 0x7eu,
         false, 0u, 5, "unexpected server message type=0x7e"},
        {FARSEE_MT_TERMINAL_PROTOCOL_FAILURE, ok, RFB_ERR_PROTOCOL, 0u,
         false, 0u, 5, "framebuffer decode failed"},
        {FARSEE_MT_TERMINAL_PROTOCOL_FAILURE, ok, RFB_ERR_LIMIT, 0u, false,
         0u, 5, "input/size limit exceeded"},
        {FARSEE_MT_TERMINAL_PROTOCOL_FAILURE, ok, RFB_ERR_UNSUPPORTED, 0x11u,
         false, 0u, 5, "type=0x11"},
        {FARSEE_MT_TERMINAL_PROTOCOL_FAILURE, ok, RFB_ERR_UNSUPPORTED, 0u,
         false, 0u, 5, "feature (err=8)"},
        {FARSEE_MT_TERMINAL_PEER_CLOSED, ok, RFB_ERR_EOF, 0u, false, 0u, 5,
         "peer closed the connection"},
        {FARSEE_MT_TERMINAL_PEER_CLOSED, ok, RFB_ERR_IO, 0u, false, 0u, 5,
         "peer closed the connection"},
        {FARSEE_MT_TERMINAL_PROTOCOL_FAILURE, ok, RFB_ERR_AUTH, 0u, false,
         0u, 5, "protocol loop ended [err=9]"},
        {FARSEE_MT_TERMINAL_REQUESTED_STOP, ok, RFB_ERR_CANCELLED, 0u, true,
         3u, 0, "disconnected (signal / leader quit) after 3 present(s)"},
        {FARSEE_MT_TERMINAL_REQUESTED_STOP, ok, RFB_ERR_CANCELLED, 0u, true,
         0u, 0, "disconnected (signal / leader quit)"},
        {FARSEE_MT_TERMINAL_PEER_CLOSED, ok, RFB_OK, 0u, false, 2u, 0,
         "session ended after 2 present(s)"},
        {FARSEE_MT_TERMINAL_PEER_CLOSED, ok, RFB_OK, 0u, false, 0u, 0,
         NULL},
    };

    for (size_t i = 0u; i < sizeof cases / sizeof cases[0]; i++) {
        FILE *diagnostic = tmpfile();
        RFB_CHECK(diagnostic != NULL);
        if (diagnostic == NULL) {
            continue;
        }
        const rfb_live_outcome_case *test_case = &cases[i];
        const int code = farsee_rfb_live_report_outcome(
            test_case->terminal_kind, test_case->mt_error,
            test_case->protocol_error, test_case->unexpected_type,
            test_case->stop_requested, test_case->present_count, diagnostic);
        RFB_CHECK_EQ_INT(code, test_case->expected_code);
        if (test_case->expected_text != NULL) {
            RFB_CHECK(stream_contains(diagnostic, test_case->expected_text));
        } else {
            RFB_CHECK(stream_is_empty(diagnostic));
        }
        RFB_CHECK_EQ_INT(fclose(diagnostic), 0);
    }
}

static int make_loopback_listener(uint16_t *out_port)
{
    if (out_port == NULL) {
        return -1;
    }
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) {
        return -1;
    }
    int one = 1;
    (void)setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in address;
    memset(&address, 0, sizeof address);
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    socklen_t length = (socklen_t)sizeof address;
    if (bind(listener, (struct sockaddr *)&address, sizeof address) != 0 ||
        listen(listener, 1) != 0 ||
        getsockname(listener, (struct sockaddr *)&address, &length) != 0) {
        (void)close(listener);
        return -1;
    }
    *out_port = ntohs(address.sin_port);
    return listener;
}

static bool fd_write_all(int fd, const uint8_t *bytes, size_t count)
{
    size_t offset = 0u;
    while (offset < count) {
        const ssize_t written = send(fd, bytes + offset, count - offset, 0);
        if (written > 0) {
            offset += (size_t)written;
            continue;
        }
        if (written < 0 && errno == EINTR) {
            continue;
        }
        return false;
    }
    return true;
}

static bool fd_read_all(int fd, uint8_t *bytes, size_t count)
{
    size_t offset = 0u;
    while (offset < count) {
        const ssize_t received = recv(fd, bytes + offset, count - offset, 0);
        if (received > 0) {
            offset += (size_t)received;
            continue;
        }
        if (received < 0 && errno == EINTR) {
            continue;
        }
        return false;
    }
    return true;
}

static bool pipe_write_all(int fd, const uint8_t *bytes, size_t count)
{
    size_t offset = 0u;
    while (offset < count) {
        const ssize_t written = write(fd, bytes + offset, count - offset);
        if (written > 0) {
            offset += (size_t)written;
            continue;
        }
        if (written < 0 && errno == EINTR) {
            continue;
        }
        return false;
    }
    return true;
}

static int password_pipe(const uint8_t *bytes, size_t count)
{
    int descriptors[2] = {-1, -1};
    if (pipe(descriptors) != 0) {
        return -1;
    }
    if (!pipe_write_all(descriptors[1], bytes, count) ||
        close(descriptors[1]) != 0) {
        (void)close(descriptors[0]);
        (void)close(descriptors[1]);
        return -1;
    }
    return descriptors[0];
}

static bool serve_unsupported_security(int listener)
{
    int peer = accept(listener, NULL, NULL);
    if (peer < 0) {
        return false;
    }
    struct timeval timeout = {.tv_sec = 2, .tv_usec = 0};
    (void)setsockopt(peer, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
    (void)setsockopt(peer, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout);

    static const uint8_t banner[] = "RFB 003.008\n";
    static const uint8_t unsupported[] = {0x01u, 0x7eu};
    uint8_t client_banner[sizeof banner - 1u];
    const bool ok =
        fd_write_all(peer, banner, sizeof banner - 1u) &&
        fd_read_all(peer, client_banner, sizeof client_banner) &&
        memcmp(client_banner, banner, sizeof client_banner) == 0 &&
        fd_write_all(peer, unsupported, sizeof unsupported);
    (void)close(peer);
    return ok;
}

static bool serve_none_auth_rejection(int listener)
{
    int peer = accept(listener, NULL, NULL);
    if (peer < 0) {
        return false;
    }
    struct timeval timeout = {.tv_sec = 2, .tv_usec = 0};
    (void)setsockopt(peer, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
    (void)setsockopt(peer, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout);

    static const uint8_t banner[] = "RFB 003.008\n";
    static const uint8_t security[] = {0x01u, 0x01u};
    static const uint8_t rejection[] = {
        0x00u, 0x00u, 0x00u, 0x01u,
        0x00u, 0x00u, 0x00u, 0x06u,
        'd', 'e', 'n', 'i', 'e', 'd',
    };
    uint8_t client_banner[sizeof banner - 1u];
    uint8_t selection = 0u;
    const bool ok =
        fd_write_all(peer, banner, sizeof banner - 1u) &&
        fd_read_all(peer, client_banner, sizeof client_banner) &&
        memcmp(client_banner, banner, sizeof client_banner) == 0 &&
        fd_write_all(peer, security, sizeof security) &&
        fd_read_all(peer, &selection, 1u) && selection == 0x01u &&
        fd_write_all(peer, rejection, sizeof rejection);
    (void)close(peer);
    return ok;
}

static bool serve_immediate_close(int listener)
{
    const int peer = accept(listener, NULL, NULL);
    if (peer < 0) {
        return false;
    }
    return close(peer) == 0;
}

typedef bool (*rfb_live_server_fn)(int listener);

static pid_t start_loopback_server(int listener, rfb_live_server_fn serve)
{
    const pid_t server = fork();
    if (server == 0) {
        const bool ok = serve(listener);
        (void)close(listener);
        _exit(ok ? 0 : 1);
    }
    return server;
}

static int accept_classic_none_after_setup(int listener)
{
    int peer = accept(listener, NULL, NULL);
    if (peer < 0) {
        return -1;
    }
    struct timeval timeout = {.tv_sec = 2, .tv_usec = 0};
    (void)setsockopt(peer, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
    (void)setsockopt(peer, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout);

    static const uint8_t banner[] = "RFB 003.008\n";
    static const uint8_t security[] = {0x01u, 0x01u};
    static const uint8_t security_ok[] = {0u, 0u, 0u, 0u};
    static const uint8_t server_init[] = {
        0x00u, 0x01u, 0x00u, 0x01u,
        0x20u, 0x18u, 0x00u, 0x01u,
        0x00u, 0xffu, 0x00u, 0xffu, 0x00u, 0xffu,
        0x10u, 0x08u, 0x00u,
        0x00u, 0x00u, 0x00u,
        0x00u, 0x00u, 0x00u, 0x00u,
    };
    uint8_t client_banner[sizeof banner - 1u];
    uint8_t selection = 0u;
    uint8_t client_init = 0u;
    uint8_t setup[54];
    const bool ok =
        fd_write_all(peer, banner, sizeof banner - 1u) &&
        fd_read_all(peer, client_banner, sizeof client_banner) &&
        memcmp(client_banner, banner, sizeof client_banner) == 0 &&
        fd_write_all(peer, security, sizeof security) &&
        fd_read_all(peer, &selection, 1u) && selection == 0x01u &&
        fd_write_all(peer, security_ok, sizeof security_ok) &&
        fd_read_all(peer, &client_init, 1u) && client_init == 0x01u &&
        fd_write_all(peer, server_init, sizeof server_init) &&
        fd_read_all(peer, setup, sizeof setup) &&
        setup[0] == 0x00u && setup[20] == 0x02u && setup[44] == 0x03u;
    if (!ok) {
        (void)close(peer);
        return -1;
    }
    return peer;
}

static bool serve_classic_none_then_unexpected(int listener)
{
    int peer = accept_classic_none_after_setup(listener);
    if (peer < 0) {
        return false;
    }
    const uint8_t unexpected = 0x7eu;
    const bool ok = fd_write_all(peer, &unexpected, 1u);
    (void)close(peer);
    return ok;
}

static bool read_update_request(int peer, bool incremental, uint16_t width,
                                uint16_t height)
{
    uint8_t request[10];
    if (!fd_read_all(peer, request, sizeof request)) {
        return false;
    }
    return request[0] == 0x03u && request[1] == (incremental ? 1u : 0u) &&
           request[2] == 0u && request[3] == 0u && request[4] == 0u &&
           request[5] == 0u &&
           request[6] == (uint8_t)(width >> 8u) &&
           request[7] == (uint8_t)width &&
           request[8] == (uint8_t)(height >> 8u) &&
           request[9] == (uint8_t)height;
}

static bool serve_classic_frames_then_close(int listener)
{
    int peer = accept_classic_none_after_setup(listener);
    if (peer < 0) {
        return false;
    }
    static const uint8_t raw_1x1[] = {
        0x00u, 0x00u, 0x00u, 0x01u,
        0x00u, 0x00u, 0x00u, 0x00u,
        0x00u, 0x01u, 0x00u, 0x01u,
        0x00u, 0x00u, 0x00u, 0x00u,
        0x00u, 0x00u, 0xffu, 0x00u,
    };
    static const uint8_t resize_2x1[] = {
        0x00u, 0x00u, 0x00u, 0x01u,
        0x00u, 0x00u, 0x00u, 0x00u,
        0x00u, 0x02u, 0x00u, 0x01u,
        0xffu, 0xffu, 0xffu, 0x21u,
    };
    static const uint8_t raw_2x1[] = {
        0x00u, 0x00u, 0x00u, 0x01u,
        0x00u, 0x00u, 0x00u, 0x00u,
        0x00u, 0x02u, 0x00u, 0x01u,
        0x00u, 0x00u, 0x00u, 0x00u,
        0x00u, 0x00u, 0xffu, 0x00u,
        0x00u, 0xffu, 0x00u, 0x00u,
    };

    bool ok = fd_write_all(peer, raw_1x1, sizeof raw_1x1) &&
              read_update_request(peer, true, 1u, 1u);
    (void)poll(NULL, 0, 100);
    ok = ok && fd_write_all(peer, resize_2x1, sizeof resize_2x1) &&
         read_update_request(peer, false, 2u, 1u);
    (void)poll(NULL, 0, 100);
    ok = ok && fd_write_all(peer, raw_2x1, sizeof raw_2x1) &&
         read_update_request(peer, true, 2u, 1u);
    (void)poll(NULL, 0, 100);
    (void)close(peer);
    return ok;
}

static bool serve_zero_desktop_size(int listener)
{
    int peer = accept_classic_none_after_setup(listener);
    if (peer < 0) {
        return false;
    }
    static const uint8_t zero_width[] = {
        0x00u, 0x00u, 0x00u, 0x01u,
        0x00u, 0x00u, 0x00u, 0x00u,
        0x00u, 0x00u, 0x00u, 0x01u,
        0xffu, 0xffu, 0xffu, 0x21u,
    };
    const bool ok = fd_write_all(peer, zero_width, sizeof zero_width);
    (void)poll(NULL, 0, 100);
    (void)close(peer);
    return ok;
}

RFB_TEST(rfb_live, run_rfb__null_host__closes_owned_password_fd)
{
    stderr_capture capture;
    char diagnostic[128];
    RFB_CHECK(stderr_capture_begin(&capture));
    static const uint8_t password[] = "unused";
    const int password_fd = password_pipe(password, sizeof password - 1u);
    RFB_CHECK(password_fd >= 0);

    const int code = farsee_run_rfb(
        NULL, 5900u, NULL, password_fd, false, true, APPLE_ATTACH_LOGIN,
        FARSEE_AUTH_MODE_VNC, RFB_APPLE_POSTAUTH_CLEARTEXT, false, false,
        "null", 30u, true, false, NULL, 50u, 50u, false, false);
    RFB_CHECK(stderr_capture_end(&capture, diagnostic, sizeof diagnostic));

    RFB_CHECK_EQ_INT(code, 2);
    RFB_CHECK(strstr(diagnostic, "missing host argument") != NULL);
    errno = 0;
    RFB_CHECK_EQ_INT(fcntl(password_fd, F_GETFD), -1);
    RFB_CHECK_EQ_INT(errno, EBADF);
}

RFB_TEST(rfb_live, run_rfb__unreadable_passwords__fail_before_connect)
{
    for (int unreadable = 0; unreadable < 2; unreadable++) {
        stderr_capture capture;
        char diagnostic[256];
        RFB_CHECK(stderr_capture_begin(&capture));
        const int password_fd = password_pipe(NULL, 0u);
        RFB_CHECK(password_fd >= 0);
        if (unreadable != 0) {
            RFB_CHECK_EQ_INT(close(password_fd), 0);
        }

        const int code = farsee_run_rfb(
            "127.0.0.1", 1u, NULL, password_fd, false, true,
            APPLE_ATTACH_LOGIN, FARSEE_AUTH_MODE_VNC,
            RFB_APPLE_POSTAUTH_CLEARTEXT, false, false, "null", 30u, true,
            false, NULL, 50u, 50u, false, false);
        RFB_CHECK(stderr_capture_end(&capture, diagnostic,
                                     sizeof diagnostic));

        RFB_CHECK_EQ_INT(code, 2);
        const char *expected = unreadable != 0
            ? "failed to read password from fd"
            : "empty password refused";
        RFB_CHECK(strstr(diagnostic, expected) != NULL);
        errno = 0;
        RFB_CHECK_EQ_INT(fcntl(password_fd, F_GETFD), -1);
        RFB_CHECK_EQ_INT(errno, EBADF);
    }
}

RFB_TEST(rfb_live, run_rfb__unsupported_security__explains_policy)
{
    uint16_t port = 0u;
    int listener = make_loopback_listener(&port);
    RFB_CHECK(listener >= 0);
    if (listener < 0) {
        return;
    }
    const pid_t server = start_loopback_server(
        listener, serve_unsupported_security);
    RFB_CHECK(server >= 0);
    if (server < 0) {
        (void)close(listener);
        return;
    }
    (void)close(listener);

    stderr_capture capture;
    char diagnostic[2048];
    RFB_CHECK(stderr_capture_begin(&capture));
    const int code = farsee_run_rfb(
        "127.0.0.1", port, "operator", -1, true, true,
        APPLE_ATTACH_SHARE, FARSEE_AUTH_MODE_VNC,
        RFB_APPLE_POSTAUTH_CLEARTEXT, false, false, "null", 30u, true,
        false, NULL, 50u, 1000u, false, false);
    RFB_CHECK(stderr_capture_end(&capture, diagnostic, sizeof diagnostic));

    RFB_CHECK_EQ_INT(code, 4);
    RFB_CHECK(strstr(diagnostic,
                     "No usable live security path completed") != NULL);
    RFB_CHECK(strstr(diagnostic, "[err=8]") != NULL);
    int status = 0;
    RFB_CHECK_EQ_INT(waitpid(server, &status, 0), server);
    RFB_CHECK(WIFEXITED(status));
    RFB_CHECK_EQ_INT(WEXITSTATUS(status), 0);
}

RFB_TEST(rfb_live, run_rfb__rejected_none_auth__explains_auth_failure)
{
    uint16_t port = 0u;
    int listener = make_loopback_listener(&port);
    RFB_CHECK(listener >= 0);
    if (listener < 0) {
        return;
    }
    const pid_t server = start_loopback_server(
        listener, serve_none_auth_rejection);
    RFB_CHECK(server >= 0);
    if (server < 0) {
        (void)close(listener);
        return;
    }
    (void)close(listener);

    stderr_capture capture;
    char diagnostic[256];
    RFB_CHECK(stderr_capture_begin(&capture));
    const int code = farsee_run_rfb(
        "127.0.0.1", port, NULL, -1, true, true, APPLE_ATTACH_LOGIN,
        FARSEE_AUTH_MODE_VNC, RFB_APPLE_POSTAUTH_CLEARTEXT, false, false,
        "null", 30u, true, false, NULL, 50u, 1000u, false, false);
    RFB_CHECK(stderr_capture_end(&capture, diagnostic, sizeof diagnostic));

    RFB_CHECK_EQ_INT(code, 4);
    RFB_CHECK(strstr(diagnostic, "authentication failed") != NULL);
    RFB_CHECK(strstr(diagnostic, "[err=9]") != NULL);
    int status = 0;
    RFB_CHECK_EQ_INT(waitpid(server, &status, 0), server);
    RFB_CHECK(WIFEXITED(status));
    RFB_CHECK_EQ_INT(WEXITSTATUS(status), 0);
}

RFB_TEST(rfb_live, run_rfb__peer_closes_before_banner__explains_network_error)
{
    uint16_t port = 0u;
    int listener = make_loopback_listener(&port);
    RFB_CHECK(listener >= 0);
    if (listener < 0) {
        return;
    }
    const pid_t server = start_loopback_server(listener,
                                                serve_immediate_close);
    RFB_CHECK(server >= 0);
    if (server < 0) {
        (void)close(listener);
        return;
    }
    (void)close(listener);

    stderr_capture capture;
    char diagnostic[256];
    RFB_CHECK(stderr_capture_begin(&capture));
    const int code = farsee_run_rfb(
        "127.0.0.1", port, NULL, -1, true, true, APPLE_ATTACH_LOGIN,
        FARSEE_AUTH_MODE_VNC, RFB_APPLE_POSTAUTH_CLEARTEXT, false, false,
        "null", 30u, true, false, NULL, 50u, 1000u, false, false);
    RFB_CHECK(stderr_capture_end(&capture, diagnostic, sizeof diagnostic));

    RFB_CHECK_EQ_INT(code, 4);
    RFB_CHECK(strstr(diagnostic, "network / peer closed") != NULL);
    int status = 0;
    RFB_CHECK_EQ_INT(waitpid(server, &status, 0), server);
    RFB_CHECK(WIFEXITED(status));
    RFB_CHECK_EQ_INT(WEXITSTATUS(status), 0);
}

RFB_TEST(rfb_live, run_rfb__classic_none_loopback__reports_protocol_failure)
{
    uint16_t port = 0u;
    int listener = make_loopback_listener(&port);
    RFB_CHECK(listener >= 0);
    if (listener < 0) {
        return;
    }
    const pid_t server = fork();
    RFB_CHECK(server >= 0);
    if (server < 0) {
        (void)close(listener);
        return;
    }
    if (server == 0) {
        const bool ok = serve_classic_none_then_unexpected(listener);
        (void)close(listener);
        _exit(ok ? 0 : 1);
    }
    (void)close(listener);

    const int code = farsee_run_rfb(
        "127.0.0.1", port, NULL, -1, true, true, 0u,
        FARSEE_AUTH_MODE_VNC, RFB_APPLE_POSTAUTH_CLEARTEXT, false, false,
        "null", 30u, true, false, NULL, 50u, 1000u, false, false);
    RFB_CHECK_EQ_INT(code, 5);
    int status = 0;
    RFB_CHECK_EQ_INT(waitpid(server, &status, 0), server);
    RFB_CHECK(WIFEXITED(status));
    RFB_CHECK_EQ_INT(WEXITSTATUS(status), 0);
}

RFB_TEST(rfb_live, run_rfb__silent_classic_peer__returns_connect_failure)
{
    uint16_t port = 0u;
    const int listener = make_loopback_listener(&port);
    RFB_CHECK(listener >= 0);
    if (listener < 0) {
        return;
    }
    stderr_capture capture;
    char diagnostic[256];
    RFB_CHECK(stderr_capture_begin(&capture));
    const int code = farsee_run_rfb(
        "127.0.0.1", port, NULL, -1, true, true, 0u,
        FARSEE_AUTH_MODE_VNC, RFB_APPLE_POSTAUTH_CLEARTEXT, false, false,
        "null", 30u, true, false, NULL, 50u, 50u, false, false);
    RFB_CHECK(stderr_capture_end(&capture, diagnostic, sizeof diagnostic));
    RFB_CHECK_EQ_INT(code, 4);
    RFB_CHECK(strstr(diagnostic, "timeout during handshake") != NULL);
    RFB_CHECK_EQ_INT(close(listener), 0);
}

RFB_TEST(rfb_live, run_rfb__raw_and_resize_frames__drive_live_workers)
{
    uint16_t port = 0u;
    int listener = make_loopback_listener(&port);
    RFB_CHECK(listener >= 0);
    if (listener < 0) {
        return;
    }
    const pid_t server = fork();
    RFB_CHECK(server >= 0);
    if (server < 0) {
        (void)close(listener);
        return;
    }
    if (server == 0) {
        const bool ok = serve_classic_frames_then_close(listener);
        (void)close(listener);
        _exit(ok ? 0 : 1);
    }
    (void)close(listener);

    const int code = farsee_run_rfb(
        "127.0.0.1", port, NULL, -1, true, true, 0u,
        FARSEE_AUTH_MODE_VNC, RFB_APPLE_POSTAUTH_CLEARTEXT, false, false,
        "null", 60u, true, false, NULL, 50u, 1000u, false, false);
    RFB_CHECK_EQ_INT(code, 5);
    int status = 0;
    RFB_CHECK_EQ_INT(waitpid(server, &status, 0), server);
    RFB_CHECK(WIFEXITED(status));
    RFB_CHECK_EQ_INT(WEXITSTATUS(status), 0);
}

RFB_TEST(rfb_live, run_rfb__zero_desktop_size__rejects_protocol_update)
{
    uint16_t port = 0u;
    int listener = make_loopback_listener(&port);
    RFB_CHECK(listener >= 0);
    if (listener < 0) {
        return;
    }
    const pid_t server = fork();
    RFB_CHECK(server >= 0);
    if (server < 0) {
        (void)close(listener);
        return;
    }
    if (server == 0) {
        const bool ok = serve_zero_desktop_size(listener);
        (void)close(listener);
        _exit(ok ? 0 : 1);
    }
    (void)close(listener);

    const int code = farsee_run_rfb(
        "127.0.0.1", port, NULL, -1, true, true, 0u,
        FARSEE_AUTH_MODE_VNC, RFB_APPLE_POSTAUTH_CLEARTEXT, false, false,
        "null", 60u, true, false, NULL, 50u, 1000u, false, false);
    RFB_CHECK_EQ_INT(code, 5);
    int status = 0;
    RFB_CHECK_EQ_INT(waitpid(server, &status, 0), server);
    RFB_CHECK(WIFEXITED(status));
    RFB_CHECK_EQ_INT(WEXITSTATUS(status), 0);
}
