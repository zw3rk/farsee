// SPDX-License-Identifier: Apache-2.0
//
// Deterministic RFB connect lifecycle and policy coverage.

#include "rfb_test.h"

#include "farsee/rfb_capture_control.h"
#include "farsee/rfb_session.h"
#include "rfb/rfb_session_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

typedef enum capture_invalid_case {
    CAPTURE_POSTAUTH_LOW = 0,
    CAPTURE_POSTAUTH_HIGH,
    CAPTURE_QUERIES_MISSING,
    CAPTURE_RESPONSE_TIMEOUT_MISSING,
    CAPTURE_QUIET_MISSING,
    CAPTURE_INITIAL_WITH_QUERY_COUNT,
    CAPTURE_INITIAL_WITH_QUERY_POINTER,
    CAPTURE_INITIAL_WITHOUT_ZRLE,
    CAPTURE_INITIAL_WITH_MUTATION,
    CAPTURE_ZRLE_WITHOUT_INITIAL,
    CAPTURE_MUTATION_WITHOUT_QUERY,
    CAPTURE_MUTATION_TIMEOUT_MISSING,
    CAPTURE_MUTATION_CONTROL_INVALID,
    CAPTURE_MUTATION_NONCE_MISSING,
    CAPTURE_MUTATION_TRANSITION_MISSING,
    CAPTURE_MUTATION_BINDING_NULL,
    CAPTURE_MUTATION_BINDING_ZERO,
} capture_invalid_case;

static bool connect_test_set_nonblocking(int fd)
{
    const int flags = fcntl(fd, F_GETFL, 0);
    return flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

static bool connect_test_control_pair(int pair[2])
{
    if (pair == NULL || socketpair(AF_UNIX, SOCK_DGRAM, 0, pair) != 0) {
        return false;
    }
    if (!connect_test_set_nonblocking(pair[0]) ||
        !connect_test_set_nonblocking(pair[1])) {
        (void)close(pair[0]);
        (void)close(pair[1]);
        pair[0] = -1;
        pair[1] = -1;
        return false;
    }
    return true;
}

static rfb_session_config connect_test_mutation_config(
    int connected_fd, int control_fd, const rfb_capture_query *query,
    const uint8_t binding[RFB_CAPTURE_CONTROL_BINDING_SIZE])
{
    rfb_session_config config;
    memset(&config, 0, sizeof config);
    config.use_connected_fd = true;
    config.connected_fd = connected_fd;
    config.auth_mode = FARSEE_AUTH_MODE_VNC;
    config.capture_queries = query;
    config.capture_query_count = 1u;
    config.capture_response_timeout_ms = 10u;
    config.capture_quiet_ms = 10u;
    config.capture_require_mutation_ack = true;
    config.capture_mutation_timeout_ms = 10u;
    config.capture_control_fd = control_fd;
    config.capture_slot_nonce = 1u;
    config.capture_transition_id = 1u;
    config.capture_source_b_binding = binding;
    return config;
}

static void connect_test_credentials_forgotten(const rfb_session *session)
{
    RFB_CHECK(session->cfg.username == NULL);
    RFB_CHECK_EQ_UINT(session->cfg.username_len, 0u);
    RFB_CHECK(session->cfg.password == NULL);
    RFB_CHECK_EQ_UINT(session->cfg.password_len, 0u);
}

static bool connect_test_tcp_pair(int *out_client, int *out_server)
{
    if (out_client == NULL || out_server == NULL) {
        return false;
    }
    *out_client = -1;
    *out_server = -1;
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) {
        return false;
    }
    struct sockaddr_in address;
    memset(&address, 0, sizeof address);
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    socklen_t length = (socklen_t)sizeof address;
    int client = -1;
    int server = -1;
    bool ok = bind(listener, (struct sockaddr *)&address, sizeof address) == 0 &&
              listen(listener, 1) == 0 &&
              getsockname(listener, (struct sockaddr *)&address, &length) == 0;
    if (ok) {
        client = socket(AF_INET, SOCK_STREAM, 0);
        ok = client >= 0 &&
             connect(client, (struct sockaddr *)&address, sizeof address) == 0;
    }
    if (ok) {
        server = accept(listener, NULL, NULL);
        ok = server >= 0;
    }
    (void)close(listener);
    if (!ok) {
        if (client >= 0) {
            (void)close(client);
        }
        if (server >= 0) {
            (void)close(server);
        }
        return false;
    }
    *out_client = client;
    *out_server = server;
    return true;
}

static bool connect_test_write_all(int fd, const uint8_t *bytes, size_t length)
{
    size_t offset = 0u;
    while (offset < length) {
        const ssize_t written = send(fd, bytes + offset, length - offset, 0);
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

static bool connect_test_read_all(int fd, uint8_t *bytes, size_t length)
{
    size_t offset = 0u;
    while (offset < length) {
        const ssize_t received = recv(fd, bytes + offset, length - offset, 0);
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

static bool connect_test_serve_fragmented_none(int peer)
{
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
    const struct timeval timeout = {
        .tv_sec = 2,
        .tv_usec = 0,
    };

    const bool prefix =
        setsockopt(peer, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout) ==
            0 &&
        setsockopt(peer, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof timeout) ==
            0 &&
        connect_test_write_all(peer, banner, 4u);
    (void)poll(NULL, 0, 25);
    return prefix &&
           connect_test_write_all(peer, banner + 4u, sizeof banner - 5u) &&
           connect_test_read_all(peer, client_banner, sizeof client_banner) &&
           memcmp(client_banner, banner, sizeof client_banner) == 0 &&
           connect_test_write_all(peer, security, sizeof security) &&
           connect_test_read_all(peer, &selection, 1u) && selection == 0x01u &&
           connect_test_write_all(peer, security_ok, sizeof security_ok) &&
           connect_test_read_all(peer, &client_init, 1u) &&
           client_init == 0x01u &&
           connect_test_write_all(peer, server_init, sizeof server_init) &&
           connect_test_read_all(peer, setup, sizeof setup) &&
           setup[0] == 0x00u && setup[20] == 0x02u && setup[44] == 0x03u;
}

static bool connect_test_prime_none_without_server_init(int peer)
{
    static const uint8_t server_prefix[] = {
        'R', 'F', 'B', ' ', '0', '0', '3', '.', '0', '0', '8', '\n',
        0x01u, 0x01u,
        0x00u, 0x00u, 0x00u, 0x00u,
    };
    return connect_test_write_all(peer, server_prefix, sizeof server_prefix) &&
           shutdown(peer, SHUT_WR) == 0;
}

static void connect_test_apply_invalid_case(
    rfb_session_config *config, capture_invalid_case invalid_case,
    const rfb_capture_query *query, const uint8_t *zero_binding)
{
    switch (invalid_case) {
    case CAPTURE_POSTAUTH_LOW:
        config->apple_postauth_mode = (rfb_apple_postauth_mode)-1;
        break;
    case CAPTURE_POSTAUTH_HIGH:
        config->apple_postauth_mode = (rfb_apple_postauth_mode)3;
        break;
    case CAPTURE_QUERIES_MISSING:
        config->capture_queries = NULL;
        break;
    case CAPTURE_RESPONSE_TIMEOUT_MISSING:
        config->capture_response_timeout_ms = 0u;
        break;
    case CAPTURE_QUIET_MISSING:
        config->capture_quiet_ms = 0u;
        break;
    case CAPTURE_INITIAL_WITH_QUERY_COUNT:
        config->capture_initial_only = true;
        config->capture_initial_zrle_only = true;
        config->capture_require_mutation_ack = false;
        break;
    case CAPTURE_INITIAL_WITH_QUERY_POINTER:
        config->capture_initial_only = true;
        config->capture_initial_zrle_only = true;
        config->capture_require_mutation_ack = false;
        config->capture_query_count = 0u;
        config->capture_queries = query;
        break;
    case CAPTURE_INITIAL_WITHOUT_ZRLE:
        config->capture_initial_only = true;
        config->capture_require_mutation_ack = false;
        config->capture_query_count = 0u;
        config->capture_queries = NULL;
        break;
    case CAPTURE_INITIAL_WITH_MUTATION:
        config->capture_initial_only = true;
        config->capture_initial_zrle_only = true;
        config->capture_query_count = 0u;
        config->capture_queries = NULL;
        break;
    case CAPTURE_ZRLE_WITHOUT_INITIAL:
        config->capture_initial_zrle_only = true;
        config->capture_require_mutation_ack = false;
        config->capture_query_count = 0u;
        config->capture_queries = NULL;
        break;
    case CAPTURE_MUTATION_WITHOUT_QUERY:
        config->capture_query_count = 0u;
        break;
    case CAPTURE_MUTATION_TIMEOUT_MISSING:
        config->capture_mutation_timeout_ms = 0u;
        break;
    case CAPTURE_MUTATION_CONTROL_INVALID:
        config->capture_control_fd = -1;
        break;
    case CAPTURE_MUTATION_NONCE_MISSING:
        config->capture_slot_nonce = 0u;
        break;
    case CAPTURE_MUTATION_TRANSITION_MISSING:
        config->capture_transition_id = 0u;
        break;
    case CAPTURE_MUTATION_BINDING_NULL:
        config->capture_source_b_binding = NULL;
        break;
    case CAPTURE_MUTATION_BINDING_ZERO:
        config->capture_source_b_binding = zero_binding;
        break;
    }
}

RFB_TEST(rfb_session_connect,
         capture_policy_matrix__rejects_each_inconsistent_config)
{
    int control[2] = {-1, -1};
    RFB_CHECK(connect_test_control_pair(control));
    if (control[0] < 0) {
        return;
    }
    int stale_fd = socket(AF_INET, SOCK_DGRAM, 0);
    RFB_CHECK(stale_fd >= 0);
    if (stale_fd < 0) {
        (void)close(control[0]);
        (void)close(control[1]);
        return;
    }
    RFB_CHECK_EQ_INT(close(stale_fd), 0);

    const rfb_capture_query query = {
        .id = 1u,
        .width = 1u,
        .height = 1u,
    };
    uint8_t binding[RFB_CAPTURE_CONTROL_BINDING_SIZE];
    uint8_t zero_binding[RFB_CAPTURE_CONTROL_BINDING_SIZE];
    memset(binding, 0x5au, sizeof binding);
    memset(zero_binding, 0, sizeof zero_binding);

    for (int value = CAPTURE_POSTAUTH_LOW;
         value <= CAPTURE_MUTATION_BINDING_ZERO; value++) {
        rfb_session session;
        rfb_session_clear(&session);
        rfb_session_config config = connect_test_mutation_config(
            stale_fd, control[0], &query, binding);
        connect_test_apply_invalid_case(
            &config, (capture_invalid_case)value, &query, zero_binding);

        RFB_CHECK_EQ_INT(rfb_session_connect_classic(&session, &config),
                         RFB_ERR_PROTOCOL);
        RFB_CHECK_EQ_INT(session.last_error, RFB_OK);
        RFB_CHECK_EQ_INT(session.sock.fd, -1);
        rfb_session_destroy(&session);
    }

    RFB_CHECK(fcntl(control[0], F_GETFD) >= 0);
    RFB_CHECK(fcntl(control[1], F_GETFD) >= 0);
    RFB_CHECK_EQ_INT(close(control[0]), 0);
    RFB_CHECK_EQ_INT(close(control[1]), 0);
}

RFB_TEST(rfb_session_connect,
         valid_mutation_policy__adopt_failure_forgets_credentials)
{
    int control[2] = {-1, -1};
    RFB_CHECK(connect_test_control_pair(control));
    if (control[0] < 0) {
        return;
    }
    int stale_fd = socket(AF_INET, SOCK_DGRAM, 0);
    RFB_CHECK(stale_fd >= 0);
    if (stale_fd < 0) {
        (void)close(control[0]);
        (void)close(control[1]);
        return;
    }
    RFB_CHECK_EQ_INT(close(stale_fd), 0);

    const rfb_capture_query query = {
        .id = 7u,
        .width = 1u,
        .height = 1u,
    };
    uint8_t binding[RFB_CAPTURE_CONTROL_BINDING_SIZE];
    memset(binding, 0xa5, sizeof binding);
    static const uint8_t username[] = "user";
    static const uint8_t password[] = "password";
    rfb_session_config config = connect_test_mutation_config(
        stale_fd, control[0], &query, binding);
    config.username = username;
    config.username_len = sizeof username - 1u;
    config.password = password;
    config.password_len = sizeof password - 1u;

    rfb_session session;
    rfb_session_clear(&session);
    RFB_CHECK_EQ_INT(rfb_session_connect_classic(&session, &config),
                     RFB_ERR_IO);
    RFB_CHECK_EQ_INT(session.last_error, RFB_ERR_IO);
    RFB_CHECK(session.cfg.capture_queries == &query);
    RFB_CHECK(session.cfg.capture_source_b_binding == binding);
    connect_test_credentials_forgotten(&session);
    rfb_session_destroy(&session);

    RFB_CHECK(fcntl(control[0], F_GETFD) >= 0);
    RFB_CHECK(fcntl(control[1], F_GETFD) >= 0);
    RFB_CHECK_EQ_INT(close(control[0]), 0);
    RFB_CHECK_EQ_INT(close(control[1]), 0);
}

RFB_TEST(rfb_session_connect,
         invalid_allocator__fails_before_io_and_forgets_credentials)
{
    rfb_allocator invalid_allocator;
    memset(&invalid_allocator, 0, sizeof invalid_allocator);
    static const uint8_t username[] = "user";
    static const uint8_t password[] = "password";
    rfb_session_config config;
    memset(&config, 0, sizeof config);
    config.allocator = &invalid_allocator;
    config.host = "127.0.0.1";
    config.username = username;
    config.username_len = sizeof username - 1u;
    config.password = password;
    config.password_len = sizeof password - 1u;
    config.auth_mode = FARSEE_AUTH_MODE_VNC;

    rfb_session session;
    rfb_session_clear(&session);
    RFB_CHECK_EQ_INT(rfb_session_connect_classic(&session, &config),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(session.last_error, RFB_ERR_INTERNAL);
    connect_test_credentials_forgotten(&session);
    rfb_session_destroy(&session);
}

RFB_TEST(rfb_session_connect,
         borrowed_udp__is_rejected_and_credentials_are_forgotten)
{
    int datagram = socket(AF_INET, SOCK_DGRAM, 0);
    RFB_CHECK(datagram >= 0);
    if (datagram < 0) {
        return;
    }
    static const uint8_t username[] = "user";
    static const uint8_t password[] = "password";
    rfb_session_config config;
    memset(&config, 0, sizeof config);
    config.use_connected_fd = true;
    config.connected_fd = datagram;
    config.username = username;
    config.username_len = sizeof username - 1u;
    config.password = password;
    config.password_len = sizeof password - 1u;
    config.auth_mode = FARSEE_AUTH_MODE_VNC;

    rfb_session session;
    rfb_session_clear(&session);
    RFB_CHECK_EQ_INT(rfb_session_connect_classic(&session, &config),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(session.last_error, RFB_ERR_PROTOCOL);
    RFB_CHECK(!session.io_open);
    connect_test_credentials_forgotten(&session);
    rfb_session_destroy(&session);

    RFB_CHECK(fcntl(datagram, F_GETFD) >= 0);
    RFB_CHECK_EQ_INT(close(datagram), 0);
}

RFB_TEST(rfb_session_connect,
         borrowed_tcp__pre_requested_stop_cancels_after_adoption)
{
    int client = -1;
    int server = -1;
    RFB_CHECK(connect_test_tcp_pair(&client, &server));
    if (client < 0 || server < 0) {
        return;
    }
    farsee_atomic_int stop;
    farsee_atomic_int_store(&stop, 1);
    static const uint8_t username[] = "user";
    static const uint8_t password[] = "password";
    rfb_session_config config;
    memset(&config, 0, sizeof config);
    config.use_connected_fd = true;
    config.connected_fd = client;
    config.username = username;
    config.username_len = sizeof username - 1u;
    config.password = password;
    config.password_len = sizeof password - 1u;
    config.auth_mode = FARSEE_AUTH_MODE_VNC;
    config.stop_flag = &stop;

    rfb_session session;
    rfb_session_clear(&session);
    RFB_CHECK_EQ_INT(rfb_session_connect(&session, &config),
                     RFB_ERR_CANCELLED);
    RFB_CHECK_EQ_INT(session.last_error, RFB_ERR_CANCELLED);
    RFB_CHECK(session.io_open);
    RFB_CHECK(!session.active);
    connect_test_credentials_forgotten(&session);
    rfb_session_destroy(&session);

    RFB_CHECK(fcntl(client, F_GETFD) >= 0);
    RFB_CHECK_EQ_INT(close(client), 0);
    RFB_CHECK_EQ_INT(close(server), 0);
}

RFB_TEST(rfb_session_connect,
         fragmented_classic_handshake__activates_and_forgets_credentials)
{
    int client = -1;
    int server = -1;
    RFB_CHECK(connect_test_tcp_pair(&client, &server));
    if (client < 0 || server < 0) {
        return;
    }
    const pid_t child = fork();
    RFB_CHECK(child >= 0);
    if (child < 0) {
        (void)close(client);
        (void)close(server);
        return;
    }
    if (child == 0) {
        (void)close(client);
        const bool ok = connect_test_serve_fragmented_none(server);
        (void)close(server);
        _exit(ok ? 0 : 1);
    }
    (void)close(server);

    static const uint8_t username[] = "user";
    static const uint8_t password[] = "password";
    rfb_session_config config;
    memset(&config, 0, sizeof config);
    config.use_connected_fd = true;
    config.connected_fd = client;
    config.username = username;
    config.username_len = sizeof username - 1u;
    config.password = password;
    config.password_len = sizeof password - 1u;
    config.allow_none_auth = true;
    config.shared = true;
    config.auth_mode = FARSEE_AUTH_MODE_VNC;
    config.connect_timeout_ms = 1000u;

    rfb_session session;
    rfb_session_clear(&session);
    RFB_CHECK_EQ_INT(rfb_session_connect(&session, &config), RFB_OK);
    RFB_CHECK_EQ_INT(session.last_error, RFB_OK);
    RFB_CHECK(session.io_open);
    RFB_CHECK(session.active);
    RFB_CHECK_EQ_UINT(session.fb.width, 1u);
    RFB_CHECK_EQ_UINT(session.fb.height, 1u);
    connect_test_credentials_forgotten(&session);
    rfb_session_destroy(&session);

    RFB_CHECK(fcntl(client, F_GETFD) >= 0);
    RFB_CHECK_EQ_INT(close(client), 0);
    int status = 0;
    RFB_CHECK_EQ_INT(waitpid(child, &status, 0), child);
    RFB_CHECK(WIFEXITED(status));
    RFB_CHECK_EQ_INT(WEXITSTATUS(status), 0);
}

RFB_TEST(rfb_session_connect,
         internal_helpers__cover_null_inactive_and_stop_states)
{
    rfb_session_internal_flush_output(NULL, 0);
    RFB_CHECK(!rfb_session_internal_stop_requested(NULL));

    rfb_session session;
    rfb_session_clear(&session);
    rfb_session_internal_flush_output(&session, 0);
    RFB_CHECK(!rfb_session_internal_stop_requested(&session));

    farsee_atomic_int stop;
    farsee_atomic_int_store(&stop, 0);
    session.cfg.stop_flag = &stop;
    RFB_CHECK(!rfb_session_internal_stop_requested(&session));
    farsee_atomic_int_store(&stop, 1);
    RFB_CHECK(rfb_session_internal_stop_requested(&session));
}

RFB_TEST(rfb_session_connect,
         named_tcp__invalid_numeric_host_fails_resolution)
{
    static const uint8_t username[] = "user";
    static const uint8_t password[] = "password";
    rfb_session_config config;
    memset(&config, 0, sizeof config);
    config.host = "256.256.256.256";
    config.port = 5900u;
    config.auth_mode = FARSEE_AUTH_MODE_VNC;
    config.username = username;
    config.username_len = sizeof username - 1u;
    config.password = password;
    config.password_len = sizeof password - 1u;

    rfb_session session;
    rfb_session_clear(&session);
    RFB_CHECK_EQ_INT(rfb_session_connect_classic(&session, &config),
                     RFB_ERR_IO);
    RFB_CHECK_EQ_INT(session.last_error, RFB_ERR_IO);
    RFB_CHECK_EQ_INT(session.sock.fd, -1);
    connect_test_credentials_forgotten(&session);
    rfb_session_destroy(&session);
}

RFB_TEST(rfb_session_connect,
         named_tcp__pre_requested_stop_cancels_before_connect)
{
    farsee_atomic_int stop;
    farsee_atomic_int_store(&stop, 1);
    static const uint8_t username[] = "user";
    static const uint8_t password[] = "password";
    rfb_session_config config;
    memset(&config, 0, sizeof config);
    config.host = "127.0.0.1";
    config.port = 1u;
    config.auth_mode = FARSEE_AUTH_MODE_VNC;
    config.stop_flag = &stop;
    config.username = username;
    config.username_len = sizeof username - 1u;
    config.password = password;
    config.password_len = sizeof password - 1u;

    rfb_session session;
    rfb_session_clear(&session);
    RFB_CHECK_EQ_INT(rfb_session_connect_classic(&session, &config),
                     RFB_ERR_CANCELLED);
    RFB_CHECK_EQ_INT(session.last_error, RFB_ERR_CANCELLED);
    RFB_CHECK_EQ_INT(session.sock.fd, -1);
    connect_test_credentials_forgotten(&session);
    rfb_session_destroy(&session);
}

RFB_TEST(rfb_session_connect,
         classic_apple_mode__null_session_is_still_unsupported)
{
    rfb_session_config config;
    memset(&config, 0, sizeof config);
    config.host = "127.0.0.1";
    config.auth_mode = FARSEE_AUTH_MODE_APPLE;
    RFB_CHECK_EQ_INT(rfb_session_connect_classic(NULL, &config),
                     RFB_ERR_UNSUPPORTED);
}

RFB_TEST(rfb_session_connect,
         generic_connect__peer_eof_before_banner_is_reported)
{
    int client = -1;
    int server = -1;
    RFB_CHECK(connect_test_tcp_pair(&client, &server));
    if (client < 0 || server < 0) {
        return;
    }
    RFB_CHECK_EQ_INT(shutdown(server, SHUT_WR), 0);

    rfb_session_config config;
    memset(&config, 0, sizeof config);
    config.use_connected_fd = true;
    config.connected_fd = client;
    config.auth_mode = FARSEE_AUTH_MODE_VNC;
    config.connect_timeout_ms = 500u;

    rfb_session session;
    rfb_session_clear(&session);
    RFB_CHECK_EQ_INT(rfb_session_connect(&session, &config), RFB_ERR_EOF);
    RFB_CHECK_EQ_INT(session.last_error, RFB_ERR_EOF);
    RFB_CHECK(!session.active);
    rfb_session_destroy(&session);

    RFB_CHECK(fcntl(client, F_GETFD) >= 0);
    RFB_CHECK_EQ_INT(close(client), 0);
    RFB_CHECK_EQ_INT(close(server), 0);
}

RFB_TEST(rfb_session_connect,
         classic_connect__peer_eof_before_server_init_is_reported)
{
    int client = -1;
    int server = -1;
    RFB_CHECK(connect_test_tcp_pair(&client, &server));
    if (client < 0 || server < 0) {
        return;
    }
    RFB_CHECK(connect_test_prime_none_without_server_init(server));

    rfb_session_config config;
    memset(&config, 0, sizeof config);
    config.use_connected_fd = true;
    config.connected_fd = client;
    config.auth_mode = FARSEE_AUTH_MODE_VNC;
    config.allow_none_auth = true;
    config.connect_timeout_ms = 500u;

    rfb_session session;
    rfb_session_clear(&session);
    RFB_CHECK_EQ_INT(rfb_session_connect_classic(&session, &config),
                     RFB_ERR_EOF);
    RFB_CHECK_EQ_INT(session.last_error, RFB_ERR_EOF);
    RFB_CHECK(!session.active);
    rfb_session_destroy(&session);

    RFB_CHECK(fcntl(client, F_GETFD) >= 0);
    RFB_CHECK_EQ_INT(close(client), 0);
    RFB_CHECK_EQ_INT(close(server), 0);
}

RFB_TEST(rfb_session_connect,
         generic_connect__peer_eof_before_server_init_is_reported)
{
    int client = -1;
    int server = -1;
    RFB_CHECK(connect_test_tcp_pair(&client, &server));
    if (client < 0 || server < 0) {
        return;
    }
    RFB_CHECK(connect_test_prime_none_without_server_init(server));

    rfb_session_config config;
    memset(&config, 0, sizeof config);
    config.use_connected_fd = true;
    config.connected_fd = client;
    config.auth_mode = FARSEE_AUTH_MODE_VNC;
    config.allow_none_auth = true;
    config.connect_timeout_ms = 500u;

    rfb_session session;
    rfb_session_clear(&session);
    RFB_CHECK_EQ_INT(rfb_session_connect(&session, &config), RFB_ERR_EOF);
    RFB_CHECK_EQ_INT(session.last_error, RFB_ERR_EOF);
    RFB_CHECK(!session.active);
    rfb_session_destroy(&session);

    RFB_CHECK(fcntl(client, F_GETFD) >= 0);
    RFB_CHECK_EQ_INT(close(client), 0);
    RFB_CHECK_EQ_INT(close(server), 0);
}
