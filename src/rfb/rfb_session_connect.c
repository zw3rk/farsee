// SPDX-License-Identifier: Apache-2.0
//
// RFB session transport, handshake, and connect lifecycle ownership.

#include "rfb/rfb_session_internal.h"
#include "rfb/rfb_session_math.h"

#include "farsee/allocator.h"
#include "farsee/apple_auth.h"
#include "farsee/apple_type33_connect.h"
#include "farsee/buffer.h"
#include "farsee/farsee_input.h"
#include "farsee/handshake.h"
#include "farsee/limits.h"
#if defined(FARSEE_ENABLE_CAPTURE_DIAGNOSTICS) || \
    defined(FARSEE_TEST_CAPTURE_DIAGNOSTICS)
#include "farsee/rfb_capture_control.h"
#endif
#include "farsee/rfb_io_pump.h"
#include "farsee/secret.h"
#include "farsee/server_init.h"
#include "farsee/socket_posix.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define RFB_SESSION_CANDIDATES_MAX 16u

rfb_io_pump rfb_session_internal_pump(rfb_session *session)
{
    rfb_io_pump pump;
    memset(&pump, 0, sizeof pump);
    pump.alloc = session->alloc;
    pump.io = &session->io;
    pump.fd = session->sock.fd;
    pump.in = &session->in;
    pump.out = &session->out;
    pump.last_error = &session->last_error;
    pump.stop_flag = session->cfg.stop_flag;
    pump.deadline_mono_ms = session->connect_deadline_mono_ms;
    return pump;
}

void rfb_session_internal_flush_output(rfb_session *session, int timeout_ms)
{
    if (session == NULL || !session->io_open) {
        return;
    }
    rfb_io_pump pump = rfb_session_internal_pump(session);
    (void)rfb_io_drain_out(&pump, timeout_ms);
}

bool rfb_session_internal_stop_requested(const rfb_session *session)
{
    return session != NULL &&
           farsee_atomic_int_load_nonzero(session->cfg.stop_flag);
}

static void forget_borrowed_credentials(rfb_session *session)
{
    if (session == NULL) {
        return;
    }
    session->cfg.username = NULL;
    session->cfg.username_len = 0u;
    session->cfg.password = NULL;
    session->cfg.password_len = 0u;
}

static rfb_error connect_tcp(rfb_session *session, const char *host,
                             uint16_t port)
{
    rfb_io_candidate candidates[RFB_SESSION_CANDIDATES_MAX];
    size_t count = RFB_SESSION_CANDIDATES_MAX;
    rfb_error error = rfb_resolve_candidates(host, port, candidates, &count);
    if (error != RFB_OK) {
        session->last_error = error;
        return error;
    }
    if (count == 0u) {
        session->last_error = RFB_ERR_IO;
        return RFB_ERR_IO;
    }
    session->io = rfb_socket_adapter_make(&session->sock);
    session->sock.connect_deadline_mono_ms =
        session->connect_deadline_mono_ms;
    session->sock.connect_stop = session->cfg.stop_flag;
    for (size_t i = 0u; i < count; i++) {
        if (rfb_session_internal_stop_requested(session)) {
            session->last_error = RFB_ERR_CANCELLED;
            return RFB_ERR_CANCELLED;
        }
        if (session->connect_deadline_mono_ms != 0u &&
            rfb_io_mono_ms() >= session->connect_deadline_mono_ms) {
            session->last_error = RFB_ERR_TIMEOUT;
            return RFB_ERR_TIMEOUT;
        }
        if (session->io.connect(session->io.ctx, &candidates[i]) ==
            RFB_IO_OK) {
            session->io_open = true;
            (void)rfb_socket_set_nodelay(&session->sock);
            return RFB_OK;
        }
        if (session->sock.fd >= 0) {
            session->io.close(session->io.ctx);
            session->sock.fd = -1;
        }
    }
    if (rfb_session_internal_stop_requested(session)) {
        session->last_error = RFB_ERR_CANCELLED;
        return RFB_ERR_CANCELLED;
    }
    if (session->connect_deadline_mono_ms != 0u &&
        rfb_io_mono_ms() >= session->connect_deadline_mono_ms) {
        session->last_error = RFB_ERR_TIMEOUT;
        return RFB_ERR_TIMEOUT;
    }
    session->last_error = RFB_ERR_IO;
    return RFB_ERR_IO;
}

static rfb_error adopt_connected_tcp(rfb_session *session, int borrowed_fd)
{
    if (borrowed_fd < 0) {
        session->last_error = RFB_ERR_PROTOCOL;
        return RFB_ERR_PROTOCOL;
    }
    const int owned_fd = fcntl(borrowed_fd, F_DUPFD_CLOEXEC, 3);
    if (owned_fd < 0) {
        session->last_error = RFB_ERR_IO;
        return RFB_ERR_IO;
    }

    int socket_type = 0;
    socklen_t socket_type_length = (socklen_t)sizeof socket_type;
    int socket_error = 0;
    socklen_t socket_error_length = (socklen_t)sizeof socket_error;
    struct sockaddr_storage peer;
    socklen_t peer_length = (socklen_t)sizeof peer;
    memset(&peer, 0, sizeof peer);
    if (getsockopt(owned_fd, SOL_SOCKET, SO_TYPE, &socket_type,
                   &socket_type_length) != 0 || socket_type != SOCK_STREAM ||
        getpeername(owned_fd, (struct sockaddr *)(void *)&peer,
                    &peer_length) != 0 ||
        (peer.ss_family != AF_INET && peer.ss_family != AF_INET6) ||
        getsockopt(owned_fd, SOL_SOCKET, SO_ERROR, &socket_error,
                   &socket_error_length) != 0 || socket_error != 0) {
        (void)close(owned_fd);
        session->last_error = RFB_ERR_PROTOCOL;
        return RFB_ERR_PROTOCOL;
    }
    // TCP_NODELAY distinguishes the required TCP transport from another
    // AF_INET/AF_INET6 stream protocol. The duplicate owns only lifetime.
    rfb_socket_ctx candidate;
    memset(&candidate, 0, sizeof candidate);
    candidate.fd = owned_fd;
    if (!rfb_socket_set_nodelay(&candidate)) {
        (void)close(owned_fd);
        session->last_error = RFB_ERR_PROTOCOL;
        return RFB_ERR_PROTOCOL;
    }
    const int flags = fcntl(owned_fd, F_GETFL, 0);
    if (flags < 0 || fcntl(owned_fd, F_SETFL, flags | O_NONBLOCK) != 0) {
        (void)close(owned_fd);
        session->last_error = RFB_ERR_IO;
        return RFB_ERR_IO;
    }

    session->io = rfb_socket_adapter_make(&session->sock);
    session->sock.fd = owned_fd;
    session->sock.nonblocking = true;
    session->io_open = true;
    return RFB_OK;
}

static rfb_error run_handshake(rfb_session *session)
{
    if (session->cfg.auth_mode == FARSEE_AUTH_MODE_APPLE) {
        session->last_error = RFB_ERR_UNSUPPORTED;
        return RFB_ERR_UNSUPPORTED;
    }

    rfb_handshake_policy policy = rfb_handshake_policy_default();
    policy.allow_none_auth = session->cfg.allow_none_auth;
    policy.shared_flag = session->cfg.shared;
    policy.allow_vnc_auth = true;

    rfb_handshake handshake;
    rfb_handshake_init(&handshake, &policy, session->alloc);
    if (session->cfg.password != NULL && session->cfg.password_len > 0u) {
        rfb_handshake_set_password(&handshake, session->cfg.password,
                                   session->cfg.password_len);
    }

    rfb_io_pump pump = rfb_session_internal_pump(session);
    rfb_error error = RFB_OK;
    for (int i = 0; i < 10000 && !rfb_handshake_finished(&handshake); i++) {
        if (rfb_session_internal_stop_requested(session)) {
            error = RFB_ERR_CANCELLED;
            break;
        }
        if (session->connect_deadline_mono_ms != 0u &&
            rfb_io_mono_ms() >= session->connect_deadline_mono_ms) {
            error = RFB_ERR_TIMEOUT;
            break;
        }
        error = rfb_io_drain_out(&pump, 1000);
        if (error != RFB_OK) {
            break;
        }
        const rfb_hs_state state_before = handshake.state;
        const size_t input_before = rfb_buffer_length(&session->in);
        error = rfb_handshake_step(&handshake, &session->in, &session->out);
        if (error != RFB_OK || rfb_handshake_finished(&handshake)) {
            break;
        }
        if (handshake.state != state_before ||
            rfb_buffer_length(&session->in) != input_before) {
            continue;
        }

        int poll_ms = 2000;
        if (session->connect_deadline_mono_ms != 0u) {
            const uint64_t now = rfb_io_mono_ms();
            if (now >= session->connect_deadline_mono_ms) {
                error = RFB_ERR_TIMEOUT;
                break;
            }
            const uint64_t left = session->connect_deadline_mono_ms - now;
            if (left < 2000u) {
                poll_ms = (int)left;
                if (poll_ms < 1) {
                    poll_ms = 1;
                }
            }
        }
        error = rfb_io_read_some(&pump, poll_ms);
        if (error != RFB_OK) {
            break;
        }
    }

    // Every transition to FAILED returns its error from rfb_handshake_step.
    // Reaching this point with RFB_OK therefore means either DONE or that the
    // bounded loop ended before the handshake reached a terminal state.
    if (error == RFB_OK && handshake.state != RFB_HS_DONE) {
        error = RFB_ERR_TIMEOUT;
    }
    session->last_error = error;
    rfb_handshake_destroy(&handshake);
    return error;
}

static rfb_error session_setup_hook(void *opaque,
                                    const rfb_server_init *server_init)
{
    return rfb_session_internal_setup_after_server_init(
        (rfb_session *)opaque, server_init);
}

static rfb_error run_apple_type33(rfb_session *session)
{
    rfb_io_pump pump = rfb_session_internal_pump(session);
    apple_type33_connect_hooks hooks;
    memset(&hooks, 0, sizeof hooks);
    hooks.ctx = session;
    hooks.setup_after_server_init = session_setup_hook;

    uint8_t wrap[16];
    uint8_t sk32[32];
    bool has_wrap = false;
    rfb_session_dialect dialect = RFB_SESSION_DIALECT_CLASSIC;
    session->dialect = RFB_SESSION_DIALECT_APPLE_CLEARTEXT_MVP;
    rfb_error error = apple_type33_connect(
        &pump, &session->cfg, &hooks, wrap, &has_wrap, &dialect, sk32);
    if (error != RFB_OK) {
        session->dialect = RFB_SESSION_DIALECT_CLASSIC;
        rfb_secret_zero(wrap, sizeof wrap);
        rfb_secret_zero(sk32, sizeof sk32);
        return error;
    }

    if (has_wrap) {
        memcpy(session->wrap_key, wrap, sizeof session->wrap_key);
        session->has_wrap_key = true;
        memcpy(session->apple_sk32, sk32, sizeof session->apple_sk32);
        session->apple_have_sk32 = true;
    }
    rfb_secret_zero(wrap, sizeof wrap);
    rfb_secret_zero(sk32, sizeof sk32);
    session->dialect = dialect;

    if (session->cfg.apple_postauth_mode != RFB_APPLE_POSTAUTH_CLEARTEXT) {
        if (!session->has_wrap_key) {
            fprintf(stderr,
                    "farsee: Apple record mode requires wrap_key material; "
                    "refusing cleartext fallback\n");
            (void)fflush(stderr);
            session->last_error = RFB_ERR_STATE;
            return RFB_ERR_STATE;
        }
        error = rfb_session_internal_enable_apple_records(session);
        if (error != RFB_OK) {
            session->last_error = error;
            return error;
        }
    }

    session->connect_deadline_mono_ms = 0u;
    session->active = true;
    session->last_error = RFB_OK;
    return RFB_OK;
}

#if defined(FARSEE_ENABLE_CAPTURE_DIAGNOSTICS) || \
    defined(FARSEE_TEST_CAPTURE_DIAGNOSTICS)
static bool capture_binding_nonzero(const uint8_t *binding)
{
    if (binding == NULL) {
        return false;
    }
    uint8_t any = 0u;
    for (size_t i = 0u; i < RFB_CAPTURE_CONTROL_BINDING_SIZE; i++) {
        any |= binding[i];
    }
    return any != 0u;
}
#endif

static rfb_error session_prepare(rfb_session *session,
                                 const rfb_session_config *config)
{
    if (session == NULL || config == NULL) {
        return RFB_ERR_INTERNAL;
    }
    if ((!config->use_connected_fd &&
         (config->host == NULL || config->host[0] == '\0')) ||
        (config->use_connected_fd &&
         (config->connected_fd < 0 || config->host != NULL ||
          config->port != 0u))) {
        return RFB_ERR_INTERNAL;
    }
    if (config->apple_postauth_mode < RFB_APPLE_POSTAUTH_CLEARTEXT ||
        config->apple_postauth_mode > RFB_APPLE_POSTAUTH_PRIVATE_ENCODINGS) {
        return RFB_ERR_PROTOCOL;
    }
    const bool capture_requested = config->capture_query_count > 0u ||
                                   config->capture_initial_only;
    if (capture_requested &&
        ((config->capture_query_count > 0u &&
          config->capture_queries == NULL) ||
         config->capture_response_timeout_ms == 0u ||
         config->capture_quiet_ms == 0u)) {
        return RFB_ERR_PROTOCOL;
    }
    if (config->capture_initial_only &&
        (config->capture_query_count != 0u ||
         config->capture_queries != NULL ||
         !config->capture_initial_zrle_only ||
         config->capture_require_mutation_ack)) {
        return RFB_ERR_PROTOCOL;
    }
    if (!config->capture_initial_only && config->capture_initial_zrle_only) {
        return RFB_ERR_PROTOCOL;
    }
#if defined(FARSEE_ENABLE_CAPTURE_DIAGNOSTICS) || \
    defined(FARSEE_TEST_CAPTURE_DIAGNOSTICS)
    if (config->capture_require_mutation_ack &&
        (config->capture_query_count == 0u ||
         config->capture_mutation_timeout_ms == 0u ||
         !rfb_capture_control_endpoint_valid(config->capture_control_fd) ||
         config->capture_slot_nonce == 0u ||
         config->capture_transition_id == 0u ||
         !capture_binding_nonzero(config->capture_source_b_binding))) {
        return RFB_ERR_PROTOCOL;
    }
#else
    if (config->capture_require_mutation_ack) {
        return RFB_ERR_UNSUPPORTED;
    }
#endif

    memset(session, 0, sizeof *session);
    session->sock.fd = -1;
    session->transport_tx_bytes = &session->sock.tx_bytes;
    session->cfg = *config;
    session->alloc = config->allocator != NULL
                         ? config->allocator
                         : rfb_default_allocator();
    if (session->alloc->alloc == NULL || session->alloc->free == NULL) {
        session->last_error = RFB_ERR_INTERNAL;
        forget_borrowed_credentials(session);
        return RFB_ERR_INTERNAL;
    }
    farsee_key_ledger_init(&session->key_ledger);
    rfb_clip_loop_init(&session->clipboard_loop);
    session->held_buttons = 0u;
    session->connect_deadline_mono_ms = rfb_session_connect_deadline(
        rfb_io_mono_ms(), config->connect_timeout_ms);
    rfb_buffer_init(&session->in, session->alloc, RFB_LIMIT_FB_BYTES_POLICY);
    rfb_buffer_init(&session->out, session->alloc,
                    RFB_LIMIT_OUTBOUND_BYTES);
    rfb_framebuffer_init(&session->fb, session->alloc);

    rfb_error error;
    if (config->use_connected_fd) {
        error = adopt_connected_tcp(session, config->connected_fd);
    } else {
        const uint16_t port =
            config->port != 0u ? config->port : (uint16_t)5900u;
        error = connect_tcp(session, config->host, port);
    }
    if (error != RFB_OK) {
        forget_borrowed_credentials(session);
    }
    return error;
}

rfb_error rfb_session_connect_classic(rfb_session *session,
                                      const rfb_session_config *config)
{
    if (config != NULL && config->auth_mode == FARSEE_AUTH_MODE_APPLE) {
        if (session != NULL) {
            session->last_error = RFB_ERR_UNSUPPORTED;
        }
        return RFB_ERR_UNSUPPORTED;
    }

    rfb_error error = session_prepare(session, config);
    if (error != RFB_OK) {
        return error;
    }
    error = run_handshake(session);
    if (error != RFB_OK) {
        goto done;
    }

    const uint8_t client_init = config->shared ? 1u : 0u;
    error = session_queue_bytes(session, &client_init, 1u);
    if (error != RFB_OK) {
        goto done;
    }

    rfb_server_init server_init;
    memset(&server_init, 0, sizeof server_init);
    rfb_io_pump pump = rfb_session_internal_pump(session);
    error = rfb_io_read_server_init(&pump, &server_init);
    if (error != RFB_OK) {
        rfb_server_init_destroy(&server_init);
        goto done;
    }
    error = rfb_session_internal_setup_after_server_init(session,
                                                         &server_init);
    rfb_server_init_destroy(&server_init);
    if (error != RFB_OK) {
        goto done;
    }

    session->connect_deadline_mono_ms = 0u;
    session->active = true;
    session->last_error = RFB_OK;
done:
    forget_borrowed_credentials(session);
    return error;
}

rfb_error rfb_session_connect(rfb_session *session,
                              const rfb_session_config *config)
{
    rfb_error error = session_prepare(session, config);
    if (error != RFB_OK) {
        return error;
    }

    uint8_t banner[12];
    rfb_io_pump pump = rfb_session_internal_pump(session);
    for (int i = 0; i < 10000; i++) {
        if (rfb_session_internal_stop_requested(session)) {
            error = RFB_ERR_CANCELLED;
            break;
        }
        if (session->connect_deadline_mono_ms != 0u &&
            rfb_io_mono_ms() >= session->connect_deadline_mono_ms) {
            error = RFB_ERR_TIMEOUT;
            break;
        }
        if (rfb_buffer_length(&session->in) >= sizeof banner) {
            memcpy(banner, rfb_buffer_data(&session->in), sizeof banner);
            error = RFB_OK;
            break;
        }
        int poll_ms = 2000;
        if (session->connect_deadline_mono_ms != 0u) {
            const uint64_t now = rfb_io_mono_ms();
            if (now >= session->connect_deadline_mono_ms) {
                error = RFB_ERR_TIMEOUT;
                break;
            }
            const uint64_t left = session->connect_deadline_mono_ms - now;
            if (left < 2000u) {
                poll_ms = (int)left;
                if (poll_ms < 1) {
                    poll_ms = 1;
                }
            }
        }
        error = rfb_io_read_some(&pump, poll_ms);
        if (error != RFB_OK) {
            break;
        }
        error = RFB_ERR_TIMEOUT;
    }
    if (error != RFB_OK) {
        session->last_error = error;
        goto done;
    }

    const bool apple_banner =
        apple_is_dialect_003_889(banner, sizeof banner);
    if (rfb_session_prefer_apple_path(apple_banner, config->auth_mode)) {
        rfb_buffer_consume(&session->in, sizeof banner);
        error = run_apple_type33(session);
        goto done;
    }

    error = run_handshake(session);
    if (error != RFB_OK) {
        goto done;
    }
    const uint8_t client_init = config->shared ? 1u : 0u;
    error = session_queue_bytes(session, &client_init, 1u);
    if (error != RFB_OK) {
        goto done;
    }

    rfb_server_init server_init;
    memset(&server_init, 0, sizeof server_init);
    pump = rfb_session_internal_pump(session);
    error = rfb_io_read_server_init(&pump, &server_init);
    if (error != RFB_OK) {
        rfb_server_init_destroy(&server_init);
        goto done;
    }
    error = rfb_session_internal_setup_after_server_init(session,
                                                         &server_init);
    rfb_server_init_destroy(&server_init);
    if (error != RFB_OK) {
        goto done;
    }

    session->connect_deadline_mono_ms = 0u;
    session->active = true;
    session->last_error = RFB_OK;
done:
    forget_borrowed_credentials(session);
    return error;
}
