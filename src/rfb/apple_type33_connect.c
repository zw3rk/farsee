// SPDX-License-Identifier: Apache-2.0
//
// farsee — Apple SRP connect sequence.
// Client banner → security list → RSA1+SRP → ClientInit → ServerInit →
// ViewerInfo handling → setup hook. I/O uses rfb_io_pump.

#include "farsee/apple_type33_connect.h"

#include "rfb/apple_type33_connect_internal.h"

#include "farsee/apple_auth.h"
#include "farsee/apple_crypto.h"
#include "farsee/apple_postauth.h"
#include "farsee/apple_type33_live.h"
#include "farsee/apple_type36_live.h"
#include "farsee/handshake.h"
#include "farsee/secret.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static rfb_error type33_send(void *ctx, const uint8_t *data, size_t n)
{
    return rfb_io_queue_bytes((rfb_io_pump *)ctx, data, n);
}

static rfb_error type33_recv(void *ctx, uint8_t *data, size_t n)
{
    return rfb_io_recv_exact((rfb_io_pump *)ctx, data, n);
}

static rfb_error apple_authenticate(
    void *ctx, uint8_t selected_type, const apple_type33_io *io,
    const uint8_t *username, size_t username_len,
    const uint8_t *password, size_t password_len,
    uint8_t wrap_key_out[16], apple_type33_kdf_material *kdf_out,
    const char *host, uint16_t port, const char *known_hosts_path,
    bool accept_new_host, rfb_allocator *allocator)
{
    (void)ctx;
    if (selected_type == 36u) {
        return apple_type36_authenticate_ex_with_allocator(
            io, username, username_len, password, password_len, wrap_key_out,
            kdf_out, allocator);
    }
    if (selected_type != 33u) {
        return RFB_ERR_UNSUPPORTED;
    }
    return apple_type33_authenticate_ex_with_allocator(
        io, username, username_len, password, password_len, wrap_key_out,
        kdf_out, host, port, known_hosts_path, accept_new_host, allocator);
}

static bool type33_random_bytes(void *ctx, uint8_t *out, size_t len)
{
    (void)ctx;
    return rfb_crypto_random_bytes(out, len);
}

static rfb_error type33_fail_after_auth(
    rfb_io_pump *pump, rfb_error error, uint8_t wrap[16],
    apple_type33_kdf_material *kdf)
{
    (void)pump;
    rfb_secret_zero(wrap, 16u);
    apple_type33_kdf_material_zero(kdf);
    return error;
}

size_t apple_viewer_info_live_ack_consume_len(const uint8_t *data, size_t len)
{
    if (data == NULL || len < 2u) {
        return 0;
    }
    // Classic FBU starts with type 0x00 and pad 0x00 — never treat as ack.
    if (data[0] == 0x00u && data[1] == 0x00u) {
        return 0;
    }
    const uint16_t body_len =
        (uint16_t)(((uint16_t)data[0] << 8) | (uint16_t)data[1]);
    // Acknowledgements use a bounded body length. Reject zero and oversize
    // values so the demultiplexer retains unrelated bytes.
    if (body_len == 0u || body_len > APPLE_VIEWER_INFO_LIVE_ACK_BODY_MAX) {
        return 0;
    }
    const size_t need = 2u + (size_t)body_len;
    if (len < need) {
        return 0;  // incomplete — leave for later demux / more I/O
    }
    return need;
}

// Preferring 36 withdraws 33 because the shared rank puts 33 first.
farsee_rfb_security_policy apple_connect_security_policy(
    const rfb_session_config *cfg)
{
    farsee_rfb_security_policy pol = farsee_rfb_security_policy_default();
    if (cfg == NULL) {
        return pol;
    }
    pol.auth_mode = cfg->auth_mode;
    pol.allow_none = cfg->allow_none_auth;
    pol.allow_vnc = (cfg->auth_mode != FARSEE_AUTH_MODE_APPLE);
    pol.allow_type_33 = !cfg->apple_prefer_type_36;
    pol.allow_type_36 = true;
    return pol;
}

bool apple_type33_known_hosts_path(char *out, size_t cap, const char *home)
{
    if (out == NULL || cap == 0u) {
        return false;
    }
    out[0] = '\0';
    if (home == NULL || home[0] == '\0') {
        return false;
    }

    const int n = snprintf(out, cap, "%s/.farsee/vnc_known_hosts", home);
    if (n < 0 || (size_t)n >= cap) {
        out[0] = '\0';
        return false;
    }
    return true;
}

rfb_error apple_type33_connect_with_ops(
    rfb_io_pump *pump, rfb_session_config *cfg,
    const apple_type33_connect_hooks *hooks,
    uint8_t wrap_key_out[16], bool *has_wrap_key_out,
    rfb_session_dialect *dialect_out, uint8_t *sk32_out,
    const apple_type33_connect_ops *ops)
{
    if (pump == NULL || pump->in == NULL || cfg == NULL || hooks == NULL ||
        hooks->setup_after_server_init == NULL || wrap_key_out == NULL ||
        has_wrap_key_out == NULL || dialect_out == NULL || ops == NULL ||
        ops->authenticate == NULL || ops->random_bytes == NULL) {
        return RFB_ERR_INTERNAL;
    }
    if (sk32_out != NULL) {
        memset(sk32_out, 0, 32);
    }

    *has_wrap_key_out = false;
    *dialect_out = RFB_SESSION_DIALECT_CLASSIC;
    memset(wrap_key_out, 0, 16);

    static const uint8_t k_client_banner[12] = {
        'R', 'F', 'B', ' ', '0', '0', '3', '.', '8', '8', '9', '\n'
    };

    rfb_error e =
        rfb_io_queue_bytes(pump, k_client_banner, sizeof k_client_banner);
    if (e != RFB_OK) {
        return e;
    }

    // Security types: u8 count + count bytes.
    uint8_t sec_count = 0;
    e = rfb_io_recv_exact(pump, &sec_count, 1u);
    if (e != RFB_OK) {
        return e;
    }
    if (sec_count == 0u) {
        // RFC 6143: count 0 means failure; reason string follows.
        if (pump->last_error != NULL) {
            *pump->last_error = RFB_ERR_AUTH;
        }
        return RFB_ERR_AUTH;
    }
    if (sec_count > 64u) {
        if (pump->last_error != NULL) {
            *pump->last_error = RFB_ERR_PROTOCOL;
        }
        return RFB_ERR_PROTOCOL;
    }
    uint8_t offered[64];
    e = rfb_io_recv_exact(pump, offered, (size_t)sec_count);
    if (e != RFB_OK) {
        return e;
    }

    const farsee_rfb_security_policy pol = apple_connect_security_policy(cfg);

    uint8_t selected = 0;
    e = farsee_rfb_select_security(offered, (size_t)sec_count, &pol, &selected);
    if (e != RFB_OK || (selected != 33u && selected != 36u)) {
        // Reject unless security type 33 or 36 was selected.
        if (pump->last_error != NULL) {
            *pump->last_error = RFB_ERR_UNSUPPORTED;
        }
        return RFB_ERR_UNSUPPORTED;
    }
    if (cfg->username == NULL || cfg->username_len == 0u) {
        if (pump->last_error != NULL) {
            *pump->last_error = RFB_ERR_AUTH;
        }
        return RFB_ERR_AUTH;
    }
    if (cfg->password == NULL || cfg->password_len == 0u) {
        if (pump->last_error != NULL) {
            *pump->last_error = RFB_ERR_AUTH;
        }
        return RFB_ERR_AUTH;
    }

    // Each branch authenticator sends its selector and first framed message;
    // do not send the selected type separately.
    apple_type33_io io;
    io.send_all = type33_send;
    io.recv_exact = type33_recv;
    io.ctx = pump;

    uint8_t wrap[16];
    memset(wrap, 0, sizeof wrap);
    // Build the optional per-user trust-store path for the server SPKI.
    char kh_path[512];
    kh_path[0] = '\0';
    {
        const char *home = getenv("HOME");
        (void)apple_type33_known_hosts_path(kh_path, sizeof kh_path, home);
    }
    apple_type33_kdf_material kdf;
    memset(&kdf, 0, sizeof kdf);
    e = ops->authenticate(
        ops->ctx, selected, &io, cfg->username, cfg->username_len,
        cfg->password,
        cfg->password_len, wrap, &kdf, cfg->host, cfg->port,
        (kh_path[0] != '\0') ? kh_path : NULL,
        cfg->accept_new_host,
        pump->alloc != NULL ? pump->alloc : rfb_default_allocator());
    if (e != RFB_OK) {
        if (pump->last_error != NULL) {
            *pump->last_error = e;
        }
        return type33_fail_after_auth(pump, e, wrap, &kdf);
    }

    // The Apple post-SecurityResult shared-session byte is 0xc1, not the
    // classic ClientInit byte 0x01. Exclusive mode is unsupported.
    {
        uint8_t ci = 0;
        size_t ci_len = 0;
        e = apple_postauth_serialize_client_init_live(cfg->shared, &ci, 1u,
                                                      &ci_len);
        if (e != RFB_OK) {
            // Fall back to the classic shared/exclusive byte only when the
            // Apple encoder rejects the requested mode.
            ci = cfg->shared ? 1u : 0u;
            ci_len = 1u;
        }
        e = rfb_io_queue_bytes(pump, &ci, ci_len);
        if (e != RFB_OK) {
            return type33_fail_after_auth(pump, e, wrap, &kdf);
        }
    }

    rfb_server_init si;
    memset(&si, 0, sizeof si);
    e = rfb_io_read_server_init(pump, &si);
    if (e != RFB_OK) {
        rfb_server_init_destroy(&si);
        return type33_fail_after_auth(pump, e, wrap, &kdf);
    }

    // Resolve ASK after ServerInit so the chooser can inspect the desktop name.
    // Use login when the choice is missing or invalid.
    {
        uint8_t attach = cfg->apple_attach;
        if (attach == APPLE_ATTACH_ASK ||
            (attach != APPLE_ATTACH_SHARE && attach != APPLE_ATTACH_LOGIN)) {
            attach = APPLE_ATTACH_LOGIN;
            if (cfg->apple_attach_choose != NULL) {
                const char *dname =
                    (si.name != NULL && si.name[0] != '\0') ? si.name : NULL;
                const char *uname = NULL;
                char uname_buf[128];
                if (cfg->username != NULL && cfg->username_len > 0u) {
                    size_t n = cfg->username_len;
                    if (n >= sizeof uname_buf) {
                        n = sizeof uname_buf - 1u;
                    }
                    memcpy(uname_buf, cfg->username, n);
                    uname_buf[n] = '\0';
                    uname = uname_buf;
                }
                uint8_t chosen = APPLE_ATTACH_LOGIN;
                if (cfg->apple_attach_choose(cfg->apple_attach_choose_ctx,
                                             dname, uname, &chosen) &&
                    (chosen == APPLE_ATTACH_SHARE ||
                     chosen == APPLE_ATTACH_LOGIN)) {
                    attach = chosen;
                }
            }
            cfg->apple_attach = attach;
        }
    }

    // Optional ViewerInfo cleartext prelude for multi-session layouts. The
    // explicit session configuration is copied before the connection starts;
    // inherited process state cannot add bytes to the transcript.
    {
        if (cfg->apple_send_viewer_info) {
            apple_viewer_info vi;
            memset(&vi, 0, sizeof vi);
            static const char k_dev[] = "farsee";
            memcpy(vi.device_name, k_dev, sizeof k_dev - 1u);
            vi.name_len = sizeof k_dev - 1u;

            uint8_t attach = cfg->apple_attach;
            if (attach != APPLE_ATTACH_LOGIN) {
                attach = APPLE_ATTACH_SHARE;
            }

            uint8_t trailer[APPLE_VIEWER_INFO_LIVE_LOGIN_TRAILER];
            const uint8_t *tr_ptr = NULL;
            size_t tr_len = 0;
            if (attach == APPLE_ATTACH_LOGIN) {
                // Fill the opaque login trailer with CSPRNG bytes; fail if generation fails.
                memset(trailer, 0, sizeof trailer);
                if (!ops->random_bytes(ops->ctx, trailer, sizeof trailer)) {
                    rfb_server_init_destroy(&si);
                    if (pump->last_error != NULL) {
                        *pump->last_error = RFB_ERR_INTERNAL;
                    }
                    return type33_fail_after_auth(
                        pump, RFB_ERR_INTERNAL, wrap, &kdf);
                }
                tr_ptr = trailer;
                tr_len = sizeof trailer;
            }

            uint8_t vi_msg[APPLE_VIEWER_INFO_LIVE_LOGIN_LEN];
            size_t vi_len = 0;
            e = apple_postauth_serialize_viewer_info_live_attach(
                &vi, attach, tr_ptr, tr_len, vi_msg, sizeof vi_msg, &vi_len);
            if (e != RFB_OK) {
                rfb_server_init_destroy(&si);
                if (pump->last_error != NULL) {
                    *pump->last_error = e;
                }
                return type33_fail_after_auth(pump, e, wrap, &kdf);
            }
            e = rfb_io_queue_bytes(pump, vi_msg, vi_len);
            if (e != RFB_OK) {
                rfb_server_init_destroy(&si);
                return type33_fail_after_auth(pump, e, wrap, &kdf);
            }
            e = rfb_io_drain_out(pump, 2000);
            if (e != RFB_OK) {
                rfb_server_init_destroy(&si);
                return type33_fail_after_auth(pump, e, wrap, &kdf);
            }

            // Peek length-prefixed server ack: u16be body_len + body.
            // A missing acknowledgement does not hard-fail this optional path.
            size_t consumed_ack = 0;
            for (int i = 0; i < 20; i++) {
                const size_t n = rfb_buffer_length(pump->in);
                const uint8_t *d = rfb_buffer_data(pump->in);
                consumed_ack = apple_viewer_info_live_ack_consume_len(d, n);
                if (consumed_ack > 0u) {
                    rfb_buffer_consume(pump->in, consumed_ack);
                    break;
                }
                if (n >= 2u) {
                    const uint16_t body_len =
                        (uint16_t)(((uint16_t)d[0] << 8) | (uint16_t)d[1]);
                    const bool looks_like_fbu =
                        (d[0] == 0x00u && d[1] == 0x00u);
                    if (looks_like_fbu || body_len == 0u ||
                        body_len > APPLE_VIEWER_INFO_LIVE_ACK_BODY_MAX) {
                        break;
                    }
                }
                e = rfb_io_read_some(pump, 100);
                if (e == RFB_ERR_TIMEOUT) {
                    break;
                }
                if (e != RFB_OK) {
                    // Other I/O errors fail the connection.
                    rfb_server_init_destroy(&si);
                    return type33_fail_after_auth(pump, e, wrap, &kdf);
                }
            }
        }
    }

    e = hooks->setup_after_server_init(hooks->ctx, &si);
    rfb_server_init_destroy(&si);
    if (e != RFB_OK) {
        return type33_fail_after_auth(pump, e, wrap, &kdf);
    }

    memcpy(wrap_key_out, wrap, 16u);
    *has_wrap_key_out = true;
    *dialect_out = RFB_SESSION_DIALECT_APPLE_CLEARTEXT_MVP;
    if (sk32_out != NULL) {
        memcpy(sk32_out, kdf.session_key_32, 32u);
    }
    rfb_secret_zero(wrap, sizeof wrap);
    apple_type33_kdf_material_zero(&kdf);

    if (pump->last_error != NULL) {
        *pump->last_error = RFB_OK;
    }
    return RFB_OK;
}

rfb_error apple_type33_connect(rfb_io_pump *pump,
                               rfb_session_config *cfg,
                               const apple_type33_connect_hooks *hooks,
                               uint8_t wrap_key_out[16],
                               bool *has_wrap_key_out,
                               rfb_session_dialect *dialect_out,
                               uint8_t *sk32_out)
{
    static const apple_type33_connect_ops ops = {
        NULL,
        apple_authenticate,
        type33_random_bytes,
    };
    return apple_type33_connect_with_ops(
        pump, cfg, hooks, wrap_key_out, has_wrap_key_out, dialect_out,
        sk32_out, &ops);
}
