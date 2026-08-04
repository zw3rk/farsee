// SPDX-License-Identifier: Apache-2.0
//
// farsee — Apple type-33 connect sequence (extracted from rfb_session).
// Banner reply → security list → RSA1+SRP → ClientInit → ServerInit →
// ViewerInfo → setup hook. I/O via rfb_io_pump; no session struct here.

#include "farsee/apple_type33_connect.h"

#include "farsee/apple_auth.h"
#include "farsee/apple_crypto.h"
#include "farsee/apple_postauth.h"
#include "farsee/apple_type33_live.h"
#include "farsee/handshake.h"
#include "farsee/secret.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool type33_debug_enabled(void)
{
    static int cached = -1;
    if (cached < 0) {
        const char *e = getenv("FARSEE_RFB_DEBUG");
        cached = (e != NULL && e[0] != '\0') ? 1 : 0;
    }
    return cached != 0;
}

static rfb_error type33_send(void *ctx, const uint8_t *data, size_t n)
{
    return rfb_io_queue_bytes((rfb_io_pump *)ctx, data, n);
}

static rfb_error type33_recv(void *ctx, uint8_t *data, size_t n)
{
    return rfb_io_recv_exact((rfb_io_pump *)ctx, data, n);
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
    // CAPTURED / live acks use body_len in a small observed range
    // (0x4a..0x50+). Reject zero and oversize so demux keeps the bytes.
    if (body_len == 0u || body_len > APPLE_VIEWER_INFO_LIVE_ACK_BODY_MAX) {
        return 0;
    }
    const size_t need = 2u + (size_t)body_len;
    if (len < need) {
        return 0;  // incomplete — leave for later demux / more I/O
    }
    return need;
}

rfb_error apple_type33_connect(rfb_io_pump *pump,
                               rfb_session_config *cfg,
                               const apple_type33_connect_hooks *hooks,
                               uint8_t wrap_key_out[16],
                               bool *has_wrap_key_out,
                               rfb_session_dialect *dialect_out)
{
    if (pump == NULL || pump->in == NULL || cfg == NULL || hooks == NULL ||
        hooks->setup_after_server_init == NULL || wrap_key_out == NULL ||
        has_wrap_key_out == NULL || dialect_out == NULL) {
        return RFB_ERR_INTERNAL;
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

    farsee_rfb_security_policy pol = farsee_rfb_security_policy_default();
    pol.auth_mode = cfg->auth_mode;
    pol.allow_none = cfg->allow_none_auth;
    pol.allow_vnc = (cfg->auth_mode != FARSEE_AUTH_MODE_APPLE);
    pol.allow_type_33 = true;

    uint8_t selected = 0;
    e = farsee_rfb_select_security(offered, (size_t)sec_count, &pol, &selected);
    if (e != RFB_OK || selected != 33u) {
        // MVP: Apple banner without type 33 (or classic-only selection)
        // is not mid-wired. Fail closed with a clear unsupported error.
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

    // Branch entry: apple_type33_authenticate sends the 15-byte key
    // request (includes selector 0x21). Do NOT send type 33 separately.
    apple_type33_io io;
    io.send_all = type33_send;
    io.recv_exact = type33_recv;
    io.ctx = pump;

    uint8_t wrap[16];
    memset(wrap, 0, sizeof wrap);
    // TOFU store for type-33 SPKI (parity with RDP known_hosts).
    char kh_path[512];
    kh_path[0] = '\0';
    {
        const char *home = getenv("HOME");
        if (home != NULL && home[0] != '\0') {
            (void)snprintf(kh_path, sizeof kh_path,
                           "%s/.farsee/vnc_known_hosts", home);
        }
    }
    e = apple_type33_authenticate(
        &io, cfg->username, cfg->username_len, cfg->password, cfg->password_len,
        wrap, cfg->host, cfg->port,
        (kh_path[0] != '\0') ? kh_path : NULL);
    if (e != RFB_OK) {
        rfb_secret_zero(wrap, sizeof wrap);
        if (pump->last_error != NULL) {
            *pump->last_error = e;
        }
        return e;
    }

    memcpy(wrap_key_out, wrap, 16);
    rfb_secret_zero(wrap, sizeof wrap);
    *has_wrap_key_out = true;  // secret presence only
    *dialect_out = RFB_SESSION_DIALECT_APPLE_CLEARTEXT_MVP;

    // CAPTURED E8: post-SecurityResult client byte is 0xc1 (shared), not
    // classic ClientInit 0x01. Exclusive live byte is unsupported.
    {
        uint8_t ci = 0;
        size_t ci_len = 0;
        e = apple_postauth_serialize_client_init_live(cfg->shared, &ci, 1u,
                                                      &ci_len);
        if (e != RFB_OK) {
            // Fall back to classic shared/exclusive only if live encode
            // rejects (exclusive). Prefer CAPTURED path when shared.
            ci = cfg->shared ? 1u : 0u;
            ci_len = 1u;
            e = RFB_OK;
        }
        e = rfb_io_queue_bytes(pump, &ci, ci_len);
        if (e != RFB_OK) {
            return e;
        }
    }

    rfb_server_init si;
    memset(&si, 0, sizeof si);
    e = rfb_io_read_server_init(pump, &si);
    if (e != RFB_OK) {
        rfb_server_init_destroy(&si);
        return e;
    }

    // Resolve attach mode after ServerInit so ASK can show desktop name
    // (Apple-like "X is using the display"). Default when unresolved: login.
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

    // CAPTURED E8/E9: cleartext ViewerInfo after ServerInit.
    // Share (mode 1, 74 B) vs Login (mode 2, 202 B + 128 B trailer).
    {
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
            // Trailer generation is not yet CAPTURED; use CSPRNG so the
            // message shape matches E9. If the peer rejects, fail closed.
            memset(trailer, 0, sizeof trailer);
            if (!rfb_crypto_random_bytes(trailer, sizeof trailer)) {
                rfb_server_init_destroy(&si);
                if (pump->last_error != NULL) {
                    *pump->last_error = RFB_ERR_INTERNAL;
                }
                return RFB_ERR_INTERNAL;
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
            return e;
        }
        e = rfb_io_queue_bytes(pump, vi_msg, vi_len);
        if (e != RFB_OK) {
            rfb_server_init_destroy(&si);
            return e;
        }
        if (type33_debug_enabled()) {
            fprintf(stderr,
                    "farsee rfb debug: ViewerInfo attach=%u len=%zu\n",
                    (unsigned)attach, vi_len);
            (void)fflush(stderr);
        }
        e = rfb_io_drain_out(pump, 2000);
        if (e != RFB_OK) {
            rfb_server_init_destroy(&si);
            return e;
        }

        // Peek length-prefixed server ack: u16be body_len + body.
        // E8: body_len=0x50; live probe with "farsee": body_len=0x4a.
        // NEVER consume-then-append-to-tail: if pump->in already holds the
        // rest of an FBU, re-queueing a header at the tail desyncs demux.
        // Peek via buffer data/length; only consume when a full ack is
        // confirmed. FBU / incomplete / non-ack → leave bytes in place.
        size_t consumed_ack = 0;
        for (int i = 0; i < 100; i++) {
            const size_t n = rfb_buffer_length(pump->in);
            const uint8_t *d = rfb_buffer_data(pump->in);
            consumed_ack = apple_viewer_info_live_ack_consume_len(d, n);
            if (consumed_ack > 0u) {
                rfb_buffer_consume(pump->in, consumed_ack);
                break;
            }
            if (n >= 2u) {
                // Full header present but not a complete plausible ack:
                // either FBU / out-of-range (leave forever) or incomplete
                // body (keep reading). Detect "give up" vs "need more".
                const uint16_t body_len =
                    (uint16_t)(((uint16_t)d[0] << 8) | (uint16_t)d[1]);
                const bool looks_like_fbu =
                    (d[0] == 0x00u && d[1] == 0x00u);
                if (looks_like_fbu || body_len == 0u ||
                    body_len > APPLE_VIEWER_INFO_LIVE_ACK_BODY_MAX) {
                    break;  // leave bytes for demux
                }
                // Valid header, waiting for body — fall through to read.
            }
            e = rfb_io_read_some(pump, 100);
            if (e == RFB_ERR_TIMEOUT) {
                break;
            }
            if (e != RFB_OK) {
                rfb_server_init_destroy(&si);
                return e;
            }
        }
        if (type33_debug_enabled()) {
            if (consumed_ack > 0u) {
                fprintf(stderr,
                        "farsee rfb debug: ViewerInfo live ack "
                        "consumed=%zu\n",
                        consumed_ack);
            } else if (rfb_buffer_length(pump->in) == 0u) {
                fprintf(stderr,
                        "farsee rfb debug: ViewerInfo live sent; no ack "
                        "(cleartext-only peer?)\n");
            } else {
                fprintf(stderr,
                        "farsee rfb debug: ViewerInfo live: left %zu "
                        "bytes in buffer for demux (no complete ack)\n",
                        rfb_buffer_length(pump->in));
            }
            (void)fflush(stderr);
        }
    }

    e = hooks->setup_after_server_init(hooks->ctx, &si);
    rfb_server_init_destroy(&si);
    if (e != RFB_OK) {
        return e;
    }

    if (pump->last_error != NULL) {
        *pump->last_error = RFB_OK;
    }
    return RFB_OK;
}
