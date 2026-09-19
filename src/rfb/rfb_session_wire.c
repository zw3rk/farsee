// SPDX-License-Identifier: Apache-2.0
//
// RFB session wire queueing, setup, and Apple record ownership.

#include "rfb/rfb_session_internal.h"

#include "farsee/allocator.h"
#include "farsee/apple_crypto.h"
#include "farsee/apple_postauth.h"
#include "farsee/apple_record.h"
#include "farsee/apple_wire_decode.h"
#include "farsee/apple_wire_record.h"
#include "farsee/buffer.h"
#include "farsee/bytes.h"
#include "farsee/encoding.h"
#include "farsee/farsee_display.h"
#include "farsee/input.h"
#include "farsee/limits.h"
#include "farsee/pacing.h"
#include "farsee/pixel_format.h"
#include "farsee/rfb_io_pump.h"
#include "farsee/secret.h"
#include "farsee/server_init.h"

#include <stdio.h>
#include <string.h>

// Default order: ZRLE, CopyRect, Raw, Cursor, DesktopSize. Cursor and
// DesktopSize are pseudo-encodings.
static const int32_t k_default_encodings[] = {
    RFB_ENCODING_ZRLE,
    RFB_ENCODING_COPYRECT,
    RFB_ENCODING_RAW,
    RFB_ENCODING_CURSOR,
    RFB_ENCODING_DESKTOPSIZE,
};

// The Apple security path uses its own SetEncodings payload instead of this
// classic preference list.

// --- I/O pump (borrowed handles into session buffers) --------------------

rfb_error session_queue_bytes(rfb_session *s,
                              const uint8_t *data, size_t n)
{
    if (s == NULL) {
        return RFB_ERR_INTERNAL;
    }
    rfb_io_pump p = rfb_session_internal_pump(s);
    if (s->apple_records_active && data != NULL && n > 0u) {
        uint8_t wire[4096];
        size_t wire_len = 0u;
        if (n > UINT16_MAX) {
            s->last_error = RFB_ERR_PROTOCOL;
            return RFB_ERR_PROTOCOL;
        }

        const size_t plaintext_length =
            n + 2u + APPLE_WIRE_SHA1_LEN;
        const size_t padded_length =
            ((plaintext_length + APPLE_BLOCK_SIZE - 1u) /
             APPLE_BLOCK_SIZE) *
            APPLE_BLOCK_SIZE;
        const size_t required = 2u + padded_length;
        if (required > sizeof wire || s->out.length > s->out.hard_limit ||
            required > s->out.hard_limit - s->out.length) {
            s->last_error = RFB_ERR_LIMIT;
            return RFB_ERR_LIMIT;
        }

        // Reserve before sealing. The seal advances CBC and sequence state;
        // after this succeeds, appending the record cannot allocate or exceed
        // the queue limit.
        rfb_error e = rfb_buffer_reserve(&s->out, s->out.length + required);
        if (e != RFB_OK) {
            s->last_error = e;
            return e;
        }

        e = apple_wire_record_seal_with_allocator(
            &s->apple_rl, data, n, wire, sizeof wire, &wire_len, s->alloc);
        if (e != RFB_OK) {
            s->last_error = e;
            return e;
        }
        return rfb_io_queue_bytes(&p, wire, wire_len);
    }
    return rfb_io_queue_bytes(&p, data, n);
}

static bool session_crypto_random_bytes(void *opaque, uint8_t *out,
                                        size_t length)
{
    (void)opaque;
    return rfb_crypto_random_bytes(out, length);
}

rfb_error rfb_session_internal_queue_fresh_rekey(
    rfb_session *s, rfb_session_random_bytes_fn random_bytes,
    void *random_opaque)
{
    enum {
        rekey_envelope_length = 2u + 2u * APPLE_BLOCK_SIZE,
        sealed_msg14_length = 2u + 2u * APPLE_BLOCK_SIZE,
        transaction_length = rekey_envelope_length + sealed_msg14_length,
    };
    uint8_t content_key[APPLE_BLOCK_SIZE] = { 0 };
    uint8_t iv[APPLE_BLOCK_SIZE] = { 0 };
    uint8_t wire[transaction_length] = { 0 };
    apple_record_layer prepared;
    memset(&prepared, 0, sizeof prepared);
    rfb_error result = RFB_OK;

    if (s == NULL || random_bytes == NULL || !s->apple_rl_inited ||
        !s->apple_records_active || !s->apple_rl.initialized ||
        !s->apple_rl.encrypt.active || s->apple_rl.encrypt.cbc == NULL) {
        result = RFB_ERR_STATE;
        goto cleanup;
    }
    if (s->out.length > s->out.hard_limit ||
        transaction_length > s->out.hard_limit - s->out.length) {
        result = RFB_ERR_LIMIT;
        goto cleanup;
    }

    // Reserve the complete wire transaction before generating secrets or
    // advancing prepared record state. The later append cannot allocate.
    result = rfb_buffer_reserve(
        &s->out, s->out.length + (size_t)transaction_length);
    if (result != RFB_OK) {
        goto cleanup;
    }
    if (!random_bytes(random_opaque, content_key, sizeof content_key) ||
        !random_bytes(random_opaque, iv, sizeof iv)) {
        result = RFB_ERR_INTERNAL;
        goto cleanup;
    }

    wire[0] = 0x00u;
    wire[1] = 0x20u;
    if (!rfb_crypto_aes128_ecb_encrypt(s->apple_rl.wrap_key, content_key,
                                       wire + 2u) ||
        !rfb_crypto_aes128_ecb_encrypt(s->apple_rl.wrap_key, iv,
                                       wire + 2u + APPLE_BLOCK_SIZE)) {
        result = RFB_ERR_INTERNAL;
        goto cleanup;
    }

    apple_record_init(&prepared, s->apple_rl.wrap_key);
    if (!apple_record_set_direction(&prepared, APPLE_DIR_ENCRYPT,
                                    content_key, iv)) {
        result = RFB_ERR_INTERNAL;
        goto cleanup;
    }
    size_t sealed_length = 0u;
    result = apple_wire_record_seal_with_allocator(
        &prepared, apple_wire_msg14, APPLE_WIRE_MSG14_LEN,
        wire + rekey_envelope_length, sealed_msg14_length, &sealed_length,
        s->alloc);
    if (result != RFB_OK) {
        goto cleanup;
    }
    if (sealed_length != sealed_msg14_length) {
        result = RFB_ERR_INTERNAL;
        goto cleanup;
    }

    result = rfb_buffer_append(&s->out, wire, sizeof wire);
    if (result != RFB_OK) {
        goto cleanup;
    }

    // Commit only after the complete wire transaction is queued. Ownership
    // of the prepared CBC context moves into the live direction.
    {
        apple_record_direction old = s->apple_rl.encrypt;
        s->apple_rl.encrypt = prepared.encrypt;
        memset(&prepared.encrypt, 0, sizeof prepared.encrypt);
        if (old.cbc != NULL) {
            rfb_crypto_cbc_free(old.cbc);
        }
        rfb_secret_zero(&old, sizeof old);
    }

cleanup:
    apple_record_destroy(&prepared);
    rfb_secret_zero(content_key, sizeof content_key);
    rfb_secret_zero(iv, sizeof iv);
    rfb_secret_zero(wire, sizeof wire);
    if (result != RFB_OK && s != NULL) {
        s->last_error = result;
    }
    return result;
}

// --- setup messages --------------------------------------------------------

rfb_error session_send_fbur_rect(rfb_session *s, bool incremental,
                                 uint16_t x, uint16_t y,
                                 uint16_t width, uint16_t height)
{
    uint8_t msg[10];
    rfb_writer w = rfb_writer_make(msg, sizeof msg);
    rfb_error e = rfb_format_framebuffer_update_request(
        &w, incremental, x, y, width, height);
    if (e != RFB_OK) {
        s->last_error = e;
        return e;
    }
    e = session_queue_bytes(s, msg, w.length);
    if (e != RFB_OK) {
        return e;
    }
    if (s->capture_enabled &&
        s->capture.state == RFB_CAPTURE_SCHEDULER_WAIT_INITIAL) {
        e = rfb_capture_scheduler_initial_request_sent(
            &s->capture, rfb_session_internal_capture_now(s));
        if (e != RFB_OK) {
            s->last_error = e;
            return e;
        }
    }
    rfb_pacing_request_sent(&s->pacing, incremental,
                            rfb_session_internal_capture_now(s));
    return RFB_OK;
}

rfb_error rfb_session_internal_send_fbur(rfb_session *s, bool incremental)
{
    return session_send_fbur_rect(s, incremental, 0u, 0u, s->fb_width,
                                  s->fb_height);
}

static rfb_error session_queue_apple_setup(
    rfb_session *s, const uint8_t *setup, size_t setup_length)
{
    if (s == NULL || setup == NULL || setup_length == 0u) {
        return RFB_ERR_INTERNAL;
    }
    rfb_error error = rfb_buffer_append(&s->out, setup, setup_length);
    if (error != RFB_OK) {
        s->last_error = error;
        return error;
    }
    rfb_io_pump pump = rfb_session_internal_pump(s);
    return rfb_io_drain_out(&pump, 1000);
}

rfb_error session_queue_apple_modern_setup(
    rfb_session *s, bool private_encodings)
{
    if (s == NULL) {
        return RFB_ERR_INTERNAL;
    }
    if (s->cfg.capture_initial_only) {
        static const int32_t k_control[] = {
            RFB_ENCODING_ZRLE,
            RFB_ENCODING_DESKTOPSIZE,
            RFB_ENCODING_CURSOR,
        };
        uint8_t setup[82u + 4u + 3u * 4u];
        memcpy(setup, apple_wire_modern_post_si, 82u);
        rfb_writer w = rfb_writer_make(setup + 82u, sizeof setup - 82u);
        rfb_error error = rfb_format_set_encodings(
            &w, k_control,
            (uint16_t)(sizeof k_control / sizeof k_control[0]));
        if (error != RFB_OK) {
            s->last_error = error;
            return error;
        }
        return session_queue_apple_setup(s, setup, 82u + w.length);
    }
    if (private_encodings) {
        const rfb_error error = session_queue_apple_setup(
            s, apple_wire_modern_post_si, APPLE_WIRE_MODERN_POST_SI_LEN);
        return error;
    }

    static const int32_t k_mod_classic[] = {
        RFB_ENCODING_ZRLE,
        RFB_ENCODING_RAW,
        RFB_ENCODING_DESKTOPSIZE,
        RFB_ENCODING_CURSOR,
    };
    uint8_t setup[82u + 4u + 4u * 4u];
    memcpy(setup, apple_wire_modern_post_si, 82u);
    rfb_writer w = rfb_writer_make(setup + 82u, sizeof setup - 82u);
    rfb_error error = rfb_format_set_encodings(
        &w, k_mod_classic,
        (uint16_t)(sizeof k_mod_classic / sizeof k_mod_classic[0]));
    if (error != RFB_OK) {
        s->last_error = error;
        return error;
    }
    error = session_queue_apple_setup(s, setup, 82u + w.length);
    return error;
}

rfb_error rfb_session_internal_setup_after_server_init(
    rfb_session *s, const rfb_server_init *si)
{
    s->fb_width = si->width;
    s->fb_height = si->height;
    // Cursor pseudo-encodings carry a shape and hotspot, not a screen
    // position. Start the local presentation cursor at the desktop centre;
    // admitted PointerEvents replace this position.
    s->last_ptr_x = si->width > 0u ? (uint16_t)(si->width / 2u) : 0u;
    s->last_ptr_y = si->height > 0u ? (uint16_t)(si->height / 2u) : 0u;
    s->server_pf = si->pixel_format;

    // Classic path: request canonical RGBA8 (plan.md §12.2).
    // Apple cleartext mode uses the ServerInit pixel format and does not send
    // SetPixelFormat. The peer requires its negotiated format in this mode.
    if (rfb_session_internal_is_apple_cleartext(s) &&
        rfb_pixel_format_valid(&si->pixel_format)) {
        s->pf = si->pixel_format;
    } else {
        s->pf = rfb_pixel_format_canonical_request();
    }

    rfb_error e = rfb_framebuffer_resize(&s->fb, si->width, si->height,
                                         RFB_LIMIT_FB_BYTES_POLICY);
    if (e != RFB_OK) {
        s->last_error = e;
        return e;
    }

    if (s->cfg.capture_query_count > 0u || s->cfg.capture_initial_only) {
        const rfb_capture_scheduler_config capture_config = {
            .queries = s->cfg.capture_queries,
            .query_count = s->cfg.capture_query_count,
            .framebuffer_width = si->width,
            .framebuffer_height = si->height,
            .response_timeout_ms = s->cfg.capture_response_timeout_ms,
            .quiet_ms = s->cfg.capture_quiet_ms,
            .initial_only = s->cfg.capture_initial_only,
            .initial_zrle_only = s->cfg.capture_initial_zrle_only,
            .require_mutation_ack = s->cfg.capture_require_mutation_ack,
            .mutation_timeout_ms = s->cfg.capture_mutation_timeout_ms,
            .initial_rectangle_max = s->cfg.capture_initial_rectangle_max,
            .rect_observations = s->cfg.capture_rect_observations,
            .rect_observation_capacity =
                s->cfg.capture_rect_observation_capacity,
            .final_observations = s->cfg.capture_final_observations,
            .final_observation_capacity =
                s->cfg.capture_final_observation_capacity,
            .on_result = s->cfg.capture_on_result,
            .on_result_ctx = s->cfg.capture_on_result_ctx,
        };
        e = rfb_capture_scheduler_init_config(&s->capture, &capture_config);
        if (e != RFB_OK) {
            s->last_error = e;
            return e;
        }
        s->capture_enabled = true;
    }

    // Presenter open is app-owned (publish → slot only).

    // SetPixelFormat only for classic sessions (not Apple).
    if (!rfb_session_internal_is_apple_cleartext(s)) {
        uint8_t msg[20];
        rfb_writer w = rfb_writer_make(msg, sizeof msg);
        e = rfb_format_set_pixel_format(&w, &s->pf);
        if (e != RFB_OK) {
            s->last_error = e;
            return e;
        }
        e = session_queue_bytes(s, msg, w.length);
        if (e != RFB_OK) {
            return e;
        }
    }

    s->zstream = rfb_zlib_create_with_allocator(s->alloc);
    if (s->zstream == NULL) {
        s->last_error = RFB_ERR_NOMEM;
        return RFB_ERR_NOMEM;
    }

    rfb_pacing_init(&s->pacing, s->cfg.max_fps);

    // Apple post-ServerInit policy. Cleartext compatibility is the
    // zero-initialized default. Record modes queue cfg21 and SetEncodings, then
    // wait for the peer's 0x044f setup before sending FBUR.
    if (rfb_session_internal_is_apple_cleartext(s)) {
        if (s->cfg.apple_postauth_mode != RFB_APPLE_POSTAUTH_CLEARTEXT) {
            const bool private_encodings =
                s->cfg.apple_postauth_mode ==
                RFB_APPLE_POSTAUTH_PRIVATE_ENCODINGS;
            // All supported layouts share this production builder with the
            // focused byte-contract fixture.
            e = session_queue_apple_modern_setup(s, private_encodings);
            if (e != RFB_OK) {
                s->last_error = e;
                return e;
            }
            return RFB_OK; // FBUR after enable_records
        }
        // Cleartext MVP encodings (paint path).
        static const int32_t k_apple_mvp_encs[] = {
            RFB_ENCODING_ZRLE,
            RFB_ENCODING_RAW,
        };
        static const int32_t k_control_encodings[] = {
            RFB_ENCODING_ZRLE,
            RFB_ENCODING_DESKTOPSIZE,
            RFB_ENCODING_CURSOR,
        };
        const int32_t *encodings = k_apple_mvp_encs;
        uint16_t encoding_count =
            (uint16_t)(sizeof k_apple_mvp_encs /
                       sizeof k_apple_mvp_encs[0]);
        if (s->cfg.capture_initial_only) {
            encodings = k_control_encodings;
            encoding_count =
                (uint16_t)(sizeof k_control_encodings /
                           sizeof k_control_encodings[0]);
        }
        uint8_t msg[4u + 3u * 4u];
        rfb_writer w = rfb_writer_make(msg, sizeof msg);
        e = rfb_format_set_encodings(&w, encodings, encoding_count);
        if (e != RFB_OK) {
            s->last_error = e;
            return e;
        }
        e = session_queue_bytes(s, msg, w.length);
        if (e != RFB_OK) {
            return e;
        }
        e = rfb_session_internal_send_fbur(s, false);
        if (e != RFB_OK) {
            return e;
        }
        if (!s->cfg.view_only && !s->capture_enabled) {
            uint8_t setup_ptr[18];
            size_t setup_len = 0u;
            if (rfb_format_apple_setup_pointer(
                    setup_ptr, sizeof setup_ptr, &setup_len, s->fb_width,
                    s->fb_height) == RFB_OK &&
                setup_len > 0u) {
                (void)session_queue_bytes(s, setup_ptr, setup_len);
            }
        }
        return RFB_OK;
    }

    // Classic SetEncodings + first FBUR.
    {
        const int32_t *encs = k_default_encodings;
        uint16_t nenc =
            (uint16_t)(sizeof k_default_encodings /
                       sizeof k_default_encodings[0]);
        static const int32_t k_control_encodings[] = {
            RFB_ENCODING_ZRLE,
            RFB_ENCODING_DESKTOPSIZE,
            RFB_ENCODING_CURSOR,
        };
        if (s->cfg.capture_initial_only) {
            encs = k_control_encodings;
            nenc = (uint16_t)(sizeof k_control_encodings /
                              sizeof k_control_encodings[0]);
        }
        uint8_t msg[4u + 5u * 4u];
        rfb_writer w = rfb_writer_make(msg, sizeof msg);
        e = rfb_format_set_encodings(&w, encs, nenc);
        if (e != RFB_OK) {
            s->last_error = e;
            return e;
        }
        e = session_queue_bytes(s, msg, w.length);
        if (e != RFB_OK) {
            return e;
        }
    }

    e = rfb_session_internal_send_fbur(s, false);
    if (e != RFB_OK) {
        return e;
    }
    return RFB_OK;
}

// After cleartext post-ServerInit setup, wait for 0x044f, enable AES-CBC in
// both directions, queue the cleartext msg12 acknowledgement, then queue the
// configured record-mode initial output.
rfb_error rfb_session_internal_enable_apple_records(rfb_session *s)
{
    if (s == NULL || !s->has_wrap_key) {
        return RFB_ERR_INTERNAL;
    }
    if (s->apple_records_active) {
        return RFB_OK;
    }

    if (!s->apple_rl_inited) {
        apple_record_init(&s->apple_rl, s->wrap_key);
        s->apple_rl_inited = true;
        rfb_buffer_init(&s->apple_plain, s->alloc, RFB_LIMIT_FB_BYTES_POLICY);
        rfb_buffer_init(&s->apple_stage, s->alloc, RFB_LIMIT_FB_BYTES_POLICY);
    }

    rfb_io_pump pump = rfb_session_internal_pump(s);
    // Drain outbound modern cleartext first.
    rfb_error e = rfb_io_drain_out(&pump, 2000);
    if (e != RFB_OK) {
        return e;
    }

    for (int i = 0; i < 100; i++) {
        if (rfb_session_internal_stop_requested(s)) {
            return RFB_ERR_CANCELLED;
        }
        if (s->connect_deadline_mono_ms != 0u &&
            rfb_io_mono_ms() >= s->connect_deadline_mono_ms) {
            return RFB_ERR_TIMEOUT;
        }

        const uint8_t *data = rfb_buffer_data(&s->in);
        const size_t len = rfb_buffer_length(&s->in);
        apple_wire_setup_info setup;
        const size_t need = apple_wire_setup_inspect(data, len, &setup);
        const uint8_t *payload = setup.payload32;
        if (need == (size_t)-1) {
            // Unexpected cleartext — fail closed (modern peer must setup).
            s->last_error = RFB_ERR_PROTOCOL;
            return RFB_ERR_PROTOCOL;
        }
        if (need > 0u && !setup.supported) {
            // A well-formed setup envelope selected an unsupported suite.
            // Fail closed and report only the bounded type and method values.
            fprintf(stderr,
                    "farsee: unsupported Apple post-auth cipher suite "
                    "(setup52 type=0x%04x method=%u; expected type=0x%04x "
                    "method=%u). Failing closed — please report this line "
                    "with the peer's macOS version.\n",
                    (unsigned)setup.type, (unsigned)setup.method,
                    (unsigned)APPLE_WIRE_TYPE_ENABLE,
                    (unsigned)APPLE_WIRE_SETUP_METHOD_AES_CBC);
            (void)fflush(stderr);
            s->last_error = RFB_ERR_UNSUPPORTED;
            return RFB_ERR_UNSUPPORTED;
        }
        if (need > 0u && payload != NULL) {
            // S2C always: AES-ECB-dec(wrap, payload[0:16]/iv.
            if (!apple_record_enable_wrapped(&s->apple_rl, APPLE_DIR_DECRYPT,
                                             payload, payload + 16)) {
                s->last_error = RFB_ERR_INTERNAL;
                return RFB_ERR_INTERNAL;
            }
            // Product C→S keys use the same unwrap as S2C (mode 0). Private
            // alternate schedules are selectable only through the private
            // in-memory session variant used by focused tests.
            memcpy(s->apple_setup_payload32, payload, 32);
            s->apple_have_setup_payload = true;
            {
                const int mode = (int)s->wire_variants.c2s_key_mode;
                uint8_t ck[16];
                uint8_t iv[16];
                // Unwrap with ECB-dec (same as enable_wrapped / S2C).
                if (!rfb_crypto_aes128_ecb_decrypt(s->wrap_key, payload, ck) ||
                    !rfb_crypto_aes128_ecb_decrypt(s->wrap_key, payload + 16,
                                                   iv)) {
                    s->last_error = RFB_ERR_INTERNAL;
                    return RFB_ERR_INTERNAL;
                }
                bool enc_ok = false;
                if (mode == 1) {
                    uint8_t ziv[16];
                    memset(ziv, 0, sizeof ziv);
                    enc_ok = apple_record_set_direction(
                        &s->apple_rl, APPLE_DIR_ENCRYPT, ck, ziv);
                } else if (mode == 2) {
                    enc_ok = apple_record_set_direction(
                        &s->apple_rl, APPLE_DIR_ENCRYPT, iv, ck);
                } else if (mode == 3) {
                    uint8_t w2[16];
                    memcpy(w2, s->wrap_key, 16);
                    enc_ok = apple_record_set_direction(
                        &s->apple_rl, APPLE_DIR_ENCRYPT, w2, iv);
                } else if (mode == 4) {
                    enc_ok = true; // no encrypt dir
                } else if (mode == 5) {
                    enc_ok = apple_record_set_direction(
                        &s->apple_rl, APPLE_DIR_ENCRYPT, payload,
                        payload + 16);
                } else if (mode == 6) {
                    uint8_t ziv[16];
                    memset(ziv, 0, sizeof ziv);
                    enc_ok = apple_record_set_direction(
                        &s->apple_rl, APPLE_DIR_ENCRYPT, s->wrap_key, ziv);
                } else if (mode == 7 && s->apple_have_sk32) {
                    enc_ok = apple_record_set_direction(
                        &s->apple_rl, APPLE_DIR_ENCRYPT, s->apple_sk32,
                        s->apple_sk32 + 16);
                } else if (mode == 8) {
                    uint8_t ek[16], eiv[16];
                    if (!rfb_crypto_aes128_ecb_encrypt(s->wrap_key, payload,
                                                       ek) ||
                        !rfb_crypto_aes128_ecb_encrypt(
                            s->wrap_key, payload + 16, eiv)) {
                        enc_ok = false;
                    } else {
                        enc_ok = apple_record_set_direction(
                            &s->apple_rl, APPLE_DIR_ENCRYPT, ek, eiv);
                    }
                    rfb_secret_zero(ek, sizeof ek);
                    rfb_secret_zero(eiv, sizeof eiv);
                } else if (mode == 9) {
                    enc_ok = apple_record_set_direction(
                        &s->apple_rl, APPLE_DIR_ENCRYPT, ck, payload + 16);
                } else if (mode == 10) {
                    uint8_t lab[19];
                    uint8_t dig[32];
                    memcpy(lab, ck, 16);
                    lab[16] = (uint8_t)'C';
                    lab[17] = (uint8_t)'2';
                    lab[18] = (uint8_t)'S';
                    if (!rfb_crypto_sha256(lab, 19, dig)) {
                        enc_ok = false;
                    } else {
                        enc_ok = apple_record_set_direction(
                            &s->apple_rl, APPLE_DIR_ENCRYPT, dig, iv);
                    }
                    rfb_secret_zero(lab, sizeof lab);
                    rfb_secret_zero(dig, sizeof dig);
                } else if (mode == 11 && s->apple_have_sk32) {
                    uint8_t lab[64];
                    uint8_t dig[32];
                    memcpy(lab, s->apple_sk32, 32);
                    memcpy(lab + 32, payload, 32);
                    if (!rfb_crypto_sha256(lab, 64, dig)) {
                        enc_ok = false;
                    } else {
                        enc_ok = apple_record_set_direction(
                            &s->apple_rl, APPLE_DIR_ENCRYPT, dig, dig + 16);
                    }
                    rfb_secret_zero(lab, sizeof lab);
                    rfb_secret_zero(dig, sizeof dig);
                } else if (mode == 12) {
                    uint8_t ek[16], eiv[16];
                    if (!rfb_crypto_aes128_ecb_encrypt(s->wrap_key, ck, ek) ||
                        !rfb_crypto_aes128_ecb_encrypt(s->wrap_key, iv, eiv)) {
                        enc_ok = false;
                    } else {
                        enc_ok = apple_record_set_direction(
                            &s->apple_rl, APPLE_DIR_ENCRYPT, ek, eiv);
                    }
                    rfb_secret_zero(ek, sizeof ek);
                    rfb_secret_zero(eiv, sizeof eiv);
                } else {
                    enc_ok = apple_record_set_direction(
                        &s->apple_rl, APPLE_DIR_ENCRYPT, ck, iv);
                }
                rfb_secret_zero(ck, sizeof ck);
                rfb_secret_zero(iv, sizeof iv);
                if (!enc_ok) {
                    s->last_error = RFB_ERR_INTERNAL;
                    return RFB_ERR_INTERNAL;
                }
            }
            rfb_buffer_consume(&s->in, need);

            // The msg12 acknowledgement precedes the first AES-CBC client record
            // and is queued directly through the I/O pump.
            e = rfb_io_queue_bytes(&pump, apple_wire_msg12_ack,
                                   APPLE_WIRE_MSG12_ACK_LEN);
            if (e != RFB_OK) {
                return e;
            }
            e = rfb_io_drain_out(&pump, 2000);
            if (e != RFB_OK) {
                return e;
            }

            s->apple_records_active = true;
            // Client rekey variants are not set by the release
            // frontend.
            {
                const rfb_apple_rekey_variant rekey = s->wire_variants.rekey;
                if (rekey == RFB_APPLE_REKEY_ECHO &&
                    s->apple_have_setup_payload) {
                    uint8_t wire[2 + 32];
                    wire[0] = 0x00;
                    wire[1] = 0x20;
                    memcpy(wire + 2, s->apple_setup_payload32, 32);
                    e = rfb_io_queue_bytes(&pump, wire, sizeof wire);
                    if (e != RFB_OK) {
                        return e;
                    }
                    e = rfb_io_drain_out(&pump, 2000);
                    if (e != RFB_OK) {
                        return e;
                    }
                    e = session_queue_bytes(s, apple_wire_msg14,
                                            APPLE_WIRE_MSG14_LEN);
                    if (e != RFB_OK) {
                        return e;
                    }
                    return RFB_OK;
                }
                if (rekey == RFB_APPLE_REKEY_FRESH) {
                    e = rfb_session_internal_queue_fresh_rekey(
                        s, session_crypto_random_bytes, NULL);
                    if (e != RFB_OK) {
                        return e;
                    }
                    e = rfb_io_drain_out(&pump, 2000);
                    if (e != RFB_OK) {
                        return e;
                    }
                    return RFB_OK;
                }
            }

            // Standard post-enable order: cleartext msg12 acknowledgement,
            // then one AES-CBC FBUR record. A private in-memory variant supports
            // alternate ordering in focused tests.
            {
                const bool silence = s->wire_variants.suppress_fbur;
                const rfb_apple_initial_output_variant initial_output =
                    s->wire_variants.initial_output;
                if (initial_output == RFB_APPLE_INITIAL_OUTPUT_FBUR_ONLY) {
                    if (!silence) {
                        e = rfb_session_internal_send_fbur(s, false);
                        if (e != RFB_OK) {
                            return e;
                        }
                    }
                } else if (initial_output ==
                           RFB_APPLE_INITIAL_OUTPUT_MSG14_THEN_FBUR) {
                    e = session_queue_bytes(s, apple_wire_msg14,
                                            APPLE_WIRE_MSG14_LEN);
                    if (e != RFB_OK) {
                        return e;
                    }
                    if (!silence) {
                        e = rfb_session_internal_send_fbur(s, false);
                        if (e != RFB_OK) {
                            return e;
                        }
                    }
                } else if (initial_output ==
                           RFB_APPLE_INITIAL_OUTPUT_FBUR_THEN_MSG14) {
                    if (!silence) {
                        e = rfb_session_internal_send_fbur(s, false);
                        if (e != RFB_OK) {
                            return e;
                        }
                    }
                    e = session_queue_bytes(s, apple_wire_msg14,
                                            APPLE_WIRE_MSG14_LEN);
                    if (e != RFB_OK) {
                        return e;
                    }
                } else if (apple_wire_product_wants_sealed_fbur(silence)) {
                    e = rfb_session_internal_send_fbur(s, false);
                    if (e != RFB_OK) {
                        return e;
                    }
                    fprintf(stderr, "farsee: Apple AES-CBC records active\n");
                    (void)fflush(stderr);
                }
            }
            return RFB_OK;
        }

        e = rfb_io_read_some(&pump, 200);
        if (e == RFB_ERR_TIMEOUT) {
            continue;
        }
        if (e != RFB_OK) {
            return e;
        }
    }

    s->last_error = RFB_ERR_TIMEOUT;
    return RFB_ERR_TIMEOUT;
}

// Demux u16be||CBC records from s->in into s->apple_plain (classic RFB
// only). Apple typed control and msg14 ticks are consumed and dropped.
rfb_error rfb_session_internal_decrypt_apple_records(rfb_session *s, bool *progress)
{
    if (s == NULL || progress == NULL || !s->apple_records_active) {
        return RFB_ERR_INTERNAL;
    }

    for (;;) {
        const uint8_t *data = rfb_buffer_data(&s->in);
        const size_t len = rfb_buffer_length(&s->in);
        const size_t total =
            apple_wire_cipher_record_len(data, len, APPLE_RECORD_MAX_BODY);
        if (total == 0u) {
            return RFB_OK; // need more
        }
        if (total == (size_t)-1) {
            s->last_error = RFB_ERR_PROTOCOL;
            return RFB_ERR_PROTOCOL;
        }

        const uint16_t ct_len =
            (uint16_t)(((uint16_t)data[0] << 8) | (uint16_t)data[1]);
        const uint8_t *ct = data + 2;

        rfb_error e = rfb_buffer_reserve(&s->apple_stage, (size_t)ct_len);
        if (e != RFB_OK) {
            s->last_error = e;
            return e;
        }
        // open writes into stage.data
        size_t msg_len = 0u;
        // Ensure stage length is at least ct_len for open's msg_cap.
        if (s->apple_stage.capacity < (size_t)ct_len) {
            s->last_error = RFB_ERR_NOMEM;
            return RFB_ERR_NOMEM;
        }
        e = apple_wire_record_open_with_allocator(
            &s->apple_rl, ct, (size_t)ct_len, s->apple_stage.data,
            s->apple_stage.capacity, &msg_len, s->alloc);
        if (e != RFB_OK) {
            s->last_error = e;
            return e;
        }
        // Snapshot the last ciphertext block BEFORE consuming: the memmove
        // inside rfb_buffer_consume shifts the next pipelined record over
        // this position; consuming first would move the next record over it.
        if (ct_len >= 16u) {
            memcpy(s->apple_last_s2c_ct, ct + (size_t)ct_len - 16u, 16u);
            s->apple_have_last_s2c_ct = true;
        }
        rfb_buffer_consume(&s->in, total);
        *progress = true;
        s->apple_s2c_opened++;
        // Private deferred-output variant. The release frontend leaves the
        // threshold at zero, so this branch cannot be activated by inherited
        // process state.
        {
            const unsigned need_n =
                (unsigned)s->wire_variants.deferred_output_after_s2c;
            if (!s->apple_deferred_seal_sent && need_n > 0u &&
                s->apple_s2c_opened >= need_n) {
                s->apple_deferred_seal_sent = true;
                if (s->wire_variants.deferred_iv_follows_s2c &&
                    s->apple_have_last_s2c_ct) {
                    uint8_t ck[16];
                    memcpy(ck, s->apple_rl.decrypt.content_key, 16);
                    if (!apple_record_set_direction(&s->apple_rl,
                                                    APPLE_DIR_ENCRYPT, ck,
                                                    s->apple_last_s2c_ct)) {
                        rfb_secret_zero(ck, 16);
                        s->last_error = RFB_ERR_INTERNAL;
                        return RFB_ERR_INTERNAL;
                    }
                    rfb_secret_zero(ck, 16);
                }
                if (s->wire_variants.deferred_sequence_follows_s2c) {
                    s->apple_rl.encrypt.sequence = s->apple_s2c_opened;
                }
                rfb_error se =
                    s->wire_variants.deferred_output_is_msg14
                        ? session_queue_bytes(s, apple_wire_msg14,
                                              APPLE_WIRE_MSG14_LEN)
                        : rfb_session_internal_send_fbur(s, false);
                if (se != RFB_OK) {
                    return se;
                }
            }
        }

        const uint8_t *msg = s->apple_stage.data;
        if (msg_len == 0u) {
            continue;
        }
        if (apple_wire_msg_is_msg14(msg, msg_len)) {
            continue;
        }
        uint32_t atype = 0u;
        if (apple_wire_msg_is_typed(msg, msg_len, &atype)) {
            // 0x03f3 quantization-table control — store QT for dequant.
            if (atype == 0x03f3u) {
                const uint8_t *pl = NULL;
                size_t plen = 0u;
                uint32_t t = 0u;
                if (apple_wire_typed_header(msg, msg_len, &t, &pl, &plen) &&
                    pl != NULL) {
                    apple_wire_mvs_tables tabs;
                    if (apple_wire_decode_mvs_tables(pl, plen, &tabs) &&
                        tabs.qt0 != NULL && tabs.qt1 != NULL) {
                        memcpy(s->mvs_qt0, tabs.qt0, 64u);
                        memcpy(s->mvs_qt1, tabs.qt1, 64u);
                        s->mvs_have_qt = true;
                    }
                }
            }
            // Other typed control/metadata — tolerate (no FB decode).
            continue;
        }

        e = rfb_buffer_append(&s->apple_plain, msg, msg_len);
        if (e != RFB_OK) {
            s->last_error = e;
            return e;
        }
    }
}
