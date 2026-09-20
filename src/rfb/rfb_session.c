// SPDX-License-Identifier: Apache-2.0
//
// farsee — RFB live session protocol loop and lifecycle.
//
// Classic security types (None / VNC Auth) use the handshake state machine.
// Apple security types 33 and 36 use the Apple authentication path on RFB
// 003.889 banners.
// Record-mode sessions enable AES-128-CBC records after the cleartext 0x044f
// setup and require wrap_key.

#include "farsee/rfb_session.h"
#include "rfb/rfb_session_internal.h"

#include "farsee/allocator.h"
#include "farsee/apple_mvs_stream.h"
#include "farsee/apple_postauth.h"
#include "farsee/apple_crypto.h"
#include "farsee/apple_record.h"
#include "farsee/apple_wire_record.h"
#include "farsee/apple_wire_decode.h"
#include <errno.h>
#include "farsee/buffer.h"
#include "farsee/bytes.h"
#include "farsee/encoding.h"
#include "farsee/farsee_display.h"
#include "farsee/farsee_input.h"
#include "farsee/farsee_thread.h"
#include "farsee/input.h"
#include "farsee/io_adapter.h"
#include "farsee/limits.h"
#include "farsee/pacing.h"
#include "farsee/pixel_format.h"
#include "farsee/rfb_io_pump.h"
#include "farsee/rfb_server_engine.h"
#include "farsee/secret.h"
#include "farsee/server_init.h"
#include "farsee/socket_posix.h"
#include "farsee/zlib_adapter.h"

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

#define RFB_SESSION_POLL_MS        16

size_t rfb_session_size(void)
{
    return sizeof(struct rfb_session);
}

void rfb_session_clear(rfb_session *s)
{
    if (s == NULL) {
        return;
    }
    memset(s, 0, sizeof *s);
    s->sock.fd = -1;
    s->transport_tx_bytes = &s->sock.tx_bytes;
}

uint64_t rfb_session_internal_capture_now(const rfb_session *s)
{
    if (s != NULL && s->capture_enabled &&
        s->capture_clock_now_ms != NULL) {
        const uint64_t now_ms =
            s->capture_clock_now_ms(s->capture_clock_opaque);
        if (now_ms != 0u) {
            return now_ms;
        }
    }
    return s != NULL && s->capture_enabled && s->capture_now_ms != 0u
               ? s->capture_now_ms
               : rfb_io_mono_ms();
}

rfb_error rfb_session_last_error(const rfb_session *s)
{
    return s != NULL ? s->last_error : RFB_ERR_INTERNAL;
}

rfb_capture_scheduler_state rfb_session_capture_state(const rfb_session *s)
{
    return s != NULL ? s->capture.state : RFB_CAPTURE_SCHEDULER_CLEAR;
}

rfb_capture_failure rfb_session_capture_failure(const rfb_session *s)
{
    return s != NULL ? s->capture.failure : RFB_CAPTURE_FAILURE_NONE;
}

const rfb_framebuffer *rfb_session_framebuffer(const rfb_session *s)
{
    return s != NULL ? &s->fb : NULL;
}

bool rfb_session_has_wrap_key(const rfb_session *s)
{
    return s != NULL && s->has_wrap_key;
}

bool rfb_session_apple_records_active(const rfb_session *s)
{
    return s != NULL && s->apple_records_active;
}

bool rfb_session_copy_wrap_key(const rfb_session *s, uint8_t out[16])
{
    if (s == NULL || out == NULL || !s->has_wrap_key) {
        return false;
    }
    memcpy(out, s->wrap_key, 16);
    return true;
}

rfb_session_dialect rfb_session_get_dialect(const rfb_session *s)
{
    return s != NULL ? s->dialect : RFB_SESSION_DIALECT_CLASSIC;
}

void rfb_session_sample_link(rfb_session *s)
{
    if (s == NULL || !s->io_open || s->sock.fd < 0) {
        return;
    }
    const uint64_t now = farsee_thread_monotonic_ms();
    if (!farsee_link_sample_due(now, &s->next_link_sample_ms,
                                FARSEE_LINK_RATE_WINDOW_MS)) {
        return;
    }

    uint32_t rtt = 0u;
    uint64_t k_rx = 0u;
    const uint32_t mask =
        farsee_socket_tcp_stats(s->sock.fd, &rtt, &k_rx, NULL);
    // Sticky app counter for rate. RTT still comes from the kernel.
    const uint64_t rx = farsee_atomic_u64_load(&s->sock.rx_bytes);
    const bool have_rx = true;
    const bool have_rtt = (mask & FARSEE_TCP_STAT_RTT) != 0u;
    (void)k_rx;
    // Latch the rate on the producer so status reads one coherent atomic value.
    const uint64_t rate_pub = farsee_link_rate_step(
        &s->link_rate, rx, have_rx, now, FARSEE_LINK_RATE_WINDOW_MS);
    const uint64_t meta = farsee_link_meta_pack(rtt, have_rtt, have_rx);
    farsee_atomic_u64_store(&s->link_rx_bytes, rx);
    farsee_atomic_u64_store(&s->link_rate_pub, rate_pub);
    farsee_atomic_u64_store(&s->link_meta, meta);
}

void rfb_session_link_snapshot(const rfb_session *s, uint32_t *out_rtt_ms,
                               bool *out_have_rtt, uint64_t *out_rx,
                               bool *out_have_rx)
{
    rfb_session_link_snapshot_ex(s, out_rtt_ms, out_have_rtt, out_rx,
                                 out_have_rx, NULL, NULL);
}

void rfb_session_link_snapshot_ex(const rfb_session *s, uint32_t *out_rtt_ms,
                                  bool *out_have_rtt, uint64_t *out_rx,
                                  bool *out_have_rx, uint32_t *out_rate_kib,
                                  bool *out_have_rate)
{
    if (s == NULL) {
        if (out_have_rtt != NULL) {
            *out_have_rtt = false;
        }
        if (out_have_rx != NULL) {
            *out_have_rx = false;
        }
        if (out_have_rate != NULL) {
            *out_have_rate = false;
        }
        return;
    }
    const uint64_t meta = farsee_atomic_u64_load(&s->link_meta);
    farsee_link_meta_unpack(meta, out_rtt_ms, out_have_rtt, out_have_rx);
    if (out_rx != NULL) {
        *out_rx = farsee_atomic_u64_load(&s->link_rx_bytes);
    }
    if (out_rate_kib != NULL || out_have_rate != NULL) {
        const uint64_t rp = farsee_atomic_u64_load(&s->link_rate_pub);
        farsee_link_rate_unpack(rp, out_rate_kib, out_have_rate);
    }
}

bool rfb_session_prefer_apple_path(bool apple_banner,
                                   farsee_rfb_auth_mode auth_mode)
{
    if (auth_mode == FARSEE_AUTH_MODE_APPLE) {
        return true;
    }
    if (auth_mode == FARSEE_AUTH_MODE_VNC) {
        // Explicit --auth=vnc: classic path even on RFB 003.889 banners.
        return false;
    }
    // AUTO selects the Apple path for an RFB 003.889 banner.
    return apple_banner;
}

// Apple cleartext control records: u16be body_len with high byte 0 and
// body_len in [8, APPLE_VIEWER_INFO_LIVE_ACK_BODY_MAX]. Classic FBU is
// type=0 pad=0; pad≠0 on classic must not take this path.
bool rfb_session_apple_u16be_control_eligible(rfb_session_dialect dialect,
                                              const uint8_t *data,
                                              size_t len,
                                              size_t *out_total_len)
{
    if (out_total_len == NULL || data == NULL || len < 2u) {
        return false;
    }
    if (dialect != RFB_SESSION_DIALECT_APPLE_CLEARTEXT_MVP) {
        return false;
    }
    // Only type high-byte 0 with non-zero low byte (not classic FBU pad=0).
    if (data[0] != 0u || data[1] == 0u) {
        return false;
    }
    const uint16_t body_len =
        (uint16_t)(((uint16_t)data[0] << 8) | (uint16_t)data[1]);
    if (body_len < 8u || body_len > APPLE_VIEWER_INFO_LIVE_ACK_BODY_MAX) {
        return false;
    }
    *out_total_len = 2u + (size_t)body_len;
    return true;
}

// Policy: Apple post-auth cleartext MVP behaviours (demux, encodings, wake).
bool rfb_session_internal_is_apple_cleartext(const rfb_session *s)
{
    return s != NULL &&
           s->dialect == RFB_SESSION_DIALECT_APPLE_CLEARTEXT_MVP;
}

uint8_t rfb_session_last_unexpected_type(const rfb_session *s)
{
    return s != NULL ? s->eng.last_unexpected_type : 0u;
}

bool rfb_black_hint_due(uint32_t consecutive_black_frames)
{
    return consecutive_black_frames == RFB_BLACK_FRAME_HINT_FRAMES;
}

rfb_black_hint_kind rfb_black_hint_kind_for(bool apple_dialect,
                                            bool records_active,
                                            bool nonblack_seen,
                                            uint32_t consecutive_black_frames)
{
    if (!apple_dialect || nonblack_seen ||
        !rfb_black_hint_due(consecutive_black_frames)) {
        return RFB_BLACK_HINT_NONE;
    }
    return records_active ? RFB_BLACK_HINT_APPLE_RECORDS
                          : RFB_BLACK_HINT_APPLE_CLEARTEXT;
}

const char *rfb_black_hint_text(rfb_black_hint_kind kind)
{
    switch (kind) {
    case RFB_BLACK_HINT_APPLE_CLEARTEXT:
        return "Peer reached the black-frame hint threshold on the Apple "
               "cleartext path. Full-refresh and configured wake attempts "
               "continue. To test Apple record mode, retry with "
               "--apple-postauth=records, which negotiates cfg21 and the "
               "0x044f AES-CBC record layer.";
    case RFB_BLACK_HINT_APPLE_RECORDS:
        return "Peer reached the black-frame hint threshold while Apple "
               "0x044f AES-CBC records are active. Decoded framebuffer updates have "
               "not crossed the sampled non-black threshold.";
    case RFB_BLACK_HINT_NONE:
    default:
        return "";
    }
}

bool rfb_session_should_withhold_black_publish(bool apple_cleartext,
                                               bool nonblack,
                                               bool publish_black_frames)
{
    // Withhold a below-threshold Apple cleartext paint unless the caller opted
    // in to publishing it. See rfb_session.h for the contract.
    return apple_cleartext && !nonblack && !publish_black_frames;
}

rfb_error rfb_format_apple_wake_input(uint8_t *out, size_t out_cap,
                                      size_t *out_len,
                                      bool view_only,
                                      bool with_key,
                                      uint32_t wake_attempt,
                                      uint16_t fb_width,
                                      uint16_t fb_height)
{
    if (out_len == NULL) {
        return RFB_ERR_INTERNAL;
    }
    *out_len = 0u;

    // View-only: no PointerEvent / KeyEvent at all. FBUR re-request is
    // handled by the caller (session_apple_wake) independently.
    if (view_only) {
        return RFB_OK;
    }
    if (out == NULL) {
        return RFB_ERR_INTERNAL;
    }

    rfb_writer w = rfb_writer_make(out, out_cap);
    const uint16_t x = fb_width > 0u ? (uint16_t)(fb_width / 2u) : (uint16_t)0;
    const uint16_t y =
        fb_height > 0u ? (uint16_t)(fb_height / 2u) : (uint16_t)0;

    // The default policy permits pointer motion only (mask 0). Soft click and
    // Space/Shift keys require with_key so callers can suppress automatic
    // keyboard input when a login password field may be active.
    {
        rfb_error e = rfb_format_pointer_event(&w, 0u, x, y);
        if (e != RFB_OK) {
            return e;
        }
    }
    if (with_key) {
        // Strong wake: soft click on early multi-of-3 attempts + key pair.
        if (wake_attempt <= 6u && (wake_attempt % 3u) == 0u) {
            rfb_error e = rfb_format_pointer_event(&w, RFB_BUTTON_LEFT, x, y);
            if (e != RFB_OK) {
                return e;
            }
            e = rfb_format_pointer_event(&w, 0u, x, y);
            if (e != RFB_OK) {
                return e;
            }
        }
        const uint32_t key =
            ((wake_attempt % 2u) == 0u) ? (uint32_t)' ' : 0xffe1u;
        rfb_error e = rfb_format_key_event(&w, true, key);
        if (e != RFB_OK) {
            return e;
        }
        e = rfb_format_key_event(&w, false, key);
        if (e != RFB_OK) {
            return e;
        }
        if (key != (uint32_t)' ') {
            e = rfb_format_key_event(&w, true, (uint32_t)' ');
            if (e != RFB_OK) {
                return e;
            }
            e = rfb_format_key_event(&w, false, (uint32_t)' ');
            if (e != RFB_OK) {
                return e;
            }
        }
    }

    *out_len = w.length;
    return RFB_OK;
}

rfb_error rfb_format_apple_setup_pointer(uint8_t *out, size_t out_cap,
                                         size_t *out_len, uint16_t fb_width,
                                         uint16_t fb_height)
{
    // Post-ServerInit Apple-path pointer sequence: origin, quarter, center.
    // Every event uses mask 0; no button edge is injected.
    if (out_len == NULL) {
        return RFB_ERR_INTERNAL;
    }
    *out_len = 0u;
    if (out == NULL) {
        return RFB_ERR_INTERNAL;
    }
    const uint16_t cx = fb_width > 0u ? (uint16_t)(fb_width / 2u) : (uint16_t)0;
    const uint16_t cy =
        fb_height > 0u ? (uint16_t)(fb_height / 2u) : (uint16_t)0;
    const uint16_t mx =
        fb_width > 0u ? (uint16_t)(fb_width / 4u) : (uint16_t)0;
    const uint16_t my =
        fb_height > 0u ? (uint16_t)(fb_height / 4u) : (uint16_t)0;
    rfb_writer w = rfb_writer_make(out, out_cap);
    rfb_error e = rfb_format_pointer_event(&w, 0u, 0u, 0u);
    if (e != RFB_OK) {
        return e;
    }
    e = rfb_format_pointer_event(&w, 0u, mx, my);
    if (e != RFB_OK) {
        return e;
    }
    e = rfb_format_pointer_event(&w, 0u, cx, cy);
    if (e != RFB_OK) {
        return e;
    }
    *out_len = w.length;
    return RFB_OK;
}

void rfb_session_protocol_loop(rfb_session *s)
{
    if (s == NULL || !s->active) {
        return;
    }

    while (!rfb_session_internal_stop_requested(s)) {
        if (s->capture_enabled) {
            const rfb_error capture_error =
                rfb_session_internal_capture_step(s, RFB_SESSION_POLL_MS);
            if (capture_error != RFB_OK ||
                rfb_capture_scheduler_done(&s->capture)) {
                if (capture_error != RFB_OK) {
                    s->last_error = capture_error;
                }
                break;
            }
            continue;
        }
        // Normal (non-capture) loop. Capture is wholly owned by the extracted
        // production step above, so its scheduler cannot drift into this path.
        rfb_error e = RFB_OK;
        e = rfb_session_internal_drain_cmds(s);
        if (e != RFB_OK) {
            s->last_error = e;
            break;
        }
        // Process any already-buffered input.
        bool progress = false;
        e = rfb_session_internal_process_in(s, &progress);
        if (e != RFB_OK) {
            s->last_error = e;
            break;
        }
        // Poll after inbound processing so a new ServerCutText fingerprint is
        // visible before the host pasteboard can be echoed. Polling stays on
        // the protocol owner. The host callback may launch a short-lived
        // platform helper, but this avoids shared clipboard payload state and
        // is rate-limited inside the bridge.
        e = rfb_session_internal_poll_clipboard(s, rfb_io_mono_ms());
        if (e != RFB_OK) {
            s->last_error = e;
            break;
        }
        const bool allow_fbur = !s->wire_variants.suppress_fbur;
        bool incremental = false;
        const uint64_t request_now = rfb_io_mono_ms();
        if (allow_fbur &&
            rfb_pacing_should_send_request(&s->pacing, &incremental,
                                           request_now)) {
            e = rfb_session_internal_send_fbur(s, incremental);
            if (e != RFB_OK) {
                s->last_error = e;
                break;
            }
        }

        // Non-blocking outbound try; rfb_io_read_some will finish any
        // remainder with a real timeout (no POLLOUT busy-spin).
        {
            rfb_io_pump pump = rfb_session_internal_pump(s);
            e = rfb_io_drain_out(&pump, 0);
            if (e != RFB_OK) {
                s->last_error = e;
                break;
            }
            // process_in already ran until stuck (empty buffer OR incomplete
            // message). Wait for more socket data — always sleep on POLLIN only.
            (void)progress;
            e = rfb_io_read_some(&pump, RFB_SESSION_POLL_MS);
        }
        if (e == RFB_ERR_EOF || e == RFB_ERR_IO) {
            s->last_error = e;
            break;
        }
        if (e != RFB_OK && e != RFB_ERR_TIMEOUT) {
            s->last_error = e;
            break;
        }

        // While Apple cleartext has not crossed the sampled non-black
        // threshold, retry full FBURs with bounded backoff. Pointer input is
        // attempted on each retry when permitted. Key input is eligible only on
        // wake attempt 2.
        if (rfb_session_internal_is_apple_cleartext(s) &&
            !s->apple_seen_nonblack) {
            const uint64_t now = rfb_io_mono_ms();
            // Back off slightly as attempts grow: 400ms → ~2s.
            uint64_t gap = 400u;
            if (s->apple_wake_attempts > 8u) {
                gap = 1000u;
            }
            if (s->apple_wake_attempts > 20u) {
                gap = 2000u;
            }
            if (s->apple_black_retry_ms == 0u) {
                s->apple_black_retry_ms = now;
            } else if (now - s->apple_black_retry_ms >= gap) {
                const bool with_key = (s->apple_wake_attempts < 2u);
                rfb_session_internal_apple_wake(s, with_key);
                s->apple_black_retry_ms = now;
            }
        }

        // Publish status-band link metrics from the protocol thread only.
        rfb_session_sample_link(s);
    }

    // Best-effort release of stuck keys and buttons before peer teardown.
    rfb_session_release_held_inputs(s);

    if (s->cfg.stop_flag != NULL) {
        farsee_atomic_int_store(s->cfg.stop_flag, 1);
    }
}

void rfb_session_destroy(rfb_session *s)
{
    if (s == NULL) {
        return;
    }
    // Attempt input release before tearing down the socket.
    rfb_session_release_held_inputs(s);
    // Presenter lifecycle is entirely app-owned; session never closes one.
    rfb_cursor_destroy(&s->cursor, s->alloc != NULL ? s->alloc
                                                    : rfb_default_allocator());
    if (s->zstream != NULL) {
        rfb_zlib_destroy(s->zstream);
        s->zstream = NULL;
    }
    rfb_framebuffer_destroy(&s->fb);
    rfb_buffer_destroy(&s->in);
    rfb_buffer_destroy(&s->out);
    rfb_buffer_destroy(&s->apple_plain);
    rfb_buffer_destroy(&s->apple_stage);
    if (s->clipboard_host != NULL && s->alloc != NULL &&
        s->alloc->free != NULL) {
        s->alloc->free(s->alloc, s->clipboard_host);
        s->clipboard_host = NULL;
        s->clipboard_host_cap = 0u;
    }
    if (s->apple_rl_inited) {
        apple_record_destroy(&s->apple_rl);
        s->apple_rl_inited = false;
    }
    s->apple_records_active = false;
    if (s->apple_have_sk32) {
        rfb_secret_zero(s->apple_sk32, sizeof s->apple_sk32);
        s->apple_have_sk32 = false;
    }
    s->apple_have_last_s2c_ct = false;
    if (s->io_open && s->io.close != NULL) {
        s->io.close(s->io.ctx);
        s->io_open = false;
    }
    s->sock.fd = -1;
    s->active = false;
    if (s->has_wrap_key) {
        rfb_secret_zero(s->wrap_key, sizeof s->wrap_key);
        s->has_wrap_key = false;
    }
    apple_mvs_coeff_store_free(&s->mvs_coeffs);
    // Leave last_error intact for diagnostics.
}
