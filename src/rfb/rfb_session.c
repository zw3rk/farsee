// SPDX-License-Identifier: Apache-2.0
//
// farsee — RFB live session (connect + protocol loop).
//
// Classic security types (None / VNC Auth) via the handshake SM, and
// Apple type-33 (RSA1 + SRP) on RFB 003.889 banners. Do not fake
// post-auth encryption; wrap_key is stored for a future ChaCha layer.
// G17 AES-CBC must not be used against real peers.

#include "farsee/rfb_session.h"

#include "farsee/allocator.h"
#include "farsee/apple_auth.h"
#include "farsee/apple_postauth.h"
#include "farsee/apple_type33_connect.h"
#include "farsee/buffer.h"
#include "farsee/bytes.h"
#include "farsee/cpu_probe.h"
#include "farsee/encoding.h"
#include "farsee/farsee_display.h"
#include "farsee/farsee_input.h"
#include "farsee/farsee_thread.h"
#include "farsee/handshake.h"
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
#include <stdlib.h>
#include <string.h>

// Preference order: ZRLE, CopyRect, Raw, Cursor, DesktopSize (Raw last
// among lossy/primary encodings; pseudo-encodings at the end of the list
// is also common — we match server_init tests / G3 preference).
static const int32_t k_default_encodings[] = {
    RFB_ENCODING_ZRLE,
    RFB_ENCODING_COPYRECT,
    RFB_ENCODING_RAW,
    RFB_ENCODING_CURSOR,
    RFB_ENCODING_DESKTOPSIZE,
};

// Type-33 / Apple Screen Sharing: keep the encoding list minimal. Cursor /
// DesktopSize pseudo-encodings and SetPixelFormat have been observed to
// yield solid-black first paints or early peer close on some macOS hosts;
// the working Python full_auth path used classic FBUR after auth without
// those extras. Prefer ZRLE then Raw only.
static const int32_t k_apple_encodings[] = {
    RFB_ENCODING_ZRLE,
    RFB_ENCODING_RAW,
};

#define RFB_SESSION_CANDIDATES_MAX 16u
#define RFB_SESSION_POLL_MS        16

struct rfb_session {
    rfb_session_config cfg;
    rfb_socket_ctx sock;
    rfb_io_adapter io;
    bool io_open;
    bool active;
    rfb_error last_error;
    rfb_buffer in;
    rfb_buffer out;
    rfb_framebuffer fb;
    rfb_pixel_format pf;       // format we requested (canonical)
    rfb_pixel_format server_pf; // original ServerInit format (informational)
    uint16_t fb_width;
    uint16_t fb_height;
    rfb_zlib_stream *zstream;
    rfb_pacing pacing;
    rfb_cursor cursor;
    rfb_allocator *alloc;
    // Pure demux/decode state (incomplete FBU + unexpected type).
    rfb_server_engine eng;
    // Apple type-33 wrap key (zeroized on destroy). Present only after
    // successful type-33 auth; secret presence only — not a policy flag.
    // Policy uses dialect (Apple demux, encodings, wake, SPF skip).
    bool has_wrap_key;
    uint8_t wrap_key[16];
    // Post-auth dialect. CLASSIC (0) after clear/classic connect;
    // APPLE_CLEARTEXT_MVP after type-33 success.
    rfb_session_dialect dialect;
    // FARSEE_RFB_DEBUG=1: dump first FBU header once per session.
    bool debug_fbu_header_dumped;
    // Type-33: first full paint is often solid black + cursor. After the
    // first frame we emit pointer/key wake + force full FBUR so the peer
    // streams the real desktop (live: r0 nz≈88, r1 after wake = colour).
    bool apple_bootstrap_done;
    bool apple_seen_nonblack;  // true once a non-black FB has been published
    uint32_t frames_published;
    uint32_t apple_wake_attempts;
    // While still black after type-33, re-arm full FBUR on this cadence so a
    // peer that answers the first paint and then goes silent (no damage on a
    // blank desktop) cannot leave request_outstanding stuck forever.
    uint64_t apple_black_retry_ms;
    // Absolute mono-ms deadline for handshake/recv (from connect_timeout_ms).
    uint64_t connect_deadline_mono_ms;
    // Live status-band link metrics (written only on protocol thread).
    // link_meta: see farsee_link_meta_pack; link_rate_pub: farsee_link_rate_pack.
    farsee_atomic_u64 link_meta;
    farsee_atomic_u64 link_rx_bytes;
    farsee_atomic_u64 link_rate_pub; // coherent rate snapshot (loop r3 T1)
    // Protocol-only rate latch (not read cross-thread).
    farsee_link_rate link_rate;
    // Throttle sample_link to the rate window (loop r1 T5 / r2 T5).
    uint64_t next_link_sample_ms;
    // Held keys (keysym stored as physical identity) + last pointer mask for
    // RELEASE_ALL / teardown flush (2026-07-31 T5).
    farsee_key_ledger key_ledger;
    unsigned held_buttons;
    // Last successfully queued pointer coords (teardown mask-0 must not warp
    // the remote cursor to 0,0 — loop r2 claude F4).
    uint16_t last_ptr_x;
    uint16_t last_ptr_y;
};

// Diagnostic: set FARSEE_RFB_DEBUG=1 (any non-empty value) to dump unexpected
// server message prefixes and the first FramebufferUpdate header to stderr.
// Used to classify cleartext FBU vs opaque/AEAD post-auth traffic after type-33.
static bool rfb_debug_enabled(void)
{
    static int cached = -1;
    if (cached < 0) {
        const char *e = getenv("FARSEE_RFB_DEBUG");
        cached = (e != NULL && e[0] != '\0') ? 1 : 0;
    }
    return cached != 0;
}

static void rfb_debug_hexdump(const char *tag, const uint8_t *data, size_t len,
                              size_t max_dump)
{
    size_t n = len < max_dump ? len : max_dump;
    fprintf(stderr, "farsee rfb debug: %s len=%zu dump=%zu:",
            tag != NULL ? tag : "bytes", len, n);
    for (size_t i = 0; i < n; i++) {
        fprintf(stderr, " %02x", data[i]);
    }
    if (n < len) {
        fprintf(stderr, " ...");
    }
    fputc('\n', stderr);
    (void)fflush(stderr);
}

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
}

rfb_error rfb_session_last_error(const rfb_session *s)
{
    return s != NULL ? s->last_error : RFB_ERR_INTERNAL;
}

const rfb_framebuffer *rfb_session_framebuffer(const rfb_session *s)
{
    return s != NULL ? &s->fb : NULL;
}

bool rfb_session_has_wrap_key(const rfb_session *s)
{
    return s != NULL && s->has_wrap_key;
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
    // Sticky app counter for rate (loop r2 T6). RTT still from kernel.
    const uint64_t rx = farsee_atomic_u64_load(&s->sock.rx_bytes);
    const bool have_rx = true;
    const bool have_rtt = (mask & FARSEE_TCP_STAT_RTT) != 0u;
    (void)k_rx;
    // Latch rate on the producer so status reads one coherent atomic (r3 T1).
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
    // AUTO: prefer type-33 when the peer advertises the Apple dialect.
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
static bool session_is_apple_cleartext(const rfb_session *s)
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

    // Default policy (T13): pointer motion only (mask 0). Soft click and
    // Space/Shift keys require with_key (session gates on FARSEE_APPLE_WAKE
    // =input) so a login password field cannot be polluted by auto-wake.
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
    // Post-ServerInit type-33 nudge: origin → quarter → center, mask 0 only.
    // Never inject button edges here (residual multi-review T2).
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

// --- I/O pump (borrowed handles into session buffers) --------------------

static rfb_io_pump session_pump(rfb_session *s)
{
    rfb_io_pump p;
    memset(&p, 0, sizeof p);
    p.io = &s->io;
    p.fd = s->sock.fd;
    p.in = &s->in;
    p.out = &s->out;
    p.last_error = &s->last_error;
    p.stop_flag = s->cfg.stop_flag;
    p.deadline_mono_ms = s->connect_deadline_mono_ms;
    return p;
}

static bool stop_requested(const rfb_session *s)
{
    return farsee_atomic_int_load_nonzero(s->cfg.stop_flag);
}

static rfb_error session_queue_bytes(rfb_session *s,
                                     const uint8_t *data, size_t n)
{
    rfb_io_pump p = session_pump(s);
    return rfb_io_queue_bytes(&p, data, n);
}

// --- setup messages --------------------------------------------------------

static rfb_error session_send_fbur(rfb_session *s, bool incremental)
{
    uint8_t msg[10];
    rfb_writer w = rfb_writer_make(msg, sizeof msg);
    rfb_error e = rfb_format_framebuffer_update_request(
        &w, incremental, 0, 0, s->fb_width, s->fb_height);
    if (e != RFB_OK) {
        s->last_error = e;
        return e;
    }
    e = session_queue_bytes(s, msg, w.length);
    if (e != RFB_OK) {
        return e;
    }
    rfb_pacing_request_sent(&s->pacing, incremental, rfb_io_mono_ms());
    return RFB_OK;
}

static rfb_error session_setup_after_server_init(rfb_session *s,
                                                 const rfb_server_init *si)
{
    s->fb_width = si->width;
    s->fb_height = si->height;
    s->server_pf = si->pixel_format;

    // Classic path: request canonical RGBA8 (plan.md §12.2).
    // Apple cleartext MVP: decode using ServerInit pixel format; do NOT
    // send SetPixelFormat (live dumps after SetPixelFormat were solid
    // black while offline decode of the same peer's ZRLE was full colour).
    if (session_is_apple_cleartext(s) &&
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

    // Presenter open is app-owned (publish → slot only).

    // SetPixelFormat only for classic sessions (not Apple cleartext MVP).
    if (!session_is_apple_cleartext(s)) {
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

    // SetEncodings.
    {
        const int32_t *encs = session_is_apple_cleartext(s)
                                  ? k_apple_encodings
                                  : k_default_encodings;
        uint16_t nenc =
            session_is_apple_cleartext(s)
                ? (uint16_t)(sizeof k_apple_encodings /
                             sizeof k_apple_encodings[0])
                : (uint16_t)(sizeof k_default_encodings /
                             sizeof k_default_encodings[0]);
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

    s->zstream = rfb_zlib_create();
    if (s->zstream == NULL) {
        s->last_error = RFB_ERR_NOMEM;
        return RFB_ERR_NOMEM;
    }

    rfb_pacing_init(&s->pacing, s->cfg.max_fps);
    // Initial non-incremental full-screen request.
    e = session_send_fbur(s, false);
    if (e != RFB_OK) {
        return e;
    }
    // Apple cleartext MVP: pointer motion *with* the first FBUR so Screen
    // Sharing can start a real desktop capture while the (often black)
    // first paint is still in flight. A single center event is not always
    // enough on a blanked host — send a short path (origin → mid → center)
    // so the peer sees actual motion, then a soft click.
    // view_only: never inject pointer/key (FBUR already sent above).
    if (session_is_apple_cleartext(s) && !s->cfg.view_only) {
        // Motion-only path (mask 0). Do NOT inject a synthetic left-click:
        // that can activate UI on the remote (login, dialogs). Real button
        // edges belong to operator input or optional FARSEE_APPLE_WAKE=input.
        uint8_t setup_ptr[18];
        size_t setup_len = 0u;
        if (rfb_format_apple_setup_pointer(setup_ptr, sizeof setup_ptr,
                                           &setup_len, s->fb_width,
                                           s->fb_height) == RFB_OK &&
            setup_len > 0u) {
            (void)session_queue_bytes(s, setup_ptr, setup_len);
        }
        if (rfb_debug_enabled()) {
            const uint16_t cx =
                s->fb_width > 0u ? (uint16_t)(s->fb_width / 2u) : (uint16_t)0;
            const uint16_t cy =
                s->fb_height > 0u ? (uint16_t)(s->fb_height / 2u) : (uint16_t)0;
            const uint16_t mx =
                s->fb_width > 0u ? (uint16_t)(s->fb_width / 4u) : (uint16_t)0;
            const uint16_t my =
                s->fb_height > 0u ? (uint16_t)(s->fb_height / 4u) : (uint16_t)0;
            fprintf(stderr,
                    "farsee: type-33 early pointer path 0,0→%u,%u→%u,%u "
                    "(mask 0) with first FBUR (%ux%u — first real paint may "
                    "take a few seconds over the LAN)\n",
                    (unsigned)mx, (unsigned)my, (unsigned)cx, (unsigned)cy,
                    (unsigned)s->fb_width, (unsigned)s->fb_height);
            (void)fflush(stderr);
        }
    }
    return RFB_OK;
}

// --- decode path (pure engine) ---------------------------------------------

// Sparse sample: true if the framebuffer has meaningful non-black content
// (more than a tiny cursor blob). Used to suppress pure-black type-33
// first paints that leave the Kitty surface stuck on black.
static bool fb_sample_nonblack(const rfb_framebuffer *fb)
{
    if (fb == NULL || fb->rgba == NULL || fb->width == 0u ||
        fb->height == 0u) {
        return false;
    }
    const uint32_t step = 16u;
    size_t nz = 0;
    size_t samples = 0;
    for (uint32_t y = 0; y < fb->height; y += step) {
        for (uint32_t x = 0; x < fb->width; x += step) {
            const uint8_t *p = rfb_framebuffer_pixel_c(fb, x, y);
            samples++;
            if (p[0] != 0u || p[1] != 0u || p[2] != 0u) {
                nz++;
            }
        }
    }
    // Real desktops light up a large fraction of samples; a cursor-only
    // black frame is typically a few dozen nonzeros out of ~30k samples.
    (void)samples;
    return nz > 200u;
}

// Nudge the peer so it starts streaming the real desktop after type-33.
// Proven sequence (project capture): first non-incremental FBUR is solid
// black; center PointerEvent + another non-incremental full FBUR yields
// multi-MB colour when the host display has content. If the Mac is
// blanked / locked / "blank screen for observers", every paint stays black.
//
// Live probe: a parallel dump session can get colour on first frame while
// an already-connected live session stays black and goes silent (rx=0).
// Keep re-arming non-incremental FBUR + input nudges until colour or the
// operator quits — do not give up after a fixed handful of attempts.
// Strong Apple wake (click + Space/Shift) only when FARSEE_APPLE_WAKE=input.
// Default is pointer motion only so login password fields stay clean (T13).
static bool session_apple_wake_input_enabled(void)
{
    static int cached = -1;
    if (cached < 0) {
        const char *e = getenv("FARSEE_APPLE_WAKE");
        cached = (e != NULL && strcmp(e, "input") == 0) ? 1 : 0;
    }
    return cached != 0;
}

static void session_apple_wake(rfb_session *s, bool with_key)
{
    // Dialect enables wake path; view_only only suppresses Pointer/Key
    // (FBUR force-full-refresh always runs for black recovery).
    if (s == NULL || !session_is_apple_cleartext(s)) {
        return;
    }
    s->apple_wake_attempts++;

    const uint16_t x =
        s->fb_width > 0u ? (uint16_t)(s->fb_width / 2u) : (uint16_t)0;
    const uint16_t y =
        s->fb_height > 0u ? (uint16_t)(s->fb_height / 2u) : (uint16_t)0;

    // Pointer/Key wake nudges are suppressed under --view-only (P0-N1).
    // Non-incremental FBUR re-request below always runs so black recovery
    // can still request full paints without injecting input.
    // with_key is further gated by FARSEE_APPLE_WAKE=input (default off).
    const bool allow_input =
        with_key && session_apple_wake_input_enabled();
    {
        uint8_t msg[64];
        size_t n = 0u;
        if (rfb_format_apple_wake_input(msg, sizeof msg, &n,
                                        s->cfg.view_only, allow_input,
                                        s->apple_wake_attempts,
                                        s->fb_width, s->fb_height) == RFB_OK &&
            n > 0u) {
            (void)session_queue_bytes(s, msg, n);
        }
    }

    // Request another full paint (not pure incremental — a static black
    // peer has no damage, so incremental can stall forever). Allowed under
    // view_only.
    rfb_pacing_force_full_refresh(&s->pacing);

    // Verbose only: live Kitty parks the cursor on the status band, so
    // routine wake chatter was overwriting the status line. Use
    // FARSEE_RFB_DEBUG=1 for black-recovery tracing.
    if (rfb_debug_enabled()) {
        flockfile(stderr);
        fprintf(stderr,
                "farsee: type-33 wake #%u %s%u,%u%s + full FBUR "
                "(still waiting for non-black desktop)\n",
                (unsigned)s->apple_wake_attempts,
                s->cfg.view_only ? "view-only (no input) " : "pointer ",
                (unsigned)x, (unsigned)y,
                (!s->cfg.view_only && with_key) ? " + key" : "");
        (void)fflush(stderr);
        funlockfile(stderr);
    }
}

static void session_publish_frame(rfb_session *s)
{
    if (s->fb.rgba == NULL) {
        return;
    }

    farsee_cpu_probe_fbu_complete_cur();
    s->frames_published++;
    const bool nonblack = fb_sample_nonblack(&s->fb);
    const bool first_colour = nonblack && !s->apple_seen_nonblack;
    if (nonblack) {
        s->apple_seen_nonblack = true;
    }

    // Apple cleartext MVP: first paint is almost always solid black. Early
    // pointer was already sent with the first FBUR; if we still see black,
    // force one more full refresh immediately (no max_fps wait — pacing).
    if (session_is_apple_cleartext(s) && !s->apple_seen_nonblack) {
        if (!s->apple_bootstrap_done) {
            s->apple_bootstrap_done = true;
            session_apple_wake(s, /*with_key=*/false);
        } else if (s->apple_wake_attempts < 2u && s->frames_published == 3u) {
            session_apple_wake(s, /*with_key=*/true);
        }
        if (rfb_debug_enabled() && !nonblack && s->frames_published <= 3u) {
            fprintf(stderr,
                    "farsee: frame #%u still black (type-33 blank first "
                    "paint is normal; waiting for full desktop…)\n",
                    (unsigned)s->frames_published);
            (void)fflush(stderr);
        }
        // Once: still useful without debug (host/path issue), but keep it
        // rare so it does not thrash the live status band.
        if (!nonblack && rfb_black_hint_due(s->frames_published)) {
            fprintf(stderr,
                    "farsee: %u consecutive all-black full frames "
                    "(%ux%u). Peer is answering cleartext FBUR with a black "
                    "framebuffer. macOS Screen Sharing.app often still shows "
                    "a real desktop on the same host — that client uses a "
                    "different post-auth path (ViewerInfo + encrypted "
                    "records). farsee's cleartext path may stay black until "
                    "the ChaCha post-auth layer is complete. Also check "
                    "console login / display wake on the host.\n",
                    (unsigned)s->frames_published, (unsigned)s->fb.width,
                    (unsigned)s->fb.height);
            (void)fflush(stderr);
        }
    }
    if (first_colour && rfb_debug_enabled()) {
        fprintf(stderr,
                "farsee: first non-black frame #%u %ux%u\n",
                (unsigned)s->frames_published, (unsigned)s->fb.width,
                (unsigned)s->fb.height);
        (void)fflush(stderr);
    }

    const uint64_t now = rfb_io_mono_ms();
    // Rate-limit publishes (4K memcpy is expensive). Always force:
    //   - first several paints (bootstrap / black recovery visibility)
    //   - the first non-black paint (real desktop — do not wait a frame)
    //   - every paint until colour on type-33 (so Kitty is not stuck on
    //     gen=1 black while later dark FBUs are decoded but not shown)
    const bool force_publish =
        (s->frames_published <= 8u) || first_colour ||
        (session_is_apple_cleartext(s) && !s->apple_seen_nonblack);
    const bool due =
        force_publish || rfb_pacing_can_present(&s->pacing, now);

    // Publish only. App owns open/present/close of any presenter.
    // When slot is NULL, skip (no crash); production always wires a slot.
    if (due && s->cfg.slot != NULL) {
        (void)farsee_frame_slot_publish(
            s->cfg.slot, s->fb.rgba, s->fb.width, s->fb.height,
            (uint32_t)s->fb.stride, FARSEE_PIXEL_RGBA8888);
        farsee_cpu_probe_publish_cur();
        rfb_pacing_presented(&s->pacing, now, s->eng.rects_decoded, 0);
        if (rfb_debug_enabled() && session_is_apple_cleartext(s) &&
            s->frames_published <= 6u) {
            fprintf(stderr,
                    "farsee: publish frame #%u %ux%u %s\n",
                    (unsigned)s->frames_published, (unsigned)s->fb.width,
                    (unsigned)s->fb.height,
                    nonblack ? "colour" : "dark");
            (void)fflush(stderr);
        }
    }
}

// Session hooks into the pure demux engine (product side-effects only).
static void session_eng_on_publish(void *hook_ctx)
{
    session_publish_frame((rfb_session *)hook_ctx);
}

static void session_eng_on_fbu_begin(void *hook_ctx, uint16_t nrects)
{
    rfb_session *s = (rfb_session *)hook_ctx;
    (void)nrects;
    if (rfb_debug_enabled() && !s->debug_fbu_header_dumped) {
        const uint8_t *data = rfb_buffer_data(&s->in);
        size_t len = rfb_buffer_length(&s->in);
        // Header already consumed by the engine before this hook; dump is
        // best-effort residual. Prefer a one-shot note that FBU began.
        (void)data;
        (void)len;
        fprintf(stderr,
                "farsee rfb debug: first FBU header accepted nrects=%u\n",
                (unsigned)nrects);
        (void)fflush(stderr);
        s->debug_fbu_header_dumped = true;
    }
    farsee_cpu_probe_fbu_header_cur();
}

// DesktopSize: engine has already resized fb / *fb_width/*fb_height.
// Product live shells poll session geometry or the published frame size.
static void session_eng_on_desktop_size(void *hook_ctx, uint16_t width,
                                        uint16_t height)
{
    rfb_session *s = (rfb_session *)hook_ctx;
    if (s == NULL) {
        return;
    }
    s->fb_width = width;
    s->fb_height = height;
    if (rfb_debug_enabled()) {
        fprintf(stderr, "farsee rfb debug: DesktopSize %ux%u\n",
                (unsigned)width, (unsigned)height);
        (void)fflush(stderr);
    }
}

// Returns:
//   RFB_OK            — progress or need more input
//   RFB_ERR_*         — hard failure
// Sets *progress when bytes were consumed.
static rfb_error session_process_in(rfb_session *s, bool *progress)
{
    // Optional pre-engine debug: dump first server prefix when still at
    // message boundary and debug is on (product essay stays out of engine).
    if (rfb_debug_enabled() && !s->eng.in_fbupdate &&
        !s->debug_fbu_header_dumped && rfb_buffer_length(&s->in) >= 1u) {
        const uint8_t *data = rfb_buffer_data(&s->in);
        size_t len = rfb_buffer_length(&s->in);
        if (data[0] == 0u && len >= 4u) {
            rfb_debug_hexdump("first-FBU-header", data, len, 32u);
            s->debug_fbu_header_dumped = true;
        } else if (data[0] != 0u && data[0] != 1u && data[0] != 2u &&
                   data[0] != 3u) {
            char tag[48];
            (void)snprintf(tag, sizeof tag,
                           "unexpected-msg type=%u", (unsigned)data[0]);
            rfb_debug_hexdump(tag, data, len, 32u);
            fprintf(stderr,
                    "farsee rfb debug: classify: unknown/maybe AEAD\n");
            (void)fflush(stderr);
        }
    }

    rfb_server_engine_ctx ctx;
    memset(&ctx, 0, sizeof ctx);
    ctx.eng = &s->eng;
    ctx.in = &s->in;
    ctx.fb = &s->fb;
    ctx.pf = &s->pf;
    ctx.zstream = s->zstream;
    ctx.cursor = &s->cursor;
    ctx.alloc = s->alloc;
    ctx.pacing = &s->pacing;
    ctx.dialect = s->dialect;
    ctx.fb_width = &s->fb_width;
    ctx.fb_height = &s->fb_height;
    ctx.hooks.hook_ctx = s;
    ctx.hooks.on_publish = session_eng_on_publish;
    ctx.hooks.on_bell = NULL; // terminal bell is presenter-owned for now
    ctx.hooks.on_cut_text = NULL; // clipboard path not yet session-wired
    ctx.hooks.on_fbu_begin = session_eng_on_fbu_begin;
    ctx.hooks.on_desktop_size = session_eng_on_desktop_size;

    rfb_error e = rfb_server_engine_process_in(&ctx, progress);
    if (e != RFB_OK) {
        s->last_error = e;
        if (rfb_debug_enabled() && e == RFB_ERR_PROTOCOL &&
            s->eng.last_unexpected_type != 0u) {
            fprintf(stderr,
                    "farsee rfb debug: protocol fail unexpected type=%u\n",
                    (unsigned)s->eng.last_unexpected_type);
            (void)fflush(stderr);
        }
    }
    return e;
}

// --- cmd queue drain (optional shared MT) ----------------------------------

// High-res wheel (120 = 1 notch) → notch count; trunc toward zero.
static int32_t wheel_notches(int32_t high_res)
{
    if (high_res >= 0) {
        return high_res / 120;
    }
    return -((-high_res) / 120);
}

static uint8_t pointer_held_mask(unsigned buttons)
{
    uint8_t m = 0;
    if ((buttons & FARSEE_BUTTON_LEFT) != 0u) {
        m = (uint8_t)(m | RFB_BUTTON_LEFT);
    }
    if ((buttons & FARSEE_BUTTON_MIDDLE) != 0u) {
        m = (uint8_t)(m | RFB_BUTTON_MIDDLE);
    }
    if ((buttons & FARSEE_BUTTON_RIGHT) != 0u) {
        m = (uint8_t)(m | RFB_BUTTON_RIGHT);
    }
    return m;
}

size_t rfb_session_format_pointer_events(const farsee_pointer_event *pe,
                                         uint8_t *out, size_t out_cap)
{
    if (pe == NULL || out == NULL) {
        return 0;
    }
    const uint16_t x = pe->abs_x < 0 ? 0u
        : (pe->abs_x > 0xFFFF ? (uint16_t)0xFFFFu : (uint16_t)pe->abs_x);
    const uint16_t y = pe->abs_y < 0 ? 0u
        : (pe->abs_y > 0xFFFF ? (uint16_t)0xFFFFu : (uint16_t)pe->abs_y);
    const uint8_t held = pointer_held_mask(pe->buttons);

    int32_t v_notches = wheel_notches(pe->wheel_v);
    int32_t h_notches = wheel_notches(pe->wheel_h);
    // Cap multi-notch flood so a single cmd cannot blow the out buffer.
    if (v_notches > 32) {
        v_notches = 32;
    } else if (v_notches < -32) {
        v_notches = -32;
    }
    if (h_notches > 32) {
        h_notches = 32;
    } else if (h_notches < -32) {
        h_notches = -32;
    }

    const int32_t v_abs = v_notches >= 0 ? v_notches : -v_notches;
    const int32_t h_abs = h_notches >= 0 ? h_notches : -h_notches;
    // Each notch → press + release (2 msgs). Plus one motion/held msg if no
    // wheel (or always? motion is implied by press coords). Spec: press then
    // release per notch; if no wheel, single held-button event.
    const size_t n_msgs =
        (v_abs == 0 && h_abs == 0)
            ? 1u
            : (size_t)(2 * v_abs + 2 * h_abs);
    const size_t need = n_msgs * 6u;
    if (need > out_cap) {
        return 0;
    }

    size_t off = 0;
    if (v_abs == 0 && h_abs == 0) {
        rfb_writer w = rfb_writer_make(out + off, 6u);
        if (rfb_format_pointer_event(&w, held, x, y) != RFB_OK) {
            return 0;
        }
        return 6u;
    }

    const uint8_t v_bit = (v_notches > 0)   ? RFB_BUTTON_WHEEL_UP
                          : (v_notches < 0) ? RFB_BUTTON_WHEEL_DN
                                            : 0u;
    const uint8_t h_bit = (h_notches > 0)   ? RFB_BUTTON_WHEEL_RIGHT
                          : (h_notches < 0) ? RFB_BUTTON_WHEEL_LEFT
                                            : 0u;

    for (int32_t i = 0; i < v_abs; i++) {
        rfb_writer wp = rfb_writer_make(out + off, 6u);
        if (rfb_format_pointer_event(&wp, (uint8_t)(held | v_bit), x, y) !=
            RFB_OK) {
            return 0;
        }
        off += 6u;
        rfb_writer wr = rfb_writer_make(out + off, 6u);
        if (rfb_format_pointer_event(&wr, held, x, y) != RFB_OK) {
            return 0;
        }
        off += 6u;
    }
    for (int32_t i = 0; i < h_abs; i++) {
        rfb_writer wp = rfb_writer_make(out + off, 6u);
        if (rfb_format_pointer_event(&wp, (uint8_t)(held | h_bit), x, y) !=
            RFB_OK) {
            return 0;
        }
        off += 6u;
        rfb_writer wr = rfb_writer_make(out + off, 6u);
        if (rfb_format_pointer_event(&wr, held, x, y) != RFB_OK) {
            return 0;
        }
        off += 6u;
    }
    return off;
}

static void session_drain_cmds(rfb_session *s)
{
    if (s->cfg.cmds == NULL) {
        return;
    }
    // Non-blocking drain: deadline = now so empty queue returns immediately
    // (no cond wait). Avoids gettimeofday thrash on every protocol tick.
    const uint64_t now = rfb_io_mono_ms();
    farsee_cmd cmd;
    // Cap cmds per tick so a mouse flood cannot starve the socket poll.
    unsigned n = 0;
    while (n < 32u &&
           farsee_cmd_queue_pop(s->cfg.cmds, &cmd, now, s->cfg.stop_flag)) {
        n++;
        uint8_t msg[16];
        rfb_writer w = rfb_writer_make(msg, sizeof msg);
        rfb_error e = RFB_OK;
        size_t ptr_bytes = 0;
        // Up to 4 notches × 2 axes × press+release = 16 messages × 6 bytes.
        uint8_t ptr_buf[6u * 16u];
        // Stash keysym for post-queue ledger update (T10: only after OK).
        bool key_down = false;
        uint32_t key_sym = 0u;
        unsigned pending_buttons = s->held_buttons;
        bool update_buttons = false;
        switch (cmd.kind) {
        case FARSEE_CMD_KEY: {
            key_down = (cmd.key.action != FARSEE_KEY_RELEASE);
            key_sym = cmd.key.logical != 0u ? cmd.key.logical : cmd.key.unicode;
            e = rfb_format_key_event(&w, key_down, key_sym);
            break;
        }
        case FARSEE_CMD_POINTER: {
            // Wheel may expand to multiple press+release messages; use a
            // dedicated buffer so multi-notch fits (cap at 4 notches here
            // for the drain path — pure helper allows more).
            farsee_pointer_event pe = cmd.pe;
            int32_t vn = wheel_notches(pe.wheel_v);
            int32_t hn = wheel_notches(pe.wheel_h);
            if (vn > 4) {
                pe.wheel_v = 4 * 120;
            } else if (vn < -4) {
                pe.wheel_v = -4 * 120;
            }
            if (hn > 4) {
                pe.wheel_h = 4 * 120;
            } else if (hn < -4) {
                pe.wheel_h = -4 * 120;
            }
            ptr_bytes = rfb_session_format_pointer_events(&pe, ptr_buf,
                                                          sizeof ptr_buf);
            if (ptr_bytes == 0u) {
                e = RFB_ERR_INTERNAL;
            } else {
                pending_buttons = pe.buttons;
                update_buttons = true;
            }
            break;
        }
        case FARSEE_CMD_RELEASE_ALL: {
            // Emit key-ups for every tracked key + pointer mask 0.
            // Do not clear ledger until appends succeed (T10).
            farsee_physical_key keys[FARSEE_KEY_LEDGER_MAX];
            const size_t nk = farsee_key_ledger_release_all(
                &s->key_ledger, keys, FARSEE_KEY_LEDGER_MAX);
            for (size_t ki = 0; ki < nk; ki++) {
                if (keys[ki] == 0u) {
                    continue;
                }
                uint8_t km[8];
                rfb_writer kw = rfb_writer_make(km, sizeof km);
                if (rfb_format_key_event(&kw, false, keys[ki]) == RFB_OK) {
                    // Append without per-key drain; one drain at end of loop.
                    rfb_error ae = rfb_buffer_append(&s->out, km, kw.length);
                    if (ae != RFB_OK) {
                        // Re-seed failed key so teardown can retry.
                        farsee_key_event ke;
                        memset(&ke, 0, sizeof ke);
                        ke.physical = keys[ki];
                        ke.logical = keys[ki];
                        ke.action = FARSEE_KEY_PRESS;
                        (void)farsee_key_ledger_apply(&s->key_ledger, &ke);
                    }
                }
            }
            // Mask-0 at last coords — do not warp to (0,0) (loop r1 T2).
            e = rfb_format_pointer_event(&w, 0, s->last_ptr_x, s->last_ptr_y);
            pending_buttons = 0u;
            update_buttons = true;
            break;
        }
        default:
            continue;
        }
        if (cmd.kind == FARSEE_CMD_POINTER && ptr_bytes > 0u && e == RFB_OK) {
            rfb_error qe = session_queue_bytes(s, ptr_buf, ptr_bytes);
            if (qe == RFB_OK) {
                if (update_buttons) {
                    s->held_buttons = pending_buttons;
                }
                if (cmd.pe.abs_x >= 0 && cmd.pe.abs_x <= 0xFFFF &&
                    cmd.pe.abs_y >= 0 && cmd.pe.abs_y <= 0xFFFF) {
                    s->last_ptr_x = (uint16_t)cmd.pe.abs_x;
                    s->last_ptr_y = (uint16_t)cmd.pe.abs_y;
                }
            }
        } else if (e == RFB_OK) {
            rfb_error qe = session_queue_bytes(s, msg, w.length);
            if (qe == RFB_OK) {
                if (cmd.kind == FARSEE_CMD_KEY && key_sym != 0u) {
                    farsee_key_event ke;
                    memset(&ke, 0, sizeof ke);
                    ke.physical = key_sym;
                    ke.logical = key_sym;
                    ke.action = key_down ? FARSEE_KEY_PRESS : FARSEE_KEY_RELEASE;
                    if (!farsee_key_ledger_apply(&s->key_ledger, &ke) &&
                        key_down) {
                        // Ledger full: emit key-ups for held set, then track
                        // the new down (post-t11 T3 — do not forget holds).
                        farsee_physical_key drop[FARSEE_KEY_LEDGER_MAX];
                        const size_t nd = farsee_key_ledger_release_all(
                            &s->key_ledger, drop, FARSEE_KEY_LEDGER_MAX);
                        for (size_t di = 0; di < nd; di++) {
                            if (drop[di] == 0u) {
                                continue;
                            }
                            uint8_t um[8];
                            rfb_writer uw = rfb_writer_make(um, sizeof um);
                            if (rfb_format_key_event(&uw, false, drop[di]) !=
                                RFB_OK) {
                                continue;
                            }
                            if (rfb_buffer_append(&s->out, um, uw.length) !=
                                RFB_OK) {
                                farsee_key_event reseed;
                                memset(&reseed, 0, sizeof reseed);
                                reseed.physical = drop[di];
                                reseed.logical = drop[di];
                                reseed.action = FARSEE_KEY_PRESS;
                                (void)farsee_key_ledger_apply(&s->key_ledger,
                                                              &reseed);
                            }
                        }
                        (void)farsee_key_ledger_apply(&s->key_ledger, &ke);
                    }
                }
                if (update_buttons) {
                    s->held_buttons = pending_buttons;
                }
            }
        }
    }
}

// --- connect ---------------------------------------------------------------

static rfb_error connect_tcp(rfb_session *s, const char *host, uint16_t port)
{
    rfb_io_candidate cands[RFB_SESSION_CANDIDATES_MAX];
    size_t nc = RFB_SESSION_CANDIDATES_MAX;
    rfb_error e = rfb_resolve_candidates(host, port, cands, &nc);
    if (e != RFB_OK) {
        s->last_error = e;
        return e;
    }
    if (nc == 0) {
        s->last_error = RFB_ERR_IO;
        return RFB_ERR_IO;
    }
    s->io = rfb_socket_adapter_make(&s->sock);
    // Plumb connect deadline + stop into the socket adapter (T4).
    s->sock.connect_deadline_mono_ms = s->connect_deadline_mono_ms;
    s->sock.connect_stop = s->cfg.stop_flag;
    for (size_t i = 0; i < nc; i++) {
        if (stop_requested(s)) {
            s->last_error = RFB_ERR_CANCELLED;
            return RFB_ERR_CANCELLED;
        }
        if (s->connect_deadline_mono_ms != 0u &&
            rfb_io_mono_ms() >= s->connect_deadline_mono_ms) {
            s->last_error = RFB_ERR_TIMEOUT;
            return RFB_ERR_TIMEOUT;
        }
        if (s->io.connect(s->io.ctx, &cands[i]) == RFB_IO_OK) {
            s->io_open = true;
            (void)rfb_socket_set_nodelay(&s->sock);
            return RFB_OK;
        }
        // Adapter may leave a half-open fd; close and retry.
        if (s->sock.fd >= 0) {
            s->io.close(s->io.ctx);
            s->sock.fd = -1;
        }
    }
    if (stop_requested(s)) {
        s->last_error = RFB_ERR_CANCELLED;
        return RFB_ERR_CANCELLED;
    }
    if (s->connect_deadline_mono_ms != 0u &&
        rfb_io_mono_ms() >= s->connect_deadline_mono_ms) {
        s->last_error = RFB_ERR_TIMEOUT;
        return RFB_ERR_TIMEOUT;
    }
    s->last_error = RFB_ERR_IO;
    return RFB_ERR_IO;
}

static rfb_error run_handshake(rfb_session *s)
{
    // Classic path only: VNC Auth / None. Explicit APPLE mode is rejected
    // here so connect_classic stays classic-only; use rfb_session_connect
    // for type-33.
    if (s->cfg.auth_mode == FARSEE_AUTH_MODE_APPLE) {
        s->last_error = RFB_ERR_UNSUPPORTED;
        return RFB_ERR_UNSUPPORTED;
    }

    rfb_handshake_policy pol = rfb_handshake_policy_default();
    pol.allow_none_auth = s->cfg.allow_none_auth;
    pol.shared_flag = s->cfg.shared;
    // VNC mode / auto: classic types only on this driver.
    pol.allow_vnc_auth = true;

    rfb_handshake h;
    rfb_handshake_init(&h, &pol, s->alloc);
    if (s->cfg.password != NULL && s->cfg.password_len > 0) {
        rfb_handshake_set_password(&h, s->cfg.password, s->cfg.password_len);
    }

    rfb_io_pump pump = session_pump(s);
    rfb_error e = RFB_OK;
    for (int i = 0; i < 10000 && !rfb_handshake_finished(&h); i++) {
        if (stop_requested(s)) {
            e = RFB_ERR_CANCELLED;
            break;
        }
        if (s->connect_deadline_mono_ms != 0u &&
            rfb_io_mono_ms() >= s->connect_deadline_mono_ms) {
            e = RFB_ERR_TIMEOUT;
            break;
        }
        e = rfb_io_drain_out(&pump, 1000);
        if (e != RFB_OK) {
            break;
        }
        e = rfb_handshake_step(&h, &s->in, &s->out);
        if (e != RFB_OK) {
            break;
        }
        if (rfb_handshake_finished(&h)) {
            break;
        }
        // Need more input or drain — honor connect deadline poll budget.
        int poll_ms = 2000;
        if (s->connect_deadline_mono_ms != 0u) {
            uint64_t now = rfb_io_mono_ms();
            if (now >= s->connect_deadline_mono_ms) {
                e = RFB_ERR_TIMEOUT;
                break;
            }
            uint64_t left = s->connect_deadline_mono_ms - now;
            if (left < 2000u) {
                poll_ms = (int)left;
                if (poll_ms < 1) {
                    poll_ms = 1;
                }
            }
        }
        e = rfb_io_read_some(&pump, poll_ms);
        if (e != RFB_OK) {
            break;
        }
    }

    if (e == RFB_OK) {
        if (h.state == RFB_HS_DONE) {
            e = RFB_OK;
        } else if (h.state == RFB_HS_FAILED) {
            e = h.last_error != RFB_OK ? h.last_error : RFB_ERR_AUTH;
            // Apple-only peers under classic connect: RFB_ERR_UNSUPPORTED
            // when no classic security type is mutually available.
        } else {
            e = RFB_ERR_TIMEOUT;
        }
    }
    s->last_error = e;
    rfb_handshake_destroy(&h);
    return e;
}

// Apple 003.889 path via extracted apple_type33_connect + I/O pump.
static rfb_error session_setup_hook(void *ctx, const rfb_server_init *si)
{
    return session_setup_after_server_init((rfb_session *)ctx, si);
}

static rfb_error run_apple_type33(rfb_session *s)
{
    rfb_io_pump pump = session_pump(s);
    apple_type33_connect_hooks hooks;
    memset(&hooks, 0, sizeof hooks);
    hooks.ctx = s;
    hooks.setup_after_server_init = session_setup_hook;

    uint8_t wrap[16];
    bool has_wrap = false;
    rfb_session_dialect dialect = RFB_SESSION_DIALECT_CLASSIC;
    // Dialect must be APPLE_CLEARTEXT_MVP *before* setup_after_server_init
    // so SetPixelFormat is skipped and the Apple encoding list is used
    // (classic SetPixelFormat on Screen Sharing yields a black frame).
    s->dialect = RFB_SESSION_DIALECT_APPLE_CLEARTEXT_MVP;
    rfb_error e = apple_type33_connect(&pump, &s->cfg, &hooks, wrap,
                                       &has_wrap, &dialect);
    if (e != RFB_OK) {
        s->dialect = RFB_SESSION_DIALECT_CLASSIC;
        rfb_secret_zero(wrap, sizeof wrap);
        return e;
    }

    if (has_wrap) {
        memcpy(s->wrap_key, wrap, 16);
        s->has_wrap_key = true;
    }
    rfb_secret_zero(wrap, sizeof wrap);
    s->dialect = dialect;
    // Handshake no longer needs the password pointer (caller may free).
    s->cfg.password = NULL;
    s->cfg.password_len = 0u;
    s->connect_deadline_mono_ms = 0u;
    s->active = true;
    s->last_error = RFB_OK;
    return RFB_OK;
}

// Initialize session storage and TCP connect. Shared by connect variants.
static rfb_error session_prepare(rfb_session *s, const rfb_session_config *cfg)
{
    if (s == NULL || cfg == NULL) {
        return RFB_ERR_INTERNAL;
    }
    if (cfg->host == NULL || cfg->host[0] == '\0') {
        return RFB_ERR_INTERNAL;
    }

    memset(s, 0, sizeof *s);
    s->sock.fd = -1;
    s->cfg = *cfg;
    s->alloc = rfb_default_allocator();
    farsee_key_ledger_init(&s->key_ledger);
    s->held_buttons = 0u;
    if (cfg->connect_timeout_ms > 0u) {
        s->connect_deadline_mono_ms =
            rfb_io_mono_ms() + (uint64_t)cfg->connect_timeout_ms;
    }
    // Input must hold a full 4K/5K Raw FramebufferUpdate (~31.6 MiB at
    // 3840x2160x4) while assembling rectangles. Policy FB ceiling is
    // 256 MiB; the old 32 MiB (OUTBOUND*4) hard limit rejected 4K Raw
    // mid-frame with RFB_ERR_LIMIT and looked like a blank session end.
    rfb_buffer_init(&s->in, s->alloc, RFB_LIMIT_FB_BYTES_POLICY);
    rfb_buffer_init(&s->out, s->alloc, RFB_LIMIT_OUTBOUND_BYTES);
    rfb_framebuffer_init(&s->fb, s->alloc);

    uint16_t port = cfg->port != 0 ? cfg->port : (uint16_t)5900u;
    return connect_tcp(s, cfg->host, port);
}

rfb_error rfb_session_connect_classic(rfb_session *s,
                                      const rfb_session_config *cfg)
{
    // Reject APPLE mode before any I/O so tests and callers get
    // RFB_ERR_UNSUPPORTED even when no peer is listening.
    if (cfg != NULL && cfg->auth_mode == FARSEE_AUTH_MODE_APPLE) {
        if (s != NULL) {
            s->last_error = RFB_ERR_UNSUPPORTED;
        }
        return RFB_ERR_UNSUPPORTED;
    }

    rfb_error e = session_prepare(s, cfg);
    if (e != RFB_OK) {
        return e;
    }

    e = run_handshake(s);
    if (e != RFB_OK) {
        return e;
    }

    // ClientInit: one shared-flag byte (RFC 6143 §7.3.1).
    {
        uint8_t ci = cfg->shared ? 1u : 0u;
        e = session_queue_bytes(s, &ci, 1u);
        if (e != RFB_OK) {
            return e;
        }
    }

    rfb_server_init si;
    memset(&si, 0, sizeof si);
    {
        rfb_io_pump pump = session_pump(s);
        e = rfb_io_read_server_init(&pump, &si);
    }
    if (e != RFB_OK) {
        rfb_server_init_destroy(&si);
        return e;
    }

    e = session_setup_after_server_init(s, &si);
    rfb_server_init_destroy(&si);
    if (e != RFB_OK) {
        return e;
    }

    s->cfg.password = NULL;
    s->cfg.password_len = 0u;
    // Handshake budget no longer applies to the long-lived protocol loop.
    s->connect_deadline_mono_ms = 0u;
    s->active = true;
    s->last_error = RFB_OK;
    return RFB_OK;
}

rfb_error rfb_session_connect(rfb_session *s, const rfb_session_config *cfg)
{
    rfb_error e = session_prepare(s, cfg);
    if (e != RFB_OK) {
        return e;
    }

    // Peek the 12-byte ProtocolVersion banner without consume-then-append
    // (full2 T10): a single recv may already hold security-type bytes after
    // the banner; re-queueing at the tail would desync the handshake SM.
    uint8_t banner[12];
    {
        rfb_io_pump pump = session_pump(s);
        for (int i = 0; i < 10000; i++) {
            if (stop_requested(s)) {
                e = RFB_ERR_CANCELLED;
                break;
            }
            if (s->connect_deadline_mono_ms != 0u &&
                rfb_io_mono_ms() >= s->connect_deadline_mono_ms) {
                e = RFB_ERR_TIMEOUT;
                break;
            }
            if (rfb_buffer_length(&s->in) >= 12u) {
                memcpy(banner, rfb_buffer_data(&s->in), 12u);
                e = RFB_OK;
                break;
            }
            int poll_ms = 2000;
            if (s->connect_deadline_mono_ms != 0u) {
                uint64_t now = rfb_io_mono_ms();
                if (now >= s->connect_deadline_mono_ms) {
                    e = RFB_ERR_TIMEOUT;
                    break;
                }
                uint64_t left = s->connect_deadline_mono_ms - now;
                if (left < 2000u) {
                    poll_ms = (int)left;
                    if (poll_ms < 1) {
                        poll_ms = 1;
                    }
                }
            }
            e = rfb_io_read_some(&pump, poll_ms);
            if (e != RFB_OK) {
                break;
            }
            e = RFB_ERR_TIMEOUT; // keep trying until budget/deadline
        }
    }
    if (e != RFB_OK) {
        s->last_error = e;
        return e;
    }

    const bool apple_banner = apple_is_dialect_003_889(banner, sizeof banner);
    // Honor --auth=vnc: never force type-33 solely due to an Apple banner.
    // AUTO may still prefer type-33 when the peer offers 003.889.
    if (rfb_session_prefer_apple_path(apple_banner, cfg->auth_mode)) {
        // Type-33 path owns post-banner framing: consume the peeked banner.
        rfb_buffer_consume(&s->in, 12u);
        return run_apple_type33(s);
    }

    // Classic path: leave the banner in place for the handshake SM.
    e = run_handshake(s);
    if (e != RFB_OK) {
        return e;
    }

    {
        uint8_t ci = cfg->shared ? 1u : 0u;
        e = session_queue_bytes(s, &ci, 1u);
        if (e != RFB_OK) {
            return e;
        }
    }

    rfb_server_init si;
    memset(&si, 0, sizeof si);
    {
        rfb_io_pump pump = session_pump(s);
        e = rfb_io_read_server_init(&pump, &si);
    }
    if (e != RFB_OK) {
        rfb_server_init_destroy(&si);
        return e;
    }

    e = session_setup_after_server_init(s, &si);
    rfb_server_init_destroy(&si);
    if (e != RFB_OK) {
        return e;
    }

    s->connect_deadline_mono_ms = 0u;
    s->active = true;
    s->last_error = RFB_OK;
    return RFB_OK;
}

// --- protocol loop ---------------------------------------------------------

void rfb_session_protocol_loop(rfb_session *s)
{
    if (s == NULL || !s->active) {
        return;
    }

    farsee_cpu_probe probe;
    farsee_cpu_probe_begin(&probe, "protocol");
    farsee_cpu_probe_attach(&probe);

    while (!stop_requested(s)) {
        // Drain inject queue first (low latency for input).
        session_drain_cmds(s);

        // Process any already-buffered input.
        bool progress = false;
        rfb_error e = session_process_in(s, &progress);
        if (e != RFB_OK) {
            s->last_error = e;
            break;
        }

        // Maybe send the next FBUR (one outstanding + max_fps cadence).
        {
            bool incremental = false;
            const uint64_t now = rfb_io_mono_ms();
            if (rfb_pacing_should_send_request(&s->pacing, &incremental,
                                               now)) {
                e = session_send_fbur(s, incremental);
                if (e != RFB_OK) {
                    s->last_error = e;
                    break;
                }
            }
        }

        // Non-blocking outbound try; rfb_io_read_some will finish any
        // remainder with a real timeout (no POLLOUT busy-spin).
        {
            rfb_io_pump pump = session_pump(s);
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

        // Type-33 black desktop: after the first paint(s) the peer often
        // stops streaming (no damage). request_outstanding then stays true
        // forever and the screen never recovers. Keep forcing full FBUR +
        // pointer nudges until colour — no hard attempt cap (host may wake
        // later; a parallel dump can already show colour).
        //
        // Keys (Space/Shift) only on the first two wakes: continuous key
        // inject corrupts a login password field and can confuse Enter.
        if (session_is_apple_cleartext(s) && !s->apple_seen_nonblack) {
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
                session_apple_wake(s, with_key);
                s->apple_black_retry_ms = now;
            }
        }

        // Link metrics for status band (protocol thread only — T6).
        rfb_session_sample_link(s);
        farsee_cpu_probe_loop(&probe);
    }

    farsee_cpu_probe_detach();

    // Best-effort: release stuck keys/buttons before peer teardown (T5).
    rfb_session_release_held_inputs(s);

    if (s->cfg.stop_flag != NULL) {
        farsee_atomic_int_store(s->cfg.stop_flag, 1);
    }
}

void rfb_session_release_held_inputs(rfb_session *s)
{
    if (s == NULL || !s->active || s->cfg.view_only || !s->io_open) {
        return;
    }
    // Snapshot without clearing; re-seed on append fail (reaudit T8).
    farsee_physical_key keys[FARSEE_KEY_LEDGER_MAX];
    size_t nk = 0;
    if (s->key_ledger.count > FARSEE_KEY_LEDGER_MAX) {
        s->key_ledger.count = FARSEE_KEY_LEDGER_MAX;
    }
    for (size_t i = 0; i < s->key_ledger.count && nk < FARSEE_KEY_LEDGER_MAX;
         i++) {
        if (s->key_ledger.down[i] != 0u) {
            keys[nk++] = s->key_ledger.down[i];
        }
    }
    for (size_t i = 0; i < nk; i++) {
        if (keys[i] == 0u) {
            continue;
        }
        uint8_t msg[8];
        rfb_writer w = rfb_writer_make(msg, sizeof msg);
        if (rfb_format_key_event(&w, false, keys[i]) != RFB_OK) {
            continue;
        }
        if (rfb_buffer_append(&s->out, msg, w.length) == RFB_OK) {
            farsee_key_event ke;
            memset(&ke, 0, sizeof ke);
            ke.physical = keys[i];
            ke.action = FARSEE_KEY_RELEASE;
            (void)farsee_key_ledger_apply(&s->key_ledger, &ke);
        }
        // append fail: leave key in ledger for a later attempt
    }
    if (s->held_buttons != 0u || nk > 0u) {
        // Mask-0 at last known coords — do not warp to (0,0) (loop r2 F4).
        uint8_t msg[8];
        rfb_writer w = rfb_writer_make(msg, sizeof msg);
        if (rfb_format_pointer_event(&w, 0, s->last_ptr_x, s->last_ptr_y) ==
                RFB_OK &&
            rfb_buffer_append(&s->out, msg, w.length) == RFB_OK) {
            s->held_buttons = 0u;
        }
    }
    if (s->io_open) {
        rfb_io_pump pump = session_pump(s);
        (void)rfb_io_drain_out(&pump, 200);
    }
}

bool rfb_session_test_attach_connected_fd(rfb_session *s, int fd)
{
    if (s == NULL || fd < 0) {
        return false;
    }
    // Fresh session storage assumed (clear or failed connect cleaned).
    if (s->io_open && s->sock.fd >= 0 && s->sock.fd != fd) {
        if (s->io.close != NULL) {
            s->io.close(s->io.ctx);
        }
        s->io_open = false;
    }
    if (s->alloc == NULL) {
        s->alloc = rfb_default_allocator();
    }
    if (s->in.data == NULL) {
        rfb_buffer_init(&s->in, s->alloc, RFB_LIMIT_FB_BYTES_POLICY);
    }
    if (s->out.data == NULL) {
        rfb_buffer_init(&s->out, s->alloc, RFB_LIMIT_OUTBOUND_BYTES);
    }
    // make() always zeroes the ctx; set connected fd after (T4).
    s->io = rfb_socket_adapter_make(&s->sock);
    s->sock.fd = fd;
    s->sock.nonblocking = true;
    s->io_open = true;
    s->active = true;
    farsee_key_ledger_init(&s->key_ledger);
    s->held_buttons = 0u;
    return true;
}

void rfb_session_test_seed_held_key(rfb_session *s, uint32_t keysym)
{
    if (s == NULL || keysym == 0u) {
        return;
    }
    farsee_key_event ke;
    memset(&ke, 0, sizeof ke);
    ke.physical = keysym;
    ke.logical = keysym;
    ke.action = FARSEE_KEY_PRESS;
    (void)farsee_key_ledger_apply(&s->key_ledger, &ke);
}

void rfb_session_test_seed_held_buttons(rfb_session *s, unsigned buttons)
{
    if (s == NULL) {
        return;
    }
    s->held_buttons = buttons;
}

void rfb_session_destroy(rfb_session *s)
{
    if (s == NULL) {
        return;
    }
    // Best-effort release before tearing down the socket (T5).
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
    // Leave last_error intact for diagnostics.
}
