// SPDX-License-Identifier: Apache-2.0
//
// farsee — RFB live session driver (connect + protocol loop).
//
// Supports:
//   - Classic security types (None=1, VNC Auth=2) via the handshake SM
//   - Apple type-33 (RSA1 + SRP) on RFB 003.889 banners when selected
//
// After type-33 success the session stores the 16-byte wrap_key and
// proceeds with ClientInit + ServerInit. Post-auth AEAD (ChaCha records)
// is NOT faked here; classic cleartext FB updates are attempted when the
// peer still speaks them. G17 AES-CBC must not be used against real peers.

#ifndef FARSEE_INCLUDE_FARSEE_RFB_SESSION_H
#define FARSEE_INCLUDE_FARSEE_RFB_SESSION_H

#include "farsee/error.h"
#include "farsee/farsee_atomic.h"
#include "farsee/farsee_cmd_queue.h"
#include "farsee/farsee_frame_slot.h"
#include "farsee/framebuffer.h"
#include "farsee/handshake.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Post-auth session dialect. Policy decisions (Apple u16be control-record
// demux, encoding list, black-desktop wake, SetPixelFormat skip) use this
// enum — not has_wrap_key. has_wrap_key is secret presence only.
// Zero-init / classic connect → CLASSIC. Type-33 success →
// APPLE_CLEARTEXT_MVP (APPLE_AEAD reserved for a later gate).
typedef enum rfb_session_dialect {
    RFB_SESSION_DIALECT_CLASSIC = 0,
    RFB_SESSION_DIALECT_APPLE_CLEARTEXT_MVP = 1
    /* RFB_SESSION_DIALECT_APPLE_AEAD = 2 — future */
} rfb_session_dialect;

// Optional: after type-33 ServerInit, before ViewerInfo, when
// apple_attach == APPLE_ATTACH_ASK (0). desktop_name is the ServerInit
// desktop string (may include binary TLV; still useful for display).
// username is the type-33 account (may be NULL). On success set
// *out_attach to APPLE_ATTACH_SHARE or APPLE_ATTACH_LOGIN and return true.
// Return false to use the session default (login).
typedef bool (*rfb_apple_attach_choose_fn)(void *ctx,
                                           const char *desktop_name,
                                           const char *username,
                                           uint8_t *out_attach);

// Configuration for an RFB connect. Pointer fields are borrowed for the
// lifetime of the session (caller retains ownership).
typedef struct rfb_session_config {
    const char *host;
    uint16_t port;  // 0 → 5900
    // Apple type-33 username (macOS local account). Borrowed; may be NULL
    // for classic-only connects. Required (non-empty) for type-33.
    const uint8_t *username;
    size_t username_len;
    // Password. For classic VNC Auth (type 2) only the first 8 bytes are
    // used (DES key). For Apple type-33 the full length is used (up to
    // 256 bytes at the CLI boundary).
    const uint8_t *password;
    size_t password_len;
    bool allow_none_auth;
    bool shared;
    // Apple attach mode after type-33 (CAPTURED E9 ViewerInfo):
    //   APPLE_ATTACH_SHARE (1) → share the console display
    //   APPLE_ATTACH_LOGIN (2) → log in as the authenticated user (virtual
    //     concurrent session). See docs/apple/SESSION-MODE-SHARE-VS-LOGIN.md.
    //   APPLE_ATTACH_ASK (0) → call apple_attach_choose after ServerInit if
    //     set; otherwise default to login.
    // Ignored for classic VNC Auth.
    uint8_t apple_attach;
    rfb_apple_attach_choose_fn apple_attach_choose; // optional; ASK only
    void *apple_attach_choose_ctx;
    // AUTO: prefer type-33 on Apple banners, else classic.
    // VNC: classic only. APPLE: type-33 only (no classic fallback).
    farsee_rfb_auth_mode auth_mode;
    // Frame publish path (optional). When non-NULL, complete updates are
    // published as full RGBA frames (FARSEE_PIXEL_RGBA8888). The session
    // never opens/presents/closes a presenter — the app owns present
    // (e.g. farsee_mt present thread drains the slot). When NULL, publish
    // is a no-op (no crash); production live paths always pass a slot.
    farsee_frame_slot *slot;
    // Input inject queue from the input thread (optional).
    farsee_cmd_queue *cmds;
    // Cooperative stop. When non-NULL and the flag is non-zero, the
    // protocol loop exits. Also consulted during TCP connect poll (T4).
    // Atomic: may be set from a signal handler or another thread.
    farsee_atomic_int *stop_flag;
    // 0 = unlimited (pacing still enforces one outstanding FBUR).
    uint32_t max_fps;
    // Connect/handshake deadline budget in ms (0 = library default caps).
    // Used by I/O pumps to fail closed instead of polling for hours.
    uint32_t connect_timeout_ms;
    // When true, the session must not send client input (KeyEvent /
    // PointerEvent), including type-33 black-desktop wake nudges.
    // Non-incremental FBUR re-requests remain allowed. Default false
    // (zero-init).
    bool view_only;
} rfb_session_config;

// Opaque-ish session object. Callers allocate storage; connect initializes
// internals. Always call rfb_session_destroy even after a failed connect.
typedef struct rfb_session rfb_session;

// Size of the concrete session object (for stack/heap allocation by
// callers that do not need the private layout).
size_t rfb_session_size(void);

// Zero-initialize session storage (optional; connect also tolerates
// garbage only if destroy was not needed — prefer zero or destroy).
void rfb_session_clear(rfb_session *s);

// Auto-select connect path from the server banner and auth_mode:
//   auth_mode APPLE → Apple type-33 path
//   auth_mode VNC   → classic handshake (even on RFB 003.889 banners)
//   auth_mode AUTO  → type-33 when banner is 003.889, else classic
//
// On type-33 success: wrap_key is stored on the session (zeroized on
// destroy), ClientInit + ServerInit run, framebuffer sized, encodings
// + FBUR sent if the peer still accepts classic cleartext setup.
// Dialect is set to APPLE_CLEARTEXT_MVP before setup so SetPixelFormat
// is skipped on the Apple path.
//
// Returns RFB_OK when the session is ACTIVE. On Apple banner without
// type 33 (or classic-only peer under APPLE mode), returns
// RFB_ERR_UNSUPPORTED.
//
// `s` must point to at least rfb_session_size() bytes. On any error the
// session is left destroyable (partial resources cleaned by destroy).
rfb_error rfb_session_connect(rfb_session *s,
                              const rfb_session_config *cfg);

// Classic-only connect: VNC Auth / None. Apple auth modes and Apple
// banners that offer only type-33 fail closed with RFB_ERR_UNSUPPORTED.
// Prefer rfb_session_connect for production CLI paths.
rfb_error rfb_session_connect_classic(rfb_session *s,
                                      const rfb_session_config *cfg);

// Protocol thread body: poll socket, decode FramebufferUpdates into the
// canonical framebuffer, publish complete frames to cfg.slot (when set),
// drain cmd queue → Key/Pointer wire events, pace FBUR.
// Never opens or presents a display surface — the app owns present.
// Returns when *stop_flag is set or the peer dies.
void rfb_session_protocol_loop(rfb_session *s);

// Last error recorded by connect or the protocol loop (RFB_OK if none).
rfb_error rfb_session_last_error(const rfb_session *s);

// Borrowed view of the session framebuffer (valid while session is live).
const rfb_framebuffer *rfb_session_framebuffer(const rfb_session *s);

// True if type-33 auth completed and a wrap_key is present on the session.
// Secret presence only — do not use as a demux/policy flag; use dialect.
bool rfb_session_has_wrap_key(const rfb_session *s);

// Copy the 16-byte wrap_key into out when has_wrap_key. Returns false if
// no key is present. Does not clear the session copy.
bool rfb_session_copy_wrap_key(const rfb_session *s, uint8_t out[16]);

// Session dialect (CLASSIC after clear/classic connect; APPLE_CLEARTEXT_MVP
// after type-33 success). NULL → CLASSIC.
rfb_session_dialect rfb_session_get_dialect(const rfb_session *s);

// Protocol-thread sampling: TCP RTT + cumulative rx into session atomics.
// Throttled to FARSEE_LINK_RATE_WINDOW_MS; protocol loop only (not present/input).
void rfb_session_sample_link(rfb_session *s);

// Status-band snapshot (atomics only — safe from present/input threads).
// *out_rtt_ms / *out_have_rtt / *out_rx / *out_have_rx may be NULL.
void rfb_session_link_snapshot(const rfb_session *s, uint32_t *out_rtt_ms,
                               bool *out_have_rtt, uint64_t *out_rx,
                               bool *out_have_rx);

// Same as rfb_session_link_snapshot plus producer-latched rate (coherent
// single atomic — loop r3 T1). *out_rate_kib / *out_have_rate may be NULL.
void rfb_session_link_snapshot_ex(const rfb_session *s, uint32_t *out_rtt_ms,
                                  bool *out_have_rtt, uint64_t *out_rx,
                                  bool *out_have_rx, uint32_t *out_rate_kib,
                                  bool *out_have_rate);

// Pure path selection: banner + auth_mode → Apple type-33 vs classic.
// - FARSEE_AUTH_MODE_APPLE → always true (type-33 path)
// - FARSEE_AUTH_MODE_VNC   → always false (classic; never force type-33
//   solely because the peer banner is RFB 003.889)
// - FARSEE_AUTH_MODE_AUTO  → true when apple_banner is set
bool rfb_session_prefer_apple_path(bool apple_banner,
                                   farsee_rfb_auth_mode auth_mode);

// Pure demux policy for Apple cleartext u16be control records (post-auth).
// Classic dialect always returns false (type=0 pad≠0 must not take the
// Apple skip — fall through to classic FBU demux).
// Apple cleartext MVP: true when data starts with type high-byte 0 and
// pad/low-byte ≠ 0 forming body_len in [8, 256]; then *out_total_len =
// 2 + body_len. Caller waits if input shorter than *out_total_len.
// Does not require the full body to be present for eligibility.
bool rfb_session_apple_u16be_control_eligible(rfb_session_dialect dialect,
                                              const uint8_t *data,
                                              size_t len,
                                              size_t *out_total_len);

// Pure: encode one or more RFB PointerEvent messages (type 5, 6 bytes
// each) for a normalized farsee pointer event.
//
// Held buttons map to RFB bits 0–2. Wheel deltas (high-res, 120 = 1 notch)
// emit press then release per notch: vertical uses buttons 4/5, horizontal
// uses buttons 6/7 (X11/VNC convention). Held buttons are preserved on
// both press and release. Motion-only events emit a single mask-without-
// wheel message.
//
// Writes into `out` (capacity `out_cap` bytes). Returns bytes written
// (multiple of 6), or 0 if pe is NULL / out is too small for the full
// sequence.
size_t rfb_session_format_pointer_events(const farsee_pointer_event *pe,
                                         uint8_t *out, size_t out_cap);

// First unexpected server message type byte observed in the protocol
// loop (0 if none). Diagnostic only — useful after RFB_ERR_PROTOCOL on
// type-33 cleartext demux failures.
uint8_t rfb_session_last_unexpected_type(const rfb_session *s);

// Host black-desktop hint: true exactly once when consecutive all-black
// published frames hit the threshold (operator guidance, not a protocol
// error). Pure; unit-tested.
#define RFB_BLACK_FRAME_HINT_FRAMES 20u
bool rfb_black_hint_due(uint32_t consecutive_black_frames);

// Format type-33 wake PointerEvent / KeyEvent bytes (pure; no I/O).
// When view_only is true, writes nothing and returns RFB_OK with *out_len=0
// (wake input must not be queued under --view-only). When false, always
// appends center pointer motion with button mask 0. Soft left click and
// Space/Shift keys are emitted only when with_key is true (session default
// is false; opt in via FARSEE_APPLE_WAKE=input). FBUR force-full-refresh is
// the caller's responsibility and is always allowed under view_only.
// Message types: KeyEvent=4, PointerEvent=5.
rfb_error rfb_format_apple_wake_input(uint8_t *out, size_t out_cap,
                                      size_t *out_len,
                                      bool view_only,
                                      bool with_key,
                                      uint32_t wake_attempt,
                                      uint16_t fb_width,
                                      uint16_t fb_height);

// Format type-33 post-ServerInit setup pointer path (pure; no I/O).
// Always three PointerEvents (type 5): (0,0) → quarter → center, each with
// button mask 0. Never emits a synthetic click. Used by session setup after
// ServerInit on APPLE_CLEARTEXT_MVP when not view-only.
rfb_error rfb_format_apple_setup_pointer(uint8_t *out, size_t out_cap,
                                         size_t *out_len, uint16_t fb_width,
                                         uint16_t fb_height);

// Send key-ups for every held key and pointer mask 0 while the socket is
// still open (teardown / quit). Safe no-op if inactive or view-only.
// Idempotent. (2026-07-31 T5)
void rfb_session_release_held_inputs(rfb_session *s);

// --- Unit-test seams (multi-review T5 wire-capture) -------------------------
// Attach an already-connected socket as the session I/O endpoint and mark
// the session active so rfb_session_release_held_inputs can write. Caller
// retains ownership of no resources beyond the fd (session closes it on
// destroy). Returns false on NULL / bad fd.
bool rfb_session_test_attach_connected_fd(rfb_session *s, int fd);

// Seed a held keysym / button mask as if session_drain_cmds had processed
// a KEY down / POINTER. Only for tests that then call release_held_inputs.
void rfb_session_test_seed_held_key(rfb_session *s, uint32_t keysym);
void rfb_session_test_seed_held_buttons(rfb_session *s, unsigned buttons);

// Release all session resources. Safe on a cleared or failed session.
// Idempotent. Zeroizes wrap_key if present.
void rfb_session_destroy(rfb_session *s);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_RFB_SESSION_H
