// SPDX-License-Identifier: Apache-2.0
//
// farsee — RFB live session driver (connect + protocol loop).
//
// Supports classic None/VNC Auth and Apple security types 33 and 36 on RFB
// 003.889 banners. After Apple authentication, the session stores wrap_key,
// sends the selected cleartext or record-mode post-ServerInit setup, and
// decodes server traffic for the framebuffer engine.

#ifndef FARSEE_INCLUDE_FARSEE_RFB_SESSION_H
#define FARSEE_INCLUDE_FARSEE_RFB_SESSION_H

#include "farsee/allocator.h"
#include "farsee/error.h"
#include "farsee/farsee_atomic.h"
#include "farsee/farsee_cmd_queue.h"
#include "farsee/farsee_frame_slot.h"
#include "farsee/framebuffer.h"
#include "farsee/handshake.h"
#include "farsee/rfb_capture_scheduler.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Post-auth session dialect. Apple control-record demux, encoding selection,
// sampled black-frame recovery, and SetPixelFormat policy use this enum.
// has_wrap_key reports secret presence only. Clear/classic sessions use
// CLASSIC; successful Apple authentication uses APPLE_CLEARTEXT_MVP.
typedef enum rfb_session_dialect {
    RFB_SESSION_DIALECT_CLASSIC = 0,
    RFB_SESSION_DIALECT_APPLE_CLEARTEXT_MVP = 1
    /* RFB_SESSION_DIALECT_APPLE_AEAD = 2 — future */
} rfb_session_dialect;

// Optional callback after Apple ServerInit and before ViewerInfo when
// apple_attach is APPLE_ATTACH_ASK. desktop_name is the ServerInit desktop
// string and may contain binary TLV. username may be NULL. On success, set
// *out_attach to APPLE_ATTACH_SHARE or APPLE_ATTACH_LOGIN and return true.
// The connect owner calls synchronously; all arguments are borrowed only for
// the callback. Return false to use the session default, login.
typedef bool (*rfb_apple_attach_choose_fn)(void *ctx,
                                           const char *desktop_name,
                                           const char *username,
                                           uint8_t *out_attach);

// Apple post-authentication mode. Zero selects cleartext compatibility. The
// record modes use the 0x044f AES-CBC layer; PRIVATE_ENCODINGS selects the
// private Apple encoding list.
typedef enum rfb_apple_postauth_mode {
    RFB_APPLE_POSTAUTH_CLEARTEXT = 0,
    RFB_APPLE_POSTAUTH_RECORDS = 1,
    RFB_APPLE_POSTAUTH_PRIVATE_ENCODINGS = 2,
} rfb_apple_postauth_mode;

// Configuration for an RFB connect. The session does not own pointer fields;
// each field documents its required lifetime.
typedef struct rfb_session_config {
    // Optional session allocator. When set, every first-party variable-size
    // allocation is charged through it. Borrowed for the session lifetime.
    rfb_allocator *allocator;
    const char *host;
    uint16_t port;  // 0 → 5900
    // Optional already-connected TCP stream. When enabled, host must be NULL,
    // port must be zero, and connected_fd must name a connected AF_INET or
    // AF_INET6 SOCK_STREAM. The session duplicates the descriptor with
    // close-on-exec and owns only that duplicate; the caller retains its fd.
    // The duplicate shares socket status flags/options, so the caller must not
    // use the socket concurrently and must permit nonblocking/TCP_NODELAY.
    // This library API accepts descriptor 0; command-line frontends may reserve
    // descriptors 0-2 and impose a stricter inherited-descriptor boundary.
    bool use_connected_fd;
    int connected_fd;
    // Apple security-path username. Borrowed through connect; may be NULL for
    // classic-only connects and must be non-empty for Apple authentication.
    const uint8_t *username;
    size_t username_len;
    // Password. Classic VNC Auth uses the first 8 bytes as its DES key. The
    // Apple security path uses the full length, bounded by the caller policy.
    // Borrowed only through connect; the stored pointer is then cleared.
    const uint8_t *password;
    size_t password_len;
    bool allow_none_auth;
    // First-use host-key policy for Apple type 33:
    // false (default) — an unknown host key fails closed with the SPKI
    // fingerprint printed; true — accept the first-use key and pin it
    // after the server proves itself via M2 (CLI --accept-new-host).
    bool accept_new_host;
    // Require Apple security type 36 by withdrawing type 33 from policy.
    // False admits both and keeps the established preference for type 33.
    bool apple_prefer_type_36;
    // Explicit Apple wire policy. Process environment never changes these
    // values. Zero initialization preserves the established product defaults.
    rfb_apple_postauth_mode apple_postauth_mode;
    bool apple_send_viewer_info;
    bool apple_disable_wake_keys;
    bool shared;
    // Apple attach mode after ViewerInfo:
    //   APPLE_ATTACH_SHARE (1) → share the console display
    //   APPLE_ATTACH_LOGIN (2) → log in as the authenticated user (virtual
    //     concurrent session). See docs/apple/SESSION-MODE-SHARE-VS-LOGIN.md.
    //   APPLE_ATTACH_ASK (0) → call apple_attach_choose after ServerInit if
    //     set; otherwise default to login.
    // Ignored for classic VNC Auth.
    uint8_t apple_attach;
    rfb_apple_attach_choose_fn apple_attach_choose; // optional; ASK only
    void *apple_attach_choose_ctx;
    // AUTO: use the Apple path on RFB 003.889 banners, otherwise classic.
    // VNC: classic only. APPLE: Apple security types 33/36 only.
    farsee_rfb_auth_mode auth_mode;
    // Optional frame publication slot. Complete RGBA frames are published to
    // it. The session does not open, present, or close a presenter. NULL skips
    // publication.
    farsee_frame_slot *slot;
    // Input inject queue from the input thread (optional).
    farsee_cmd_queue *cmds;
    // Cooperative stop. When non-NULL and the flag is non-zero, the
    // protocol loop exits. It is also consulted during TCP connect polling.
    // Atomic: may be set from a signal handler or another thread.
    farsee_atomic_int *stop_flag;
    // 0 = unlimited (pacing still enforces one outstanding FBUR).
    uint32_t max_fps;
    // Connect/handshake deadline budget in ms (0 = library default caps).
    // Used by I/O pumps to fail closed instead of polling for hours.
    uint32_t connect_timeout_ms;
    // When true, do not send KeyEvent or PointerEvent, including Apple
    // black-frame recovery input. Full-refresh requests remain allowed.
    // Default false.
    bool view_only;
    // When true, bypass the Apple cleartext sampled-threshold withhold so the
    // slot receives those frames. Default false.
    bool publish_black_frames;
    // Optional exact-subrectangle schedule. A non-zero count disables normal
    // pacing, wake input, and sampled black-frame retries after the mandatory
    // initial full-screen request. Queries are borrowed and immutable for the
    // session lifetime. Results contain structural metadata only.
    const rfb_capture_query *capture_queries;
    size_t capture_query_count;
    uint32_t capture_response_timeout_ms;
    // Required continuous interval without framebuffer damage after a complete
    // FBU before associating the next query. Typed control activity does not
    // restart this interval.
    uint32_t capture_quiet_ms;
    // Bounded source-truth control: negotiate only ZRLE plus the frozen
    // pseudo-encodings, accept the mandatory initial nonincremental FBU,
    // then stop after continuous quiet without issuing a target request.
    bool capture_initial_only;
    bool capture_initial_zrle_only;
    // Optional mutation hold. The fd is a caller-owned,
    // nonblocking AF_UNIX datagram endpoint and remains open across the
    // session. The binding points to exactly 32 borrowed bytes.
    bool capture_require_mutation_ack;
    uint32_t capture_mutation_timeout_ms;
    int capture_control_fd;
    uint64_t capture_slot_nonce;
    uint32_t capture_transition_id;
    const uint8_t *capture_source_b_binding;
    size_t capture_initial_rectangle_max;
    rfb_capture_rect_observation_v1 *capture_rect_observations;
    size_t capture_rect_observation_capacity;
    rfb_capture_final_observation_v1 *capture_final_observations;
    size_t capture_final_observation_capacity;
    rfb_capture_result_fn capture_on_result;
    void *capture_on_result_ctx;
} rfb_session_config;

// Opaque session storage. Callers allocate at least rfb_session_size() bytes
// and clear it before first use.
typedef struct rfb_session rfb_session;

// Size of the concrete session object (for stack/heap allocation by
// callers that do not need the private layout).
size_t rfb_session_size(void);

// Initialize storage as an empty, destroyable session. Do not call this on a
// live session.
void rfb_session_clear(rfb_session *s);

// Select a connect path from the banner and auth_mode. APPLE uses the Apple
// security path; VNC uses the classic handshake; AUTO uses the Apple path for
// an RFB 003.889 banner and classic otherwise.
//
// Successful Apple authentication stores wrap_key for zeroization on destroy.
// The selected post-auth mode completes ClientInit and ServerInit, sizes the
// framebuffer, and queues its setup.
//
// Returns RFB_OK only when the session is active. Returns RFB_ERR_UNSUPPORTED
// when the selected mode has no mutually supported security type.
//
// `s` must address at least rfb_session_size() bytes and must be cleared before
// first use. After config validation succeeds, a later error leaves initialized
// session resources destroyable.
rfb_error rfb_session_connect(rfb_session *s,
                              const rfb_session_config *cfg);

// Classic-only connect for VNC Auth or None. Apple-only mode is rejected, and
// Apple banners without a mutually supported classic type fail closed. Prefer
// rfb_session_connect for production CLI paths.
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

// Optional scheduler status. A normal session reports CLEAR/NONE.
// These accessors expose no packet or credential material.
rfb_capture_scheduler_state rfb_session_capture_state(const rfb_session *s);
rfb_capture_failure rfb_session_capture_failure(const rfb_session *s);

// Borrowed view of the session framebuffer (valid while session is live).
const rfb_framebuffer *rfb_session_framebuffer(const rfb_session *s);

// True when Apple authentication produced wrap_key. Secret presence only; do
// not use this accessor as a demux or policy flag.
bool rfb_session_has_wrap_key(const rfb_session *s);

// True after the Apple path installs AES-CBC from 0x044f and begins record
// processing. wrap_key presence alone is not sufficient during connect.
bool rfb_session_apple_records_active(const rfb_session *s);

// Copy the 16-byte wrap_key into out when has_wrap_key. Returns false if
// no key is present. Does not clear the session copy.
bool rfb_session_copy_wrap_key(const rfb_session *s, uint8_t out[16]);

// Session dialect. Cleared and classic sessions report CLASSIC; successful
// Apple authentication reports APPLE_CLEARTEXT_MVP. NULL reports CLASSIC.
rfb_session_dialect rfb_session_get_dialect(const rfb_session *s);

// Protocol-thread sampling: TCP RTT + cumulative rx into session atomics.
// Throttled to FARSEE_LINK_RATE_WINDOW_MS; protocol loop only (not present/input).
void rfb_session_sample_link(rfb_session *s);

// Status-band snapshot (atomics only — safe from present/input threads).
// *out_rtt_ms / *out_have_rtt / *out_rx / *out_have_rx may be NULL.
void rfb_session_link_snapshot(const rfb_session *s, uint32_t *out_rtt_ms,
                               bool *out_have_rtt, uint64_t *out_rx,
                               bool *out_have_rx);

// Same as rfb_session_link_snapshot plus producer-latched rate in one
// coherent atomic. *out_rate_kib / *out_have_rate may be NULL.
void rfb_session_link_snapshot_ex(const rfb_session *s, uint32_t *out_rtt_ms,
                                  bool *out_have_rtt, uint64_t *out_rx,
                                  bool *out_have_rx, uint32_t *out_rate_kib,
                                  bool *out_have_rate);

// Pure path selection from banner and auth_mode. APPLE selects the Apple path;
// VNC selects classic; AUTO selects Apple only for an RFB 003.889 banner.
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

// Encode RFB PointerEvent messages for one normalized pointer event.
// Held buttons map to bits 0-2. Wheel deltas use 120 units per notch and are
// capped to 32 notches per axis. Each notch emits press then release: vertical
// uses buttons 4/5 and horizontal uses 6/7. Held buttons are preserved. An
// event without wheel notches emits one held-button/motion message.
//
// Writes the complete sequence to `out` and returns its byte count, a multiple
// of 6. Returns 0 for invalid input or insufficient capacity.
size_t rfb_session_format_pointer_events(const farsee_pointer_event *pe,
                                         uint8_t *out, size_t out_cap);

// First unexpected server message type observed by the protocol loop, or zero.
// Diagnostic only; useful for Apple cleartext demux failures.
uint8_t rfb_session_last_unexpected_type(const rfb_session *s);

// True exactly once when the consecutive-frame count reaches the black-frame
// hint threshold. This helper does not inspect framebuffer pixels.
#define RFB_BLACK_FRAME_HINT_FRAMES 20u
bool rfb_black_hint_due(uint32_t consecutive_black_frames);

// Select an operator hint when the fixed Apple frame-count threshold is reached
// while nonblack_seen is false. Text depends on records_active.
typedef enum rfb_black_hint_kind {
    RFB_BLACK_HINT_NONE = 0,        // no hint selected
    RFB_BLACK_HINT_APPLE_CLEARTEXT, // Apple cleartext path
    RFB_BLACK_HINT_APPLE_RECORDS    // Apple AES-CBC records active
} rfb_black_hint_kind;

// Pure; unit-tested. Due exactly once, at RFB_BLACK_FRAME_HINT_FRAMES.
rfb_black_hint_kind rfb_black_hint_kind_for(bool apple_dialect,
                                            bool records_active,
                                            bool nonblack_seen,
                                            uint32_t consecutive_black_frames);

// Pure; never NULL. Empty string for RFB_BLACK_HINT_NONE.
const char *rfb_black_hint_text(rfb_black_hint_kind kind);

// Pure decision for withholding an Apple cleartext frame that did not cross
// the sampled non-black threshold. publish_black_frames bypasses the withhold.
bool rfb_session_should_withhold_black_publish(bool apple_cleartext,
                                               bool nonblack,
                                               bool publish_black_frames);

// Format Apple recovery PointerEvent and KeyEvent bytes without I/O. view_only
// writes nothing. Otherwise, center pointer motion is always included; Space or
// Shift press/release is included only when with_key is true. The caller owns
// any full-refresh request.
// Message types: KeyEvent=4, PointerEvent=5.
rfb_error rfb_format_apple_wake_input(uint8_t *out, size_t out_cap,
                                      size_t *out_len,
                                      bool view_only,
                                      bool with_key,
                                      uint32_t wake_attempt,
                                      uint16_t fb_width,
                                      uint16_t fb_height);

// Format the Apple post-ServerInit pointer sequence without I/O: origin,
// quarter, then center, all with mask 0. No click is emitted.
rfb_error rfb_format_apple_setup_pointer(uint8_t *out, size_t out_cap,
                                         size_t *out_len, uint16_t fb_width,
                                         uint16_t fb_height);

// Send key-ups for every held key and pointer mask 0 while the socket is
// still open (teardown / quit). Safe no-op if inactive or view-only.
// Idempotent.
void rfb_session_release_held_inputs(rfb_session *s);

// Release all session resources. Safe on a cleared or failed session.
// Idempotent. Zeroizes wrap_key if present.
void rfb_session_destroy(rfb_session *s);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_RFB_SESSION_H
