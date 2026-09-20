// SPDX-License-Identifier: Apache-2.0
//
// farsee — private RFB session layout and cross-owner seams.
//
// This header is internal to the session implementation and test-only
// fixtures. It is never installed and is not part of the public API.

#ifndef FARSEE_SRC_RFB_RFB_SESSION_INTERNAL_H
#define FARSEE_SRC_RFB_RFB_SESSION_INTERNAL_H

#include "farsee/allocator.h"
#include "farsee/apple_mvs_stream.h"
#include "farsee/apple_record.h"
#include "farsee/buffer.h"
#include "farsee/clipboard.h"
#include "farsee/encoding.h"
#include "farsee/farsee_display.h"
#include "farsee/farsee_input.h"
#include "farsee/framebuffer.h"
#include "farsee/io_adapter.h"
#include "farsee/pacing.h"
#include "farsee/pixel_format.h"
#include "farsee/rfb_io_pump.h"
#include "farsee/rfb_server_engine.h"
#include "farsee/rfb_session.h"
#include "farsee/server_init.h"
#include "farsee/socket_posix.h"
#include "farsee/zlib_adapter.h"

#include <stdbool.h>
#include <stdint.h>

typedef uint64_t (*rfb_session_capture_clock_fn)(void *opaque);
typedef bool (*rfb_session_random_bytes_fn)(void *opaque, uint8_t *out,
                                            size_t length);

// Largest ClientCutText body that fits the current 4096-byte Apple sealed
// record staging buffer after its 8-byte RFB header and record overhead.
#define RFB_SESSION_APPLE_CLIPBOARD_MAX_BYTES ((size_t)4050u)

// Private alternate wire schedules. The release frontend never changes
// these zero-initialized values. Internal tests can select a variant without
// inheriting mutable process environment.
typedef enum rfb_apple_rekey_variant {
    RFB_APPLE_REKEY_NONE = 0,
    RFB_APPLE_REKEY_ECHO,
    RFB_APPLE_REKEY_FRESH,
} rfb_apple_rekey_variant;

typedef enum rfb_apple_initial_output_variant {
    RFB_APPLE_INITIAL_OUTPUT_STANDARD = 0,
    RFB_APPLE_INITIAL_OUTPUT_FBUR_ONLY,
    RFB_APPLE_INITIAL_OUTPUT_MSG14_THEN_FBUR,
    RFB_APPLE_INITIAL_OUTPUT_FBUR_THEN_MSG14,
} rfb_apple_initial_output_variant;

typedef struct rfb_apple_wire_variants {
    uint8_t c2s_key_mode;
    rfb_apple_rekey_variant rekey;
    rfb_apple_initial_output_variant initial_output;
    uint8_t deferred_output_after_s2c;
    bool suppress_fbur;
    bool deferred_iv_follows_s2c;
    bool deferred_sequence_follows_s2c;
    bool deferred_output_is_msg14;
    bool mvs_skip_unknown;
} rfb_apple_wire_variants;

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
    rfb_pixel_format pf;
    rfb_pixel_format server_pf;
    uint16_t fb_width;
    uint16_t fb_height;
    rfb_zlib_stream *zstream;
    rfb_pacing pacing;
    rfb_cursor cursor;
    rfb_allocator *alloc;
    rfb_server_engine eng;
    rfb_capture_scheduler capture;
    bool capture_enabled;
    // Set when processed input carried framebuffer damage. Only damage may
    // restart the capture quiet window; typed control traffic must not.
    bool capture_frame_progress;
    bool capture_control_ready_sent;
    // Production points at sock.tx_bytes. Test-only fixtures may provide a
    // counter owned by the adapter that actually performs their writes.
    farsee_atomic_u64 *transport_tx_bytes;
    // Deterministic clock for the active capture step. Engine hooks sample
    // it independently so decode time is reflected truthfully.
    rfb_session_capture_clock_fn capture_clock_now_ms;
    void *capture_clock_opaque;
    uint64_t capture_now_ms;
    bool has_wrap_key;
    uint8_t wrap_key[16];
    apple_record_layer apple_rl;
    bool apple_rl_inited;
    bool apple_records_active;
    rfb_buffer apple_plain;
    rfb_buffer apple_stage;
    uint32_t apple_s2c_opened;
    bool apple_deferred_seal_sent;
    uint8_t apple_last_s2c_ct[16];
    bool apple_have_last_s2c_ct;
    uint8_t apple_sk32[32];
    bool apple_have_sk32;
    uint8_t apple_setup_payload32[32];
    bool apple_have_setup_payload;
    rfb_session_dialect dialect;
    uint8_t mvs_qt0[64];
    uint8_t mvs_qt1[64];
    bool mvs_have_qt;
    apple_mvs_coeff_store mvs_coeffs;
    rfb_apple_wire_variants wire_variants;
    bool apple_bootstrap_done;
    bool apple_seen_nonblack;
    uint32_t frames_published;
    uint32_t apple_wake_attempts;
    uint64_t apple_black_retry_ms;
    uint64_t connect_deadline_mono_ms;
    farsee_atomic_u64 link_meta;
    farsee_atomic_u64 link_rx_bytes;
    farsee_atomic_u64 link_rate_pub;
    farsee_link_rate link_rate;
    uint64_t next_link_sample_ms;
    farsee_key_ledger key_ledger;
    unsigned held_buttons;
    uint16_t last_ptr_x;
    uint16_t last_ptr_y;
    uint8_t *clipboard_host;
    size_t clipboard_host_cap;
    uint64_t clipboard_next_poll_ms;
    rfb_clip_loop clipboard_loop;
    uint32_t clipboard_last_local_hash;
    bool clipboard_has_last_local;
};

// Execute exactly one iteration of the production capture branch. Every
// transition refreshes this clock after I/O; test-only fixtures supply a
// deterministic clock while the product supplies CLOCK_MONOTONIC.
rfb_error rfb_session_capture_step_with_clock(
    rfb_session *session, rfb_session_capture_clock_fn clock_now_ms,
    void *clock_opaque, int poll_ms);

// Private production operations used by the test-only post-auth fixture.
// They remain the sole queue/seal and FBUR formatting paths.
rfb_error session_queue_bytes(rfb_session *session,
                              const uint8_t *data, size_t length);
rfb_error session_queue_apple_modern_setup(
    rfb_session *session, bool private_encodings);
rfb_error session_send_fbur_rect(rfb_session *session, bool incremental,
                                 uint16_t x, uint16_t y,
                                 uint16_t width, uint16_t height);

// Best-effort output drain through the session's borrowed I/O pump.
rfb_io_pump rfb_session_internal_pump(rfb_session *session);
void rfb_session_internal_flush_output(rfb_session *session, int timeout_ms);
bool rfb_session_internal_stop_requested(const rfb_session *session);
uint64_t rfb_session_internal_capture_now(const rfb_session *session);
bool rfb_session_internal_is_apple_cleartext(const rfb_session *session);
rfb_error rfb_session_internal_send_fbur(rfb_session *session,
                                         bool incremental);
rfb_error rfb_session_internal_decrypt_apple_records(
    rfb_session *session, bool *progress);
rfb_error rfb_session_internal_capture_step(rfb_session *session,
                                            int poll_ms);

// Cross-owner connect seams. The connect owner drives transport and
// authentication. The wire owner initializes protocol output and Apple
// records after ServerInit.
rfb_error rfb_session_internal_setup_after_server_init(
    rfb_session *session, const rfb_server_init *server_init);
rfb_error rfb_session_internal_enable_apple_records(rfb_session *session);

// One-step production operations used by the live loop. Their declarations
// also let the separately linked test adapter drive the same implementation.
rfb_error rfb_session_internal_drain_cmds(rfb_session *session);
rfb_error rfb_session_internal_process_in(rfb_session *session,
                                          bool *progress);
rfb_error rfb_session_internal_publish_frame(rfb_session *session);
void rfb_session_internal_apple_wake(rfb_session *session, bool with_key);
void rfb_session_internal_receive_clipboard(rfb_session *session,
                                            const uint8_t *text,
                                            size_t length);
rfb_error rfb_session_internal_poll_clipboard(rfb_session *session,
                                              uint64_t now_ms);

// Build one dormant fresh-rekey transaction with caller-supplied random
// bytes. The complete cleartext rekey envelope and sealed msg14 are queued as
// one transaction before the prepared encrypt direction replaces the old one.
rfb_error rfb_session_internal_queue_fresh_rekey(
    rfb_session *session, rfb_session_random_bytes_fn random_bytes,
    void *random_opaque);

#endif  // FARSEE_SRC_RFB_RFB_SESSION_INTERNAL_H
