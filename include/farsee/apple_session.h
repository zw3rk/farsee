// SPDX-License-Identifier: Apache-2.0
//
// farsee — Apple post-auth session driver (goals.md G19).
//
// Drives the Apple post-authentication protocol using the G15 fake auth
// provider (deterministic wrap key) and the G17 record layer. This is
// the deterministic fake-server path: real-macOS interop is NEEDS-HARDWARE.
//
// The session is a single-threaded state machine driven by
// apple_session_step(). It is independent of sockets: it consumes
// decrypted plaintext records and emits plaintext records to be encrypted
// by the caller. This keeps it ASan-safe and testable without real I/O.
//
// FIELD CLASSIFICATION (goals.md §14, apple-wire-spec.md):
//   The exact encrypted message type IDs are UNKNOWN pending key-material
//   capture. The fake server (G19) defines a deterministic, self-consistent
//   set of type IDs (see apple_postauth.h). The cleartext prelude fields
//   (hostname, device name) are CAPTURED.
//
// DIVERGENCE NOTE: the G17 record layer uses AES-128-CBC; the captured
// wire uses ChaCha20-Poly1305. For the fake-server path both sides use
// the G17 layer (deterministic). Real macOS requires the captured cipher.

#ifndef FARSEE_INCLUDE_FARSEE_APPLE_SESSION_H
#define FARSEE_INCLUDE_FARSEE_APPLE_SESSION_H

#include "farsee/apple_postauth.h"
#include "farsee/apple_record.h"
#include "farsee/error.h"
#include "farsee/framebuffer.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// ---------------------------------------------------------------------------
// Session phases (state machine).
//
// The Apple post-auth session progresses through these phases. Each is
// driven by apple_session_step() feeding a decrypted plaintext record or
// a cleartext prelude byte span.
// ---------------------------------------------------------------------------
typedef enum {
    APPLE_SESSION_PRELUDE = 0,     // cleartext: ClientInit → ServerInit → ViewerInfo → SetEncryption → SetMode
    APPLE_SESSION_REKEY,           // rekey arrives mid-prelude (CAPTURED structure)
    APPLE_SESSION_DISPLAY_CONFIG,  // encrypted SetDisplayConfiguration
    APPLE_SESSION_ENCODINGS,       // encrypted SetEncodings
    APPLE_SESSION_ARMED,           // AutoFrameBufferUpdate armed
    APPLE_SESSION_STREAMING,       // framebuffer updates flowing
    APPLE_SESSION_RESIZE,          // display layout change (CAPTURED: authoritative Apple resize)
    APPLE_SESSION_CLOSED,          // clean close
} apple_session_phase;

// The direction of a record handed to apple_session_step().
typedef enum {
    APPLE_STEP_CLEARTEXT = 0,  // prelude plaintext (not yet encrypted)
    APPLE_STEP_ENCRYPTED = 1,  // a decrypted record from the server
} apple_step_kind;

// A single input record for apple_session_step().
typedef struct apple_session_record {
    apple_step_kind kind;
    const uint8_t *data;
    size_t         len;
} apple_session_record;

// ---------------------------------------------------------------------------
// Cursor cache entry (bounded memory, plan.md §6.4).
//
// INFERRED: Apple caches cursor sprites by index. The cache is bounded to
// APPLE_CURSOR_CACHE_MAX entries. STORE replaces; SELECT activates.
// ---------------------------------------------------------------------------
typedef struct apple_cursor_cache_entry {
    uint8_t  index;
    uint16_t width;
    uint16_t height;
    uint16_t hotspot_x;
    uint16_t hotspot_y;
    bool     valid;
    // RGBA bytes owned by the session (allocated via the session allocator).
    uint8_t *rgba;
    size_t   rgba_len;
} apple_cursor_cache_entry;

// ---------------------------------------------------------------------------
// Session context.
//
// Owns: the record layer reference (borrowed), the framebuffer (borrowed),
// the cursor cache (owned, bounded), and the current phase.
// Does NOT own the record layer or framebuffer lifetime — those are
// managed by the caller so the session can be tested with synthetic state.
// ---------------------------------------------------------------------------
typedef struct apple_session {
    apple_session_phase phase;

    // Borrowed record layer (for rekey mid-prelude). May be NULL when the
    // caller drives records externally; rekey_step then records the request.
    apple_record_layer *rl;

    // Borrowed framebuffer (authoritative RGBA8). The session resizes it
    // on display-config and writes pixels on framebuffer updates.
    rfb_framebuffer *fb;

    // Borrowed allocator (for cursor cache).
    rfb_allocator *alloc;

    // Captured/prelude state.
    apple_server_init server_init;
    apple_viewer_info viewer_info;
    bool encryption_enabled;
    uint8_t mode;

    // Cursor cache (bounded).
    apple_cursor_cache_entry cursor_cache[APPLE_CURSOR_CACHE_MAX];
    uint8_t active_cursor;

    // AutoFrameBufferUpdate arming state.
    bool auto_update_armed;
    uint16_t auto_update_rate;

    // Diagnostics: counts (no secrets).
    uint32_t records_processed;
    uint32_t updates_rendered;
    uint32_t resizes;
    uint32_t rekeys;
    uint32_t unknown_messages_tolerated;

    // Byte limit for framebuffer allocation (plan.md §6.4).
    size_t fb_byte_limit;

    // Last error message (static literal; never remote-controlled text).
    const char *last_error;
} apple_session;

// Initialize a session with borrowed record layer, framebuffer, allocator.
// The framebuffer must already be initialized (may be zero-size until the
// first ServerInit). fb_byte_limit bounds framebuffer allocations.
void apple_session_init(apple_session *s, apple_record_layer *rl,
                        rfb_framebuffer *fb, rfb_allocator *alloc,
                        size_t fb_byte_limit);

// Release owned resources (cursor cache). Does not destroy the borrowed
// record layer or framebuffer. Zeroizes the cursor cache.
void apple_session_destroy(apple_session *s);

// Feed one record (cleartext or decrypted) to the session state machine.
// On success advances the phase and may mutate the framebuffer. On failure
// sets s->last_error and returns the typed error; the phase may advance to
// APPLE_SESSION_CLOSED on fatal errors.
//
// `out_bytes`/`out_cap`/`out_len`: if the step produces a client→server
// response (e.g. ViewerInfo after ServerInit), it is serialized into
// out_bytes and *out_len is set. out_len is set to 0 if no response.
rfb_error apple_session_step(apple_session *s, const apple_session_record *step,
                             uint8_t *out_bytes, size_t out_cap, size_t *out_len);

// Arm the AutoFrameBufferUpdate (client→server). Serializes the arm message
// into out_bytes. Returns RFB_OK or an error.
rfb_error apple_session_arm_auto_update(apple_session *s, uint16_t max_rate,
                                        uint8_t *out_bytes, size_t out_cap,
                                        size_t *out_len);

// Apply a display resize (authoritative Apple layout). Transactionally
// resizes the framebuffer. Returns RFB_OK or RFB_ERR_LIMIT/RFB_ERR_NOMEM.
rfb_error apple_session_resize(apple_session *s, uint16_t width, uint16_t height);

// Store a cursor into the bounded cache. Replaces any entry at the index.
// Copies the RGBA bytes (caller retains ownership of `rgba`).
rfb_error apple_session_cursor_store(apple_session *s, uint8_t index,
                                     uint16_t width, uint16_t height,
                                     uint16_t hotspot_x, uint16_t hotspot_y,
                                     const uint8_t *rgba, size_t rgba_len);

// Select (activate) a cached cursor. Returns RFB_ERR_PROTOCOL if the index
// is empty/invalid.
rfb_error apple_session_cursor_select(apple_session *s, uint8_t index);

// Current phase (for diagnostics). Returns a static literal.
const char *apple_session_phase_name(apple_session_phase p);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_APPLE_SESSION_H
