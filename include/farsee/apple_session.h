// SPDX-License-Identifier: Apache-2.0
//
// farsee — Apple post-auth session driver.
//
// Processes Apple post-authentication messages after record-layer framing and
// protection have been removed by the caller. Responses are returned as
// plaintext for caller-managed framing and protection.
//
// apple_session_step() drives a single-threaded state machine. The session
// retains borrowed record-layer, framebuffer, and allocator pointers. It owns
// cursor byte copies for a fixed number of entries and stores parsed prelude fields, phase labels, and
// diagnostic counters.
//
// Control-message type IDs are declared in apple_postauth.h. Record protection
// is owned by the caller's Apple record layer; this API receives cleartext
// prelude bytes or already-decrypted record bytes.

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
// The phase starts at PRELUDE. Handled display-configuration and auto-update
// records set DISPLAY_CONFIG and ARMED. The other values remain available as
// phase labels, but this implementation does not enter them.
// ---------------------------------------------------------------------------
typedef enum {
    APPLE_SESSION_PRELUDE = 0,     // initial phase
    APPLE_SESSION_REKEY,           // rekey phase label
    APPLE_SESSION_DISPLAY_CONFIG,  // set after display configuration
    APPLE_SESSION_ENCODINGS,       // encodings phase label
    APPLE_SESSION_ARMED,           // set after AutoFrameBufferUpdate
    APPLE_SESSION_STREAMING,       // streaming phase label
    APPLE_SESSION_RESIZE,          // resize phase label
    APPLE_SESSION_CLOSED,          // checked terminal phase label
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
// Cursor cache.
//
// Apple cursor sprites are cached by index. The cache is bounded to
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
// Retains borrowed pointers to the record layer, framebuffer, and allocator.
// Owns cursor byte copies for a fixed number of entries plus its phase and counters.
// The caller manages every borrowed object's lifetime; this module can be
// initialized with synthetic state.
// ---------------------------------------------------------------------------
typedef struct apple_session {
    apple_session_phase phase;

    // Borrowed record layer retained for caller integration. This implementation
    // does not dereference it and permits NULL.
    apple_record_layer *rl;

    // Borrowed framebuffer. Display-configuration handling and explicit resize
    // calls can resize it.
    rfb_framebuffer *fb;

    // Borrowed allocator (for cursor cache).
    rfb_allocator *alloc;

    // Prelude state.
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

    // Byte limit for framebuffer allocation.
    size_t fb_byte_limit;

    // Last error message (static literal; never remote-controlled text).
    const char *last_error;
} apple_session;

// Initialize with borrowed pointers. The framebuffer may be zero-sized;
// successful display-configuration handling or apple_session_resize() resizes
// it. fb_byte_limit bounds framebuffer allocations.
void apple_session_init(apple_session *s, apple_record_layer *rl,
                        rfb_framebuffer *fb, rfb_allocator *alloc,
                        size_t fb_byte_limit);

// Release owned resources (cursor cache). Does not destroy the borrowed
// record layer or framebuffer. Zeroizes the cursor cache.
void apple_session_destroy(apple_session *s);

// Feed one cleartext or decrypted record to the state machine.
// On success, the call may store fields, serialize a response, resize the
// framebuffer, or update the cursor cache. On failure it sets last_error and
// returns the error; this module does not set APPLE_SESSION_CLOSED.
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

// Resize the borrowed framebuffer transactionally. Returns RFB_OK or
// RFB_ERR_LIMIT/RFB_ERR_NOMEM.
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
