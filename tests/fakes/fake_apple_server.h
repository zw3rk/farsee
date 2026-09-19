// SPDX-License-Identifier: Apache-2.0
//
// farsee — deterministic fake Apple server.
//
// Simulates the full Apple type-33 session byte stream for integration
// testing: prelude, rekey interleaving, metadata bursts, fragmented
// encrypted messages, resize-before-pixels, cursor cache, lock/login
// transition, and clean close. Deterministic — the same inputs always
// produce the same byte stream (no RNG, no time, no sockets).
//
// The fake server controls both sides of the deterministic path, so it uses
// the record layer (AES-128-CBC) with fixed keys. SRP-derived key wrapping
// is outside this fake.

#ifndef FARSEE_TESTS_FAKES_FAKE_APPLE_SERVER_H
#define FARSEE_TESTS_FAKES_FAKE_APPLE_SERVER_H

#include "farsee/apple_postauth.h"
#include "farsee/apple_record.h"
#include "farsee/error.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Maximum bytes the fake server emits in one scenario (policy cap).
#define FAKE_APPLE_SERVER_MAX_OUT (1024u * 1024u)

// Default deterministic framebuffer dimensions for the fake server.
#define FAKE_APPLE_DEFAULT_WIDTH  64u
#define FAKE_APPLE_DEFAULT_HEIGHT 64u

// Scenario selection for the fake server.
typedef enum {
    FAKE_SCENARIO_BASIC = 0,        // prelude → display-config → arm → pixels → close
    FAKE_SCENARIO_REKEY_MID_PRELUDE,// rekey arrives between ServerInit and display-config
    FAKE_SCENARIO_RESIZE_BEFORE_PIXELS, // DesktopSize then pixel rectangles
    FAKE_SCENARIO_FRAGMENTED,       // one logical record split across emit calls
    FAKE_SCENARIO_CURSOR_CACHE,     // STORE then SELECT reuse
    FAKE_SCENARIO_LOCK_LOGIN,       // lock transition then re-arm then pixels
    FAKE_SCENARIO_CLEAN_CLOSE,      // close after pixels, no corruption
} fake_apple_scenario;

// Configuration for the fake server scenario.
typedef struct fake_apple_config {
    fake_apple_scenario scenario;
    uint16_t width;
    uint16_t height;
    bool send_cursor_cache;     // emit cursor STORE/SELECT
    bool fragment_records;      // split logical records into multiple emits
    bool send_lock_transition;  // emit a lock/login transition
} fake_apple_config;

// The fake server state. Owns an output buffer (caller-supplied). The
// record layer is borrowed so the test and server share keys (deterministic).
typedef struct fake_apple_server {
    fake_apple_config cfg;
    apple_record_layer *rl;     // borrowed; shared keys with the session

    // Output staging buffer (caller-owned).
    uint8_t *out;
    size_t   out_cap;
    size_t   out_len;

    // Internal step cursor through the scenario.
    size_t   step_index;
    bool     done;

    // Deterministic pixel fill color (R,G,B,A) for the framebuffer.
    uint8_t  fill_r, fill_g, fill_b, fill_a;

    // Diagnostics (no secrets).
    uint32_t records_emitted;
    uint32_t bytes_emitted;
} fake_apple_server;

// Default configuration for a given scenario.
fake_apple_config fake_apple_default_config(fake_apple_scenario sc);

// Initialize the fake server. `out`/`out_cap` is the staging buffer;
// `rl` is the shared record layer (the test initializes both directions).
void fake_apple_server_init(fake_apple_server *s, fake_apple_config cfg,
                            apple_record_layer *rl,
                            uint8_t *out, size_t out_cap);

// Emit the next chunk of the scenario into the staging buffer. Sets
// *out_len to the number of bytes appended this call. Returns RFB_OK,
// RFB_ERR_LIMIT if the staging buffer is full, or RFB_ERR_STATE if the
// scenario is already done. When the scenario is complete, *out_len=0
// and s->done is true.
rfb_error fake_apple_server_emit(fake_apple_server *s, size_t *out_len);

// True iff the scenario has emitted all its bytes.
bool fake_apple_server_done(const fake_apple_server *s);

// Reset the staging buffer (keep scenario state). Used between emits.
void fake_apple_server_reset_buffer(fake_apple_server *s);

// ---------------------------------------------------------------------------
// Encryption helpers.
//
// The fake server encrypts a plaintext record (already serialized via
// apple_postauth) using the record layer (deterministic). The session
// decrypts it with the same keys. This keeps the byte stream deterministic
// without depending on a live SRP-derived key wrap.
//
// Layout of an encrypted record as emitted by the fake server:
//   u32_be  ciphertext_len   (length of the following ciphertext)
//   byte[]  ciphertext       (encrypted plaintext)
// The session reads the length prefix, then decrypts the body.
// ---------------------------------------------------------------------------

// Encrypt a plaintext record into `out` with the length prefix. Sets
// *out_len. Returns RFB_OK or an error.
rfb_error fake_apple_encrypt_record(apple_record_layer *rl,
                                    const uint8_t *plaintext, size_t pt_len,
                                    uint8_t *out, size_t out_cap, size_t *out_len);

// The length-prefix header size (u32_be).
#define FAKE_APPLE_LEN_PREFIX 4u

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_TESTS_FAKES_FAKE_APPLE_SERVER_H
