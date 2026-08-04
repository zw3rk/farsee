// SPDX-License-Identifier: Apache-2.0
//
// farsee — RFB version negotiation and security handshake (plan.md §G2,
// §11, RFC 6143 §7.1).
//
// The handshake is an incremental state machine: it consumes bytes from
// the input buffer (which may arrive in arbitrary fragments) and produces
// bytes into the output buffer (the messages we send to the server). Every
// state transition is testable by feeding exact bytes and asserting exact
// output bytes and the resulting state.
//
// Design constraints (plan.md §6.3, §8, §11):
//   - Pure protocol core: no sockets, no Kitty, no CLI.
//   - Bounded: server-controlled lengths (security-list count, failure-
//     reason length) are checked against hard limits before allocation.
//   - Fail-closed: unknown version, malformed banner, unsupported security
//     type, or length mismatch yields RFB_ERR_PROTOCOL and a clean state.
//   - Vendor-banner policy: only exact 3.3/3.7/3.8 banners are accepted
//     by default; known vendor banners (Apple) map through a table
//     (plan.md §11). Unknown syntactically-valid banners are rejected
//     with an actionable error unless a tested downgrade policy exists.

#ifndef FARSEE_INCLUDE_FARSEE_HANDSHAKE_H
#define FARSEE_INCLUDE_FARSEE_HANDSHAKE_H

#include "farsee/buffer.h"
#include "farsee/crypto_provider.h"
#include "farsee/error.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// RFB protocol version we negotiate toward, when the server allows it.
// Derived from RFC 6143 §7.1.1.
typedef enum {
    RFB_VERSION_UNKNOWN = 0,
    RFB_VERSION_3_3     = 33,
    RFB_VERSION_3_7     = 37,
    RFB_VERSION_3_8     = 38,
} rfb_version;

// Handshake state machine states (plan.md §11).
typedef enum {
    RFB_HS_READ_PROTOCOL_VERSION = 0,  // waiting for the server's 12-byte banner
    RFB_HS_WRITE_PROTOCOL_VERSION,     // banner parsed; emit our version
    RFB_HS_READ_SECURITY_TYPES,        // 3.7/3.8: list; 3.3: single u32
    RFB_HS_WRITE_SECURITY_SELECTION,   // emit chosen security type
    RFB_HS_READ_VNC_CHALLENGE,         // 16-byte challenge for VNC auth
    RFB_HS_WRITE_VNC_RESPONSE,         // emit encrypted response
    RFB_HS_READ_SECURITY_RESULT,       // u32 OK/fail
    RFB_HS_READ_SECURITY_FAILURE_REASON, // 3.8: u32 len + reason
    RFB_HS_DONE,                       // authenticated; ClientInit is next (G3)
    RFB_HS_FAILED,                     // unrecoverable; see last_error
} rfb_hs_state;

// Security types we recognize (RFC 6143 §7.2, IANA registry).
typedef enum {
    RFB_SECURITY_INVALID = 0,
    RFB_SECURITY_NONE    = 1,
    RFB_SECURITY_VNC     = 2,
} rfb_security_type;

// Negotiation policy. Caller constructs this; the state machine consults
// it at decision points (e.g. whether None auth is permitted).
typedef struct rfb_handshake_policy {
    // True iff the user passed --allow-none-auth (plan.md §G2, §17).
    bool allow_none_auth;
    // True iff the client advertises VNC Authentication support.
    bool allow_vnc_auth;
    // True iff we send a shared-flag=1 ClientInit (default). G3 consumes.
    bool shared_flag;
} rfb_handshake_policy;

// The handshake state machine. Caller owns it and feeds bytes into
// `input` (the receive buffer) and reads bytes from `output` (the send
// buffer). The crypto provider (G2 VNC auth) is wired in G2's later
// slices; the banner/selection slices do not need it.
typedef struct rfb_handshake {
    rfb_hs_state state;
    rfb_version  version;
    rfb_handshake_policy policy;
    rfb_security_type    selected_security;
    rfb_error    last_error;
    // Scratch for multi-byte fields. The state machine is single-threaded
    // and these are only live within a single state.
    uint8_t  challenge[16];
    uint8_t  response[16];
    // VNC auth: the 8-byte password (first 8 bytes, zero-padded). The
    // caller sets this before the SM enters READ_VNC_CHALLENGE. It is
    // zeroized by rfb_handshake_destroy (plan.md §6.3).
    uint8_t  password[8];
    bool     password_set;
    rfb_des_ecb_encrypt_fn des;  // provider; default set in _init
    // Selected server security types (3.7/3.8 list). Bounded by
    // RFB_LIMIT_SECURITY_TYPES_MAX (RFC 6143 §7.1.2: "the number of
    // security types ... is at most 255").
    uint8_t server_security_types[256];
    uint8_t server_security_count;
    // Failure reason, accumulated for 3.8 failed auth. Bounded by
    // RFB_LIMIT_SECURITY_REASON_MAX.
    rfb_buffer failure_reason;
} rfb_handshake;

// Default policy: VNC auth allowed, None forbidden, shared.
rfb_handshake_policy rfb_handshake_policy_default(void);

// Initialize a handshake state machine. Does not allocate.
void rfb_handshake_init(rfb_handshake *h, const rfb_handshake_policy *policy,
                        rfb_allocator *alloc);

// Release scratch storage (failure-reason buffer) and zeroize the password
// (plan.md §6.3: password zeroized on every exit path).
void rfb_handshake_destroy(rfb_handshake *h);

// Set the VNC auth password. Copies up to 8 bytes (zero-padded if shorter)
// into the handshake's internal buffer. The caller's `password` may be
// zero-length. The handshake owns its copy and zeroizes it on destroy.
void rfb_handshake_set_password(rfb_handshake *h,
                                const uint8_t *password, size_t n);

// Override the DES provider (tests inject a stub). Defaults to the
// platform provider in _init.
void rfb_handshake_set_des_provider(rfb_handshake *h, rfb_des_ecb_encrypt_fn des);

// Banner parser: parse the server's 12-byte banner from `in` (exactly 12
// bytes available). Returns RFB_OK and sets `*out_version` on a recognized
// banner; RFB_ERR_PROTOCOL on a malformed or unknown banner. `in` may be
// NULL only if in_len < 12.
rfb_error rfb_parse_banner(const uint8_t *in, size_t in_len,
                           rfb_version *out_version);

// Format our client banner (12 bytes, "RFB 003.00x\n") for the given
// version into `out` (must have room for 12 bytes). Returns RFB_OK.
rfb_error rfb_format_banner(rfb_version v, uint8_t *out, size_t out_cap);

// --- Incremental state machine -------------------------------------------
//
// `rfb_handshake_step` advances the handshake as far as it can given the
// current input and output buffers. It is safe to call repeatedly with
// freshly-arrived input bytes; it consumes input from the front of
// `input` and appends output bytes to `output`.
//
// Returns:
//   RFB_OK              — made progress; there may be more to do, call again
//                         (or wait for more input/output drain).
//   RFB_ERR_PROTOCOL    — the peer violated the protocol; state is FAILED.
//   RFB_ERR_UNSUPPORTED — e.g. unknown version or no mutually-agreed
//                         security type; state is FAILED.
//   RFB_ERR_LIMIT       — a server-controlled length exceeded the cap.
//   RFB_ERR_NOMEM       — allocation failure (failure-reason buffer).
//   RFB_ERR_INTERNAL    — NULL argument or invariant violation.
//
// When the state reaches RFB_HS_DONE, the caller proceeds to ClientInit
// (G3). When it reaches RFB_HS_FAILED, `last_error` holds the cause and
// `failure_reason` holds the server's reason string (escaped on demand).
//
// Input is consumed from the front via rfb_buffer_consume; output is
// appended to `output` and the caller drains it.
rfb_error rfb_handshake_step(rfb_handshake *h,
                             rfb_buffer *input,
                             rfb_buffer *output);

// True iff the state machine has reached a terminal state (DONE or FAILED).
static inline bool rfb_handshake_finished(const rfb_handshake *h)
{
    return h != NULL && (h->state == RFB_HS_DONE || h->state == RFB_HS_FAILED);
}

// --- Pure security-type selection (CLI --auth auto|vnc|apple) ------------
//
// Ranking among eligible types: 33 > 36 > 35 > 30 > 2 > 1
//
// Eligibility is gated by auth_mode and the allow_* product flags. Types
// not present in the server's offered list are never selected. 36/35 stay
// off by default until their gates land.

typedef enum {
    FARSEE_AUTH_MODE_AUTO  = 0,  // Apple types if offered, else classic
    FARSEE_AUTH_MODE_VNC   = 1,  // classic only (2, and 1 with allow_none)
    FARSEE_AUTH_MODE_APPLE = 2,  // Apple-only (33/36/35/30)
} farsee_rfb_auth_mode;

typedef struct farsee_rfb_security_policy {
    farsee_rfb_auth_mode auth_mode;
    bool allow_none;           // type 1 (None); default false
    bool allow_legacy_apple;   // type 30; default false
    bool allow_type_33;        // Apple RSA/SRP; default true
    bool allow_type_36;        // Direct SRP; default false (until G23/G24)
    bool allow_type_35;        // Kerberos/GSS; default false
    bool allow_vnc;            // type 2 (VNC Auth); default true
} farsee_rfb_security_policy;

// Safe product defaults: auto mode, VNC + type-33 on, None/legacy/36/35 off.
farsee_rfb_security_policy farsee_rfb_security_policy_default(void);

// Select one RFB security type from the server's offered list under policy.
// On success returns RFB_OK and sets *out_type to a value in
// {1, 2, 30, 33, 35, 36}. On failure returns RFB_ERR_UNSUPPORTED and sets
// *out_type to 0. NULL policy uses farsee_rfb_security_policy_default().
// NULL out_type returns RFB_ERR_INTERNAL. Empty/NULL offered list is
// RFB_ERR_UNSUPPORTED.
rfb_error farsee_rfb_select_security(const uint8_t *offered, size_t count,
                                     const farsee_rfb_security_policy *policy,
                                     uint8_t *out_type);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_HANDSHAKE_H
