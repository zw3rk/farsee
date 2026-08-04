// SPDX-License-Identifier: Apache-2.0
//
// farsee — Apple post-auth message codecs (goals.md G19).
//
// Pure, bounded serializers/parsers for the Apple post-authentication
// messages observed in docs/apple/apple-wire-spec.md. These codecs are
// byte-level over caller-owned buffers: no socket, no crypto provider,
// no global state. They are ASan-safe and trivially fragmentable.
//
// FIELD CLASSIFICATION (goals.md §14, apple-wire-spec.md):
//   Every field is marked CAPTURED, INFERRED, UNKNOWN, or CONFLICTING.
//   Production behavior may not depend on UNKNOWN. The fake-server
//   deterministic path (G19) controls both sides and therefore defines
//   a self-consistent byte layout; real-macOS interop is NEEDS-HARDWARE
//   until the encrypted record format is captured.
//
// DIVERGENCE NOTE: the G17 record layer uses AES-128-CBC; the captured
// wire uses ChaCha20-Poly1305 (apple-wire-spec.md §"Record layer").
// For the fake-server path both sides use the G17 layer, so the
// divergence does not affect determinism. Real macOS requires the
// captured AEAD cipher.

#ifndef FARSEE_INCLUDE_FARSEE_APPLE_POSTAUTH_H
#define FARSEE_INCLUDE_FARSEE_APPLE_POSTAUTH_H

#include "farsee/error.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// ---------------------------------------------------------------------------
// Apple post-auth message types.
//
// The classic RFB client→server message types (0=SetPixelFormat,
// 2=SetEncodings, 3=FramebufferUpdateRequest, 4=KeyEvent, 5=PointerEvent,
// 6=ClientCutText) are reused inside encrypted records where the captured
// evidence supports them.
//
// The Apple-specific cleartext prelude messages and the encrypted control
// messages use type IDs that are INFERRED from the observed session
// structure (apple-wire-spec.md "Post-auth session"). The exact type IDs
// inside the encrypted records are UNKNOWN pending key-material capture.
// The fake server (G19) defines a deterministic, self-consistent set.
// ---------------------------------------------------------------------------
#define APPLE_POSTAUTH_CLIENT_INIT       0u   // shared flag (CAPTURED: RFC 6143 §7.3.3 semantics)
#define APPLE_POSTAUTH_VIEWER_INFO      100u  // client device info (INFERRED)
#define APPLE_POSTAUTH_SET_ENCRYPTION   101u  // enable encryption (INFERRED)
#define APPLE_POSTAUTH_SET_MODE         102u  // session mode (INFERRED)
#define APPLE_POSTAUTH_SERVER_INFO      103u  // Apple ServerInit variant (INFERRED framing)
#define APPLE_POSTAUTH_SET_DISPLAY_CFG  104u  // display layout (INFERRED)
#define APPLE_POSTAUTH_SET_ENCODINGS    105u  // encoding list (INFERRED)
#define APPLE_POSTAUTH_AUTO_FBUPDATE    106u  // arm auto update (INFERRED)
#define APPLE_POSTAUTH_CURSOR_STORE     107u  // cursor cache store (INFERRED)
#define APPLE_POSTAUTH_CURSOR_SELECT    108u  // cursor cache select (INFERRED)
#define APPLE_POSTAUTH_DESKTOPSIZE      109u  // display resize (INFERRED)

// Maximum device-name length observed (CAPTURED: 'MacBook Air' = 11 chars).
#define APPLE_POSTAUTH_DEVICE_NAME_MAX 64u

// Maximum server-name length in the Apple ServerInit variant
// (CAPTURED: 138-byte total; 'aarch64-darwin-1' + runner name).
#define APPLE_POSTAUTH_SERVER_NAME_MAX 256u

// Cursor cache bound (policy: bounded memory, plan.md §6.4).
#define APPLE_CURSOR_CACHE_MAX 64u

// ---------------------------------------------------------------------------
// Apple ServerInit (bounded).
//
// The captured Apple ServerInit is 138 bytes total: a standard RFC 6143
// 24-byte header (width, height, pixel-format, name-length) followed by
// a desktop name and TLV metadata (CAPTURED: '80 04 00 xx 00 00' pattern).
// The exact TLV semantics are INFERRED; we parse width/height/pixel-format
// (CAPTURED) and treat the remainder as bounded opaque metadata.
//
// Captured pixel format: red_max=255, green_max=255, blue_max=255,
// shifts=(16,8,0), bpp=32, depth=24, true_color=1.
// ---------------------------------------------------------------------------

typedef struct apple_server_init {
    uint16_t  width;
    uint16_t  height;
    // Pixel format fields (CAPTURED from apple-wire-spec.md).
    uint8_t   bits_per_pixel;
    uint8_t   depth;
    uint8_t   big_endian;
    uint8_t   true_color;
    uint16_t  red_max;
    uint16_t  green_max;
    uint16_t  blue_max;
    uint8_t   red_shift;
    uint8_t   green_shift;
    uint8_t   blue_shift;
    // Desktop name (CAPTURED: null-terminated UTF-8, may contain ESC).
    char      name[APPLE_POSTAUTH_SERVER_NAME_MAX];
    size_t    name_len;
} apple_server_init;

// Minimum ServerInit header size (24 bytes: RFC 6143 §7.3.2).
#define APPLE_SERVER_INIT_HEADER_LEN 24u

// Parse a bounded Apple ServerInit. The first 24 bytes are the standard
// RFC 6143 ServerInit; the remaining bytes are the desktop name + Apple
// metadata (bounded by in_len). Returns RFB_OK, RFB_ERR_PROTOCOL on
// truncation/invalid format, RFB_ERR_LIMIT if the name exceeds the cap,
// RFB_ERR_INTERNAL on NULL.
rfb_error apple_postauth_parse_server_init(const uint8_t *in, size_t in_len,
                                           apple_server_init *out);

// Serialize a bounded Apple ServerInit for the fake server. Writes the
// 24-byte header + name bytes. *out_len is set to the total. Returns
// RFB_OK, RFB_ERR_LIMIT if out_cap is too small, RFB_ERR_INTERNAL on NULL.
rfb_error apple_postauth_serialize_server_init(const apple_server_init *si,
                                               uint8_t *out, size_t out_cap,
                                               size_t *out_len);

// ---------------------------------------------------------------------------
// ClientInit (shared flag).
//
// Classic RFC 6143 §7.3.3: 1 byte, 0=exclusive, 1=shared.
// CAPTURED (E8 2026-07-29, Screen Sharing.app → real macOS type-33):
// after SecurityResult the client sends 0xc1 (not 0x01). Use
// apple_postauth_serialize_client_init_live for live Apple peers.
// ---------------------------------------------------------------------------

// Serialize classic ClientInit. Returns RFB_OK; *out_len = 1.
rfb_error apple_postauth_serialize_client_init(bool shared,
                                               uint8_t *out, size_t out_cap,
                                               size_t *out_len);

// CAPTURED live Apple post-auth first client byte (E8).
// Shared sessions: 0xc1. Exclusive: not yet CAPTURED → RFB_ERR_UNSUPPORTED.
#define APPLE_POSTAUTH_CLIENT_INIT_LIVE_SHARED 0xc1u

rfb_error apple_postauth_serialize_client_init_live(bool shared,
                                                    uint8_t *out,
                                                    size_t out_cap,
                                                    size_t *out_len);

// ---------------------------------------------------------------------------
// ViewerInfo (client device info, cleartext).
//
// Two layouts exist:
//
// 1) INFERRED (fake-server / G19 deterministic path):
//   u8   type = APPLE_POSTAUTH_VIEWER_INFO (100)
//   u8   reserved
//   u16_be name_len
//   byte[name_len] device_name
//
// 2) CAPTURED live (E8 Screen Sharing.app, 74 bytes total):
//   u16_be body_len = 0x48 (72)
//   body[72] = { 00 01 00 00 00 00 01 00 | name | zero pad }
// Device name 'MacBook Air' appears at body offset 8.
// Use apple_postauth_serialize_viewer_info_live against real macOS.
// ---------------------------------------------------------------------------

typedef struct apple_viewer_info {
    char     device_name[APPLE_POSTAUTH_DEVICE_NAME_MAX];
    size_t   name_len;
} apple_viewer_info;

// Live ViewerInfo sizes (CAPTURED E8 share / E9 login).
// Share:  u16be body_len=0x48 (72)  → total 74
// Login:  u16be body_len=0xC8 (200) → total 202  (72-byte share layout + 128 B)
#define APPLE_VIEWER_INFO_LIVE_LEN           74u
#define APPLE_VIEWER_INFO_LIVE_BODY_LEN      72u
#define APPLE_VIEWER_INFO_LIVE_LOGIN_LEN    202u
#define APPLE_VIEWER_INFO_LIVE_LOGIN_BODY   200u
#define APPLE_VIEWER_INFO_LIVE_LOGIN_TRAILER 128u
// Server reply after live ViewerInfo is u16be body_len + body.
// E8 Screen Sharing observed body_len=0x50 (82 total); farsee probe
// observed body_len=0x4a (76 total). Cap bounds the read.
// Observed CAPTURED ViewerInfo live acks are 0x4a / 0x50. Keep a margin
// below 256 so SetColourMapEntries (type 0x01 + pad 0x00 = 0x0100) cannot
// be mis-eaten as an ack body length.
#define APPLE_VIEWER_INFO_LIVE_ACK_BODY_MAX 128u

// CAPTURED E9 attach mode in ViewerInfo body (bytes 1 and 6).
// Share the display → 1; Log in as yourself → 2.
// CLI may use APPLE_ATTACH_ASK (0): resolve to share/login before connect.
#define APPLE_ATTACH_ASK   0u
#define APPLE_ATTACH_SHARE 1u
#define APPLE_ATTACH_LOGIN 2u

rfb_error apple_postauth_serialize_viewer_info(const apple_viewer_info *vi,
                                               uint8_t *out, size_t out_cap,
                                               size_t *out_len);

rfb_error apple_postauth_parse_viewer_info(const uint8_t *in, size_t in_len,
                                           apple_viewer_info *out);

// CAPTURED live ViewerInfo, share path (E8): mode=1, 74 bytes.
// Name at body offset 8; name_len must be < 64.
rfb_error apple_postauth_serialize_viewer_info_live(
    const apple_viewer_info *vi,
    uint8_t *out, size_t out_cap, size_t *out_len);

// CAPTURED live ViewerInfo with attach mode (E9).
//   attach=APPLE_ATTACH_SHARE → 74-byte message (trailer ignored)
//   attach=APPLE_ATTACH_LOGIN → 202-byte message; trailer must be
//     APPLE_VIEWER_INFO_LIVE_LOGIN_TRAILER bytes (or NULL → zeros, for
//     tests only). Production login should pass CSPRNG bytes until the
//     trailer derivation is CAPTURED.
rfb_error apple_postauth_serialize_viewer_info_live_attach(
    const apple_viewer_info *vi,
    uint8_t attach,
    const uint8_t *login_trailer, size_t login_trailer_len,
    uint8_t *out, size_t out_cap, size_t *out_len);

// Parse CAPTURED live ViewerInfo (share 74 or login 202). Sets *out_attach
// to APPLE_ATTACH_SHARE or APPLE_ATTACH_LOGIN when out_attach non-NULL.
rfb_error apple_postauth_parse_viewer_info_live(const uint8_t *in,
                                                size_t in_len,
                                                apple_viewer_info *out);

rfb_error apple_postauth_parse_viewer_info_live_attach(
    const uint8_t *in, size_t in_len,
    apple_viewer_info *out, uint8_t *out_attach);

// ---------------------------------------------------------------------------
// SetEncryption / SetMode (cleartext prelude).
//
// INFERRED: these arm the encrypted record layer and select the session
// mode. Modeled as simple typed messages for the deterministic path.
//   u8  type
//   u8  flags   (SetEncryption: bit0 = enable)
//   u8  mode    (SetMode: 0=full-quality, 1=adaptive [not enabled])
// ---------------------------------------------------------------------------

#define APPLE_MODE_FULL_QUALITY 0u
#define APPLE_MODE_ADAPTIVE     1u  // NOT ENABLED (goals.md G19: exclude HEVC)

rfb_error apple_postauth_serialize_set_encryption(bool enable,
                                                  uint8_t *out, size_t out_cap,
                                                  size_t *out_len);

rfb_error apple_postauth_serialize_set_mode(uint8_t mode,
                                            uint8_t *out, size_t out_cap,
                                            size_t *out_len);

// ---------------------------------------------------------------------------
// SetDisplayConfiguration (encrypted).
//
// INFERRED: Apple sends the authoritative display layout (width, height,
// DPI, display index). The fake server uses this to drive resize.
//   u16_be width
//   u16_be height
//   u8     display_index
//   u8     flags
// ---------------------------------------------------------------------------

typedef struct apple_display_config {
    uint16_t width;
    uint16_t height;
    uint8_t  display_index;
    uint8_t  flags;
} apple_display_config;

rfb_error apple_postauth_serialize_display_config(const apple_display_config *dc,
                                                  uint8_t *out, size_t out_cap,
                                                  size_t *out_len);

rfb_error apple_postauth_parse_display_config(const uint8_t *in, size_t in_len,
                                              apple_display_config *out);

// ---------------------------------------------------------------------------
// AutoFrameBufferUpdate arm.
//
// INFERRED: arms the server to send automatic framebuffer updates. This is
// Apple's mechanism replacing the classic one-request-one-update loop.
//   u8  type
//   u8  enable
//   u16_be max_rate  (updates per second cap, 0 = unlimited)
// ---------------------------------------------------------------------------

rfb_error apple_postauth_serialize_auto_fbupdate(bool enable, uint16_t max_rate,
                                                 uint8_t *out, size_t out_cap,
                                                 size_t *out_len);

// ---------------------------------------------------------------------------
// Cursor STORE / SELECT cache (bounded memory).
//
// INFERRED: Apple caches cursor sprites server-side by index. STORE adds
// a cursor to the cache; SELECT activates a cached cursor without
// retransmitting pixels. The cache is bounded to APPLE_CURSOR_CACHE_MAX.
//
// STORE layout:
//   u8  type = APPLE_POSTAUTH_CURSOR_STORE
//   u8  cache_index
//   u16_be width
//   u16_be height
//   u16_be hotspot_x
//   u16_be hotspot_y
//   (cursor pixel bytes follow, caller-supplied)
//
// SELECT layout:
//   u8  type = APPLE_POSTAUTH_CURSOR_SELECT
//   u8  cache_index
// ---------------------------------------------------------------------------

rfb_error apple_postauth_serialize_cursor_store(uint8_t cache_index,
                                                uint16_t width, uint16_t height,
                                                uint16_t hotspot_x,
                                                uint16_t hotspot_y,
                                                const uint8_t *rgba, size_t rgba_len,
                                                uint8_t *out, size_t out_cap,
                                                size_t *out_len);

rfb_error apple_postauth_serialize_cursor_select(uint8_t cache_index,
                                                 uint8_t *out, size_t out_cap,
                                                 size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_APPLE_POSTAUTH_H
