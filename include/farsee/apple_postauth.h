// SPDX-License-Identifier: Apache-2.0
//
// farsee — Apple post-auth message codecs.
//
// Byte serializers and parsers for selected Apple post-authentication fields
// defined in docs/apple/apple-wire-spec.md. They operate on complete,
// caller-owned buffers and own no socket, crypto provider, record layer, or
// global state. Session code applies any state change represented by the bytes.

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
// 6=ClientCutText) are reused inside encrypted records.
//
// The Apple-specific cleartext prelude messages and encrypted control
// messages use the stable type IDs below. The deterministic test peer uses
// the same values.
// ---------------------------------------------------------------------------
#define APPLE_POSTAUTH_CLIENT_INIT       0u   // RFC 6143 shared flag
#define APPLE_POSTAUTH_VIEWER_INFO      100u  // client device info
#define APPLE_POSTAUTH_SET_ENCRYPTION   101u  // enable encryption
#define APPLE_POSTAUTH_SET_MODE         102u  // session mode
#define APPLE_POSTAUTH_SERVER_INFO      103u  // Apple ServerInit variant
#define APPLE_POSTAUTH_SET_DISPLAY_CFG  104u  // display layout
#define APPLE_POSTAUTH_SET_ENCODINGS    105u  // encoding list
#define APPLE_POSTAUTH_AUTO_FBUPDATE    106u  // arm auto update
#define APPLE_POSTAUTH_CURSOR_STORE     107u  // cursor cache store
#define APPLE_POSTAUTH_CURSOR_SELECT    108u  // cursor cache select
#define APPLE_POSTAUTH_DESKTOPSIZE      109u  // display resize

// Maximum accepted device-name length.
#define APPLE_POSTAUTH_DEVICE_NAME_MAX 64u

// Maximum server-name length in the Apple ServerInit variant.
#define APPLE_POSTAUTH_SERVER_NAME_MAX 256u

// Cursor cache bound (policy: bounded memory, plan.md §6.4).
#define APPLE_CURSOR_CACHE_MAX 64u

// ---------------------------------------------------------------------------
// Apple ServerInit (bounded).
//
// The parser copies selected fields from the standard 24-byte ServerInit
// header and the declared desktop-name bytes. It bounds the name length but
// does not validate pixel-format support. Trailing input bytes are accepted
// and ignored.
// ---------------------------------------------------------------------------

typedef struct apple_server_init {
    uint16_t  width;
    uint16_t  height;
    // Pixel format fields.
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
    // Desktop-name bytes and length; a full-size name has no terminator.
    char      name[APPLE_POSTAUTH_SERVER_NAME_MAX];
    size_t    name_len;
} apple_server_init;

// Minimum ServerInit header size (24 bytes: RFC 6143 §7.3.2).
#define APPLE_SERVER_INIT_HEADER_LEN 24u

// Parse selected fields from a 24-byte ServerInit and copy the declared
// desktop-name bytes. Returns RFB_OK, RFB_ERR_PROTOCOL on truncation,
// RFB_ERR_LIMIT when the name length exceeds the cap, or RFB_ERR_INTERNAL on
// NULL. Pixel-format support and trailing input are not validated here.
rfb_error apple_postauth_parse_server_init(const uint8_t *in, size_t in_len,
                                           apple_server_init *out);

// Serialize a 24-byte ServerInit header and `name_len` name bytes for test
// peers. The serializer rejects lengths beyond the fixed name array.
rfb_error apple_postauth_serialize_server_init(const apple_server_init *si,
                                               uint8_t *out, size_t out_cap,
                                               size_t *out_len);

// ---------------------------------------------------------------------------
// ClientInit (shared flag).
//
// Classic RFC 6143 §7.3.3: 1 byte, 0=exclusive, 1=shared.
// After SecurityResult, Apple type-33 shared sessions use 0xc1 instead of
// the classic 0x01. Use apple_postauth_serialize_client_init_live for this
// form.
// ---------------------------------------------------------------------------

// Serialize classic ClientInit. Returns RFB_OK; *out_len = 1.
rfb_error apple_postauth_serialize_client_init(bool shared,
                                               uint8_t *out, size_t out_cap,
                                               size_t *out_len);

// Apple post-auth first client byte for a shared session. The exclusive form
// is unsupported.
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
// 1) Compact deterministic layout:
//   u8   type = APPLE_POSTAUTH_VIEWER_INFO (100)
//   u8   reserved
//   u16_be name_len
//   byte[name_len] device_name
//
// 2) Apple peer layout (74 bytes total):
//   u16_be body_len = 0x48 (72)
//   body[72] = { 00 01 00 00 00 00 01 00 | name | zero pad }
// The deterministic test fixture places 'MacBook Air' at body offset 8.
// Use apple_postauth_serialize_viewer_info_live for Apple peers.
//
// The default connect configuration omits this optional message; explicit
// session configuration can enable it.
// ---------------------------------------------------------------------------

typedef struct apple_viewer_info {
    char     device_name[APPLE_POSTAUTH_DEVICE_NAME_MAX];
    size_t   name_len;
} apple_viewer_info;

// ViewerInfo sizes for share and login modes.
// Share:  u16be body_len=0x48 (72)  → total 74
// Login:  u16be body_len=0xC8 (200) → total 202  (72-byte share layout + 128 B)
#define APPLE_VIEWER_INFO_LIVE_LEN           74u
#define APPLE_VIEWER_INFO_LIVE_BODY_LEN      72u
#define APPLE_VIEWER_INFO_LIVE_LOGIN_LEN    202u
#define APPLE_VIEWER_INFO_LIVE_LOGIN_BODY   200u
#define APPLE_VIEWER_INFO_LIVE_LOGIN_TRAILER 128u
// Server reply after ViewerInfo is u16be body_len + body. Accepted body
// lengths are 0x4a and 0x50. The cap remains below 256 so the
// SetColourMapEntries prefix 0x0100 cannot be consumed as an acknowledgement.
#define APPLE_VIEWER_INFO_LIVE_ACK_BODY_MAX 128u

// Attach mode in ViewerInfo body bytes 1 and 6.
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

// ViewerInfo share path: mode=1, 74 bytes.
// Name at body offset 8; name_len must be at most 64.
rfb_error apple_postauth_serialize_viewer_info_live(
    const apple_viewer_info *vi,
    uint8_t *out, size_t out_cap, size_t *out_len);

// ViewerInfo with attach mode.
//   attach=APPLE_ATTACH_SHARE → 74-byte message (trailer ignored)
//   attach=APPLE_ATTACH_LOGIN → 202-byte message; trailer must be
//     APPLE_VIEWER_INFO_LIVE_LOGIN_TRAILER bytes (or NULL → zeros, for
//     tests only). Production login passes CSPRNG bytes.
rfb_error apple_postauth_serialize_viewer_info_live_attach(
    const apple_viewer_info *vi,
    uint8_t attach,
    const uint8_t *login_trailer, size_t login_trailer_len,
    uint8_t *out, size_t out_cap, size_t *out_len);

// Parse ViewerInfo (share 74 or login 202). Sets *out_attach
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
// These serializers emit a type byte and one value byte. SetEncryption uses
// bit 0 as the enable flag. SetMode accepts full-quality mode and rejects the
// adaptive value.
// ---------------------------------------------------------------------------

#define APPLE_MODE_FULL_QUALITY 0u
#define APPLE_MODE_ADAPTIVE     1u  // not enabled; HEVC is out of scope

rfb_error apple_postauth_serialize_set_encryption(bool enable,
                                                  uint8_t *out, size_t out_cap,
                                                  size_t *out_len);

rfb_error apple_postauth_serialize_set_mode(uint8_t mode,
                                            uint8_t *out, size_t out_cap,
                                            size_t *out_len);

// ---------------------------------------------------------------------------
// SetDisplayConfiguration (encrypted).
//
// The body serializer carries width, height, display index, and flags. The
// caller supplies the preceding message-type byte when needed.
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
// The serializer writes the message type, enable flag, and maximum-rate value.
// Session code interprets the fields.
//   u8  type
//   u8  enable
//   u16_be max_rate  (0 means unlimited)
// ---------------------------------------------------------------------------

rfb_error apple_postauth_serialize_auto_fbupdate(bool enable, uint16_t max_rate,
                                                 uint8_t *out, size_t out_cap,
                                                 size_t *out_len);

// ---------------------------------------------------------------------------
// Cursor STORE / SELECT cache (bounded memory).
//
// The STORE layout includes an index, geometry, hotspot, and caller-supplied
// pixels. SELECT contains an index. Session code enforces the cache bound and
// applies these operations.
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
