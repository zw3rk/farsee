// SPDX-License-Identifier: Apache-2.0
//
// farsee — Apple post-auth message codecs.
//
// Pure, bounded serializers/parsers for the Apple post-auth messages.
// All functions are byte-level over caller-owned buffers: no sockets,
// no crypto provider, no global state. The header documents each supported
// message layout and its validation rules.

#include "farsee/apple_postauth.h"

#include <string.h>

// ---------------------------------------------------------------------------
// Internal byte helpers (big-endian; no external dependency).
// ---------------------------------------------------------------------------

static void put_be16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xFFu);
}

static uint16_t get_be16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static void put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)(v & 0xFFu);
}

static uint32_t get_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

// ---------------------------------------------------------------------------
// ClientInit (RFC 6143 §7.3.3).
// ---------------------------------------------------------------------------

rfb_error apple_postauth_serialize_client_init(bool shared,
                                               uint8_t *out, size_t out_cap,
                                               size_t *out_len)
{
    if (out == NULL || out_len == NULL) return RFB_ERR_INTERNAL;
    if (out_cap < 1u) return RFB_ERR_LIMIT;
    out[0] = shared ? 0x01u : 0x00u;
    *out_len = 1u;
    return RFB_OK;
}

rfb_error apple_postauth_serialize_client_init_live(bool shared,
                                                    uint8_t *out,
                                                    size_t out_cap,
                                                    size_t *out_len)
{
    if (out == NULL || out_len == NULL) {
        return RFB_ERR_INTERNAL;
    }
    if (out_cap < 1u) {
        return RFB_ERR_LIMIT;
    }
    // Apple shared sessions use 0xc1. No exclusive-session value is
    // supported, so fail closed.
    if (!shared) {
        return RFB_ERR_UNSUPPORTED;
    }
    out[0] = APPLE_POSTAUTH_CLIENT_INIT_LIVE_SHARED;
    *out_len = 1u;
    return RFB_OK;
}

// ---------------------------------------------------------------------------
// ServerInit parse/serialize.
// ---------------------------------------------------------------------------

rfb_error apple_postauth_parse_server_init(const uint8_t *in, size_t in_len,
                                           apple_server_init *out)
{
    if (in == NULL || out == NULL) return RFB_ERR_INTERNAL;
    if (in_len < APPLE_SERVER_INIT_HEADER_LEN) return RFB_ERR_PROTOCOL;

    memset(out, 0, sizeof *out);
    out->width  = get_be16(in + 0);
    out->height = get_be16(in + 2);

    // Pixel format: 16 bytes at offset 4 (RFC 6143 §7.3.2 PIXEL_FORMAT).
    out->bits_per_pixel = in[4];
    out->depth          = in[5];
    out->big_endian     = in[6];
    out->true_color     = in[7];
    out->red_max   = get_be16(in + 8);
    out->green_max = get_be16(in + 10);
    out->blue_max  = get_be16(in + 12);
    out->red_shift   = in[14];
    out->green_shift = in[15];
    // in[16..18] are the remaining shift + padding (RFC 6143).

    uint32_t name_length = get_be32(in + 20);
    if ((size_t)name_length > APPLE_POSTAUTH_SERVER_NAME_MAX)
        return RFB_ERR_LIMIT;
    size_t needed = APPLE_SERVER_INIT_HEADER_LEN + (size_t)name_length;
    if (in_len < needed) return RFB_ERR_PROTOCOL;

    out->name_len = (size_t)name_length;
    if (name_length > 0u) {
        memcpy(out->name, in + APPLE_SERVER_INIT_HEADER_LEN, name_length);
    }
    return RFB_OK;
}

rfb_error apple_postauth_serialize_server_init(const apple_server_init *si,
                                               uint8_t *out, size_t out_cap,
                                               size_t *out_len)
{
    if (si == NULL || out == NULL || out_len == NULL) return RFB_ERR_INTERNAL;
    if (si->name_len > APPLE_POSTAUTH_SERVER_NAME_MAX) {
        return RFB_ERR_PROTOCOL;
    }
    size_t total = APPLE_SERVER_INIT_HEADER_LEN + si->name_len;
    if (out_cap < total) return RFB_ERR_LIMIT;

    memset(out, 0, APPLE_SERVER_INIT_HEADER_LEN);
    put_be16(out + 0, si->width);
    put_be16(out + 2, si->height);
    out[4] = si->bits_per_pixel;
    out[5] = si->depth;
    out[6] = si->big_endian;
    out[7] = si->true_color;
    put_be16(out + 8,  si->red_max);
    put_be16(out + 10, si->green_max);
    put_be16(out + 12, si->blue_max);
    out[14] = si->red_shift;
    out[15] = si->green_shift;
    out[16] = si->blue_shift;
    put_be32(out + 20, (uint32_t)si->name_len);
    if (si->name_len > 0u) {
        memcpy(out + APPLE_SERVER_INIT_HEADER_LEN, si->name, si->name_len);
    }
    *out_len = total;
    return RFB_OK;
}

// ---------------------------------------------------------------------------
// ViewerInfo.
// ---------------------------------------------------------------------------

rfb_error apple_postauth_serialize_viewer_info(const apple_viewer_info *vi,
                                               uint8_t *out, size_t out_cap,
                                               size_t *out_len)
{
    if (vi == NULL || out == NULL || out_len == NULL) return RFB_ERR_INTERNAL;
    if (vi->name_len > APPLE_POSTAUTH_DEVICE_NAME_MAX) return RFB_ERR_PROTOCOL;

    size_t total = 4u + vi->name_len;
    if (out_cap < total) return RFB_ERR_LIMIT;

    out[0] = (uint8_t)APPLE_POSTAUTH_VIEWER_INFO;
    out[1] = 0u;  // reserved
    put_be16(out + 2, (uint16_t)vi->name_len);
    if (vi->name_len > 0u) {
        memcpy(out + 4, vi->device_name, vi->name_len);
    }
    *out_len = total;
    return RFB_OK;
}

rfb_error apple_postauth_parse_viewer_info(const uint8_t *in, size_t in_len,
                                           apple_viewer_info *out)
{
    if (in == NULL || out == NULL) return RFB_ERR_INTERNAL;
    if (in_len < 4u) return RFB_ERR_PROTOCOL;
    if (in[0] != (uint8_t)APPLE_POSTAUTH_VIEWER_INFO) return RFB_ERR_PROTOCOL;

    memset(out, 0, sizeof *out);
    uint16_t name_len = get_be16(in + 2);
    if ((size_t)name_len > APPLE_POSTAUTH_DEVICE_NAME_MAX)
        return RFB_ERR_LIMIT;
    size_t needed = 4u + (size_t)name_len;
    if (in_len < needed) return RFB_ERR_PROTOCOL;

    out->name_len = (size_t)name_len;
    if (name_len > 0u) {
        memcpy(out->device_name, in + 4, name_len);
    }
    return RFB_OK;
}

// Body header: 00 <mode> 00 00 00 00 <mode> 00
static void fill_viewer_info_live_hdr(uint8_t hdr[8], uint8_t mode)
{
    hdr[0] = 0x00u;
    hdr[1] = mode;
    hdr[2] = 0x00u;
    hdr[3] = 0x00u;
    hdr[4] = 0x00u;
    hdr[5] = 0x00u;
    hdr[6] = mode;
    hdr[7] = 0x00u;
}

rfb_error apple_postauth_serialize_viewer_info_live_attach(
    const apple_viewer_info *vi,
    uint8_t attach,
    const uint8_t *login_trailer, size_t login_trailer_len,
    uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (vi == NULL || out == NULL || out_len == NULL) {
        return RFB_ERR_INTERNAL;
    }
    if (attach != APPLE_ATTACH_SHARE && attach != APPLE_ATTACH_LOGIN) {
        return RFB_ERR_PROTOCOL;
    }
    if (vi->name_len > (APPLE_VIEWER_INFO_LIVE_BODY_LEN - 8u)) {
        return RFB_ERR_PROTOCOL;
    }

    const size_t total = (attach == APPLE_ATTACH_LOGIN)
                             ? APPLE_VIEWER_INFO_LIVE_LOGIN_LEN
                             : APPLE_VIEWER_INFO_LIVE_LEN;
    const uint16_t body_len = (attach == APPLE_ATTACH_LOGIN)
                                  ? (uint16_t)APPLE_VIEWER_INFO_LIVE_LOGIN_BODY
                                  : (uint16_t)APPLE_VIEWER_INFO_LIVE_BODY_LEN;
    if (out_cap < total) {
        return RFB_ERR_LIMIT;
    }
    if (attach == APPLE_ATTACH_LOGIN && login_trailer != NULL &&
        login_trailer_len != APPLE_VIEWER_INFO_LIVE_LOGIN_TRAILER) {
        return RFB_ERR_PROTOCOL;
    }

    memset(out, 0, total);
    put_be16(out, body_len);
    {
        uint8_t hdr[8];
        fill_viewer_info_live_hdr(hdr, attach);
        memcpy(out + 2, hdr, sizeof hdr);
    }
    if (vi->name_len > 0u) {
        memcpy(out + 2u + 8u, vi->device_name, vi->name_len);
    }
    if (attach == APPLE_ATTACH_LOGIN) {
        // Trailer at body offset 72 (message offset 2+72).
        uint8_t *tr = out + 2u + APPLE_VIEWER_INFO_LIVE_BODY_LEN;
        if (login_trailer != NULL) {
            memcpy(tr, login_trailer, APPLE_VIEWER_INFO_LIVE_LOGIN_TRAILER);
        }
        // Otherwise retain the zero-filled trailer.
    }
    *out_len = total;
    return RFB_OK;
}

rfb_error apple_postauth_serialize_viewer_info_live(
    const apple_viewer_info *vi,
    uint8_t *out, size_t out_cap, size_t *out_len)
{
    return apple_postauth_serialize_viewer_info_live_attach(
        vi, APPLE_ATTACH_SHARE, NULL, 0u, out, out_cap, out_len);
}

rfb_error apple_postauth_parse_viewer_info_live_attach(
    const uint8_t *in, size_t in_len,
    apple_viewer_info *out, uint8_t *out_attach)
{
    if (in == NULL || out == NULL) {
        return RFB_ERR_INTERNAL;
    }
    if (in_len < 2u) {
        return RFB_ERR_PROTOCOL;
    }
    const uint16_t body_len = get_be16(in);
    const size_t need = 2u + (size_t)body_len;
    if (in_len < need) {
        return RFB_ERR_PROTOCOL;
    }
    if (body_len != (uint16_t)APPLE_VIEWER_INFO_LIVE_BODY_LEN &&
        body_len != (uint16_t)APPLE_VIEWER_INFO_LIVE_LOGIN_BODY) {
        return RFB_ERR_PROTOCOL;
    }
    if (need < 10u) {
        return RFB_ERR_PROTOCOL;
    }
    const uint8_t mode = in[3];
    if (mode != APPLE_ATTACH_SHARE && mode != APPLE_ATTACH_LOGIN) {
        return RFB_ERR_PROTOCOL;
    }
    // Required header: body[0]==0, body[1]==mode, body[6]==mode, body[7]==0.
    if (in[2] != 0x00u || in[3] != mode || in[8] != mode || in[9] != 0x00u) {
        return RFB_ERR_PROTOCOL;
    }
    if ((mode == APPLE_ATTACH_SHARE &&
         body_len != (uint16_t)APPLE_VIEWER_INFO_LIVE_BODY_LEN) ||
        (mode == APPLE_ATTACH_LOGIN &&
         body_len != (uint16_t)APPLE_VIEWER_INFO_LIVE_LOGIN_BODY)) {
        return RFB_ERR_PROTOCOL;
    }

    memset(out, 0, sizeof *out);
    const uint8_t *name = in + 2u + 8u;
    const size_t name_cap = APPLE_VIEWER_INFO_LIVE_BODY_LEN - 8u;
    size_t n = 0;
    while (n < name_cap && name[n] != 0u) {
        n++;
    }
    if (n > APPLE_POSTAUTH_DEVICE_NAME_MAX) {
        return RFB_ERR_LIMIT;
    }
    out->name_len = n;
    if (n > 0u) {
        memcpy(out->device_name, name, n);
    }
    if (out_attach != NULL) {
        *out_attach = mode;
    }
    return RFB_OK;
}

rfb_error apple_postauth_parse_viewer_info_live(const uint8_t *in,
                                                size_t in_len,
                                                apple_viewer_info *out)
{
    return apple_postauth_parse_viewer_info_live_attach(in, in_len, out, NULL);
}

// ---------------------------------------------------------------------------
// SetEncryption / SetMode.
// ---------------------------------------------------------------------------

rfb_error apple_postauth_serialize_set_encryption(bool enable,
                                                  uint8_t *out, size_t out_cap,
                                                  size_t *out_len)
{
    if (out == NULL || out_len == NULL) return RFB_ERR_INTERNAL;
    if (out_cap < 2u) return RFB_ERR_LIMIT;
    out[0] = (uint8_t)APPLE_POSTAUTH_SET_ENCRYPTION;
    out[1] = enable ? 0x01u : 0x00u;
    *out_len = 2u;
    return RFB_OK;
}

rfb_error apple_postauth_serialize_set_mode(uint8_t mode,
                                            uint8_t *out, size_t out_cap,
                                            size_t *out_len)
{
    if (out == NULL || out_len == NULL) return RFB_ERR_INTERNAL;
    // HEVC and adaptive media are out of scope.
    if (mode == APPLE_MODE_ADAPTIVE) return RFB_ERR_UNSUPPORTED;
    if (out_cap < 2u) return RFB_ERR_LIMIT;
    out[0] = (uint8_t)APPLE_POSTAUTH_SET_MODE;
    out[1] = mode;
    *out_len = 2u;
    return RFB_OK;
}

// ---------------------------------------------------------------------------
// SetDisplayConfiguration.
// ---------------------------------------------------------------------------

rfb_error apple_postauth_serialize_display_config(const apple_display_config *dc,
                                                  uint8_t *out, size_t out_cap,
                                                  size_t *out_len)
{
    if (dc == NULL || out == NULL || out_len == NULL) return RFB_ERR_INTERNAL;
    if (out_cap < 6u) return RFB_ERR_LIMIT;
    put_be16(out + 0, dc->width);
    put_be16(out + 2, dc->height);
    out[4] = dc->display_index;
    out[5] = dc->flags;
    *out_len = 6u;
    return RFB_OK;
}

rfb_error apple_postauth_parse_display_config(const uint8_t *in, size_t in_len,
                                              apple_display_config *out)
{
    if (in == NULL || out == NULL) return RFB_ERR_INTERNAL;
    if (in_len < 6u) return RFB_ERR_PROTOCOL;
    memset(out, 0, sizeof *out);
    out->width  = get_be16(in + 0);
    out->height = get_be16(in + 2);
    out->display_index = in[4];
    out->flags = in[5];
    return RFB_OK;
}

// ---------------------------------------------------------------------------
// AutoFrameBufferUpdate arm.
// ---------------------------------------------------------------------------

rfb_error apple_postauth_serialize_auto_fbupdate(bool enable, uint16_t max_rate,
                                                 uint8_t *out, size_t out_cap,
                                                 size_t *out_len)
{
    if (out == NULL || out_len == NULL) return RFB_ERR_INTERNAL;
    if (out_cap < 4u) return RFB_ERR_LIMIT;
    out[0] = (uint8_t)APPLE_POSTAUTH_AUTO_FBUPDATE;
    out[1] = enable ? 0x01u : 0x00u;
    put_be16(out + 2, max_rate);
    *out_len = 4u;
    return RFB_OK;
}

// ---------------------------------------------------------------------------
// Cursor STORE / SELECT cache.
// ---------------------------------------------------------------------------

rfb_error apple_postauth_serialize_cursor_store(uint8_t cache_index,
                                                uint16_t width, uint16_t height,
                                                uint16_t hotspot_x,
                                                uint16_t hotspot_y,
                                                const uint8_t *rgba, size_t rgba_len,
                                                uint8_t *out, size_t out_cap,
                                                size_t *out_len)
{
    if (out == NULL || out_len == NULL) return RFB_ERR_INTERNAL;
    if (rgba == NULL && rgba_len > 0u) return RFB_ERR_INTERNAL;

    // header: u8 type + u8 index + 4x u16 = 10 bytes
    if (rgba_len > SIZE_MAX - 10u) return RFB_ERR_LIMIT;
    size_t total = 10u + rgba_len;
    if (out_cap < total) return RFB_ERR_LIMIT;

    out[0] = (uint8_t)APPLE_POSTAUTH_CURSOR_STORE;
    out[1] = cache_index;
    put_be16(out + 2, width);
    put_be16(out + 4, height);
    put_be16(out + 6, hotspot_x);
    put_be16(out + 8, hotspot_y);
    if (rgba_len > 0u) {
        memcpy(out + 10, rgba, rgba_len);
    }
    *out_len = total;
    return RFB_OK;
}

rfb_error apple_postauth_serialize_cursor_select(uint8_t cache_index,
                                                 uint8_t *out, size_t out_cap,
                                                 size_t *out_len)
{
    if (out == NULL || out_len == NULL) return RFB_ERR_INTERNAL;
    if (out_cap < 2u) return RFB_ERR_LIMIT;
    out[0] = (uint8_t)APPLE_POSTAUTH_CURSOR_SELECT;
    out[1] = cache_index;
    *out_len = 2u;
    return RFB_OK;
}
