// SPDX-License-Identifier: Apache-2.0
//
// G19 — Apple post-auth message codec tests (goals.md G19).
// Golden byte assertions for every serializer/parser in apple_postauth.
// Fields are classified CAPTURED/INFERRED/UNKNOWN per apple-wire-spec.md.

#include "rfb_test.h"
#include "farsee/apple_postauth.h"

#include <string.h>

// --- ClientInit (CAPTURED: RFC 6143 §7.3.3) -------------------------------

RFB_TEST(g19_postauth, client_init__shared__byte_0x01) {
    uint8_t out[8] = { 0 };
    size_t n = 0;
    RFB_CHECK_EQ_INT(
        apple_postauth_serialize_client_init(true, out, sizeof out, &n),
        RFB_OK);
    RFB_CHECK_EQ_UINT(n, 1u);
    RFB_CHECK_EQ_UINT(out[0], 0x01u);
}

RFB_TEST(g19_postauth, client_init__exclusive__byte_0x00) {
    uint8_t out[8] = { 0 };
    size_t n = 0;
    RFB_CHECK_EQ_INT(
        apple_postauth_serialize_client_init(false, out, sizeof out, &n),
        RFB_OK);
    RFB_CHECK_EQ_UINT(n, 1u);
    RFB_CHECK_EQ_UINT(out[0], 0x00u);
}

RFB_TEST(g19_postauth, client_init__null_buffer__returns_internal) {
    size_t n = 0;
    RFB_CHECK_EQ_INT(
        apple_postauth_serialize_client_init(true, NULL, 0, &n),
        RFB_ERR_INTERNAL);
}

RFB_TEST(g19_postauth, client_init__too_small_cap__returns_limit) {
    uint8_t out[1] = { 0 };
    size_t n = 0;
    RFB_CHECK_EQ_INT(
        apple_postauth_serialize_client_init(true, out, 0, &n),
        RFB_ERR_LIMIT);
}

// --- ServerInit parse (CAPTURED pixel format) ----------------------------

RFB_TEST(g19_postauth, server_init__parse__captured_pixel_format) {
    // CAPTURED: width/height from a 138-byte Apple ServerInit. Build a
    // minimal valid ServerInit: 24-byte header + 16-byte name.
    uint8_t buf[APPLE_SERVER_INIT_HEADER_LEN + 16] = { 0 };
    // width=1024, height=640
    buf[0] = 0x04; buf[1] = 0x00;
    buf[2] = 0x02; buf[3] = 0x80;
    // pixel format: bpp=32, depth=24, big_endian=0, true_color=1
    buf[4] = 32; buf[5] = 24; buf[6] = 0; buf[7] = 1;
    // red_max=255 (be16), green_max=255, blue_max=255
    buf[8] = 0; buf[9] = 255;
    buf[10] = 0; buf[11] = 255;
    buf[12] = 0; buf[13] = 255;
    // shifts: red=16, green=8, blue=0
    buf[14] = 16; buf[15] = 8; buf[16] = 0;
    // 3 pad bytes at 17,18,19
    // name_length = 16
    buf[20] = 0; buf[21] = 0; buf[22] = 0; buf[23] = 16;
    memcpy(buf + 24, "aarch64-darwin-1", 16);

    apple_server_init si;
    RFB_CHECK_EQ_INT(
        apple_postauth_parse_server_init(buf, sizeof buf, &si), RFB_OK);
    RFB_CHECK_EQ_UINT(si.width, 1024u);
    RFB_CHECK_EQ_UINT(si.height, 640u);
    RFB_CHECK_EQ_UINT(si.bits_per_pixel, 32u);
    RFB_CHECK_EQ_UINT(si.depth, 24u);
    RFB_CHECK_EQ_UINT(si.true_color, 1u);
    RFB_CHECK_EQ_UINT(si.red_max, 255u);
    RFB_CHECK_EQ_UINT(si.green_max, 255u);
    RFB_CHECK_EQ_UINT(si.blue_max, 255u);
    RFB_CHECK_EQ_UINT(si.red_shift, 16u);
    RFB_CHECK_EQ_UINT(si.green_shift, 8u);
    RFB_CHECK_EQ_UINT(si.blue_shift, 0u);
    RFB_CHECK_EQ_UINT(si.name_len, 16u);
    RFB_CHECK_MEM_EQ(si.name, "aarch64-darwin-1", 16);
}

RFB_TEST(g19_postauth, server_init__truncated__returns_protocol) {
    uint8_t buf[10] = { 0 };  // less than 24-byte header
    apple_server_init si;
    RFB_CHECK_EQ_INT(
        apple_postauth_parse_server_init(buf, sizeof buf, &si),
        RFB_ERR_PROTOCOL);
}

// --- ViewerInfo (CAPTURED: 'MacBook Air') --------------------------------

RFB_TEST(g19_postauth, viewer_info__serialize__device_name_mactellurair) {
    apple_viewer_info vi;
    memset(&vi, 0, sizeof vi);
    memcpy(vi.device_name, "MacBook Air", 11);
    vi.name_len = 11;

    uint8_t out[128] = { 0 };
    size_t n = 0;
    RFB_CHECK_EQ_INT(
        apple_postauth_serialize_viewer_info(&vi, out, sizeof out, &n),
        RFB_OK);
    // u8 type + u8 reserved + u16 name_len + name bytes = 4 + 11 = 15
    RFB_CHECK_EQ_UINT(n, 15u);
    RFB_CHECK_EQ_UINT(out[0], APPLE_POSTAUTH_VIEWER_INFO);
    RFB_CHECK_EQ_UINT(out[2], 0u);
    RFB_CHECK_EQ_UINT(out[3], 11u);
    RFB_CHECK_MEM_EQ(out + 4, "MacBook Air", 11);
}

RFB_TEST(g19_postauth, viewer_info__roundtrip) {
    apple_viewer_info vi;
    memset(&vi, 0, sizeof vi);
    memcpy(vi.device_name, "probe-test", 10);
    vi.name_len = 10;

    uint8_t buf[128] = { 0 };
    size_t n = 0;
    RFB_CHECK_EQ_INT(
        apple_postauth_serialize_viewer_info(&vi, buf, sizeof buf, &n), RFB_OK);

    apple_viewer_info parsed;
    RFB_CHECK_EQ_INT(
        apple_postauth_parse_viewer_info(buf, n, &parsed), RFB_OK);
    RFB_CHECK_EQ_UINT(parsed.name_len, 10u);
    RFB_CHECK_MEM_EQ(parsed.device_name, "probe-test", 10);
}

RFB_TEST(g19_postauth, viewer_info__oversize_name__returns_limit) {
    apple_viewer_info vi;
    memset(&vi, 0, sizeof vi);
    vi.name_len = APPLE_POSTAUTH_DEVICE_NAME_MAX + 1;
    uint8_t out[256] = { 0 };
    size_t n = 0;
    RFB_CHECK_EQ_INT(
        apple_postauth_serialize_viewer_info(&vi, out, sizeof out, &n),
        RFB_ERR_PROTOCOL);
}

// --- ClientInit live (CAPTURED E8: 0xc1) ---------------------------------

RFB_TEST(g19_postauth, client_init_live__shared__byte_0xc1) {
    uint8_t out[8] = { 0 };
    size_t n = 0;
    RFB_CHECK_EQ_INT(
        apple_postauth_serialize_client_init_live(true, out, sizeof out, &n),
        RFB_OK);
    RFB_CHECK_EQ_UINT(n, 1u);
    RFB_CHECK_EQ_UINT(out[0], APPLE_POSTAUTH_CLIENT_INIT_LIVE_SHARED);
    RFB_CHECK_EQ_UINT(out[0], 0xc1u);
}

RFB_TEST(g19_postauth, client_init_live__exclusive__unsupported) {
    uint8_t out[8] = { 0 };
    size_t n = 0;
    RFB_CHECK_EQ_INT(
        apple_postauth_serialize_client_init_live(false, out, sizeof out, &n),
        RFB_ERR_UNSUPPORTED);
}

// --- ViewerInfo live (CAPTURED E8 74-byte Screen Sharing layout) ---------

// Golden: docs/gates/interop-evidence/e7e8-apple-postauth/golden_viewer_info.bin
static const uint8_t k_e8_viewer_info_macbook_air[APPLE_VIEWER_INFO_LIVE_LEN] = {
    0x00, 0x48, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x4d, 0x61,
    0x63, 0x42, 0x6f, 0x6f, 0x6b, 0x20, 0x41, 0x69, 0x72, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00
};

RFB_TEST(g19_postauth, viewer_info_live__serialize__matches_e8_macbook_air) {
    apple_viewer_info vi;
    memset(&vi, 0, sizeof vi);
    memcpy(vi.device_name, "MacBook Air", 11);
    vi.name_len = 11;

    uint8_t out[APPLE_VIEWER_INFO_LIVE_LEN + 8] = { 0 };
    size_t n = 0;
    RFB_CHECK_EQ_INT(
        apple_postauth_serialize_viewer_info_live(&vi, out, sizeof out, &n),
        RFB_OK);
    RFB_CHECK_EQ_UINT(n, APPLE_VIEWER_INFO_LIVE_LEN);
    RFB_CHECK_MEM_EQ(out, k_e8_viewer_info_macbook_air,
                     APPLE_VIEWER_INFO_LIVE_LEN);
}

RFB_TEST(g19_postauth, viewer_info_live__parse__e8_macbook_air) {
    apple_viewer_info vi;
    RFB_CHECK_EQ_INT(
        apple_postauth_parse_viewer_info_live(
            k_e8_viewer_info_macbook_air, sizeof k_e8_viewer_info_macbook_air,
            &vi),
        RFB_OK);
    RFB_CHECK_EQ_UINT(vi.name_len, 11u);
    RFB_CHECK_MEM_EQ(vi.device_name, "MacBook Air", 11);
}

RFB_TEST(g19_postauth, viewer_info_live__roundtrip__farsee) {
    apple_viewer_info vi;
    memset(&vi, 0, sizeof vi);
    memcpy(vi.device_name, "farsee", 6);
    vi.name_len = 6;

    uint8_t buf[APPLE_VIEWER_INFO_LIVE_LEN] = { 0 };
    size_t n = 0;
    RFB_CHECK_EQ_INT(
        apple_postauth_serialize_viewer_info_live(&vi, buf, sizeof buf, &n),
        RFB_OK);

    apple_viewer_info parsed;
    RFB_CHECK_EQ_INT(
        apple_postauth_parse_viewer_info_live(buf, n, &parsed), RFB_OK);
    RFB_CHECK_EQ_UINT(parsed.name_len, 6u);
    RFB_CHECK_MEM_EQ(parsed.device_name, "farsee", 6);
}

RFB_TEST(g19_postauth, viewer_info_live__truncated__returns_protocol) {
    uint8_t buf[10] = { 0 };
    apple_viewer_info vi;
    RFB_CHECK_EQ_INT(
        apple_postauth_parse_viewer_info_live(buf, sizeof buf, &vi),
        RFB_ERR_PROTOCOL);
}

// CAPTURED E9: login ViewerInfo mode=2, body_len=0xC8, 128-byte trailer.
RFB_TEST(g19_postauth, viewer_info_live_login__serialize__mode2_and_trailer) {
    apple_viewer_info vi;
    memset(&vi, 0, sizeof vi);
    memcpy(vi.device_name, "MacBook Air", 11);
    vi.name_len = 11;

    uint8_t trailer[APPLE_VIEWER_INFO_LIVE_LOGIN_TRAILER];
    for (size_t i = 0; i < sizeof trailer; i++) {
        trailer[i] = (uint8_t)(0xA0u + (i & 0x0Fu));
    }

    uint8_t out[APPLE_VIEWER_INFO_LIVE_LOGIN_LEN + 8];
    size_t n = 0;
    RFB_CHECK_EQ_INT(
        apple_postauth_serialize_viewer_info_live_attach(
            &vi, APPLE_ATTACH_LOGIN, trailer, sizeof trailer, out, sizeof out,
            &n),
        RFB_OK);
    RFB_CHECK_EQ_UINT(n, APPLE_VIEWER_INFO_LIVE_LOGIN_LEN);
    RFB_CHECK_EQ_UINT(out[0], 0x00u);
    RFB_CHECK_EQ_UINT(out[1], 0xC8u); // body_len 200
    RFB_CHECK_EQ_UINT(out[3], APPLE_ATTACH_LOGIN);
    RFB_CHECK_EQ_UINT(out[8], APPLE_ATTACH_LOGIN);
    RFB_CHECK_MEM_EQ(out + 10, "MacBook Air", 11);
    RFB_CHECK_MEM_EQ(out + 2u + APPLE_VIEWER_INFO_LIVE_BODY_LEN, trailer,
                     sizeof trailer);

    apple_viewer_info parsed;
    uint8_t attach = 0;
    RFB_CHECK_EQ_INT(
        apple_postauth_parse_viewer_info_live_attach(out, n, &parsed, &attach),
        RFB_OK);
    RFB_CHECK_EQ_UINT(attach, APPLE_ATTACH_LOGIN);
    RFB_CHECK_EQ_UINT(parsed.name_len, 11u);
    RFB_CHECK_MEM_EQ(parsed.device_name, "MacBook Air", 11);
}

RFB_TEST(g19_postauth, viewer_info_live_login__matches_e9_header) {
    // First 10 bytes of CAPTURED login-viewer-info.bin (length + hdr).
    static const uint8_t k_e9_login_head[] = {
        0x00, 0xc8, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00
    };
    apple_viewer_info vi;
    memset(&vi, 0, sizeof vi);
    memcpy(vi.device_name, "MacBook Air", 11);
    vi.name_len = 11;
    uint8_t trailer[APPLE_VIEWER_INFO_LIVE_LOGIN_TRAILER];
    memset(trailer, 0x5A, sizeof trailer);
    uint8_t out[APPLE_VIEWER_INFO_LIVE_LOGIN_LEN];
    size_t n = 0;
    RFB_CHECK_EQ_INT(
        apple_postauth_serialize_viewer_info_live_attach(
            &vi, APPLE_ATTACH_LOGIN, trailer, sizeof trailer, out, sizeof out,
            &n),
        RFB_OK);
    RFB_CHECK_MEM_EQ(out, k_e9_login_head, sizeof k_e9_login_head);
}

// --- SetEncryption / SetMode (INFERRED) ----------------------------------

RFB_TEST(g19_postauth, set_encryption__enable__flag_set) {
    uint8_t out[8] = { 0 };
    size_t n = 0;
    RFB_CHECK_EQ_INT(
        apple_postauth_serialize_set_encryption(true, out, sizeof out, &n),
        RFB_OK);
    RFB_CHECK_EQ_UINT(n, 2u);
    RFB_CHECK_EQ_UINT(out[0], APPLE_POSTAUTH_SET_ENCRYPTION);
    RFB_CHECK_EQ_UINT(out[1], 0x01u);
}

RFB_TEST(g19_postauth, set_mode__full_quality__mode_zero) {
    uint8_t out[8] = { 0 };
    size_t n = 0;
    RFB_CHECK_EQ_INT(
        apple_postauth_serialize_set_mode(APPLE_MODE_FULL_QUALITY,
                                          out, sizeof out, &n),
        RFB_OK);
    RFB_CHECK_EQ_UINT(n, 2u);
    RFB_CHECK_EQ_UINT(out[0], APPLE_POSTAUTH_SET_MODE);
    RFB_CHECK_EQ_UINT(out[1], 0u);
}

RFB_TEST(g19_postauth, set_mode__adaptive_rejected__unsupported) {
    // goals.md G19: exclude HEVC/Adaptive.
    uint8_t out[8] = { 0 };
    size_t n = 0;
    RFB_CHECK_EQ_INT(
        apple_postauth_serialize_set_mode(APPLE_MODE_ADAPTIVE,
                                          out, sizeof out, &n),
        RFB_ERR_UNSUPPORTED);
}

// --- DisplayConfiguration (INFERRED) -------------------------------------

RFB_TEST(g19_postauth, display_config__serialize_roundtrip) {
    apple_display_config dc = { .width = 1920, .height = 1080,
                                .display_index = 0, .flags = 0 };
    uint8_t out[16] = { 0 };
    size_t n = 0;
    RFB_CHECK_EQ_INT(
        apple_postauth_serialize_display_config(&dc, out, sizeof out, &n),
        RFB_OK);
    RFB_CHECK_EQ_UINT(n, 6u);

    apple_display_config parsed;
    RFB_CHECK_EQ_INT(
        apple_postauth_parse_display_config(out, n, &parsed), RFB_OK);
    RFB_CHECK_EQ_UINT(parsed.width, 1920u);
    RFB_CHECK_EQ_UINT(parsed.height, 1080u);
    RFB_CHECK_EQ_UINT(parsed.display_index, 0u);
}

RFB_TEST(g19_postauth, display_config__truncated__returns_protocol) {
    uint8_t buf[3] = { 0 };
    apple_display_config dc;
    RFB_CHECK_EQ_INT(
        apple_postauth_parse_display_config(buf, sizeof buf, &dc),
        RFB_ERR_PROTOCOL);
}

// --- AutoFrameBufferUpdate arm (INFERRED) ---------------------------------

RFB_TEST(g19_postauth, auto_fbupdate__arm__bytes_correct) {
    uint8_t out[8] = { 0 };
    size_t n = 0;
    RFB_CHECK_EQ_INT(
        apple_postauth_serialize_auto_fbupdate(true, 30, out, sizeof out, &n),
        RFB_OK);
    RFB_CHECK_EQ_UINT(n, 4u);
    RFB_CHECK_EQ_UINT(out[0], APPLE_POSTAUTH_AUTO_FBUPDATE);
    RFB_CHECK_EQ_UINT(out[1], 0x01u);
    RFB_CHECK_EQ_UINT(out[2], 0u);
    RFB_CHECK_EQ_UINT(out[3], 30u);
}

// --- Cursor STORE / SELECT cache (INFERRED, bounded) ----------------------

RFB_TEST(g19_postauth, cursor_store__serialize_with_rgba) {
    static const uint8_t rgba[16] = {  // 1x1 pixel RGBA
        0xFF, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    uint8_t out[64] = { 0 };
    size_t n = 0;
    RFB_CHECK_EQ_INT(
        apple_postauth_serialize_cursor_store(
            /*cache_index=*/2, /*width=*/2, /*height=*/2,
            /*hotspot_x=*/0, /*hotspot_y=*/0,
            rgba, sizeof rgba, out, sizeof out, &n),
        RFB_OK);
    // header = u8 type + u8 index + 4x u16 = 10 bytes; + 16 rgba = 26
    RFB_CHECK_EQ_UINT(n, 26u);
    RFB_CHECK_EQ_UINT(out[0], APPLE_POSTAUTH_CURSOR_STORE);
    RFB_CHECK_EQ_UINT(out[1], 2u);
    RFB_CHECK_MEM_EQ(out + 10, rgba, 16);
}

RFB_TEST(g19_postauth, cursor_select__serialize_index) {
    uint8_t out[8] = { 0 };
    size_t n = 0;
    RFB_CHECK_EQ_INT(
        apple_postauth_serialize_cursor_select(5, out, sizeof out, &n),
        RFB_OK);
    RFB_CHECK_EQ_UINT(n, 2u);
    RFB_CHECK_EQ_UINT(out[0], APPLE_POSTAUTH_CURSOR_SELECT);
    RFB_CHECK_EQ_UINT(out[1], 5u);
}

RFB_TEST(g19_postauth, cursor_store__null_rgba__returns_internal) {
    uint8_t out[64] = { 0 };
    size_t n = 0;
    RFB_CHECK_EQ_INT(
        apple_postauth_serialize_cursor_store(
            0, 2, 2, 0, 0, NULL, 16, out, sizeof out, &n),
        RFB_ERR_INTERNAL);
}
