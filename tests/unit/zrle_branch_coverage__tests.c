// SPDX-License-Identifier: Apache-2.0
//
// ZRLE + handshake branch coverage tests — drives the remaining semantic
// dispatch branches to reach plan.md §15.5 90% branch.

#include "rfb_test.h"
#include "farsee/encoding.h"
#include "farsee/encoding_zrle.h"
#include "farsee/zlib_adapter.h"
#include "farsee/framebuffer.h"
#include "farsee/pixel_format.h"
#include "farsee/handshake.h"
#include "farsee/buffer.h"
#include "farsee/allocator.h"
#include "farsee/error.h"

#include <zlib.h>
#include <string.h>

static bool zbr_stub_des(const uint8_t key[8], const uint8_t in[8], uint8_t out[8])
{
    for (int i = 0; i < 8; i++) out[i] = (uint8_t)(in[i] ^ key[i]);
    return true;
}

static void zbr_run(rfb_handshake *h, rfb_buffer *in, rfb_buffer *out, int max)
{
    for (int i = 0; i < max && !rfb_handshake_finished(h); i++) {
        if (rfb_handshake_step(h, in, out) != RFB_OK) break;
    }
}

// ===== ZRLE: packed-palette with 4 colors (2 bits/pixel) =====
// Exercises the bits_per_idx=2 path in the packed-palette decoder.
RFB_TEST(br_zrle2, zrle__packed_palette_4_colors__decodes) {
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_resize(&fb, 4, 1, 1u << 20);
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();
    // subenc=4 (4-entry palette, 2 bits/pixel).
    uint8_t tile[16];
    int pos = 0;
    tile[pos++] = 4;
    // Palette: red, green, blue, white (3-byte CPIXEL each).
    tile[pos++] = 0; tile[pos++] = 0; tile[pos++] = 0xFF;
    tile[pos++] = 0; tile[pos++] = 0xFF; tile[pos++] = 0;
    tile[pos++] = 0xFF; tile[pos++] = 0; tile[pos++] = 0;
    tile[pos++] = 0xFF; tile[pos++] = 0xFF; tile[pos++] = 0xFF;
    // 4 pixels at 2 bits: indices 0,1,2,3 → bits 00,01,10,11 = 0x1B.
    tile[pos++] = 0x1B;
    uint8_t comp[64]; uLongf clen = sizeof comp;
    compress2(comp, &clen, tile, (uLong)pos, Z_DEFAULT_COMPRESSION);
    rfb_rect_header rh = { 0, 0, 4, 1, RFB_ENCODING_ZRLE };
    rfb_zlib_stream *zs = rfb_zlib_create();
    rfb_rect dmg;
    RFB_CHECK_EQ_INT(rfb_decode_zrle(&fb, &pf, &rh, zs, comp, clen, 1u<<20, &dmg), RFB_OK);
    RFB_CHECK_EQ_UINT(rfb_framebuffer_pixel_c(&fb, 0, 0)[0], 0xFFu);  // red
    RFB_CHECK_EQ_UINT(rfb_framebuffer_pixel_c(&fb, 1, 0)[1], 0xFFu);  // green
    RFB_CHECK_EQ_UINT(rfb_framebuffer_pixel_c(&fb, 2, 0)[2], 0xFFu);  // blue
    rfb_zlib_destroy(zs);
    rfb_framebuffer_destroy(&fb);
}

// ZRLE: packed-palette with 16 colors (4 bits/pixel) — bits_per_idx=4.
RFB_TEST(br_zrle2, zrle__packed_palette_16_colors__decodes) {
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_resize(&fb, 4, 1, 1u << 20);
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();
    uint8_t tile[64];
    int pos = 0;
    tile[pos++] = 16;  // 16-entry palette
    for (int i = 0; i < 16; i++) {
        tile[pos++] = (uint8_t)(i * 16);  // R
        tile[pos++] = 0;
        tile[pos++] = 0;
    }
    // 4 pixels at 4 bits: indices 0,5,10,15 → 0x05 0xAF (packed 4+4=8 bits = 1 byte)
    // Pixel 0 (idx 0) + Pixel 1 (idx 5): 0000_0101 = 0x05
    tile[pos++] = 0x05;
    // Pixel 2 (idx 10) + Pixel 3 (idx 15): 1010_1111 = 0xAF
    tile[pos++] = 0xAF;
    uint8_t comp[64]; uLongf clen = sizeof comp;
    compress2(comp, &clen, tile, (uLong)pos, Z_DEFAULT_COMPRESSION);
    rfb_rect_header rh = { 0, 0, 4, 1, RFB_ENCODING_ZRLE };
    rfb_zlib_stream *zs = rfb_zlib_create();
    rfb_rect dmg;
    RFB_CHECK_EQ_INT(rfb_decode_zrle(&fb, &pf, &rh, zs, comp, clen, 1u<<20, &dmg), RFB_OK);
    rfb_zlib_destroy(zs);
    rfb_framebuffer_destroy(&fb);
}

// ZRLE: palette RLE with 1-color palette (subenc=129).
RFB_TEST(br_zrle2, zrle__palette_rle_1_color__decodes) {
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_resize(&fb, 4, 1, 1u << 20);
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();
    uint8_t tile[16];
    int pos = 0;
    tile[pos++] = 129;  // palette RLE, 1 color
    tile[pos++] = 0; tile[pos++] = 0; tile[pos++] = 0xFF;  // red CPIXEL
    // Run: index 0, length 4 (RFC: bit7 set → length follows).
    tile[pos++] = (uint8_t)(0x80u | 0u);
    tile[pos++] = 3;  // run-1 = 3 (4 pixels)
    uint8_t comp[64]; uLongf clen = sizeof comp;
    compress2(comp, &clen, tile, (uLong)pos, Z_DEFAULT_COMPRESSION);
    rfb_rect_header rh = { 0, 0, 4, 1, RFB_ENCODING_ZRLE };
    rfb_zlib_stream *zs = rfb_zlib_create();
    rfb_rect dmg;
    RFB_CHECK_EQ_INT(rfb_decode_zrle(&fb, &pf, &rh, zs, comp, clen, 1u<<20, &dmg), RFB_OK);
    RFB_CHECK_EQ_UINT(rfb_framebuffer_pixel_c(&fb, 0, 0)[0], 0xFFu);
    rfb_zlib_destroy(zs);
    rfb_framebuffer_destroy(&fb);
}

// ZRLE: palette RLE single-pixel runs (bit7 clear, no length byte).
RFB_TEST(br_zrle2, zrle__palette_rle_single_pixel_runs__decodes) {
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_resize(&fb, 3, 1, 1u << 20);
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();
    uint8_t tile[16];
    int pos = 0;
    tile[pos++] = 130;  // 2-color palette
    tile[pos++] = 0; tile[pos++] = 0; tile[pos++] = 0xFF;  // red
    tile[pos++] = 0; tile[pos++] = 0xFF; tile[pos++] = 0;  // green
    tile[pos++] = 0;  // red, run 1
    tile[pos++] = 1;  // green, run 1
    tile[pos++] = 0;  // red, run 1
    uint8_t comp[64]; uLongf clen = sizeof comp;
    compress2(comp, &clen, tile, (uLong)pos, Z_DEFAULT_COMPRESSION);
    rfb_rect_header rh = { 0, 0, 3, 1, RFB_ENCODING_ZRLE };
    rfb_zlib_stream *zs = rfb_zlib_create();
    rfb_rect dmg;
    RFB_CHECK_EQ_INT(rfb_decode_zrle(&fb, &pf, &rh, zs, comp, clen, 1u<<20, &dmg), RFB_OK);
    RFB_CHECK_EQ_UINT(rfb_framebuffer_pixel_c(&fb, 0, 0)[0], 0xFFu);
    RFB_CHECK_EQ_UINT(rfb_framebuffer_pixel_c(&fb, 1, 0)[1], 0xFFu);
    RFB_CHECK_EQ_UINT(rfb_framebuffer_pixel_c(&fb, 2, 0)[0], 0xFFu);
    rfb_zlib_destroy(zs);
    rfb_framebuffer_destroy(&fb);
}

// ZRLE: palette RLE invalid index (>= palette size).
RFB_TEST(br_zrle2, zrle__palette_rle_invalid_index__fails) {
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_resize(&fb, 2, 1, 1u << 20);
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();
    uint8_t tile[16];
    int pos = 0;
    tile[pos++] = 129;  // 1-color palette
    tile[pos++] = 0; tile[pos++] = 0; tile[pos++] = 0xFF;
    // Index 5 (but palette only has 1 entry → invalid); bit7 clear → run 1.
    tile[pos++] = 5;
    uint8_t comp[64]; uLongf clen = sizeof comp;
    compress2(comp, &clen, tile, (uLong)pos, Z_DEFAULT_COMPRESSION);
    rfb_rect_header rh = { 0, 0, 2, 1, RFB_ENCODING_ZRLE };
    rfb_zlib_stream *zs = rfb_zlib_create();
    rfb_rect dmg;
    rfb_error e = rfb_decode_zrle(&fb, &pf, &rh, zs, comp, clen, 1u<<20, &dmg);
    RFB_CHECK_EQ_INT(e, RFB_ERR_PROTOCOL);
    rfb_zlib_destroy(zs);
    rfb_framebuffer_destroy(&fb);
}

// ZRLE: plain RLE run overflow beyond tile pixels.
RFB_TEST(br_zrle2, zrle__plain_rle_run_exceeds_tile__fails) {
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_resize(&fb, 2, 1, 1u << 20);
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();
    uint8_t tile[8];
    int pos = 0;
    tile[pos++] = 128;
    tile[pos++] = 0; tile[pos++] = 0; tile[pos++] = 0xFF;
    tile[pos++] = 10;  // run 11, but tile only has 2 pixels
    uint8_t comp[64]; uLongf clen = sizeof comp;
    compress2(comp, &clen, tile, (uLong)pos, Z_DEFAULT_COMPRESSION);
    rfb_rect_header rh = { 0, 0, 2, 1, RFB_ENCODING_ZRLE };
    rfb_zlib_stream *zs = rfb_zlib_create();
    rfb_rect dmg;
    rfb_error e = rfb_decode_zrle(&fb, &pf, &rh, zs, comp, clen, 1u<<20, &dmg);
    RFB_CHECK_EQ_INT(e, RFB_ERR_PROTOCOL);
    rfb_zlib_destroy(zs);
    rfb_framebuffer_destroy(&fb);
}

// ZRLE: read_run_length overflow (runs out of data).
RFB_TEST(br_zrle2, zrle__run_length_no_terminator__fails) {
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_resize(&fb, 2, 1, 1u << 20);
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();
    // Plain RLE with CPIXEL then only 255 bytes (no terminator < 255).
    uint8_t tile[8];
    int pos = 0;
    tile[pos++] = 128;
    tile[pos++] = 0; tile[pos++] = 0; tile[pos++] = 0xFF;
    tile[pos++] = 255;  // add 255, need more → but no more bytes
    uint8_t comp[64]; uLongf clen = sizeof comp;
    compress2(comp, &clen, tile, (uLong)pos, Z_DEFAULT_COMPRESSION);
    rfb_rect_header rh = { 0, 0, 2, 1, RFB_ENCODING_ZRLE };
    rfb_zlib_stream *zs = rfb_zlib_create();
    rfb_rect dmg;
    rfb_error e = rfb_decode_zrle(&fb, &pf, &rh, zs, comp, clen, 1u<<20, &dmg);
    RFB_CHECK(e != RFB_OK);
    rfb_zlib_destroy(zs);
    rfb_framebuffer_destroy(&fb);
}

// ZRLE: subenc=3 (3-entry palette, 2 bits/pixel — exercises bits_per_idx ceil).
RFB_TEST(br_zrle2, zrle__packed_palette_3_colors__decodes) {
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    rfb_framebuffer_resize(&fb, 4, 1, 1u << 20);
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();
    uint8_t tile[16];
    int pos = 0;
    tile[pos++] = 3;
    tile[pos++] = 0; tile[pos++] = 0; tile[pos++] = 0xFF;
    tile[pos++] = 0; tile[pos++] = 0xFF; tile[pos++] = 0;
    tile[pos++] = 0xFF; tile[pos++] = 0; tile[pos++] = 0;
    // 4 pixels at 2 bits: 0,1,2,0 → 00,01,10,00 = 0x28.
    tile[pos++] = 0x28;
    uint8_t comp[64]; uLongf clen = sizeof comp;
    compress2(comp, &clen, tile, (uLong)pos, Z_DEFAULT_COMPRESSION);
    rfb_rect_header rh = { 0, 0, 4, 1, RFB_ENCODING_ZRLE };
    rfb_zlib_stream *zs = rfb_zlib_create();
    rfb_rect dmg;
    RFB_CHECK_EQ_INT(rfb_decode_zrle(&fb, &pf, &rh, zs, comp, clen, 1u<<20, &dmg), RFB_OK);
    rfb_zlib_destroy(zs);
    rfb_framebuffer_destroy(&fb);
}

// ===== handshake.c: additional version-specific branches =====

// 3.3 None auth with opt-in → DONE (exercises the 3.3 None path).
RFB_TEST(br_hs, rfb33_none_with_optin__done) {
    static const uint8_t T[] = {
        'R','F','B',' ','0','0','3','.','0','0','3','\n',
        0x00,0x00,0x00,0x01,  // None
    };
    rfb_handshake_policy pol = rfb_handshake_policy_default();
    pol.allow_none_auth = true;
    rfb_handshake h; rfb_handshake_init(&h, &pol, rfb_default_allocator());
    rfb_buffer in, out;
    rfb_buffer_init(&in, rfb_default_allocator(), 4096);
    rfb_buffer_init(&out, rfb_default_allocator(), 4096);
    rfb_buffer_append(&in, T, sizeof T);
    zbr_run(&h, &in, &out, 16);
    RFB_CHECK_EQ_INT(h.state, RFB_HS_DONE);
    RFB_CHECK_EQ_INT(h.selected_security, RFB_SECURITY_NONE);
    rfb_buffer_destroy(&in); rfb_buffer_destroy(&out);
    rfb_handshake_destroy(&h);
}

// 3.7 VNC auth → DONE (no result u32) with successful challenge.
RFB_TEST(br_hs, rfb37_vnc_auth_success__done) {
    static const uint8_t T[] = {
        'R','F','B',' ','0','0','3','.','0','0','7','\n',
        0x01, 0x02,  // VNC
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,  // challenge
        0,0,0,0,  // 3.7 SecurityResult = 0 (success)
    };
    rfb_handshake_policy pol = rfb_handshake_policy_default();
    rfb_handshake h; rfb_handshake_init(&h, &pol, rfb_default_allocator());
    rfb_handshake_set_des_provider(&h, zbr_stub_des);
    rfb_handshake_set_password(&h, (const uint8_t*)"pass", 4);
    rfb_buffer in, out;
    rfb_buffer_init(&in, rfb_default_allocator(), 4096);
    rfb_buffer_init(&out, rfb_default_allocator(), 4096);
    rfb_buffer_append(&in, T, sizeof T);
    zbr_run(&h, &in, &out, 16);
    RFB_CHECK_EQ_INT(h.state, RFB_HS_DONE);
    rfb_buffer_destroy(&in); rfb_buffer_destroy(&out);
    rfb_handshake_destroy(&h);
}

// 3.8 None auth → result OK → DONE.
RFB_TEST(br_hs, rfb38_none_with_optin_result_ok__done) {
    static const uint8_t T[] = {
        'R','F','B',' ','0','0','3','.','0','0','8','\n',
        0x01, 0x01,  // None
        0x00,0x00,0x00,0x00,  // OK
    };
    rfb_handshake_policy pol = rfb_handshake_policy_default();
    pol.allow_none_auth = true;
    rfb_handshake h; rfb_handshake_init(&h, &pol, rfb_default_allocator());
    rfb_buffer in, out;
    rfb_buffer_init(&in, rfb_default_allocator(), 4096);
    rfb_buffer_init(&out, rfb_default_allocator(), 4096);
    rfb_buffer_append(&in, T, sizeof T);
    zbr_run(&h, &in, &out, 16);
    RFB_CHECK_EQ_INT(h.state, RFB_HS_DONE);
    rfb_buffer_destroy(&in); rfb_buffer_destroy(&out);
    rfb_handshake_destroy(&h);
}

// 3.8: security types list with multiple types.
RFB_TEST(br_hs, rfb38_multiple_security_types__selects_vnc) {
    static const uint8_t T[] = {
        'R','F','B',' ','0','0','3','.','0','0','8','\n',
        0x03, 0x01, 0x02, 0x05,  // 3 types: None, VNC, unknown
    };
    rfb_handshake_policy pol = rfb_handshake_policy_default();
    pol.allow_none_auth = true;
    rfb_handshake h; rfb_handshake_init(&h, &pol, rfb_default_allocator());
    rfb_handshake_set_des_provider(&h, zbr_stub_des);
    rfb_handshake_set_password(&h, (const uint8_t*)"pass", 4);
    rfb_buffer in, out;
    rfb_buffer_init(&in, rfb_default_allocator(), 4096);
    rfb_buffer_init(&out, rfb_default_allocator(), 4096);
    rfb_buffer_append(&in, T, sizeof T);
    zbr_run(&h, &in, &out, 16);
    RFB_CHECK_EQ_INT(h.selected_security, RFB_SECURITY_VNC);
    rfb_buffer_destroy(&in); rfb_buffer_destroy(&out);
    rfb_handshake_destroy(&h);
}

// 3.8 VNC auth failure with reason.
RFB_TEST(br_hs, rfb38_vnc_auth_failure_with_reason__failed) {
    static const uint8_t T[] = {
        'R','F','B',' ','0','0','3','.','0','0','8','\n',
        0x01, 0x02,
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0x00,0x00,0x00,0x01,  // failed
        0x00,0x00,0x00,0x03, 'b','a','d',
    };
    rfb_handshake_policy pol = rfb_handshake_policy_default();
    rfb_handshake h; rfb_handshake_init(&h, &pol, rfb_default_allocator());
    rfb_handshake_set_des_provider(&h, zbr_stub_des);
    rfb_handshake_set_password(&h, (const uint8_t*)"pass", 4);
    rfb_buffer in, out;
    rfb_buffer_init(&in, rfb_default_allocator(), 4096);
    rfb_buffer_init(&out, rfb_default_allocator(), 4096);
    rfb_buffer_append(&in, T, sizeof T);
    zbr_run(&h, &in, &out, 16);
    RFB_CHECK_EQ_INT(h.state, RFB_HS_FAILED);
    rfb_buffer_destroy(&in); rfb_buffer_destroy(&out);
    rfb_handshake_destroy(&h);
}
