// SPDX-License-Identifier: Apache-2.0
//
// G3 — ServerInit parser + SetPixelFormat/SetEncodings tests
// (plan.md §G3, RFC 6143 §7.3.2, §7.4.1, §7.5.1, §7.5.2). RED step.

#include "rfb_test.h"
#include "farsee/pixel_format.h"
#include "farsee/bytes.h"
#include "farsee/buffer.h"
#include "farsee/allocator.h"
#include "farsee/error.h"
#include "farsee/server_init.h"

#include <string.h>

// Helper to build a ServerInit body into a buffer (big-endian, per RFC).
static void build_server_init(rfb_buffer *out,
                              uint16_t width, uint16_t height,
                              const rfb_pixel_format *pf,
                              const char *name)
{
    uint8_t hdr[24];
    hdr[0] = (uint8_t)(width >> 8); hdr[1] = (uint8_t)width;
    hdr[2] = (uint8_t)(height >> 8); hdr[3] = (uint8_t)height;
    hdr[4] = pf->bits_per_pixel;
    hdr[5] = pf->depth;
    hdr[6] = pf->big_endian;
    hdr[7] = pf->true_color;
    hdr[8] = (uint8_t)(pf->red_max >> 8); hdr[9] = (uint8_t)pf->red_max;
    hdr[10] = (uint8_t)(pf->green_max >> 8); hdr[11] = (uint8_t)pf->green_max;
    hdr[12] = (uint8_t)(pf->blue_max >> 8); hdr[13] = (uint8_t)pf->blue_max;
    hdr[14] = pf->red_shift;
    hdr[15] = pf->green_shift;
    hdr[16] = pf->blue_shift;
    hdr[17] = 0; hdr[18] = 0; hdr[19] = 0;  // padding
    size_t name_len = strlen(name);
    hdr[20] = (uint8_t)(name_len >> 24);
    hdr[21] = (uint8_t)(name_len >> 16);
    hdr[22] = (uint8_t)(name_len >> 8);
    hdr[23] = (uint8_t)name_len;
    rfb_buffer_append(out, hdr, sizeof hdr);
    rfb_buffer_append(out, name, name_len);
}

// --- minimal 1x1 ServerInit ---------------------------------------------

RFB_TEST(server_init, server_init__1x1_canonical__parses) {
    rfb_buffer buf;
    rfb_buffer_init(&buf, rfb_default_allocator(), 4096);
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();
    build_server_init(&buf, 1, 1, &pf, "test");
    rfb_server_init parsed;
    memset(&parsed, 0xEE, sizeof parsed);
    RFB_CHECK_EQ_INT(
        rfb_parse_server_init(rfb_buffer_data(&buf), rfb_buffer_length(&buf),
                              &parsed, 4096),
        RFB_OK);
    RFB_CHECK_EQ_UINT(parsed.width, 1u);
    RFB_CHECK_EQ_UINT(parsed.height, 1u);
    RFB_CHECK_EQ_UINT(parsed.pixel_format.bits_per_pixel, 32u);
    RFB_CHECK_EQ_UINT(parsed.pixel_format.true_color, 1u);
    RFB_CHECK_EQ_UINT(parsed.name_length, 4u);
    RFB_CHECK(parsed.name != NULL);
    RFB_CHECK(strncmp(parsed.name, "test", 4) == 0);
    rfb_server_init_destroy(&parsed);
    rfb_buffer_destroy(&buf);
}

// --- pixel format round-trips --------------------------------------------

RFB_TEST(server_init, server_init__16bpp_format__round_trips) {
    rfb_buffer buf;
    rfb_buffer_init(&buf, rfb_default_allocator(), 4096);
    rfb_pixel_format pf = { .bits_per_pixel = 16, .depth = 16,
                            .big_endian = 1, .true_color = 1,
                            .red_max = 31, .green_max = 63, .blue_max = 31,
                            .red_shift = 11, .green_shift = 5, .blue_shift = 0 };
    build_server_init(&buf, 320, 200, &pf, "rgb565");
    rfb_server_init parsed;
    RFB_CHECK_EQ_INT(
        rfb_parse_server_init(rfb_buffer_data(&buf), rfb_buffer_length(&buf),
                              &parsed, 4096), RFB_OK);
    RFB_CHECK_EQ_UINT(parsed.pixel_format.bits_per_pixel, 16u);
    RFB_CHECK_EQ_UINT(parsed.pixel_format.big_endian, 1u);
    RFB_CHECK_EQ_UINT(parsed.pixel_format.red_max, 31u);
    RFB_CHECK_EQ_UINT(parsed.pixel_format.green_max, 63u);
    RFB_CHECK_EQ_UINT(parsed.pixel_format.red_shift, 11u);
    rfb_server_init_destroy(&parsed);
    rfb_buffer_destroy(&buf);
}

// --- truncation: need at least 24 bytes of fixed header ------------------

RFB_TEST(server_init, server_init__truncated_header__fails_protocol) {
    static const uint8_t too_short[23] = { 0 };
    rfb_server_init parsed;
    RFB_CHECK_EQ_INT(rfb_parse_server_init(too_short, sizeof too_short,
                                           &parsed, 4096),
                     RFB_ERR_PROTOCOL);
}

// --- name length boundary: 0 --------------------------------------------

RFB_TEST(server_init, server_init__empty_name__succeeds_with_null) {
    rfb_buffer buf;
    rfb_buffer_init(&buf, rfb_default_allocator(), 4096);
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();
    build_server_init(&buf, 10, 10, &pf, "");
    rfb_server_init parsed;
    RFB_CHECK_EQ_INT(
        rfb_parse_server_init(rfb_buffer_data(&buf), rfb_buffer_length(&buf),
                              &parsed, 4096), RFB_OK);
    RFB_CHECK_EQ_UINT(parsed.name_length, 0u);
    rfb_server_init_destroy(&parsed);
    rfb_buffer_destroy(&buf);
}

// --- name length over cap → LIMIT ---------------------------------------

RFB_TEST(server_init, server_init__name_over_cap__fails_limit) {
    rfb_buffer buf;
    rfb_buffer_init(&buf, rfb_default_allocator(), 1u << 20);
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();
    // Build a ServerInit whose name-length field claims 10000 bytes but
    // the cap passed is 4096.
    uint8_t hdr[24];
    hdr[0] = 0; hdr[1] = 10; hdr[2] = 0; hdr[3] = 10;  // 10x10
    hdr[4] = pf.bits_per_pixel; hdr[5] = pf.depth; hdr[6] = 0; hdr[7] = 1;
    hdr[8] = 0; hdr[9] = 255; hdr[10] = 0; hdr[11] = 255;
    hdr[12] = 0; hdr[13] = 255; hdr[14] = 16; hdr[15] = 8; hdr[16] = 0;
    hdr[17] = 0; hdr[18] = 0; hdr[19] = 0;
    hdr[20] = 0; hdr[21] = 0; hdr[22] = 0x27; hdr[23] = 0x10;  // 10000
    rfb_buffer_append(&buf, hdr, sizeof hdr);
    rfb_server_init parsed;
    RFB_CHECK_EQ_INT(
        rfb_parse_server_init(rfb_buffer_data(&buf), rfb_buffer_length(&buf),
                              &parsed, 4096),
        RFB_ERR_LIMIT);
    rfb_buffer_destroy(&buf);
}

// --- name with embedded control bytes is kept verbatim (escaping happens
//     only at the logging layer; the parser stores raw bytes). -----------

RFB_TEST(server_init, server_init__name_with_control_bytes__stored_verbatim) {
    rfb_buffer buf;
    rfb_buffer_init(&buf, rfb_default_allocator(), 4096);
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();
    build_server_init(&buf, 2, 2, &pf, "a\x1B""b");
    rfb_server_init parsed;
    RFB_CHECK_EQ_INT(
        rfb_parse_server_init(rfb_buffer_data(&buf), rfb_buffer_length(&buf),
                              &parsed, 4096), RFB_OK);
    RFB_CHECK_EQ_UINT(parsed.name_length, 3u);
    RFB_CHECK_EQ_UINT((uint8_t)parsed.name[1], 0x1Bu);  // ESC stored verbatim
    rfb_server_init_destroy(&parsed);
    rfb_buffer_destroy(&buf);
}

// --- invalid pixel format → PROTOCOL -------------------------------------

RFB_TEST(server_init, server_init__invalid_pixel_format__fails_protocol) {
    rfb_buffer buf;
    rfb_buffer_init(&buf, rfb_default_allocator(), 4096);
    // depth > bpp
    rfb_pixel_format pf = { .bits_per_pixel = 16, .depth = 24,
                            .big_endian = 0, .true_color = 1,
                            .red_max = 255, .green_max = 255, .blue_max = 255,
                            .red_shift = 0, .green_shift = 8, .blue_shift = 16 };
    build_server_init(&buf, 4, 4, &pf, "x");
    rfb_server_init parsed;
    RFB_CHECK_EQ_INT(
        rfb_parse_server_init(rfb_buffer_data(&buf), rfb_buffer_length(&buf),
                              &parsed, 4096),
        RFB_ERR_PROTOCOL);
    rfb_buffer_destroy(&buf);
}

// --- SetPixelFormat exact bytes -----------------------------------------

RFB_TEST(server_init, set_pixel_format__canonical__exact_bytes) {
    uint8_t out[20];
    rfb_writer w = rfb_writer_make(out, sizeof out);
    rfb_pixel_format pf = rfb_pixel_format_canonical_request();
    RFB_CHECK_EQ_INT(rfb_format_set_pixel_format(&w, &pf), RFB_OK);
    // Message type 0, padding[3], then 16-byte PIXEL_FORMAT.
    RFB_CHECK_EQ_UINT(out[0], 0u);  // message-type
    RFB_CHECK_EQ_UINT(out[1], 0u);  // pad
    RFB_CHECK_EQ_UINT(out[2], 0u);
    RFB_CHECK_EQ_UINT(out[3], 0u);
    RFB_CHECK_EQ_UINT(out[4], 32u); // bpp
    RFB_CHECK_EQ_UINT(out[5], 24u); // depth
    RFB_CHECK_EQ_UINT(out[7], 1u);  // true-color
    RFB_CHECK_EQ_UINT(w.length, 20u);
}

// --- SetEncodings exact bytes + ordering --------------------------------

RFB_TEST(server_init, set_encodings__raw_copyrect_zrle__exact_bytes) {
    uint8_t out[64];
    rfb_writer w = rfb_writer_make(out, sizeof out);
    // Advertise in preference order: ZRLE(16), CopyRect(1), Raw(0),
    // Cursor(-239), DesktopSize(-223). Raw is always last as fallback.
    static const int32_t encs[] = { 16, 1, 0, -239, -223 };
    RFB_CHECK_EQ_INT(rfb_format_set_encodings(&w, encs, 5), RFB_OK);
    RFB_CHECK_EQ_UINT(out[0], 2u);  // message-type
    RFB_CHECK_EQ_UINT(out[1], 0u);  // pad
    RFB_CHECK_EQ_UINT((uint16_t)((out[2] << 8) | out[3]), 5u);  // count
    // First encoding (ZRLE=16) as a big-endian i32.
    RFB_CHECK_EQ_UINT(out[4], 0u); RFB_CHECK_EQ_UINT(out[7], 16u);
    RFB_CHECK_EQ_UINT(w.length, 4u + 5u * 4u);  // header + 5 i32s
}
