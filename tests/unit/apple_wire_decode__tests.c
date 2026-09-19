// SPDX-License-Identifier: Apache-2.0
//
// Unit tests for the pure Apple wire field parsers and MVS helpers.

#include "rfb_test.h"
#include "farsee/apple_wire_decode.h"
#include "farsee/apple_wire_record.h"

#include <string.h>

static bool mvs_test_pack_bits(uint8_t *out, size_t cap, size_t *bit_pos,
                              uint32_t value, unsigned nbits)
{
    if (out == NULL || bit_pos == NULL || nbits == 0u || nbits > 32u ||
        cap > SIZE_MAX / 8u ||
        *bit_pos > cap * 8u || nbits > cap * 8u - *bit_pos) {
        return false;
    }
    for (unsigned i = 0u; i < nbits; i++) {
        const unsigned shift = nbits - i - 1u;
        const size_t bit = *bit_pos + i;
        if (((value >> shift) & 1u) != 0u) {
            out[bit / 8u] |= (uint8_t)(1u << (7u - (bit & 7u)));
        }
    }
    *bit_pos += nbits;
    return true;
}

static size_t mvs_test_extended_repeat_plane(uint8_t *out, size_t cap,
                                             uint8_t group0, uint8_t group1,
                                             uint8_t group2)
{
    size_t bit = 0u;
    memset(out, 0, cap);
    RFB_CHECK(mvs_test_pack_bits(out, cap, &bit, 0u, 1u));    // format
    RFB_CHECK(mvs_test_pack_bits(out, cap, &bit, 5u, 3u));    // numeric ID
    RFB_CHECK(mvs_test_pack_bits(out, cap, &bit, 1u, 1u));    // extended
    RFB_CHECK(mvs_test_pack_bits(out, cap, &bit, 15u, 4u));   // byte groups
    RFB_CHECK(mvs_test_pack_bits(out, cap, &bit, group0, 8u));
    RFB_CHECK(mvs_test_pack_bits(out, cap, &bit, group1, 8u));
    RFB_CHECK(mvs_test_pack_bits(out, cap, &bit, group2, 8u));
    RFB_CHECK(mvs_test_pack_bits(out, cap, &bit, 0x6du, 8u)); // marker
    return (bit + 7u) / 8u;
}

typedef struct mvs_test_walk_result {
    unsigned calls;
    apple_wire_mvs_command_record record;
} mvs_test_walk_result;

static bool mvs_test_record_command(void *opaque,
                                    const apple_wire_mvs_command_record *record)
{
    mvs_test_walk_result *result = (mvs_test_walk_result *)opaque;
    result->calls++;
    result->record = *record;
    return true;
}

static bool mvs_test_reject_command(
    void *opaque, const apple_wire_mvs_command_record *record)
{
    mvs_test_walk_result *result = (mvs_test_walk_result *)opaque;
    result->calls++;
    result->record = *record;
    return false;
}

static void apple_wire_test_cfg21_scale(uint8_t *cfg, uint32_t bits)
{
    memset(cfg, 0, 48u);
    cfg[0] = 0x21u;
    cfg[3] = 44u;
    cfg[44] = (uint8_t)(bits >> 24u);
    cfg[45] = (uint8_t)(bits >> 16u);
    cfg[46] = (uint8_t)(bits >> 8u);
    cfg[47] = (uint8_t)bits;
}

static size_t mvs_test_image_plane(uint8_t *out, size_t cap,
                                   unsigned payload_bits)
{
    size_t bit = 0u;
    memset(out, 0, cap);
    for (unsigned i = 0u; i < payload_bits; i++) {
        RFB_CHECK(mvs_test_pack_bits(out, cap, &bit, i & 1u, 1u));
    }
    RFB_CHECK(mvs_test_pack_bits(out, cap, &bit, 0x6du, 8u));
    return (bit + 7u) / 8u;
}

// 0x0455 payload after the typed header.
static const uint8_t k_kb_layout[] = {
    0x00, 0x1e, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x16, 'c',  'o',
    'm',  '.',  'a',  'p',  'p',  'l',  'e',  '.',  'k',  'e',  'y',  'l',
    'a',  'y',  'o',  'u',  't',  '.',  'U',  'S'};

// 0x03f3 typed payload: table_len=0x81, n_tables=2, QT head bytes.
static const uint8_t k_mvs_tables_head[] = {
    0x00, 0x00, 0x00, 0x81, 0x02, 0x0c, 0x09, 0x09};

// 0x03f3 FBU rectangle data after x,y,w,h,encoding: solid black.
static const uint8_t k_mvs_rect[] = {0x00, 0x00, 0x00, 0x0f, 0x00, 0x03, 0x05,
                                    0x00, 0x00, 0x0b, 0x41, 0xff, 0x72, 0xfb,
                                    0x68, 0x00, 0x20, 0x81, 0xb4};

// msg14 tick.
static const uint8_t k_msg14_param4[] = {0x14, 0x00, 0x00, 0x04,
                                       0x00, 0x01, 0x00, 0x04};

RFB_TEST(apple_wire_decode, msg14_family_fields)
{
    apple_wire_msg14_fields f;
    RFB_CHECK(apple_wire_decode_msg14(k_msg14_param4, 8, &f));
    RFB_CHECK_EQ_UINT(f.type, 0x14u);
    RFB_CHECK_EQ_UINT(f.len_field, 4u);
    RFB_CHECK_EQ_UINT(f.flags, 1u);
    RFB_CHECK_EQ_UINT(f.param, 4u);

    RFB_CHECK(apple_wire_decode_msg14(apple_wire_msg14, 8, &f));
    RFB_CHECK_EQ_UINT(f.param, 0x0cu);

    RFB_CHECK(!apple_wire_decode_msg14(k_msg14_param4, 7, &f));
}

RFB_TEST(apple_wire_decode, kb_layout_us)
{
    apple_wire_kb_layout k;
    RFB_CHECK(apple_wire_decode_kb_layout(k_kb_layout, sizeof k_kb_layout, &k));
    RFB_CHECK_EQ_UINT(k.body_len, 0x1eu);
    RFB_CHECK_EQ_UINT(k.name_len, 0x16u);
    RFB_CHECK(memcmp(k.name, "com.apple.keylayout.US", 22) == 0);
}

RFB_TEST(apple_wire_decode, mvs_tables_and_rect)
{
    // Pad tables to claimed length for success path.
    uint8_t buf[4 + 0x81];
    memset(buf, 0, sizeof buf);
    memcpy(buf, k_mvs_tables_head, sizeof k_mvs_tables_head);
    // Fill two 64-byte QTs with distinct markers after n_tables byte.
    buf[4] = 2; // n_tables
    buf[5] = 0xaa;
    buf[5 + 63] = 0xab; // end of qt0
    buf[5 + 64] = 0xbb; // start of qt1
    buf[5 + 64 + 63] = 0xbc;

    apple_wire_mvs_tables t;
    RFB_CHECK(apple_wire_decode_mvs_tables(buf, sizeof buf, &t));
    RFB_CHECK_EQ_UINT(t.table_len, 0x81u);
    RFB_CHECK_EQ_UINT(t.n_tables, 2u);
    RFB_CHECK(t.qt0 != NULL);
    RFB_CHECK(t.qt1 != NULL);
    RFB_CHECK_EQ_UINT(t.qt0[0], 0xaau);
    RFB_CHECK_EQ_UINT(t.qt0[63], 0xabu);
    RFB_CHECK_EQ_UINT(t.qt1[0], 0xbbu);
    RFB_CHECK_EQ_UINT(t.qt1[63], 0xbcu);

    apple_wire_mvs_rect r;
    RFB_CHECK(apple_wire_decode_mvs_rect_data(k_mvs_rect, sizeof k_mvs_rect, &r));
    RFB_CHECK_EQ_UINT(r.data_len, 0x0fu);
    RFB_CHECK_EQ_UINT(r.data[0], 0x00u);
    RFB_CHECK_EQ_UINT(r.data[14], 0xb4u);

    apple_wire_mvs_rect_hdr h;
    RFB_CHECK(apple_wire_decode_mvs_rect_hdr(r.data, r.data_len, &h));
    RFB_CHECK_EQ_UINT(h.type, 0u);
    RFB_CHECK_EQ_UINT(h.normal_count, 3u);
    RFB_CHECK_EQ_UINT(h.large_count, 5u);
    RFB_CHECK_EQ_UINT(h.image_buffer_offset, 11u);
    RFB_CHECK(h.is_low_quality_pair);
    RFB_CHECK(!h.is_high_quality_pair);
    RFB_CHECK_EQ_UINT(h.bitstream_len, 5u);
    RFB_CHECK(h.bitstream == r.data + 6u);
    RFB_CHECK_EQ_UINT(h.image_buffer_len, 4u);
    RFB_CHECK(h.image_buffer == r.data + 11u);

    apple_wire_mvs_command_stats stats;
    RFB_CHECK(apple_wire_validate_mvs_partial_commands(&h, 12288u, &stats));
    RFB_CHECK_EQ_UINT(stats.tiles, 12288u);
    RFB_CHECK_EQ_UINT(stats.records, 2u);
    RFB_CHECK_EQ_UINT(stats.command_tiles[4], 1u);
    RFB_CHECK_EQ_UINT(stats.command_tiles[1], 12287u);
    RFB_CHECK_EQ_UINT(stats.marker_end_bits, 37u);
    RFB_CHECK_EQ_UINT(stats.padding_bits, 3u);

    // Self-consistent high-quality type-0 header with image data at byte 6.
    static const uint8_t k_colour_hq_head[] = {0x00, 0x0f, 0x19, 0x00,
                                               0x00, 0x06, 0x00};
    RFB_CHECK(apple_wire_decode_mvs_rect_hdr(k_colour_hq_head,
                                             sizeof k_colour_hq_head, &h));
    RFB_CHECK_EQ_UINT(h.normal_count, 15u);
    RFB_CHECK_EQ_UINT(h.large_count, 25u);
    RFB_CHECK_EQ_UINT(h.image_buffer_offset, 6u);
    RFB_CHECK(h.is_high_quality_pair);
    RFB_CHECK(!h.is_low_quality_pair);
    RFB_CHECK_EQ_UINT(h.bitstream_len, 0u);
}

RFB_TEST(apple_wire_decode, mvs_rect_header_fresh_low_origins)
{
    uint8_t body_a[1496];
    uint8_t body_b[1435];
    memset(body_a, 0, sizeof body_a);
    memset(body_b, 0, sizeof body_b);
    const uint8_t head_a[] = {0x00u, 0x03u, 0x05u, 0x00u,
                              0x05u, 0xd7u, 0x5fu, 0xe9u};
    const uint8_t head_b[] = {0x00u, 0x03u, 0x05u, 0x00u,
                              0x05u, 0x9au, 0x5fu, 0xe9u};
    memcpy(body_a, head_a, sizeof head_a);
    memcpy(body_b, head_b, sizeof head_b);
    apple_wire_mvs_rect_hdr h;
    RFB_CHECK(apple_wire_decode_mvs_rect_hdr(body_a, sizeof body_a, &h));
    RFB_CHECK_EQ_UINT(h.image_buffer_offset, 1495u);
    RFB_CHECK_EQ_UINT(h.bitstream_len, 1489u);
    RFB_CHECK(h.bitstream == body_a + 6u);
    RFB_CHECK_EQ_UINT(h.bitstream[0], 0x5fu);

    RFB_CHECK(apple_wire_decode_mvs_rect_hdr(body_b, sizeof body_b, &h));
    RFB_CHECK_EQ_UINT(h.image_buffer_offset, 1434u);
    RFB_CHECK(h.bitstream == body_b + 6u);
}

RFB_TEST(apple_wire_decode, mvs_rect_header_rejects_short_and_unknown_type)
{
    const uint8_t short_body[] = {0x00u, 0x03u, 0x05u, 0x00u, 0x05u};
    const uint8_t type_one[] = {0x01u, 0x03u, 0x05u, 0x00u, 0x00u, 0x00u};
    apple_wire_mvs_rect_hdr h;
    RFB_CHECK(!apple_wire_decode_mvs_rect_hdr(short_body, sizeof short_body,
                                               &h));
    RFB_CHECK(!apple_wire_decode_mvs_rect_hdr(type_one, sizeof type_one, &h));

    const uint8_t offset_too_small[] = {0x00u, 0x03u, 0x05u,
                                        0x00u, 0x00u, 0x05u};
    const uint8_t offset_too_large[] = {0x00u, 0x03u, 0x05u,
                                        0x00u, 0x00u, 0x07u};
    RFB_CHECK(!apple_wire_decode_mvs_rect_hdr(offset_too_small,
                                               sizeof offset_too_small, &h));
    RFB_CHECK(!apple_wire_decode_mvs_rect_hdr(offset_too_large,
                                               sizeof offset_too_large, &h));
}

RFB_TEST(apple_wire_decode, mvs_partial_commands_reject_bad_endpoint)
{
    uint8_t body[] = {0x00u, 0x03u, 0x05u, 0x00u, 0x00u, 0x0bu,
                      0x41u, 0xffu, 0x72u, 0xfbu, 0x68u,
                      0x00u, 0x20u, 0x81u, 0xb4u};
    apple_wire_mvs_rect_hdr h;
    apple_wire_mvs_command_stats stats;
    RFB_CHECK(apple_wire_decode_mvs_rect_hdr(body, sizeof body, &h));
    RFB_CHECK(!apple_wire_validate_mvs_partial_commands(&h, 12287u, &stats));

    body[10] ^= 0x20u; // corrupt the unaligned 'm' marker
    RFB_CHECK(apple_wire_decode_mvs_rect_hdr(body, sizeof body, &h));
    RFB_CHECK(!apple_wire_validate_mvs_partial_commands(&h, 12288u, &stats));
    mvs_test_walk_result walked;
    memset(&walked, 0, sizeof walked);
    RFB_CHECK(!apple_wire_walk_mvs_partial_commands(
        &h, 12288u, mvs_test_record_command, &walked, &stats));
    RFB_CHECK_EQ_UINT(walked.calls, 0u);
    body[10] ^= 0x20u;

    body[10] ^= 0x01u; // non-zero pad after a valid marker
    RFB_CHECK(apple_wire_decode_mvs_rect_hdr(body, sizeof body, &h));
    RFB_CHECK(!apple_wire_validate_mvs_partial_commands(&h, 12288u, &stats));
}

RFB_TEST(apple_wire_decode, mvs_repeat_terminal_group_uses_all_eight_bits)
{
    static const struct {
        uint8_t group2;
        uint32_t repeat;
    } cases[] = {
        {0x7fu, 2097167u},
        {0x80u, 2113551u},
        {0xffu, 4194319u},
    };

    for (size_t i = 0u; i < sizeof cases / sizeof cases[0]; i++) {
        uint8_t plane[8];
        const size_t plane_len = mvs_test_extended_repeat_plane(
            plane, sizeof plane, 0xffu, 0xffu, cases[i].group2);
        apple_wire_mvs_rect_hdr hdr;
        memset(&hdr, 0, sizeof hdr);
        hdr.type = 0u;
        hdr.bitstream = plane;
        hdr.bitstream_len = plane_len;

        mvs_test_walk_result walked;
        memset(&walked, 0, sizeof walked);
        apple_wire_mvs_command_stats stats;
        RFB_CHECK(apple_wire_walk_mvs_partial_commands(
            &hdr, cases[i].repeat + 1u, mvs_test_record_command, &walked,
            &stats));
        RFB_CHECK_EQ_UINT(walked.calls, 1u);
        RFB_CHECK_EQ_UINT(walked.record.command, 5u);
        RFB_CHECK_EQ_UINT(walked.record.first_tile, 0u);
        RFB_CHECK_EQ_UINT(walked.record.repeat, cases[i].repeat);
        RFB_CHECK_EQ_UINT(walked.record.run, cases[i].repeat + 1u);
        RFB_CHECK_EQ_UINT(walked.record.command_start_bits, 1u);
        RFB_CHECK_EQ_UINT(walked.record.command_end_bits, 33u);
        RFB_CHECK_EQ_UINT(stats.tiles, cases[i].repeat + 1u);
    }
}

RFB_TEST(apple_wire_decode, mvs_repeat_maximum_rejects_grid_overrun)
{
    uint8_t plane[8];
    const size_t plane_len = mvs_test_extended_repeat_plane(
        plane, sizeof plane, 0xffu, 0xffu, 0xffu);
    apple_wire_mvs_rect_hdr hdr;
    memset(&hdr, 0, sizeof hdr);
    hdr.type = 0u;
    hdr.bitstream = plane;
    hdr.bitstream_len = plane_len;

    apple_wire_mvs_command_stats stats;
    RFB_CHECK(!apple_wire_walk_mvs_partial_commands(
        &hdr, 4194319u, NULL, NULL, &stats));
    RFB_CHECK_EQ_UINT(stats.tiles, 0u);
    RFB_CHECK_EQ_UINT(stats.records, 0u);
}

RFB_TEST(apple_wire_decode, mvs_repeat_forms_and_truncations)
{
    static const struct {
        uint8_t bytes[6];
        size_t len;
        uint32_t repeat;
    } valid[] = {
        {{0x03u, 0x68u}, 2u, 0u},
        {{0x08u, 0x36u, 0x80u}, 3u, 1u},
        {{0x0fu, 0x36u, 0x80u}, 3u, 15u},
        {{0x0fu, 0x80u, 0x36u, 0x80u}, 4u, 16u},
        {{0x0fu, 0xbfu, 0xb6u, 0x80u}, 4u, 143u},
        {{0x0fu, 0xc0u, 0x00u, 0x36u, 0x80u}, 5u, 16u},
        {{0x0fu, 0xc0u, 0x00u, 0xb6u, 0x80u}, 5u, 144u},
        {{0x0fu, 0xffu, 0xbfu, 0xb6u, 0x80u}, 5u, 16399u},
        {{0x0fu, 0xc0u, 0x40u, 0x00u, 0x36u, 0x80u}, 6u, 16u},
        {{0x0fu, 0xc0u, 0x40u, 0x3fu, 0xb6u, 0x80u}, 6u, 2080784u},
        {{0x0fu, 0xc0u, 0x40u, 0x40u, 0x36u, 0x80u}, 6u, 2097168u},
        {{0x0fu, 0xc0u, 0x40u, 0x7fu, 0xb6u, 0x80u}, 6u, 4177936u},
        {{0x0fu, 0xffu, 0xffu, 0xffu, 0xb6u, 0x80u}, 6u, 4194319u},
    };
    for (size_t i = 0u; i < sizeof valid / sizeof valid[0]; i++) {
        apple_wire_mvs_rect_hdr hdr;
        memset(&hdr, 0, sizeof hdr);
        hdr.type = 0u;
        hdr.bitstream = valid[i].bytes;
        hdr.bitstream_len = valid[i].len;
        mvs_test_walk_result walked;
        memset(&walked, 0, sizeof walked);
        RFB_CHECK(apple_wire_walk_mvs_partial_commands(
            &hdr, valid[i].repeat + 1u, mvs_test_record_command, &walked,
            NULL));
        RFB_CHECK_EQ_UINT(walked.calls, 1u);
        RFB_CHECK_EQ_UINT(walked.record.command, 0u);
        RFB_CHECK_EQ_UINT(walked.record.repeat, valid[i].repeat);
        RFB_CHECK_EQ_UINT(walked.record.run, valid[i].repeat + 1u);
        if (valid[i].repeat != 0u) {
            RFB_CHECK(!apple_wire_walk_mvs_partial_commands(
                &hdr, valid[i].repeat, NULL, NULL, NULL));
        }
    }

    static const struct {
        uint8_t bytes[4];
        size_t len;
        uint32_t expected_tiles;
    } truncated[] = {
        {{0x00u}, 1u, 2u},
        {{0x0fu}, 1u, 1u},
        {{0x0fu, 0xc0u}, 2u, 1u},
        {{0x0fu, 0xc0u, 0x40u}, 3u, 1u},
        {{0x0fu, 0xc0u, 0x40u, 0x40u}, 4u, 1u},
    };
    for (size_t i = 0u; i < sizeof truncated / sizeof truncated[0]; i++) {
        apple_wire_mvs_rect_hdr hdr;
        memset(&hdr, 0, sizeof hdr);
        hdr.type = 0u;
        hdr.bitstream = truncated[i].bytes;
        hdr.bitstream_len = truncated[i].len;
        RFB_CHECK(!apple_wire_walk_mvs_partial_commands(
            &hdr, truncated[i].expected_tiles, NULL, NULL, NULL));
    }

    static const uint8_t cumulative[] = {0x00u, 0x83u, 0x68u};
    apple_wire_mvs_rect_hdr hdr;
    memset(&hdr, 0, sizeof hdr);
    hdr.type = 0u;
    hdr.bitstream = cumulative;
    hdr.bitstream_len = sizeof cumulative;
    RFB_CHECK(apple_wire_walk_mvs_partial_commands(&hdr, 3u, NULL, NULL,
                                                   NULL));
    RFB_CHECK(!apple_wire_walk_mvs_partial_commands(&hdr, 2u, NULL, NULL,
                                                    NULL));
}

RFB_TEST(apple_wire_decode, mvs_image_suffix_accepts_every_pad_width)
{
    for (unsigned pad = 0u; pad < 8u; pad++) {
        uint8_t plane[4];
        const unsigned payload_bits = (8u - pad) & 7u;
        const size_t plane_len =
            mvs_test_image_plane(plane, sizeof plane, payload_bits);
        apple_wire_mvs_rect_hdr hdr;
        memset(&hdr, 0, sizeof hdr);
        hdr.type = 0u;
        hdr.image_buffer = plane;
        hdr.image_buffer_len = plane_len;

        apple_wire_mvs_image_stats stats;
        RFB_CHECK(apple_wire_validate_mvs_partial_image_suffix(&hdr, &stats));
        RFB_CHECK_EQ_UINT(stats.marker_start_bits, payload_bits);
        RFB_CHECK_EQ_UINT(stats.marker_end_bits, payload_bits + 8u);
        RFB_CHECK_EQ_UINT(stats.padding_bits, pad);
    }
}

RFB_TEST(apple_wire_decode, mvs_image_suffix_rejects_false_endpoints)
{
    uint8_t valid[4];
    const size_t valid_len = mvs_test_image_plane(valid, sizeof valid, 3u);
    apple_wire_mvs_rect_hdr hdr;
    memset(&hdr, 0, sizeof hdr);
    hdr.type = 0u;
    hdr.image_buffer = valid;
    hdr.image_buffer_len = valid_len;

    apple_wire_mvs_image_stats stats;
    RFB_CHECK(apple_wire_validate_mvs_partial_image_suffix(&hdr, &stats));

    uint8_t bad[5];
    memcpy(bad, valid, valid_len);
    bad[valid_len - 1u] ^= 0x20u; // corrupt marker
    hdr.image_buffer = bad;
    RFB_CHECK(!apple_wire_validate_mvs_partial_image_suffix(&hdr, &stats));

    memcpy(bad, valid, valid_len);
    bad[valid_len - 1u] |= 0x01u; // non-zero pad
    RFB_CHECK(!apple_wire_validate_mvs_partial_image_suffix(&hdr, &stats));

    memcpy(bad, valid, valid_len);
    bad[valid_len] = 0u; // full trailing byte: suffix is no longer final
    hdr.image_buffer_len = valid_len + 1u;
    RFB_CHECK(!apple_wire_validate_mvs_partial_image_suffix(&hdr, &stats));

    static const uint8_t internal_marker[] = {0x6du, 0xa5u};
    hdr.image_buffer = internal_marker;
    hdr.image_buffer_len = sizeof internal_marker;
    RFB_CHECK(!apple_wire_validate_mvs_partial_image_suffix(&hdr, &stats));

    static const uint8_t wrong_word[] = {'m', 'v', 's'};
    hdr.image_buffer = wrong_word;
    hdr.image_buffer_len = sizeof wrong_word;
    RFB_CHECK(!apple_wire_validate_mvs_partial_image_suffix(&hdr, &stats));

    hdr.image_buffer = NULL;
    hdr.image_buffer_len = 0u;
    RFB_CHECK(!apple_wire_validate_mvs_partial_image_suffix(&hdr, &stats));
}

RFB_TEST(apple_wire_decode, mvs_tile_constants_and_grid)
{
    // Tile command identifiers, invalid sentinel, and fixed per-tile DCT geometry.
    RFB_CHECK_EQ_UINT(APPLE_MVS_TILE_WHITE, 0u);
    RFB_CHECK_EQ_UINT(APPLE_MVS_TILE_LAST_MATCH, 1u);
    RFB_CHECK_EQ_UINT(APPLE_MVS_TILE_UPPER_MATCH, 2u);
    RFB_CHECK_EQ_UINT(APPLE_MVS_TILE_BLACK_WHITE, 3u);
    RFB_CHECK_EQ_UINT(APPLE_MVS_TILE_TWO_COLOR, 4u);
    RFB_CHECK_EQ_UINT(APPLE_MVS_TILE_DCT, 5u);
    RFB_CHECK_EQ_UINT(APPLE_MVS_TILE_INVALID, 0xffu);
    RFB_CHECK_EQ_UINT(APPLE_MVS_MAX_LUMA_COEFFS, 64u);
    RFB_CHECK_EQ_UINT(APPLE_MVS_MAX_CB_COEFFS, 15u);
    RFB_CHECK_EQ_UINT(APPLE_MVS_MAX_CR_COEFFS, 20u);
    RFB_CHECK_EQ_UINT(APPLE_MVS_START_BYTE_LUMINOSITY, 3u);
    RFB_CHECK_EQ_UINT(APPLE_MVS_START_BYTE_CB, 67u);
    RFB_CHECK_EQ_UINT(APPLE_MVS_START_BYTE_CR, 82u);
    RFB_CHECK_EQ_UINT(APPLE_MVS_START_BYTE_HASH, 168u);

    uint32_t tx = 0, ty = 0, n = 0;
    apple_wire_mvs_tile_grid(1024, 768, &tx, &ty, &n);
    RFB_CHECK_EQ_UINT(tx, 128u);
    RFB_CHECK_EQ_UINT(ty, 96u);
    RFB_CHECK_EQ_UINT(n, 12288u);

    apple_wire_mvs_tile_grid(1, 1, &tx, &ty, &n);
    RFB_CHECK_EQ_UINT(tx, 1u);
    RFB_CHECK_EQ_UINT(ty, 1u);
    RFB_CHECK_EQ_UINT(n, 1u);

    RFB_CHECK(apple_wire_mvs_tile_grid_checked(UINT32_MAX, 1u, &tx, &ty,
                                               &n));
    RFB_CHECK_EQ_UINT(tx, 536870912u);
    RFB_CHECK_EQ_UINT(ty, 1u);
    RFB_CHECK_EQ_UINT(n, 536870912u);
    RFB_CHECK(!apple_wire_mvs_tile_grid_checked(UINT32_MAX, UINT32_MAX, &tx,
                                                &ty, &n));
    RFB_CHECK_EQ_UINT(tx, 0u);
    RFB_CHECK_EQ_UINT(ty, 0u);
    RFB_CHECK_EQ_UINT(n, 0u);
    RFB_CHECK(!apple_wire_mvs_tile_grid_checked(0u, 8u, &tx, &ty, &n));
}

RFB_TEST(apple_wire_decode, mvs_solid_black_sample_and_fill)
{
    apple_wire_mvs_rect r;
    RFB_CHECK(apple_wire_decode_mvs_rect_data(k_mvs_rect, sizeof k_mvs_rect, &r));
    RFB_CHECK(apple_wire_mvs_is_solid_black_sample(r.data, r.data_len));

    // Negative: wrong length
    RFB_CHECK(!apple_wire_mvs_is_solid_black_sample(r.data, r.data_len - 1u));
    // Negative: flipped byte
    uint8_t mut[15];
    memcpy(mut, r.data, 15);
    mut[7] ^= 0x01u;
    RFB_CHECK(!apple_wire_mvs_is_solid_black_sample(mut, 15));

    uint8_t fb[8 * 4 * 4]; // 8×4 RGBA
    memset(fb, 0x5a, sizeof fb);
    RFB_CHECK(apple_wire_mvs_fill_solid_black(fb, sizeof fb, 8, 4, 8 * 4));
    for (size_t i = 0; i < sizeof fb; i += 4u) {
        RFB_CHECK_EQ_UINT(fb[i], 0u);
        RFB_CHECK_EQ_UINT(fb[i + 1u], 0u);
        RFB_CHECK_EQ_UINT(fb[i + 2u], 0u);
        RFB_CHECK_EQ_UINT(fb[i + 3u], 255u);
    }
    // Bad stride
    RFB_CHECK(!apple_wire_mvs_fill_solid_black(fb, sizeof fb, 8, 4, 8));
    // Extreme dimensions and stride must fail without arithmetic wraparound.
    RFB_CHECK(!apple_wire_mvs_fill_solid_black(fb, sizeof fb, UINT32_MAX, 1u,
                                               SIZE_MAX));
}

RFB_TEST(apple_wire_decode, cfg21_scale)
{
    // cfg21 with scale 2.0 at body offset 40.
    static const uint8_t cfg[] = {
        0x21, 0x00, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
        0x00, 0x06, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x1a, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x02, 0xb0, 0x00,
        0x0c, 0x03, 0x90, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    apple_wire_cfg21 c;
    RFB_CHECK(apple_wire_decode_cfg21(cfg, sizeof cfg, &c));
    RFB_CHECK_EQ_UINT(c.body_len, 0x3eu);
    RFB_CHECK(c.has_scale);
    RFB_CHECK(c.scale > 1.9f && c.scale < 2.1f);
}

RFB_TEST(apple_wire_decode, cfg21_noncanonical_scale_preserves_ieee_value)
{
    uint8_t cfg[48];
    apple_wire_test_cfg21_scale(cfg, 0x3f000000u); // 0.5f

    apple_wire_cfg21 decoded;
    RFB_CHECK(apple_wire_decode_cfg21(cfg, sizeof cfg, &decoded));
    RFB_CHECK(decoded.has_scale);
    RFB_CHECK(decoded.scale > 0.49f && decoded.scale < 0.51f);
}

RFB_TEST(apple_wire_decode, typed_header)
{
    uint8_t msg[20];
    memset(msg, 0, sizeof msg);
    msg[3] = 1;
    msg[14] = 0x04;
    msg[15] = 0x51;
    msg[16] = 0xaa;
    uint32_t t = 0;
    const uint8_t *p = NULL;
    size_t pl = 0;
    RFB_CHECK(apple_wire_typed_header(msg, sizeof msg, &t, &p, &pl));
    RFB_CHECK_EQ_UINT(t, 0x0451u);
    RFB_CHECK_EQ_UINT(pl, 4u);
    RFB_CHECK_EQ_UINT(p[0], 0xaau);
}

RFB_TEST(apple_wire_decode, fixed_field_decoders_fail_closed)
{
    uint8_t typed[20];
    memset(typed, 0, sizeof typed);
    typed[3] = 1u;
    typed[15] = 0x21u;
    RFB_CHECK(apple_wire_typed_header(typed, sizeof typed, NULL, NULL, NULL));

    uint32_t type = 7u;
    const uint8_t *payload = typed;
    size_t payload_len = 7u;
    RFB_CHECK(!apple_wire_typed_header(NULL, sizeof typed, &type, &payload,
                                       &payload_len));
    RFB_CHECK_EQ_UINT(type, 0u);
    RFB_CHECK(payload == NULL);
    RFB_CHECK_EQ_UINT(payload_len, 0u);
    RFB_CHECK(!apple_wire_typed_header(typed, 15u, NULL, NULL, NULL));
    for (size_t word = 0u; word < 3u; word++) {
        uint8_t bad[sizeof typed];
        memcpy(bad, typed, sizeof bad);
        bad[word * 4u] = 1u;
        RFB_CHECK(!apple_wire_typed_header(bad, sizeof bad, NULL, NULL, NULL));
    }

    apple_wire_msg14_fields msg14;
    memset(&msg14, 0xa5, sizeof msg14);
    RFB_CHECK(!apple_wire_decode_msg14(k_msg14_param4,
                                       sizeof k_msg14_param4, NULL));
    RFB_CHECK(!apple_wire_decode_msg14(NULL, sizeof k_msg14_param4, &msg14));
    RFB_CHECK_EQ_UINT(msg14.type, 0u);
    uint8_t wrong_msg14[sizeof k_msg14_param4];
    memcpy(wrong_msg14, k_msg14_param4, sizeof wrong_msg14);
    wrong_msg14[0] = 0x13u;
    RFB_CHECK(!apple_wire_decode_msg14(wrong_msg14, sizeof wrong_msg14,
                                       &msg14));

    apple_wire_kb_layout kb;
    memset(&kb, 0xa5, sizeof kb);
    RFB_CHECK(!apple_wire_decode_kb_layout(k_kb_layout, sizeof k_kb_layout,
                                           NULL));
    RFB_CHECK(!apple_wire_decode_kb_layout(NULL, sizeof k_kb_layout, &kb));
    RFB_CHECK(kb.name == NULL);
    RFB_CHECK(!apple_wire_decode_kb_layout(k_kb_layout, 11u, &kb));
    uint8_t long_name[12];
    memset(long_name, 0, sizeof long_name);
    long_name[9] = 3u;
    RFB_CHECK(!apple_wire_decode_kb_layout(long_name, sizeof long_name, &kb));
}

RFB_TEST(apple_wire_decode, mvs_envelope_decoders_cover_optional_tables)
{
    uint8_t tables[4u + 65u];
    memset(tables, 0, sizeof tables);
    apple_wire_mvs_tables decoded_tables;
    RFB_CHECK(!apple_wire_decode_mvs_tables(tables, sizeof tables, NULL));
    RFB_CHECK(!apple_wire_decode_mvs_tables(NULL, sizeof tables,
                                            &decoded_tables));
    RFB_CHECK(decoded_tables.tables == NULL);
    RFB_CHECK(!apple_wire_decode_mvs_tables(tables, 3u, &decoded_tables));
    tables[3] = 1u;
    RFB_CHECK(!apple_wire_decode_mvs_tables(tables, 4u, &decoded_tables));

    memset(tables, 0, sizeof tables);
    RFB_CHECK(apple_wire_decode_mvs_tables(tables, 4u, &decoded_tables));
    RFB_CHECK_EQ_UINT(decoded_tables.n_tables, 0u);
    RFB_CHECK(decoded_tables.qt0 == NULL);
    tables[3] = 1u;
    tables[4] = 0u;
    RFB_CHECK(apple_wire_decode_mvs_tables(tables, 5u, &decoded_tables));
    RFB_CHECK_EQ_UINT(decoded_tables.n_tables, 0u);
    RFB_CHECK(decoded_tables.qt0 == NULL);
    tables[3] = 65u;
    tables[4] = 1u;
    RFB_CHECK(apple_wire_decode_mvs_tables(tables, sizeof tables,
                                           &decoded_tables));
    RFB_CHECK(decoded_tables.qt0 != NULL);
    RFB_CHECK(decoded_tables.qt1 == NULL);

    apple_wire_mvs_rect rect;
    RFB_CHECK(!apple_wire_decode_mvs_rect_data(k_mvs_rect, sizeof k_mvs_rect,
                                               NULL));
    RFB_CHECK(!apple_wire_decode_mvs_rect_data(NULL, sizeof k_mvs_rect,
                                               &rect));
    RFB_CHECK(rect.data == NULL);
    RFB_CHECK(!apple_wire_decode_mvs_rect_data(k_mvs_rect, 3u, &rect));
    uint8_t oversized[] = {0u, 0u, 0u, 2u, 0u};
    RFB_CHECK(!apple_wire_decode_mvs_rect_data(oversized, sizeof oversized,
                                               &rect));

    apple_wire_mvs_rect_hdr hdr;
    RFB_CHECK(!apple_wire_decode_mvs_rect_hdr(k_mvs_rect + 4u, 15u, NULL));
    RFB_CHECK(!apple_wire_decode_mvs_rect_hdr(NULL, 15u, &hdr));
    RFB_CHECK(hdr.bitstream == NULL);
}

RFB_TEST(apple_wire_decode, mvs_walk_rejects_invalid_inputs_and_visitor)
{
    static const uint8_t one_tile[] = {0x03u, 0x68u};
    apple_wire_mvs_rect_hdr hdr;
    memset(&hdr, 0, sizeof hdr);
    hdr.type = 0u;
    hdr.bitstream = one_tile;
    hdr.bitstream_len = sizeof one_tile;

    apple_wire_mvs_command_stats stats;
    memset(&stats, 0xa5, sizeof stats);
    RFB_CHECK(!apple_wire_walk_mvs_partial_commands(NULL, 1u, NULL, NULL,
                                                    &stats));
    RFB_CHECK_EQ_UINT(stats.tiles, 0u);
    hdr.type = 1u;
    RFB_CHECK(!apple_wire_validate_mvs_partial_commands(&hdr, 1u, NULL));
    hdr.type = 0u;
    hdr.bitstream = NULL;
    RFB_CHECK(!apple_wire_validate_mvs_partial_commands(&hdr, 1u, NULL));
    hdr.bitstream = one_tile;
    hdr.bitstream_len = 0u;
    RFB_CHECK(!apple_wire_validate_mvs_partial_commands(&hdr, 1u, NULL));
    hdr.bitstream_len = sizeof one_tile;
    RFB_CHECK(!apple_wire_validate_mvs_partial_commands(&hdr, 0u, NULL));

    static const uint8_t bad_leading[] = {0x80u};
    hdr.bitstream = bad_leading;
    hdr.bitstream_len = sizeof bad_leading;
    RFB_CHECK(!apple_wire_validate_mvs_partial_commands(&hdr, 1u, NULL));

    static const uint8_t trailing_byte[] = {0x03u, 0x68u, 0x00u};
    hdr.bitstream = trailing_byte;
    hdr.bitstream_len = sizeof trailing_byte;
    RFB_CHECK(!apple_wire_validate_mvs_partial_commands(&hdr, 1u, NULL));

    hdr.bitstream = one_tile;
    hdr.bitstream_len = sizeof one_tile;
    mvs_test_walk_result walked;
    memset(&walked, 0, sizeof walked);
    memset(&stats, 0xa5, sizeof stats);
    RFB_CHECK(!apple_wire_walk_mvs_partial_commands(
        &hdr, 1u, mvs_test_reject_command, &walked, &stats));
    RFB_CHECK_EQ_UINT(walked.calls, 1u);
    RFB_CHECK_EQ_UINT(walked.record.run, 1u);
    RFB_CHECK_EQ_UINT(stats.tiles, 0u);
}

RFB_TEST(apple_wire_decode, mvs_image_and_buffer_guards)
{
    static const uint8_t marker[] = {0x6du};
    apple_wire_mvs_rect_hdr hdr;
    memset(&hdr, 0, sizeof hdr);
    hdr.type = 0u;
    hdr.image_buffer = marker;
    hdr.image_buffer_len = sizeof marker;
    RFB_CHECK(apple_wire_validate_mvs_partial_image_suffix(&hdr, NULL));
    RFB_CHECK(!apple_wire_validate_mvs_partial_image_suffix(NULL, NULL));
    hdr.type = 1u;
    RFB_CHECK(!apple_wire_validate_mvs_partial_image_suffix(&hdr, NULL));
    hdr.type = 0u;
    hdr.image_buffer = NULL;
    RFB_CHECK(!apple_wire_validate_mvs_partial_image_suffix(&hdr, NULL));
    hdr.image_buffer = marker;
    hdr.image_buffer_len = 0u;
    RFB_CHECK(!apple_wire_validate_mvs_partial_image_suffix(&hdr, NULL));
    hdr.image_buffer_len = SIZE_MAX;
    RFB_CHECK(!apple_wire_validate_mvs_partial_image_suffix(&hdr, NULL));

    RFB_CHECK(!apple_wire_mvs_is_solid_black_sample(NULL, 15u));
    uint8_t rgba[32];
    RFB_CHECK(!apple_wire_mvs_fill_solid_black(NULL, sizeof rgba, 8u, 1u,
                                               sizeof rgba));
    RFB_CHECK(!apple_wire_mvs_fill_solid_black(rgba, sizeof rgba, 0u, 1u,
                                               sizeof rgba));
    RFB_CHECK(!apple_wire_mvs_fill_solid_black(rgba, sizeof rgba, 8u, 0u,
                                               sizeof rgba));
    RFB_CHECK(!apple_wire_mvs_fill_solid_black(rgba, sizeof rgba - 1u, 8u,
                                               1u, sizeof rgba));

    RFB_CHECK(apple_wire_mvs_tile_grid_checked(8u, 8u, NULL, NULL, NULL));
    uint32_t tx = 9u;
    RFB_CHECK(!apple_wire_mvs_tile_grid_checked(8u, 0u, &tx, NULL, NULL));
    RFB_CHECK_EQ_UINT(tx, 0u);
}

RFB_TEST(apple_wire_decode, cfg21_rejects_envelope_and_scale_edges)
{
    uint8_t cfg[48];
    apple_wire_cfg21 decoded;
    apple_wire_test_cfg21_scale(cfg, 0x3f800000u);
    RFB_CHECK(!apple_wire_decode_cfg21(cfg, sizeof cfg, NULL));
    memset(&decoded, 0xa5, sizeof decoded);
    RFB_CHECK(!apple_wire_decode_cfg21(NULL, sizeof cfg, &decoded));
    RFB_CHECK(!decoded.has_scale);
    RFB_CHECK(!apple_wire_decode_cfg21(cfg, 3u, &decoded));
    cfg[0] = 0x20u;
    RFB_CHECK(!apple_wire_decode_cfg21(cfg, sizeof cfg, &decoded));
    apple_wire_test_cfg21_scale(cfg, 0x3f800000u);
    cfg[3] = 45u;
    RFB_CHECK(!apple_wire_decode_cfg21(cfg, sizeof cfg, &decoded));

    apple_wire_test_cfg21_scale(cfg, 0x3f800000u);
    cfg[3] = 43u;
    RFB_CHECK(apple_wire_decode_cfg21(cfg, sizeof cfg, &decoded));
    RFB_CHECK(!decoded.has_scale);

    static const uint32_t rejected[] = {
        0x00000000u, // zero
        0xbf800000u, // -1.0f
        0x41800000u, // 16.0f
        0x7f800000u, // positive infinity
        0x7fc00000u, // quiet NaN
    };
    for (size_t i = 0u; i < sizeof rejected / sizeof rejected[0]; i++) {
        apple_wire_test_cfg21_scale(cfg, rejected[i]);
        RFB_CHECK(apple_wire_decode_cfg21(cfg, sizeof cfg, &decoded));
        RFB_CHECK(!decoded.has_scale);
    }
}
