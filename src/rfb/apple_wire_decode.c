// SPDX-License-Identifier: Apache-2.0
//
// Pure Apple wire field decoders, including MultiVariant (0x03f3).

#include "farsee/apple_wire_decode.h"

#include "farsee/apple_mvs_bits.h"
#include "farsee/checked.h"

#include <string.h>

// Solid-black 0x03f3 rect payload after u32be data_len.
static const uint8_t k_mvs_solid_black_payload[15] = {
    0x00, 0x03, 0x05, 0x00, 0x00, 0x0b, 0x41, 0xff,
    0x72, 0xfb, 0x68, 0x00, 0x20, 0x81, 0xb4};

// be32 returns the numeric IEEE-754 bit pattern. Assign that pattern directly;
// byte-swapping it again would corrupt every value except the fast paths that
// happened to return before the conversion.
static float float_from_be_bits(uint32_t bits)
{
    union {
        uint32_t u;
        float f;
    } value;
    value.u = bits;
    return value.f;
}

static uint16_t be16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static uint32_t be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

bool apple_wire_typed_header(const uint8_t *msg, size_t n, uint32_t *out_type,
                             const uint8_t **out_payload, size_t *out_plen)
{
    if (out_type != NULL) {
        *out_type = 0u;
    }
    if (out_payload != NULL) {
        *out_payload = NULL;
    }
    if (out_plen != NULL) {
        *out_plen = 0u;
    }
    if (msg == NULL || n < 16u) {
        return false;
    }
    if (be32(msg) != 1u || be32(msg + 4) != 0u || be32(msg + 8) != 0u) {
        return false;
    }
    if (out_type != NULL) {
        *out_type = be32(msg + 12);
    }
    if (out_payload != NULL) {
        *out_payload = msg + 16;
    }
    if (out_plen != NULL) {
        *out_plen = n - 16u;
    }
    return true;
}

bool apple_wire_decode_msg14(const uint8_t *msg, size_t n,
                             apple_wire_msg14_fields *out)
{
    if (out == NULL) {
        return false;
    }
    memset(out, 0, sizeof *out);
    if (msg == NULL || n != 8u || msg[0] != 0x14u) {
        return false;
    }
    out->type = msg[0];
    // Byte 1 is ignored; raw u16be fields start at bytes 2, 4, and 6.
    out->len_field = be16(msg + 2); // raw u16be value from bytes 2..3
    out->flags = be16(msg + 4);     // raw u16be value from bytes 4..5
    out->param = be16(msg + 6);     // raw u16be value from bytes 6..7
    return true;
}

bool apple_wire_decode_kb_layout(const uint8_t *payload, size_t n,
                                 apple_wire_kb_layout *out)
{
    if (out == NULL) {
        return false;
    }
    memset(out, 0, sizeof *out);
    if (payload == NULL || n < 12u) {
        return false;
    }
    out->body_len = be16(payload);
    out->unk = be16(payload + 2);
    // payload+4..7 are not interpreted by this parser.
    out->name_len = be16(payload + 8);
    if (10u + (size_t)out->name_len > n) {
        return false;
    }
    out->name = payload + 10;
    return true;
}

bool apple_wire_decode_mvs_tables(const uint8_t *payload, size_t n,
                                  apple_wire_mvs_tables *out)
{
    if (out == NULL) {
        return false;
    }
    memset(out, 0, sizeof *out);
    if (payload == NULL || n < 4u) {
        return false;
    }
    out->table_len = be32(payload);
    if ((size_t)out->table_len > n - 4u) {
        return false;
    }
    out->tables = payload + 4;
    if (out->table_len >= 1u) {
        out->n_tables = out->tables[0];
    }
    // Layout: n_tables | QT0[64] | QT1[64] | …  (RASTER order: index =
    // vertical frequency * 8 + horizontal frequency)
    if (out->n_tables >= 1u && out->table_len >= 1u + 64u) {
        out->qt0 = out->tables + 1;
    }
    if (out->n_tables >= 2u && out->table_len >= 1u + 128u) {
        out->qt1 = out->tables + 1u + 64u;
    }
    return true;
}

bool apple_wire_decode_mvs_rect_data(const uint8_t *data, size_t n,
                                     apple_wire_mvs_rect *out)
{
    if (out == NULL) {
        return false;
    }
    memset(out, 0, sizeof *out);
    if (data == NULL || n < 4u) {
        return false;
    }
    out->data_len = be32(data);
    if ((size_t)out->data_len > n - 4u) {
        return false;
    }
    // The parser exposes data_len bytes and does not interpret trailing bytes.
    out->data = data + 4;
    return true;
}

bool apple_wire_decode_mvs_rect_hdr(const uint8_t *payload, size_t n,
                                    apple_wire_mvs_rect_hdr *out)
{
    if (out == NULL) {
        return false;
    }
    memset(out, 0, sizeof *out);
    if (payload == NULL || n < 6u) {
        return false;
    }
    // Partial-update type 0. Types with different envelopes must not
    // be misparsed as this header or allowed to shift the command bitstream.
    out->type = payload[0];
    if (out->type != 0u) {
        memset(out, 0, sizeof *out);
        return false;
    }
    out->normal_count = payload[1];
    out->large_count = payload[2];
    out->image_buffer_offset = ((uint32_t)payload[3] << 16) |
                               ((uint32_t)payload[4] << 8) |
                               (uint32_t)payload[5];
    if (out->image_buffer_offset < 6u ||
        (size_t)out->image_buffer_offset > n) {
        memset(out, 0, sizeof *out);
        return false;
    }
    out->bitstream = payload + 6;
    out->bitstream_len = (size_t)out->image_buffer_offset - 6u;
    out->image_buffer = payload + out->image_buffer_offset;
    out->image_buffer_len = n - (size_t)out->image_buffer_offset;
    out->is_low_quality_pair =
        (out->normal_count == 3u && out->large_count == 5u);
    out->is_high_quality_pair =
        (out->normal_count == 15u && out->large_count == 25u);
    return true;
}

static bool mvs_partial_repeat_get(apple_mvs_bit_reader *br,
                                   uint32_t *out_repeat)
{
    uint32_t lead = 0u;
    if (!apple_mvs_bit_reader_get(br, 1u, &lead)) {
        return false;
    }
    if (lead == 0u) {
        *out_repeat = 0u;
        return true;
    }

    uint32_t nibble = 0u;
    if (!apple_mvs_bit_reader_get(br, 4u, &nibble)) {
        return false;
    }
    if (nibble != 15u) {
        *out_repeat = nibble + 1u;
        return true;
    }

    uint32_t group0 = 0u;
    if (!apple_mvs_bit_reader_get(br, 8u, &group0)) {
        return false;
    }
    if ((group0 & 0x80u) == 0u) {
        *out_repeat = group0 + 16u;
        return true;
    }

    uint32_t group1 = 0u;
    if (!apple_mvs_bit_reader_get(br, 8u, &group1)) {
        return false;
    }
    if ((group1 & 0x80u) == 0u) {
        *out_repeat = 16u + (group0 & 0x7fu) +
                      ((group1 & 0x7fu) << 7u);
        return true;
    }

    uint32_t group2 = 0u;
    if (!apple_mvs_bit_reader_get(br, 8u, &group2)) {
        return false;
    }
    *out_repeat = 16u + (group0 & 0x7fu) +
                  ((group1 & 0x7fu) << 7u) + (group2 << 14u);
    return true;
}

static bool mvs_walk_partial_commands_pass(
    const apple_wire_mvs_rect_hdr *hdr, uint32_t expected_tiles,
    apple_wire_mvs_command_visitor visitor, void *opaque,
    apple_wire_mvs_command_stats *out)
{
    if (out != NULL) {
        memset(out, 0, sizeof *out);
    }
    if (hdr == NULL || hdr->type != 0u || hdr->bitstream == NULL ||
        hdr->bitstream_len == 0u || expected_tiles == 0u) {
        return false;
    }

    apple_mvs_bit_reader br;
    apple_mvs_bit_reader_init(&br, hdr->bitstream, hdr->bitstream_len);
    apple_wire_mvs_command_stats stats;
    memset(&stats, 0, sizeof stats);

    uint32_t leading = 0u;
    if (!apple_mvs_bit_reader_get(&br, 1u, &leading) || leading != 0u) {
        return false;
    }

    while (stats.tiles < expected_tiles) {
        const size_t command_start_bits =
            apple_mvs_bit_reader_bits_consumed(&br);
        uint32_t command = 0u;
        uint32_t repeat = 0u;
        if (!apple_mvs_bit_reader_get(&br, 3u, &command) ||
            !mvs_partial_repeat_get(&br, &repeat)) {
            return false;
        }
        const uint32_t run = repeat + 1u;
        if (run == 0u || run > expected_tiles - stats.tiles ||
            stats.command_tiles[command] > UINT32_MAX - run ||
            stats.records == UINT32_MAX) {
            return false;
        }
        apple_wire_mvs_command_record record;
        record.command = (uint8_t)command;
        record.first_tile = stats.tiles;
        record.repeat = repeat;
        record.run = run;
        record.command_start_bits = command_start_bits;
        record.command_end_bits = apple_mvs_bit_reader_bits_consumed(&br);
        if (visitor != NULL && !visitor(opaque, &record)) {
            return false;
        }
        stats.tiles += run;
        stats.command_tiles[command] += run;
        stats.records++;
    }

    uint32_t marker = 0u;
    if (!apple_mvs_bit_reader_get(&br, 8u, &marker) || marker != 0x6du) {
        return false;
    }
    stats.marker_end_bits = apple_mvs_bit_reader_bits_consumed(&br);
    const size_t remainder = stats.marker_end_bits & 7u;
    const size_t expected_padding = (remainder == 0u) ? 0u : 8u - remainder;
    if (apple_mvs_bit_reader_bits_left(&br) != expected_padding) {
        return false;
    }
    for (size_t i = 0u; i < expected_padding; i++) {
        uint32_t pad = 0u;
        if (!apple_mvs_bit_reader_get(&br, 1u, &pad) || pad != 0u) {
            return false;
        }
    }
    stats.padding_bits = expected_padding;
    if (out != NULL) {
        *out = stats;
    }
    return true;
}

bool apple_wire_walk_mvs_partial_commands(
    const apple_wire_mvs_rect_hdr *hdr, uint32_t expected_tiles,
    apple_wire_mvs_command_visitor visitor, void *opaque,
    apple_wire_mvs_command_stats *out)
{
    if (out != NULL) {
        memset(out, 0, sizeof *out);
    }

    // Do not expose records to a callback until the complete command endpoint
    // is known-good. A semantic caller can therefore decode into disposable
    // scratch without seeing any record from a malformed command plane.
    apple_wire_mvs_command_stats validated;
    if (!mvs_walk_partial_commands_pass(hdr, expected_tiles, NULL, NULL,
                                        &validated)) {
        return false;
    }
    if (visitor == NULL) {
        if (out != NULL) {
            *out = validated;
        }
        return true;
    }
    return mvs_walk_partial_commands_pass(hdr, expected_tiles, visitor,
                                          opaque, out);
}

bool apple_wire_validate_mvs_partial_commands(
    const apple_wire_mvs_rect_hdr *hdr, uint32_t expected_tiles,
    apple_wire_mvs_command_stats *out)
{
    return apple_wire_walk_mvs_partial_commands(hdr, expected_tiles, NULL,
                                                NULL, out);
}

static bool mvs_bits_at(const uint8_t *data, size_t len, size_t start,
                        unsigned nbits, uint32_t *out)
{
    if (data == NULL || out == NULL || nbits == 0u || nbits > 24u ||
        len > SIZE_MAX / 8u) {
        return false;
    }
    const size_t total = len * 8u;
    if (start > total || (size_t)nbits > total - start) {
        return false;
    }
    uint32_t value = 0u;
    for (unsigned i = 0u; i < nbits; i++) {
        const size_t bit = start + i;
        value = (value << 1u) |
                (uint32_t)((data[bit / 8u] >> (7u - (bit & 7u))) & 1u);
    }
    *out = value;
    return true;
}

bool apple_wire_validate_mvs_partial_image_suffix(
    const apple_wire_mvs_rect_hdr *hdr, apple_wire_mvs_image_stats *out)
{
    if (out != NULL) {
        memset(out, 0, sizeof *out);
    }
    if (hdr == NULL || hdr->type != 0u || hdr->image_buffer == NULL ||
        hdr->image_buffer_len == 0u ||
        hdr->image_buffer_len > SIZE_MAX / 8u) {
        return false;
    }

    const size_t total_bits = hdr->image_buffer_len * 8u;
    unsigned matches = 0u;
    apple_wire_mvs_image_stats found;
    memset(&found, 0, sizeof found);
    for (size_t pad = 0u; pad < 8u; pad++) {
        if (total_bits < 8u + pad) {
            continue;
        }
        const size_t marker_start = total_bits - 8u - pad;
        uint32_t marker = 0u;
        if (!mvs_bits_at(hdr->image_buffer, hdr->image_buffer_len,
                         marker_start, 8u, &marker) ||
            marker != 0x6du) {
            continue;
        }
        bool zero_pad = true;
        for (size_t i = 0u; i < pad; i++) {
            uint32_t bit = 0u;
            if (!mvs_bits_at(hdr->image_buffer, hdr->image_buffer_len,
                             marker_start + 8u + i, 1u, &bit) ||
                bit != 0u) {
                zero_pad = false;
                break;
            }
        }
        if (!zero_pad) {
            continue;
        }
        matches++;
        found.marker_start_bits = marker_start;
        found.marker_end_bits = marker_start + 8u;
        found.padding_bits = pad;
    }
    if (matches != 1u) {
        return false;
    }
    if (out != NULL) {
        *out = found;
    }
    return true;
}

bool apple_wire_mvs_is_solid_black_sample(const uint8_t *payload, size_t n)
{
    if (payload == NULL || n != sizeof k_mvs_solid_black_payload) {
        return false;
    }
    return memcmp(payload, k_mvs_solid_black_payload,
                  sizeof k_mvs_solid_black_payload) == 0;
}

bool apple_wire_mvs_fill_solid_black(uint8_t *rgba, size_t rgba_len,
                                    uint32_t w, uint32_t h,
                                    size_t stride_bytes)
{
    size_t row_bytes = 0u;
    if (rgba == NULL || w == 0u || h == 0u) {
        return false;
    }
    if (!rfb_checked_mul_size((size_t)w, 4u, &row_bytes) ||
        stride_bytes < row_bytes) {
        return false;
    }
    // Overflow-safe: need h rows of stride.
    if (h > 0u && stride_bytes > rgba_len / (size_t)h) {
        return false;
    }
    for (uint32_t y = 0u; y < h; y++) {
        uint8_t *row = rgba + (size_t)y * stride_bytes;
        for (uint32_t x = 0u; x < w; x++) {
            uint8_t *p = row + (size_t)x * 4u;
            p[0] = 0u;
            p[1] = 0u;
            p[2] = 0u;
            p[3] = 255u;
        }
    }
    return true;
}

bool apple_wire_mvs_tile_grid_checked(uint32_t w, uint32_t h,
                                      uint32_t *out_tiles_x,
                                      uint32_t *out_tiles_y,
                                      uint32_t *out_n_tiles)
{
    if (out_tiles_x != NULL) {
        *out_tiles_x = 0u;
    }
    if (out_tiles_y != NULL) {
        *out_tiles_y = 0u;
    }
    if (out_n_tiles != NULL) {
        *out_n_tiles = 0u;
    }
    if (w == 0u || h == 0u) {
        return false;
    }
    const uint32_t tx = w / APPLE_MVS_TILE_PX +
                        ((w % APPLE_MVS_TILE_PX) != 0u ? 1u : 0u);
    const uint32_t ty = h / APPLE_MVS_TILE_PX +
                        ((h % APPLE_MVS_TILE_PX) != 0u ? 1u : 0u);
    if (tx != 0u && ty > UINT32_MAX / tx) {
        return false;
    }
    if (out_tiles_x != NULL) {
        *out_tiles_x = tx;
    }
    if (out_tiles_y != NULL) {
        *out_tiles_y = ty;
    }
    if (out_n_tiles != NULL) {
        *out_n_tiles = tx * ty;
    }
    return true;
}

void apple_wire_mvs_tile_grid(uint32_t w, uint32_t h, uint32_t *out_tiles_x,
                             uint32_t *out_tiles_y, uint32_t *out_n_tiles)
{
    (void)apple_wire_mvs_tile_grid_checked(w, h, out_tiles_x, out_tiles_y,
                                           out_n_tiles);
}

bool apple_wire_decode_cfg21(const uint8_t *msg, size_t n,
                             apple_wire_cfg21 *out)
{
    if (out == NULL) {
        return false;
    }
    memset(out, 0, sizeof *out);
    if (msg == NULL || n < 4u || msg[0] != 0x21u) {
        return false;
    }
    out->body_len = be16(msg + 2);
    if (4u + (size_t)out->body_len > n) {
        return false;
    }
    // The scale is a big-endian float at body offset 40.
    if (out->body_len >= 44u) {
        const uint8_t *p = msg + 4 + 40;
        uint32_t bits = be32(p);
        float f = float_from_be_bits(bits);
        if (f > 0.0f && f < 16.0f) {
            out->scale = f;
            out->has_scale = true;
        }
    }
    return true;
}
