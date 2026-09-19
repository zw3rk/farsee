// SPDX-License-Identifier: Apache-2.0
//
// farsee — pure field decoders for Apple modern control messages.

#ifndef FARSEE_INCLUDE_FARSEE_APPLE_WIRE_DECODE_H
#define FARSEE_INCLUDE_FARSEE_APPLE_WIRE_DECODE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// ---------------------------------------------------------------------------
// Encoding ID 0x03f3 = MultiVariant (MVS) — Apple private paint encoding.
// Both the rect payload and the quantization-table control carry this ID.
// ---------------------------------------------------------------------------

// Tile command identifiers; 0xff is an out-of-band invalid sentinel.
enum apple_wire_mvs_tile_cmd {
    APPLE_MVS_TILE_WHITE = 0,
    APPLE_MVS_TILE_LAST_MATCH = 1,
    APPLE_MVS_TILE_UPPER_MATCH = 2,
    APPLE_MVS_TILE_BLACK_WHITE = 3,
    APPLE_MVS_TILE_TWO_COLOR = 4,
    APPLE_MVS_TILE_DCT = 5,
    APPLE_MVS_TILE_INVALID = 0xff
};

// Fixed geometry of the per-tile DCT render data.
enum apple_wire_mvs_dct_layout {
    APPLE_MVS_MAX_LUMA_COEFFS = 64,  // luma coefficients per tile
    APPLE_MVS_MAX_CB_COEFFS = 15,    // Cb coefficients per tile
    APPLE_MVS_MAX_CR_COEFFS = 20,    // Cr coefficients per tile
    APPLE_MVS_HIGH_QUALITY_COUNT = 15,
    APPLE_MVS_START_BYTE_LUMINOSITY = 3,
    APPLE_MVS_START_BYTE_CB = 67,              // 0x43
    APPLE_MVS_START_BYTE_CR = 82,              // 0x52
    APPLE_MVS_START_BYTE_SCALED_LUMINOSITY = 102, // 0x66
    APPLE_MVS_START_BYTE_HASH = 168             // 0xa8
};

// Tile size is 8×8 (standard DCT block); grid = ceil(w/8)×ceil(h/8).
#define APPLE_MVS_TILE_PX 8u

// Typed envelope: u32be 1 | 0 | 0 | type | payload
bool apple_wire_typed_header(const uint8_t *msg, size_t n, uint32_t *out_type,
                             const uint8_t **out_payload, size_t *out_plen);

// msg14 family: 8 B, type 0x14 (S→C tick).
typedef struct apple_wire_msg14_fields {
    uint8_t type;       // 0x14
    uint16_t len_field; // raw u16be value from bytes 2..3
    uint16_t flags;     // raw u16be value from bytes 4..5
    uint16_t param;     // raw u16be value from bytes 6..7
} apple_wire_msg14_fields;

bool apple_wire_decode_msg14(const uint8_t *msg, size_t n,
                             apple_wire_msg14_fields *out);

// 0x0455 keyboard layout: u16be body_len | u16be unknown | u32 uninterpreted |
// u16be name_len | name[name_len].
typedef struct apple_wire_kb_layout {
    uint16_t body_len;
    uint16_t unk;
    uint16_t name_len;
    const uint8_t *name; // not NUL-terminated; name_len bytes
} apple_wire_kb_layout;

bool apple_wire_decode_kb_layout(const uint8_t *payload, size_t n,
                                 apple_wire_kb_layout *out);

// 0x03f3 quantization-table control:
//   u32be table_len | u8 n_tables | n_tables × 64-byte QT
// Supported layout: table_len=129, n_tables=2, followed by luma QT[64] and
// chroma QT[64].
// Table bytes are RASTER order — index = vertical frequency * 8 + horizontal
// frequency, the same natural order the coefficients use — not zig-zag.
typedef struct apple_wire_mvs_tables {
    uint32_t table_len;
    uint8_t n_tables; // tables[0] when table_len>=1
    const uint8_t *tables; // full table_len bytes (incl. n_tables byte)
    const uint8_t *qt0;    // 64 B luma, or NULL if n_tables<1 / short
    const uint8_t *qt1;    // 64 B chroma, or NULL if n_tables<2 / short
} apple_wire_mvs_tables;

bool apple_wire_decode_mvs_tables(const uint8_t *payload, size_t n,
                                  apple_wire_mvs_tables *out);

// 0x03f3 FBU rect data after classic rect header (x,y,w,h,enc):
//   u32be data_len | data[data_len]
// Type-0 data[] has a six-byte header followed by independent packed command
// and image planes. See apple_wire_mvs_rect_hdr.
typedef struct apple_wire_mvs_rect {
    uint32_t data_len;
    const uint8_t *data;
} apple_wire_mvs_rect;

bool apple_wire_decode_mvs_rect_data(const uint8_t *data, size_t n,
                                     apple_wire_mvs_rect *out);

// Type-0 partial-update header (body after u32be data_len):
//   u8 type | u8 normal_count | u8 large_count |
//   u24be image_buffer_offset | packed command plane | image plane
typedef struct apple_wire_mvs_rect_hdr {
    uint8_t type;          // [0]; only type 0 is currently decoded
    uint16_t normal_count; // [1]; supported: 3 or 15
    uint8_t large_count;   // [2]; supported: 5 or 25 (0x19)
    uint32_t image_buffer_offset; // u24be [3..5]
    const uint8_t *bitstream; // command plane [6..image_buffer_offset)
    size_t bitstream_len;
    const uint8_t *image_buffer; // render plane at image_buffer_offset
    size_t image_buffer_len;
    // Classify the two recognized quality pairs.
    bool is_low_quality_pair;
    bool is_high_quality_pair;
} apple_wire_mvs_rect_hdr;

bool apple_wire_decode_mvs_rect_hdr(const uint8_t *payload, size_t n,
                                    apple_wire_mvs_rect_hdr *out);

typedef struct apple_wire_mvs_command_stats {
    uint32_t tiles;
    uint32_t records;
    uint32_t command_tiles[8];
    size_t marker_end_bits;
    size_t padding_bits;
} apple_wire_mvs_command_stats;

// One numeric type-0 command record. The command ID is deliberately not given
// pixel semantics here: this iterator establishes only wire structure.
typedef struct apple_wire_mvs_command_record {
    uint8_t command;
    uint32_t first_tile;
    uint32_t repeat;
    uint32_t run;
    size_t command_start_bits;
    size_t command_end_bits;
} apple_wire_mvs_command_record;

typedef bool (*apple_wire_mvs_command_visitor)(
    void *opaque, const apple_wire_mvs_command_record *record);

// Walk the independently bounded type-0 command plane through exactly the
// expected tile grid and endpoint. A non-NULL visitor is invoked only after a
// complete validation pass, then receives each numeric record in wire order.
// It must write only disposable scratch; commit remains the caller's job.
bool apple_wire_walk_mvs_partial_commands(
    const apple_wire_mvs_rect_hdr *hdr, uint32_t expected_tiles,
    apple_wire_mvs_command_visitor visitor, void *opaque,
    apple_wire_mvs_command_stats *out);

// Validate the type-0 command plane through exactly expected_tiles, followed
// by its unaligned 'm' marker and zero-to-byte-boundary padding.
bool apple_wire_validate_mvs_partial_commands(
    const apple_wire_mvs_rect_hdr *hdr, uint32_t expected_tiles,
    apple_wire_mvs_command_stats *out);

typedef struct apple_wire_mvs_image_stats {
    size_t marker_start_bits;
    size_t marker_end_bits;
    size_t padding_bits;
} apple_wire_mvs_image_stats;

// Validate the structural suffix of the independent type-0
// image plane: one final unaligned 0x6d marker and zero pad to its byte end.
// This proves only the plane boundary; it does not assign image semantics.
bool apple_wire_validate_mvs_partial_image_suffix(
    const apple_wire_mvs_rect_hdr *hdr, apple_wire_mvs_image_stats *out);

// Recognize one exact 15-byte solid-black payload after u32be data_len.
// This known-answer case does not implement general Huffman decoding.
bool apple_wire_mvs_is_solid_black_sample(const uint8_t *payload, size_t n);

// Fill RGBA8 buffer with opaque black. w*h must fit; stride_bytes >= w*4.
// Returns false on bad args. Does not interpret Huffman — use only after
// apple_wire_mvs_is_solid_black_sample (or when peer FB is known black).
bool apple_wire_mvs_fill_solid_black(uint8_t *rgba, size_t rgba_len,
                                    uint32_t w, uint32_t h,
                                    size_t stride_bytes);

// cfg21 body after type/pad/u16be body_len: decode scale float if present.
typedef struct apple_wire_cfg21 {
    uint16_t body_len;
    float scale; // BE float at body+40 when body_len>=44; else 0
    bool has_scale;
} apple_wire_cfg21;

bool apple_wire_decode_cfg21(const uint8_t *msg, size_t n,
                             apple_wire_cfg21 *out);

// Tile grid for a rect of pixel size (w,h).
bool apple_wire_mvs_tile_grid_checked(uint32_t w, uint32_t h,
                                      uint32_t *out_tiles_x,
                                      uint32_t *out_tiles_y,
                                      uint32_t *out_n_tiles);

// Compatibility wrapper. Overflow or an empty dimension yields zero outputs.
void apple_wire_mvs_tile_grid(uint32_t w, uint32_t h, uint32_t *out_tiles_x,
                             uint32_t *out_tiles_y, uint32_t *out_n_tiles);

#ifdef __cplusplus
}
#endif

#endif
