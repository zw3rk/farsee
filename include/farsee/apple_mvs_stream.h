// SPDX-License-Identifier: Apache-2.0
//
// farsee — legacy inline MultiVariant tile walker.
// This is the full-update residual grammar and is not the independent
// command/image-plane grammar used by type-0 partial-update bodies.

#ifndef FARSEE_INCLUDE_FARSEE_APPLE_MVS_STREAM_H
#define FARSEE_INCLUDE_FARSEE_APPLE_MVS_STREAM_H

#include "farsee/allocator.h"
#include "farsee/apple_mvs_bits.h"
#include "farsee/error.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum apple_mvs_tile_kind {
    APPLE_MVS_KIND_WHITE = 0,
    APPLE_MVS_KIND_LAST_MATCH,
    APPLE_MVS_KIND_CACHE_HIT,
    APPLE_MVS_KIND_CACHE_ID,
    APPLE_MVS_KIND_FULL,
    APPLE_MVS_KIND_TRAILER_MVS,
    APPLE_MVS_KIND_EOF
} apple_mvs_tile_kind;

typedef struct apple_mvs_tile_event {
    apple_mvs_tile_kind kind;
    uint16_t cache_id;
} apple_mvs_tile_event;

// Per-tile saved coefficients (Y/Cb/Cr natural order, pre-dequant).
// valid=false → treat as zero baseline (first FULL is still differential).
//
// cb_count/cr_count are saved-coefficient writeback markers. Their entry values
// do not gate AC. On the high path with non-NULL state, decode_full runs chroma
// AC after DC and sets both markers to 1 on RFB_OK, including atomic
// soft-continue. The low path and NULL-state skip path stay DC-only and leave
// their entry values unchanged.
typedef struct apple_mvs_tile_state {
    int16_t y[64];
    int16_t cb[64];
    int16_t cr[64];
    uint8_t cb_count;
    uint8_t cr_count;
    bool valid;
} apple_mvs_tile_state;

// Decoded FULL residual planes (natural order, pre-IDCT) — snapshot after
// differential apply (same values written back to tile_state on success).
typedef struct apple_mvs_full_coeffs {
    int16_t y[64];
    int16_t cb[64];
    int16_t cr[64];
    uint32_t n_sig;
    uint32_t fidelity;
} apple_mvs_full_coeffs;

// Framebuffer-indexed saved-coefficient store (grid = ceil(w/8)×ceil(h/8)).
typedef struct apple_mvs_coeff_store {
    apple_mvs_tile_state *tiles;
    uint32_t tiles_x;
    uint32_t tiles_y;
    uint32_t ntiles;
    rfb_allocator *alloc;
} apple_mvs_coeff_store;

// Decode one legacy inline tile event. Product type-0 rectangles do not route
// through this helper.
rfb_error apple_mvs_stream_next(apple_mvs_bit_reader *br,
                                apple_mvs_tile_event *out);

// Small residual: 0 | 10 | 11 → 0, +1, -1.
bool apple_mvs_stream_small_diff_get(apple_mvs_bit_reader *br, int32_t *out);

// Decode FULL residual after FULL prefix.
// fidelity: quality normal_count (Cb max_k). Typical 15 (high) or 3 (low).
// large_count: Cr max_k from the quality pair; 0 → tier default (25 high,
//   5 low). Both are clamped into 1..63 before use as an AC max_k.
// state: optional saved coefficients in/out. NULL → zero baseline, no writeback.
//   Writeback occurs only on RFB_OK. White/LastMatch/Cache callers leave
//   state unchanged.
// out_coeffs may be NULL (skip-only).
// Grammar: n_sig=get(6)+1; first=min(n_sig,fid);
//   first-form: saved[i] += small_diff for i in 1..first-1;
//   second-form: if saved[i]==0 mag else signed 3-bit; saved[i] += d;
//   chroma DC ×2 small_diff on saved.cb[0]/cr[0].
//   Chroma AC: on the high path with non-NULL state, decode_full always calls
//   the Annex K chrominance decoder after DC. Entry count markers do not gate
//   AC. Cb max_k=fidelity; Cr max_k=large_count. This API covers k0..max_k
//   inclusive, so M terms map to max_k=M with k0=1.
//   On AC Huffman failure or over-budget success, Cb and Cr are one
//   transaction. The post-DC reader and both coefficient planes are restored,
//   DC is retained, and RFB_OK writes back count markers of 1.
rfb_error apple_mvs_stream_decode_full(apple_mvs_bit_reader *br,
                                       uint32_t fidelity,
                                       uint32_t large_count,
                                       apple_mvs_tile_state *state,
                                       apple_mvs_full_coeffs *out_coeffs);

// Conservative high-path AC-consumption cutoff used by decode_full. An
// over-budget success rolls the Cb/Cr transaction back to its post-DC
// snapshot. The transaction commits only if each attempted plane decodes
// successfully and stays at or below the cutoff.
#define APPLE_MVS_SEEDED_AC_BUDGET_BITS 64u

// True when `seeded` selects the plane and its consumption exceeds budget_bits.
// Pure decision; exported for unit testing.
bool apple_mvs_seeded_ac_over_budget(bool seeded, size_t bits_consumed,
                                     size_t budget_bits);

// Skip wrapper: fidelity=15, no state, no writeback.
rfb_error apple_mvs_stream_skip_full_payload(apple_mvs_bit_reader *br);

// --- FB-indexed saved-coefficient store -----------------------------------

// Ensure store covers fb_w×fb_h tile grid. Realloc+zero on geometry change.
// Returns false on OOM.
bool apple_mvs_coeff_store_ensure(apple_mvs_coeff_store *s, uint32_t fb_w,
                                  uint32_t fb_h);

// Allocator-aware form for session-scoped accounting. The allocator is
// borrowed and must outlive the store.
bool apple_mvs_coeff_store_ensure_with_allocator(
    apple_mvs_coeff_store *s, uint32_t fb_w, uint32_t fb_h,
    rfb_allocator *allocator);

// Zero all slots (keep allocation). Call on DesktopSize after ensure.
void apple_mvs_coeff_store_clear(apple_mvs_coeff_store *s);

void apple_mvs_coeff_store_free(apple_mvs_coeff_store *s);

// Slot for absolute pixel (px,py) → tile (px/8, py/8). NULL if OOB/empty.
apple_mvs_tile_state *apple_mvs_coeff_store_at(apple_mvs_coeff_store *s,
                                               uint16_t px, uint16_t py);

#ifdef __cplusplus
}
#endif

#endif
