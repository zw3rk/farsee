// SPDX-License-Identifier: Apache-2.0
//
// MultiVariant bitstream walker — tile prefixes + FULL residual decode
// against the per-tile saved coefficients (the legacy full-update grammar).

#include "farsee/apple_mvs_stream.h"

#include "farsee/apple_mvs_dct.h"
#include "farsee/apple_mvs_mag.h"
#include "farsee/apple_wire_decode.h"
#include "farsee/checked.h"

#include <stdlib.h>
#include <string.h>

bool apple_mvs_stream_small_diff_get(apple_mvs_bit_reader *br, int32_t *out)
{
    if (br == NULL || out == NULL) {
        return false;
    }
    uint32_t b0 = 0;
    if (!apple_mvs_bit_reader_get(br, 1u, &b0)) {
        return false;
    }
    if (b0 == 0u) {
        *out = 0;
        return true;
    }
    uint32_t b1 = 0;
    if (!apple_mvs_bit_reader_get(br, 1u, &b1)) {
        return false;
    }
    *out = (b1 == 0u) ? 1 : -1;
    return true;
}

// Second form residual.
//
// When the saved template ≠ 0: signed delta only (3-bit high / 4-bit low).
// When template == 0: peek at the next 2 bits. A 00 prefix selects a magnitude
// residual; every other prefix selects the signed 3/4-bit form. The peek does
// not consume the reader.
static bool second_form_get(apple_mvs_bit_reader *br, int16_t template_v,
                            bool high_path, int32_t *out)
{
    const unsigned nbits = high_path ? 3u : 4u;
    const int32_t half = high_path ? 4 : 8;
    const int32_t wrap = high_path ? 8 : 16;

    if (template_v == 0) {
        apple_mvs_bit_reader peek = *br;
        uint32_t b2 = 0;
        if (!apple_mvs_bit_reader_get(&peek, 2u, &b2)) {
            return false;
        }
        if (b2 == 0u) {
            return apple_mvs_mag_get(br, out);
        }
        // Fall through to signed n-bit (do not consume the peek copy).
    }
    uint32_t v = 0;
    if (!apple_mvs_bit_reader_get(br, nbits, &v)) {
        return false;
    }
    int32_t s = (int32_t)v;
    if (s >= half) {
        s -= wrap;
    }
    *out = s;
    return true;
}

// First-form residual: high path uses small_diff {0, +1, −1}.
// Low path (fidelity ≤ 14): mag if next 2 bits are 00, else signed 3-bit.
static bool first_form_get(apple_mvs_bit_reader *br, bool high_path, int32_t *out)
{
    if (high_path) {
        return apple_mvs_stream_small_diff_get(br, out);
    }
    apple_mvs_bit_reader peek = *br;
    uint32_t b2 = 0;
    if (!apple_mvs_bit_reader_get(&peek, 2u, &b2)) {
        return false;
    }
    if (b2 == 0u) {
        return apple_mvs_mag_get(br, out);
    }
    uint32_t v = 0;
    if (!apple_mvs_bit_reader_get(br, 3u, &v)) {
        return false;
    }
    int32_t s = (int32_t)v;
    if (s >= 4) {
        s -= 8;
    }
    *out = s;
    return true;
}

static int16_t clamp_i16_add(int16_t base, int32_t delta)
{
    int32_t sum = (int32_t)base + delta;
    if (sum > 32767) {
        sum = 32767;
    } else if (sum < -32768) {
        sum = -32768;
    }
    return (int16_t)sum;
}

// Conservative AC-consumption cutoff for a selected plane. Decode_full applies
// it after a successful high-path AC decode; an over-budget result makes that
// tile transaction roll back to its post-DC snapshot.
//
// `seeded` selects whether this call applies the cutoff. Decode_full passes true
// for every high-path plane it attempts. The transaction commits only if each
// attempted plane decodes successfully and stays at or below the cutoff.
bool apple_mvs_seeded_ac_over_budget(bool seeded, size_t bits_consumed,
                                     size_t budget_bits)
{
    return seeded && (bits_consumed > budget_bits);
}

rfb_error apple_mvs_stream_next(apple_mvs_bit_reader *br,
                                apple_mvs_tile_event *out)
{
    if (br == NULL || out == NULL) {
        return RFB_ERR_INTERNAL;
    }
    memset(out, 0, sizeof *out);

    if (apple_mvs_bit_reader_bits_left(br) >= 24u) {
        apple_mvs_bit_reader peek = *br;
        uint32_t a = 0, b = 0, c = 0;
        if (apple_mvs_bit_reader_get(&peek, 8u, &a) &&
            apple_mvs_bit_reader_get(&peek, 8u, &b) &&
            apple_mvs_bit_reader_get(&peek, 8u, &c) && a == 0x6du &&
            b == 0x76u && c == 0x73u) {
            *br = peek;
            out->kind = APPLE_MVS_KIND_TRAILER_MVS;
            return RFB_OK;
        }
    }

    if (apple_mvs_bit_reader_bits_left(br) < 2u) {
        out->kind = APPLE_MVS_KIND_EOF;
        return RFB_OK;
    }

    uint32_t b2 = 0;
    apple_mvs_bit_reader peek2 = *br;
    if (!apple_mvs_bit_reader_get(&peek2, 2u, &b2)) {
        out->kind = APPLE_MVS_KIND_EOF;
        return RFB_OK;
    }

    if (b2 == 0x0u) {
        (void)apple_mvs_bit_reader_get(br, 2u, &b2);
        out->kind = APPLE_MVS_KIND_WHITE;
        return RFB_OK;
    }
    if (b2 == 0x2u) {
        (void)apple_mvs_bit_reader_get(br, 2u, &b2);
        out->kind = APPLE_MVS_KIND_LAST_MATCH;
        return RFB_OK;
    }
    if (b2 == 0x1u) {
        (void)apple_mvs_bit_reader_get(br, 2u, &b2);
        out->kind = APPLE_MVS_KIND_FULL;
        return RFB_OK;
    }
    uint32_t b3 = 0;
    if (!apple_mvs_bit_reader_get(br, 3u, &b3)) {
        return RFB_ERR_PROTOCOL;
    }
    if (b3 == 0x7u) {
        out->kind = APPLE_MVS_KIND_CACHE_HIT;
        return RFB_OK;
    }
    if (b3 == 0x6u) {
        uint32_t id = 0;
        if (!apple_mvs_bit_reader_get(br, 16u, &id)) {
            return RFB_ERR_PROTOCOL;
        }
        out->kind = APPLE_MVS_KIND_CACHE_ID;
        out->cache_id = (uint16_t)id;
        return RFB_OK;
    }
    return RFB_ERR_PROTOCOL;
}

rfb_error apple_mvs_stream_decode_full(apple_mvs_bit_reader *br,
                                       uint32_t fidelity,
                                       uint32_t large_count,
                                       apple_mvs_tile_state *state,
                                       apple_mvs_full_coeffs *out_coeffs)
{
    if (br == NULL) {
        return RFB_ERR_INTERNAL;
    }
    if (fidelity == 0u || fidelity > 64u) {
        fidelity = 15u;
    }
    // Quality counts: normal_count → Cb max_k; large_count → Cr max_k.
    // When the caller does not supply large_count (0), fall back to the tier
    // default: high path (fidelity>14) uses 25, low path uses 5.
    const bool high_path = (fidelity > 14u);
    if (large_count == 0u) {
        large_count = high_path ? 25u : 5u;
    }
    // Clamp into 1..63 for the AC API (k0..max_k inclusive; a limit of M terms
    // maps to max_k = M with k0 = 1). Cap Cr at the decoder's supported
    // coefficient count.
    int max_cb = (int)(fidelity > 63u ? 63u : (fidelity < 1u ? 1u : fidelity));
    uint32_t cr_terms = large_count;
    if (cr_terms > (uint32_t)APPLE_MVS_MAX_CR_COEFFS) {
        cr_terms = (uint32_t)APPLE_MVS_MAX_CR_COEFFS;
    }
    if (cr_terms < 1u) {
        cr_terms = 1u;
    }
    int max_cr = (int)cr_terms;

    // Work on a copy; write back only after full success.
    apple_mvs_tile_state work;
    if (state != NULL && state->valid) {
        work = *state;
    } else {
        memset(&work, 0, sizeof work);
    }

    // High path (fidelity > 14): small_diff first-form + 3-bit second-form.
    // Low path: mag/3-bit first-form + 4-bit second-form.
    //
    // The saved Cb/Cr count is a writeback marker, not an AC-length input. With
    // a non-NULL state, the high path runs chroma AC after DC regardless of the
    // entry count. RFB_OK writeback sets both count markers to 1. The low path
    // and the NULL-state skip path stay DC-only and leave entry counts unchanged.
    const bool run_ac = high_path && (state != NULL);

    uint32_t nm1 = 0;
    if (!apple_mvs_bit_reader_get(br, 6u, &nm1)) {
        return RFB_ERR_PROTOCOL;
    }
    uint32_t n_sig = nm1 + 1u;
    if (n_sig > 64u) {
        return RFB_ERR_PROTOCOL;
    }

    uint32_t first = n_sig < fidelity ? n_sig : fidelity;

    // First-form: coeffs[1 .. first-1] into saved (y[0] not residual-coded).
    for (uint32_t i = 1u; i < first; i++) {
        int32_t d = 0;
        if (!first_form_get(br, high_path, &d)) {
            return RFB_ERR_PROTOCOL;
        }
        work.y[i] = clamp_i16_add(work.y[i], d);
    }
    // Second-form: coeffs[first .. n_sig-1]; template = pre-update saved[i].
    for (uint32_t i = first; i < n_sig; i++) {
        int16_t tmpl = work.y[i];
        int32_t d = 0;
        if (!second_form_get(br, tmpl, high_path, &d)) {
            return RFB_ERR_PROTOCOL;
        }
        work.y[i] = clamp_i16_add(work.y[i], d);
    }

    // Chroma: special DC residual via small_diff×2 (Cb then Cr). This DC is
    // *always* present; count is saved-coefficient validity (expect 1), not an
    // AC-length oracle.
    {
        int32_t d = 0;
        if (!apple_mvs_stream_small_diff_get(br, &d)) {
            return RFB_ERR_PROTOCOL;
        }
        work.cb[0] = clamp_i16_add(work.cb[0], d);
        if (!apple_mvs_stream_small_diff_get(br, &d)) {
            return RFB_ERR_PROTOCOL;
        }
        work.cr[0] = clamp_i16_add(work.cr[0], d);
    }

    // On the high path with non-NULL state, decode_full runs Annex K chrominance
    // JPEG AC after DC. The count markers do not gate it. Cb max_k comes from
    // fidelity; Cr max_k comes from large_count. The AC API covers k0..max_k
    // inclusive, so a limit of M terms maps to max_k=M with k0=1.
    //
    // Soft-continue is atomic across Cb and Cr. The helper snapshots the post-DC
    // reader and both coefficient planes, decodes Cb, then decodes Cr only if Cb
    // stayed within policy. Huffman failure or an over-budget success restores
    // the snapshot and drops AC from both planes while retaining DC. RFB_OK then
    // writes back the DC-only result. Cr does not re-read Cb bytes after rollback.
    //
    // The budget is a conservative policy cutoff, not a correctness proof.
    if (run_ac) {
        apple_mvs_bit_reader br_post_dc = *br;
        int16_t cb_save[64];
        int16_t cr_save[64];
        memcpy(cb_save, work.cb, sizeof cb_save);
        memcpy(cr_save, work.cr, sizeof cr_save);

        bool ac_ok = true;

        {
            const size_t bits_before = apple_mvs_bit_reader_bits_left(br);
            const bool ok =
                apple_mvs_jpeg_ac_decode(br, work.cb, 1, max_cb);
            const size_t bits_after = apple_mvs_bit_reader_bits_left(br);
            const size_t consumed =
                (bits_before > bits_after) ? (bits_before - bits_after) : 0u;
            if (!ok) {
                ac_ok = false;
            } else if (apple_mvs_seeded_ac_over_budget(
                           true, consumed, APPLE_MVS_SEEDED_AC_BUDGET_BITS)) {
                ac_ok = false;
            }
        }
        if (ac_ok) {
            const size_t bits_before = apple_mvs_bit_reader_bits_left(br);
            const bool ok =
                apple_mvs_jpeg_ac_decode(br, work.cr, 1, max_cr);
            const size_t bits_after = apple_mvs_bit_reader_bits_left(br);
            const size_t consumed =
                (bits_before > bits_after) ? (bits_before - bits_after) : 0u;
            if (!ok) {
                ac_ok = false;
            } else if (apple_mvs_seeded_ac_over_budget(
                           true, consumed, APPLE_MVS_SEEDED_AC_BUDGET_BITS)) {
                ac_ok = false;
            }
        }
        if (!ac_ok) {
            *br = br_post_dc;
            memcpy(work.cb, cb_save, sizeof work.cb);
            memcpy(work.cr, cr_save, sizeof work.cr);
        }

        // High-path FULL always writes count=1 for both planes
        // (saved-coefficient validity), whether AC committed or was atomically
        // rolled back to DC-only for this tile.
        work.cb_count = 1u;
        work.cr_count = 1u;
    }

    work.valid = true;

    if (out_coeffs != NULL) {
        memcpy(out_coeffs->y, work.y, sizeof work.y);
        memcpy(out_coeffs->cb, work.cb, sizeof work.cb);
        memcpy(out_coeffs->cr, work.cr, sizeof work.cr);
        out_coeffs->n_sig = n_sig;
        out_coeffs->fidelity = fidelity;
    }
    if (state != NULL) {
        *state = work;
    }
    return RFB_OK;
}

rfb_error apple_mvs_stream_skip_full_payload(apple_mvs_bit_reader *br)
{
    // Prefer normal high-tier fidelity 15 for skip-only; no saved state. DC-only
    // NULL-state path (large_count=0 → high default 25, but run_ac is false).
    return apple_mvs_stream_decode_full(br, 15u, 0u, NULL, NULL);
}

// --- coeff store ----------------------------------------------------------

bool apple_mvs_coeff_store_ensure(apple_mvs_coeff_store *s, uint32_t fb_w,
                                  uint32_t fb_h)
{
    return apple_mvs_coeff_store_ensure_with_allocator(
        s, fb_w, fb_h, rfb_default_allocator());
}

bool apple_mvs_coeff_store_ensure_with_allocator(
    apple_mvs_coeff_store *s, uint32_t fb_w, uint32_t fb_h,
    rfb_allocator *allocator)
{
    if (s == NULL || fb_w == 0u || fb_h == 0u || allocator == NULL ||
        allocator->alloc == NULL || allocator->free == NULL) {
        return false;
    }
    const uint32_t tx = fb_w / 8u + (fb_w % 8u != 0u ? 1u : 0u);
    const uint32_t ty = fb_h / 8u + (fb_h % 8u != 0u ? 1u : 0u);
    size_t n = 0u;
    size_t bytes = 0u;
    if (!rfb_checked_mul_size((size_t)tx, (size_t)ty, &n) || n == 0u ||
        n > UINT32_MAX ||
        !rfb_checked_mul_size(n, sizeof(apple_mvs_tile_state), &bytes)) {
        return false;
    }
    if (s->tiles != NULL && s->tiles_x == tx && s->tiles_y == ty &&
        s->ntiles == (uint32_t)n) {
        return true;
    }
    apple_mvs_tile_state *p =
        (apple_mvs_tile_state *)allocator->alloc(allocator, bytes);
    if (p == NULL) {
        return false;
    }
    memset(p, 0, bytes);
    if (s->tiles != NULL) {
        rfb_allocator *old_allocator =
            s->alloc != NULL ? s->alloc : rfb_default_allocator();
        old_allocator->free(old_allocator, s->tiles);
    }
    s->tiles = p;
    s->tiles_x = tx;
    s->tiles_y = ty;
    s->ntiles = (uint32_t)n;
    s->alloc = allocator;
    return true;
}

void apple_mvs_coeff_store_clear(apple_mvs_coeff_store *s)
{
    if (s == NULL || s->tiles == NULL || s->ntiles == 0u) {
        return;
    }
    memset(s->tiles, 0, (size_t)s->ntiles * sizeof(apple_mvs_tile_state));
}

void apple_mvs_coeff_store_free(apple_mvs_coeff_store *s)
{
    if (s == NULL) {
        return;
    }
    if (s->tiles != NULL) {
        rfb_allocator *allocator =
            s->alloc != NULL ? s->alloc : rfb_default_allocator();
        allocator->free(allocator, s->tiles);
    }
    s->tiles = NULL;
    s->tiles_x = 0u;
    s->tiles_y = 0u;
    s->ntiles = 0u;
    s->alloc = NULL;
}

apple_mvs_tile_state *apple_mvs_coeff_store_at(apple_mvs_coeff_store *s,
                                               uint16_t px, uint16_t py)
{
    if (s == NULL || s->tiles == NULL || s->tiles_x == 0u) {
        return NULL;
    }
    const uint32_t col = (uint32_t)px / 8u;
    const uint32_t row = (uint32_t)py / 8u;
    if (col >= s->tiles_x || row >= s->tiles_y) {
        return NULL;
    }
    const uint32_t idx = row * s->tiles_x + col;
    if (idx >= s->ntiles) {
        return NULL;
    }
    return &s->tiles[idx];
}
