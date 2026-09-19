// SPDX-License-Identifier: Apache-2.0
//
// Unit tests: MVS tile prefix walker + small_diff + saved coefficients.

#include "rfb_test.h"
#include "farsee/apple_mvs_bits.h"
#include "farsee/apple_mvs_dct.h"
#include "farsee/apple_mvs_mag.h"
#include "farsee/apple_mvs_stream.h"
#include "farsee/memory_budget.h"
#include "farsee/apple_wire_decode.h"

#include <string.h>

// Helper: append Annex K *chrominance* AC into a writer — one 0x01 sym
// (run0,sz1) = code 01 + 1 value bit, then EOB (sym 0x00 = code 00, len2).
// Chrominance table differs from luminance (EOB is short 00 here, not 1010).
// val_bit: 0 → -1, 1 → +1 (receive_extend sz=1).
static void put_ac_one_then_eob(apple_mvs_bit_writer *bw, int val_bit)
{
    (void)apple_mvs_bit_writer_put(bw, 1u, 2u);   // sym 0x01 (sz1,run0)
    (void)apple_mvs_bit_writer_put(bw, val_bit ? 1u : 0u, 1u);
    (void)apple_mvs_bit_writer_put(bw, 0u, 2u);   // EOB 00
}

static void put_ac_eob_only(apple_mvs_bit_writer *bw)
{
    (void)apple_mvs_bit_writer_put(bw, 0u, 2u);   // EOB 00
}

RFB_TEST(apple_mvs_stream, small_diff_roundtrip)
{
    uint8_t buf[8];
    apple_mvs_bit_writer bw;
    apple_mvs_bit_writer_init(&bw, buf, sizeof buf);
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 0u, 1u)); // 0
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 2u, 2u)); // 10 → +1
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 3u, 2u)); // 11 → -1
    RFB_CHECK(apple_mvs_bit_writer_finish(&bw));

    apple_mvs_bit_reader br;
    apple_mvs_bit_reader_init(&br, buf, bw.len);
    int32_t v = 99;
    RFB_CHECK(apple_mvs_stream_small_diff_get(&br, &v));
    RFB_CHECK_EQ_INT(v, 0);
    RFB_CHECK(apple_mvs_stream_small_diff_get(&br, &v));
    RFB_CHECK_EQ_INT(v, 1);
    RFB_CHECK(apple_mvs_stream_small_diff_get(&br, &v));
    RFB_CHECK_EQ_INT(v, -1);
}

RFB_TEST(apple_mvs_stream, prefixes_white_last_full_cache)
{
    uint8_t buf[32];
    apple_mvs_bit_writer bw;
    apple_mvs_bit_writer_init(&bw, buf, sizeof buf);
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 0u, 2u)); // White
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 2u, 2u)); // LastMatch
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 1u, 2u)); // FULL
    // minimal FULL: n_sig=1 → put(0,6), no residuals, 2× chroma DC 0
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 0u, 6u));
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 0u, 1u));
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 0u, 1u));
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 7u, 3u)); // CACHE_HIT
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 6u, 3u)); // CACHE_ID
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 0x1234u, 16u));
    RFB_CHECK(apple_mvs_bit_writer_finish(&bw));

    apple_mvs_bit_reader br;
    apple_mvs_bit_reader_init(&br, buf, bw.len);
    apple_mvs_tile_event ev;

    RFB_CHECK(apple_mvs_stream_next(&br, &ev) == RFB_OK);
    RFB_CHECK(ev.kind == APPLE_MVS_KIND_WHITE);

    RFB_CHECK(apple_mvs_stream_next(&br, &ev) == RFB_OK);
    RFB_CHECK(ev.kind == APPLE_MVS_KIND_LAST_MATCH);

    RFB_CHECK(apple_mvs_stream_next(&br, &ev) == RFB_OK);
    RFB_CHECK(ev.kind == APPLE_MVS_KIND_FULL);
    RFB_CHECK(apple_mvs_stream_skip_full_payload(&br) == RFB_OK);

    RFB_CHECK(apple_mvs_stream_next(&br, &ev) == RFB_OK);
    RFB_CHECK(ev.kind == APPLE_MVS_KIND_CACHE_HIT);

    RFB_CHECK(apple_mvs_stream_next(&br, &ev) == RFB_OK);
    RFB_CHECK(ev.kind == APPLE_MVS_KIND_CACHE_ID);
    RFB_CHECK_EQ_UINT(ev.cache_id, 0x1234u);
}

// Saved coefficients: first FULL from !valid is zero-baseline differential (+=).
// n_sig=3, fidelity=15 -> first=3 -> first form for y[1] and y[2].
// Wire: small +1, small -1; chroma DC 0,0; then Cb/Cr EOB because
// decode_full receives non-NULL state on the high path.
RFB_TEST(apple_mvs_stream, lastsaved_first_full_zero_baseline)
{
    uint8_t buf[16];
    apple_mvs_bit_writer bw;
    apple_mvs_bit_writer_init(&bw, buf, sizeof buf);
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 2u, 6u)); // n_sig-1 = 2 → n_sig=3
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 2u, 2u)); // +1 for y[1]
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 3u, 2u)); // -1 for y[2]
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 0u, 1u)); // cb DC
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 0u, 1u)); // cr DC
    put_ac_eob_only(&bw);                             // cb AC EOB
    put_ac_eob_only(&bw);                             // cr AC EOB
    RFB_CHECK(apple_mvs_bit_writer_finish(&bw));

    apple_mvs_tile_state st;
    memset(&st, 0, sizeof st);
    apple_mvs_full_coeffs fc;
    apple_mvs_bit_reader br;
    apple_mvs_bit_reader_init(&br, buf, bw.len);
    RFB_CHECK(apple_mvs_stream_decode_full(&br, 15u, 25u, &st, &fc) == RFB_OK);
    RFB_CHECK(st.valid);
    RFB_CHECK_EQ_INT(st.y[1], 1);
    RFB_CHECK_EQ_INT(st.y[2], -1);
    RFB_CHECK_EQ_INT(fc.y[1], 1);
    RFB_CHECK_EQ_INT(fc.y[2], -1);
}

// Second FULL adds into the saved coefficients (not replace).
RFB_TEST(apple_mvs_stream, lastsaved_second_full_is_differential)
{
    uint8_t buf[16];
    apple_mvs_bit_writer bw;
    apple_mvs_bit_writer_init(&bw, buf, sizeof buf);
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 2u, 6u)); // n_sig=3
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 2u, 2u)); // +1
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 2u, 2u)); // +1
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 0u, 1u));
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 0u, 1u));
    put_ac_eob_only(&bw);                             // cb AC EOB
    put_ac_eob_only(&bw);                             // cr AC EOB
    RFB_CHECK(apple_mvs_bit_writer_finish(&bw));

    apple_mvs_tile_state st;
    memset(&st, 0, sizeof st);
    st.y[1] = 5;
    st.y[2] = 10;
    st.valid = true;

    apple_mvs_full_coeffs fc;
    apple_mvs_bit_reader br;
    apple_mvs_bit_reader_init(&br, buf, bw.len);
    RFB_CHECK(apple_mvs_stream_decode_full(&br, 15u, 25u, &st, &fc) == RFB_OK);
    RFB_CHECK_EQ_INT(st.y[1], 6);
    RFB_CHECK_EQ_INT(st.y[2], 11);
    RFB_CHECK_EQ_INT(fc.y[1], 6);
    RFB_CHECK_EQ_INT(fc.y[2], 11);
}

// High-path second-form: when saved[i]!=0 use signed 3-bit (not mag).
// n_sig=16, fidelity=15 → first=15 → second-form on y[15] only.
RFB_TEST(apple_mvs_stream, second_form_uses_saved_template)
{
    uint8_t buf[64];
    apple_mvs_bit_writer bw;
    apple_mvs_bit_writer_init(&bw, buf, sizeof buf);
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 15u, 6u)); // n_sig=16
    for (int i = 0; i < 14; i++) {
        RFB_CHECK(apple_mvs_bit_writer_put(&bw, 0u, 1u)); // first-form y[1..14]
    }
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 2u, 3u)); // high second-form y[15] +2
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 0u, 1u));
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 0u, 1u));
    put_ac_eob_only(&bw);
    put_ac_eob_only(&bw);
    RFB_CHECK(apple_mvs_bit_writer_finish(&bw));

    apple_mvs_tile_state st;
    memset(&st, 0, sizeof st);
    st.y[15] = 7;
    st.valid = true;

    apple_mvs_full_coeffs fc;
    apple_mvs_bit_reader br;
    apple_mvs_bit_reader_init(&br, buf, bw.len);
    RFB_CHECK(apple_mvs_stream_decode_full(&br, 15u, 25u, &st, &fc) == RFB_OK);
    RFB_CHECK_EQ_INT(st.y[15], 9); // 7 + 2
}

// template==0 + wire not starting 00 → signed 3-bit (not always-mag).
// n_sig=16, fidelity=15 → first=15 → second-form on y[15] only (high path).
// Wire 0b010 = +2; peek of first 2 bits is 01 ≠ 00 so mag must not win.
RFB_TEST(apple_mvs_stream, second_form_template_zero_wire_peek_3bit)
{
    uint8_t buf[64];
    apple_mvs_bit_writer bw;
    apple_mvs_bit_writer_init(&bw, buf, sizeof buf);
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 15u, 6u)); // n_sig=16
    for (int i = 0; i < 14; i++) {
        RFB_CHECK(apple_mvs_bit_writer_put(&bw, 0u, 1u)); // first-form y[1..14]
    }
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 2u, 3u)); // second-form y[15] +2
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 0u, 1u));
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 0u, 1u));
    put_ac_eob_only(&bw);
    put_ac_eob_only(&bw);
    RFB_CHECK(apple_mvs_bit_writer_finish(&bw));

    apple_mvs_tile_state st;
    memset(&st, 0, sizeof st); // y[15]==0 template
    st.valid = true;

    apple_mvs_full_coeffs fc;
    apple_mvs_bit_reader br;
    apple_mvs_bit_reader_init(&br, buf, bw.len);
    RFB_CHECK(apple_mvs_stream_decode_full(&br, 15u, 25u, &st, &fc) == RFB_OK);
    RFB_CHECK_EQ_INT(st.y[15], 2);
}

// Low-path (fidelity ≤ 14) second-form uses signed 4-bit when template ≠ 0.
// n_sig=2, fidelity=1 → first=1 → second-form only for y[1].
RFB_TEST(apple_mvs_stream, second_form_low_path_uses_4bit)
{
    uint8_t buf[16];
    apple_mvs_bit_writer bw;
    apple_mvs_bit_writer_init(&bw, buf, sizeof buf);
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 1u, 6u)); // n_sig=2
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 5u, 4u)); // 4-bit +5 (not 3-bit)
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 0u, 1u));
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 0u, 1u));
    RFB_CHECK(apple_mvs_bit_writer_finish(&bw));

    apple_mvs_tile_state st;
    memset(&st, 0, sizeof st);
    st.y[1] = 3;
    st.valid = true;
    st.cb_count = 1u;
    st.cr_count = 1u;

    apple_mvs_full_coeffs fc;
    apple_mvs_bit_reader br;
    apple_mvs_bit_reader_init(&br, buf, bw.len);
    RFB_CHECK(apple_mvs_stream_decode_full(&br, 1u, 5u, &st, &fc) == RFB_OK);
    RFB_CHECK_EQ_INT(st.y[1], 8); // 3 + 5
}

// Second-form with template 0: mag path (00 prefix = zero residual).
RFB_TEST(apple_mvs_stream, second_form_mag_when_saved_zero)
{
    uint8_t buf[16];
    apple_mvs_bit_writer bw;
    apple_mvs_bit_writer_init(&bw, buf, sizeof buf);
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 1u, 6u)); // n_sig=2
    RFB_CHECK(apple_mvs_mag_put(&bw, 0));             // mag zero
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 0u, 1u));
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 0u, 1u));
    RFB_CHECK(apple_mvs_bit_writer_finish(&bw));

    apple_mvs_tile_state st;
    memset(&st, 0, sizeof st);
    st.valid = true; // y[1]==0 template

    apple_mvs_full_coeffs fc;
    apple_mvs_bit_reader br;
    apple_mvs_bit_reader_init(&br, buf, bw.len);
    RFB_CHECK(apple_mvs_stream_decode_full(&br, 1u, 5u, &st, &fc) == RFB_OK);
    RFB_CHECK_EQ_INT(st.y[1], 0);
}

// Failed decode must not write back (state unchanged).
RFB_TEST(apple_mvs_stream, lastsaved_no_writeback_on_error)
{
    uint8_t buf[2] = {0x80, 0x00}; // n_sig high but truncated body
    apple_mvs_tile_state st;
    memset(&st, 0, sizeof st);
    st.y[1] = 42;
    st.valid = true;

    apple_mvs_bit_reader br;
    apple_mvs_bit_reader_init(&br, buf, 1u); // only 8 bits → get(6) ok then fail
    // n_sig from top bits, then small_diff will run out
    rfb_error e = apple_mvs_stream_decode_full(&br, 15u, 25u, &st, NULL);
    RFB_CHECK(e != RFB_OK);
    RFB_CHECK_EQ_INT(st.y[1], 42);
    RFB_CHECK(st.valid);
}

// --- chroma AC Huffman (high-path always-AC) -------------------------------

// (+) High path (fidelity 15) + non-NULL state always runs chroma AC after the
// DC, regardless of the incoming count value. Here the slot is pre-seeded with
// cb_count=cr_count=2 (a stale value that must not gate AC). AC is consumed
// and the writeback count is 1. Cb gets one +1 at zigzag[1]; Cr is DC-only
// (EOB).
// Luma n_sig=1 → no luma residuals; chroma DC 0,0 first.
RFB_TEST(apple_mvs_stream, chroma_ac_always_runs_high_path)
{
    uint8_t buf[32];
    apple_mvs_bit_writer bw;
    apple_mvs_bit_writer_init(&bw, buf, sizeof buf);
    (void)apple_mvs_bit_writer_put(&bw, 0u, 6u);  // n_sig=1 → first=1, no luma
    (void)apple_mvs_bit_writer_put(&bw, 0u, 1u);  // cb DC small_diff = 0
    (void)apple_mvs_bit_writer_put(&bw, 0u, 1u);  // cr DC small_diff = 0
    put_ac_one_then_eob(&bw, 1);                  // Cb AC: +1 then EOB
    put_ac_eob_only(&bw);                         // Cr AC: EOB only
    RFB_CHECK(apple_mvs_bit_writer_finish(&bw));

    apple_mvs_tile_state st;
    memset(&st, 0, sizeof st);
    st.cb_count = 2u;          // stale count; must not gate AC
    st.cr_count = 2u;
    st.valid = true;

    apple_mvs_full_coeffs fc;
    apple_mvs_bit_reader br;
    apple_mvs_bit_reader_init(&br, buf, bw.len);
    const size_t left_in = apple_mvs_bit_reader_bits_left(&br);
    RFB_CHECK(apple_mvs_stream_decode_full(&br, 15u, 25u, &st, &fc) == RFB_OK);
    // AC consumed: bits_left strictly decreased past the chroma DC.
    RFB_CHECK(apple_mvs_bit_reader_bits_left(&br) < left_in);
    // First AC term (k=1) maps to natural index apple_mvs_zigzag[1].
    RFB_CHECK_EQ_INT(st.cb[apple_mvs_zigzag[1]], 1);
    RFB_CHECK_EQ_INT(fc.cb[apple_mvs_zigzag[1]], 1);
    // DC untouched by AC (small_diff was 0); adjacent AC slots zero.
    RFB_CHECK_EQ_INT(st.cb[0], 0);
    RFB_CHECK_EQ_INT(st.cb[apple_mvs_zigzag[2]], 0);
    // Cr EOB consumed no coeffs: all Cr AC stay zero.
    for (int i = 1; i < 64; i++) {
        RFB_CHECK_EQ_INT(st.cr[i], 0);
    }
    // Writeback count is 1 for both planes, not the stale 2 — count is
    // saved-coefficient validity, not an AC-length oracle.
    RFB_CHECK_EQ_UINT(st.cb_count, 1u);
    RFB_CHECK_EQ_UINT(st.cr_count, 1u);
}

// (+) Low path with zero count markers does not run chroma AC. Trailing
// AC-shaped bits remain for the caller because run_ac is false.
RFB_TEST(apple_mvs_stream, dc_only_when_fid_lt_15_count_zero_ignores_ac)
{
    uint8_t buf[32];
    apple_mvs_bit_writer bw;
    apple_mvs_bit_writer_init(&bw, buf, sizeof buf);
    (void)apple_mvs_bit_writer_put(&bw, 0u, 6u);  // n_sig=1
    (void)apple_mvs_bit_writer_put(&bw, 0u, 1u);  // cb DC
    (void)apple_mvs_bit_writer_put(&bw, 0u, 1u);  // cr DC
    // Deliberately append AC bytes after the DC — DC-only must not read them.
    put_ac_one_then_eob(&bw, 1);
    put_ac_eob_only(&bw);
    RFB_CHECK(apple_mvs_bit_writer_finish(&bw));

    apple_mvs_tile_state st;
    memset(&st, 0, sizeof st); // cb_count=cr_count=0 → DC-only
    st.valid = true;

    apple_mvs_full_coeffs fc;
    apple_mvs_bit_reader br;
    apple_mvs_bit_reader_init(&br, buf, bw.len);
    RFB_CHECK(apple_mvs_stream_decode_full(&br, 3u, 5u, &st, &fc) == RFB_OK);
    // No AC consumed: the slot the AC test writes (cb[zigzag[1]]) untouched,
    // all chroma AC zero.
    RFB_CHECK_EQ_INT(st.cb[apple_mvs_zigzag[1]], 0);
    for (int i = 1; i < 64; i++) {
        RFB_CHECK_EQ_INT(st.cb[i], 0);
        RFB_CHECK_EQ_INT(st.cr[i], 0);
    }
    // Low fidelity skips AC, so both count markers remain 0.
    RFB_CHECK_EQ_UINT(st.cb_count, 0u);
    RFB_CHECK_EQ_UINT(st.cr_count, 0u);
}

// (+) High path with non-NULL state runs AC even when entry count markers are
// zero. This first-touch state decodes Cb +1 and Cr EOB, then writes both
// markers as 1.
RFB_TEST(apple_mvs_stream, chroma_ac_runs_count_zero_high_path)
{
    uint8_t buf[32];
    apple_mvs_bit_writer bw;
    apple_mvs_bit_writer_init(&bw, buf, sizeof buf);
    (void)apple_mvs_bit_writer_put(&bw, 0u, 6u);  // n_sig=1 → no luma
    (void)apple_mvs_bit_writer_put(&bw, 0u, 1u);  // cb DC small_diff = 0
    (void)apple_mvs_bit_writer_put(&bw, 0u, 1u);  // cr DC small_diff = 0
    put_ac_one_then_eob(&bw, 1);                  // Cb AC: +1 then EOB
    put_ac_eob_only(&bw);                         // Cr AC: EOB only
    RFB_CHECK(apple_mvs_bit_writer_finish(&bw));

    apple_mvs_tile_state st;
    memset(&st, 0, sizeof st);   // cb_count=cr_count=0, !valid (first touch)

    apple_mvs_full_coeffs fc;
    apple_mvs_bit_reader br;
    apple_mvs_bit_reader_init(&br, buf, bw.len);
    RFB_CHECK(apple_mvs_stream_decode_full(&br, 15u, 25u, &st, &fc) == RFB_OK);
    // AC consumed: Cb first AC term (k=1) lands at natural zigzag[1], value +1.
    RFB_CHECK_EQ_INT(st.cb[apple_mvs_zigzag[1]], 1);
    RFB_CHECK_EQ_INT(fc.cb[apple_mvs_zigzag[1]], 1);
    RFB_CHECK_EQ_INT(st.cb[0], 0);
    // Cr DC-only payload (EOB only) consumed; no AC coeffs land.
    for (int i = 1; i < 64; i++) {
        RFB_CHECK_EQ_INT(st.cr[i], 0);
    }
    // Writeback count is 1, not the stale 0 / not MAX.
    RFB_CHECK_EQ_UINT(st.cb_count, 1u);
    RFB_CHECK_EQ_UINT(st.cr_count, 1u);
    RFB_CHECK(st.valid);
}

// (+) Entry count markers of 1 do not gate high-path AC. With non-NULL state,
// decode_full consumes Cb +1 and Cr EOB after the DC values.
RFB_TEST(apple_mvs_stream, chroma_ac_consumed_when_count_one_high_path)
{
    uint8_t buf[32];
    apple_mvs_bit_writer bw;
    apple_mvs_bit_writer_init(&bw, buf, sizeof buf);
    (void)apple_mvs_bit_writer_put(&bw, 0u, 6u);  // n_sig=1
    (void)apple_mvs_bit_writer_put(&bw, 0u, 1u);  // cb DC
    (void)apple_mvs_bit_writer_put(&bw, 0u, 1u);  // cr DC
    put_ac_one_then_eob(&bw, 1);                  // Cb AC: +1 then EOB
    put_ac_eob_only(&bw);                         // Cr AC: EOB only
    RFB_CHECK(apple_mvs_bit_writer_finish(&bw));

    apple_mvs_tile_state st;
    memset(&st, 0, sizeof st);
    st.cb_count = 1u;          // saved validity (NOT a DC-only escape)
    st.cr_count = 1u;
    st.valid = true;

    apple_mvs_full_coeffs fc;
    apple_mvs_bit_reader br;
    apple_mvs_bit_reader_init(&br, buf, bw.len);
    const size_t left_in = apple_mvs_bit_reader_bits_left(&br);
    RFB_CHECK(apple_mvs_stream_decode_full(&br, 15u, 25u, &st, &fc) == RFB_OK);
    // AC consumed: bits_left strictly decreased past the chroma DC, and the Cb
    // first AC term lands at zigzag[1].
    RFB_CHECK(apple_mvs_bit_reader_bits_left(&br) < left_in);
    RFB_CHECK_EQ_INT(st.cb[apple_mvs_zigzag[1]], 1);
    // Cr EOB consumed no coeffs.
    for (int i = 1; i < 64; i++) {
        RFB_CHECK_EQ_INT(st.cr[i], 0);
    }
    // Writeback count stays 1 (validity preserved across the AC decode).
    RFB_CHECK_EQ_UINT(st.cb_count, 1u);
    RFB_CHECK_EQ_UINT(st.cr_count, 1u);
}

// (+) Chrominance EOB short success. A chroma plane whose payload is a
// lone EOB — code 00 (2 bits) in the Annex K *chrominance* table — must decode
// true, consume only those 2 bits, and leave all AC coeffs zero. This is the
// tightest genuine EOB-class payload (under budget). Exercises the chrominance
// table directly via the AC decode entry point.
RFB_TEST(apple_mvs_stream, chrominance_eob_short_success)
{
    uint8_t buf[8];
    apple_mvs_bit_writer bw;
    apple_mvs_bit_writer_init(&bw, buf, sizeof buf);
    (void)apple_mvs_bit_writer_put(&bw, 0u, 2u);  // chrominance EOB = 00
    RFB_CHECK(apple_mvs_bit_writer_finish(&bw));

    apple_mvs_bit_reader br;
    apple_mvs_bit_reader_init(&br, buf, bw.len);
    const size_t left_in = apple_mvs_bit_reader_bits_left(&br);
    int16_t coeffs[64];
    memset(coeffs, 0, sizeof coeffs);
    coeffs[0] = 9; // DC sentinel — AC must not touch it
    RFB_CHECK(apple_mvs_jpeg_ac_decode(&br, coeffs, 1, 15));
    RFB_CHECK_EQ_INT(coeffs[0], 9);                 // DC untouched
    for (int i = 1; i < 64; i++) {
        RFB_CHECK_EQ_INT(coeffs[i], 0);             // no AC landed
    }
    RFB_CHECK_EQ_UINT(apple_mvs_bit_reader_bits_left(&br), left_in - 2u);
}

// (-) A high-path Cb Huffman failure after DC soft-continues. The reader and
// both AC planes roll back to the post-DC snapshot, DC remains, both count
// markers become 1, and decode_full returns RFB_OK. The checked sentinel keeps
// its pre-AC value across rollback.
RFB_TEST(apple_mvs_stream, ac_truncated_soft_continue)
{
    uint8_t buf[16];
    apple_mvs_bit_writer bw;
    apple_mvs_bit_writer_init(&bw, buf, sizeof buf);
    (void)apple_mvs_bit_writer_put(&bw, 0u, 6u);  // n_sig=1
    (void)apple_mvs_bit_writer_put(&bw, 0u, 1u);  // cb DC small_diff = 0
    (void)apple_mvs_bit_writer_put(&bw, 0u, 1u);  // cr DC small_diff = 0
    // Cb AC: all-ones — no chrominance Huffman code is all-ones (longest is
    // 1111111111111110), so this forces a deterministic Huffman failure even
    // with the zero-pad EOB the writer appends. In the chrominance table,
    // 0b00 is EOB and therefore succeeds.
    for (int i = 0; i < 16; i++) {
        (void)apple_mvs_bit_writer_put(&bw, 1u, 1u);
    }
    RFB_CHECK(apple_mvs_bit_writer_finish(&bw));

    apple_mvs_tile_state st;
    memset(&st, 0, sizeof st);
    st.cb_count = 2u;       // stale count; the always-AC path ignores it
    st.cr_count = 2u;
    st.cb[5] = 42;          // sentinel: AC rollback restores it
    st.cr[9] = -7;
    st.valid = true;

    apple_mvs_bit_reader br;
    apple_mvs_bit_reader_init(&br, buf, bw.len);
    rfb_error e = apple_mvs_stream_decode_full(&br, 15u, 25u, &st, NULL);
    RFB_CHECK(e == RFB_OK);                        // soft-continue, not PROTOCOL
    // Failed-plane AC rolled back: sentinel restored, all Cb AC stay at their
    // pre-AC value (the sentinel at cb[5] survives; others 0).
    RFB_CHECK_EQ_INT(st.cb[5], 42);
    // DC remains zero; RFB_OK writes both count markers as 1.
    RFB_CHECK_EQ_INT(st.cb[0], 0);
    RFB_CHECK_EQ_UINT(st.cb_count, 1u);
    RFB_CHECK_EQ_UINT(st.cr_count, 1u);
    RFB_CHECK(st.valid);
}

// (+) Cb failure rolls back the atomic Cb/Cr transaction to the post-DC reader.
// Cr is not attempted from the restored Cb bytes. decode_full returns RFB_OK
// with the retained DC values.
RFB_TEST(apple_mvs_stream, seeded_ac_soft_continue)
{
    uint8_t buf[16];
    apple_mvs_bit_writer bw;
    apple_mvs_bit_writer_init(&bw, buf, sizeof buf);
    (void)apple_mvs_bit_writer_put(&bw, 0u, 6u);  // n_sig=1 → no luma
    (void)apple_mvs_bit_writer_put(&bw, 2u, 2u);  // cb DC small_diff +1
    (void)apple_mvs_bit_writer_put(&bw, 3u, 2u);  // cr DC small_diff -1
    // No real AC payload: 16 all-one bits force a deterministic chrominance
    // Huffman failure (no chroma code is all-ones; longest is
    // 1111111111111110). The writer's trailing zero-pad is EOB-class but never
    // reached because the leading all-ones fail first.
    for (int i = 0; i < 16; i++) {
        (void)apple_mvs_bit_writer_put(&bw, 1u, 1u);
    }
    RFB_CHECK(apple_mvs_bit_writer_finish(&bw));

    apple_mvs_tile_state st;
    memset(&st, 0, sizeof st);
    st.y[3] = 7;             // prior saved luma sentinel — must survive
    st.valid = true;
    // Zero count markers do not gate high-path AC with non-NULL state.

    apple_mvs_full_coeffs fc;
    apple_mvs_bit_reader br;
    apple_mvs_bit_reader_init(&br, buf, bw.len);
    const size_t left_before = apple_mvs_bit_reader_bits_left(&br);
    rfb_error e = apple_mvs_stream_decode_full(&br, 15u, 25u, &st, &fc);
    RFB_CHECK(e == RFB_OK);                        // soft-continue, not PROTOCOL
    RFB_CHECK_EQ_INT(st.cb[0], 1);                 // DC kept (0 +1)
    RFB_CHECK_EQ_INT(st.cr[0], -1);                // DC kept (0 -1)
    RFB_CHECK_EQ_INT(st.y[3], 7);                  // prior saved luma preserved
    RFB_CHECK_EQ_INT(fc.cb[0], 1);                 // out_coeffs carries DC-only
    RFB_CHECK_EQ_INT(fc.cr[0], -1);
    // Partial AC dropped: only DC landed, all AC slots stay zero.
    for (int i = 1; i < 64; i++) {
        RFB_CHECK_EQ_INT(st.cb[i], 0);
        RFB_CHECK_EQ_INT(st.cr[i], 0);
    }
    // Atomic soft-continue writes both count markers as 1.
    RFB_CHECK_EQ_UINT(st.cb_count, 1u);
    RFB_CHECK_EQ_UINT(st.cr_count, 1u);
    // Reader restored to the pre-AC position (n_sig 6 + cb DC 2 + cr DC 2 = 10
    // bits in): the all-ones AC bits remain unconsumed (without rollback the
    // reader would sit 16 bits deeper still).
    RFB_CHECK_EQ_UINT(apple_mvs_bit_reader_bits_left(&br), left_before - 10u);
}

// Pure helper matrix for the conservative AC-consumption cutoff. `seeded`
// selects whether the supplied consumption is checked against the budget.
RFB_TEST(apple_mvs_stream, seeded_ac_over_budget_matrix)
{
    // seeded=false: return false regardless of consumption.
    RFB_CHECK(!apple_mvs_seeded_ac_over_budget(false, 1000u, 64u));
    // seeded=true below budget: return false.
    RFB_CHECK(!apple_mvs_seeded_ac_over_budget(true, 10u, 64u));
    // Equality is not over budget: return false.
    RFB_CHECK(!apple_mvs_seeded_ac_over_budget(true, 64u, 64u));
    // seeded=true above budget: return true.
    RFB_CHECK(apple_mvs_seeded_ac_over_budget(true, 65u, 64u));
}

// (-) A successful Cb AC decode over the 64-bit budget rolls back the atomic
// Cb/Cr transaction to post-DC. Cr is not attempted and decode_full returns
// RFB_OK with the DC-only result.
RFB_TEST(apple_mvs_stream, seeded_ac_success_over_budget_soft_continue)
{
    uint8_t buf[32];
    apple_mvs_bit_writer bw;
    apple_mvs_bit_writer_init(&bw, buf, sizeof buf);
    (void)apple_mvs_bit_writer_put(&bw, 0u, 6u);  // n_sig=1 → no luma
    (void)apple_mvs_bit_writer_put(&bw, 2u, 2u);  // cb DC small_diff +1
    (void)apple_mvs_bit_writer_put(&bw, 3u, 2u);  // cr DC small_diff -1
    // Cb AC: 15 × sym 0x03 (run0, sz3). Chrominance sym0x03 code = 1010
    // (4 bits), each followed by a 3-bit value (000 → -4 via receive_extend).
    // 15 terms fill the whole Cb AC band (k 1..15, then k=16 > max_k=15 exits
    // the loop) → true return consuming 15 × 7 = 105 bits (> 64 budget).
    for (int i = 0; i < 15; i++) {
        (void)apple_mvs_bit_writer_put(&bw, 0xAu, 4u); // sym 0x03 (code 1010)
        (void)apple_mvs_bit_writer_put(&bw, 0x0u, 3u); // sz3 value 000 → -4
    }
    RFB_CHECK(apple_mvs_bit_writer_finish(&bw));

    apple_mvs_tile_state st;
    memset(&st, 0, sizeof st);
    st.y[3] = 7;            // prior saved luma sentinel — must survive
    st.valid = true;
    // Zero count markers do not gate the high-path AC transaction.

    apple_mvs_full_coeffs fc;
    apple_mvs_bit_reader br;
    apple_mvs_bit_reader_init(&br, buf, bw.len);
    const size_t left_before = apple_mvs_bit_reader_bits_left(&br);
    rfb_error e = apple_mvs_stream_decode_full(&br, 15u, 25u, &st, &fc);
    RFB_CHECK(e == RFB_OK);                        // soft-continue, not PROTOCOL
    RFB_CHECK_EQ_INT(st.cb[0], 1);                 // DC kept (0 +1)
    RFB_CHECK_EQ_INT(st.cr[0], -1);                // Cr DC kept (0 -1)
    RFB_CHECK_EQ_INT(st.y[3], 7);                  // prior saved luma preserved
    RFB_CHECK_EQ_INT(fc.cb[0], 1);                 // out_coeffs carries DC-only
    RFB_CHECK_EQ_INT(fc.cr[0], -1);
    // The over-budget Cb AC result is dropped; its AC slots remain zero.
    for (int i = 1; i < 64; i++) {
        RFB_CHECK_EQ_INT(st.cb[i], 0);
    }
    // Atomic soft-continue writes both count markers as 1.
    RFB_CHECK_EQ_UINT(st.cb_count, 1u);
    RFB_CHECK_EQ_UINT(st.cr_count, 1u);
    // Reader restored to the pre-AC position: the 105 over-long AC bits remain
    // unconsumed. Pre-AC sits 10 bits past the buffer start (n_sig 6 + cb DC 2
    // + cr DC 2); without rollback the reader would be 105 bits deeper still.
    RFB_CHECK_EQ_UINT(apple_mvs_bit_reader_bits_left(&br), left_before - 10u);
}

// (-) Atomic dual-plane: after Cb AC over-budget failure, Cr must not consume
// the following EOB from the rolled-back cursor. A per-plane rollback would
// restore Cb and then let Cr consume the same bytes, advancing the reader on a
// 2-bit chroma EOB. The atomic path skips Cr and preserves the pre-AC position.
RFB_TEST(apple_mvs_stream, ac_atomic_cb_fail_skips_cr_eob)
{
    uint8_t buf[40];
    apple_mvs_bit_writer bw;
    apple_mvs_bit_writer_init(&bw, buf, sizeof buf);
    (void)apple_mvs_bit_writer_put(&bw, 0u, 6u); // n_sig=1
    (void)apple_mvs_bit_writer_put(&bw, 0u, 1u); // cb DC 0
    (void)apple_mvs_bit_writer_put(&bw, 0u, 1u); // cr DC 0
    // Over-long Cb AC: 15 × (sym0x03 + val3) = 105 bits > 64 budget.
    for (int i = 0; i < 15; i++) {
        (void)apple_mvs_bit_writer_put(&bw, 0xAu, 4u);
        (void)apple_mvs_bit_writer_put(&bw, 0x0u, 3u);
    }
    // Chrominance EOB = 2-bit 00. Independent Cr would swallow this.
    (void)apple_mvs_bit_writer_put(&bw, 0u, 2u);
    RFB_CHECK(apple_mvs_bit_writer_finish(&bw));

    apple_mvs_tile_state st;
    memset(&st, 0, sizeof st);
    st.valid = true;

    apple_mvs_bit_reader br;
    apple_mvs_bit_reader_init(&br, buf, bw.len);
    const size_t left_before = apple_mvs_bit_reader_bits_left(&br);
    RFB_CHECK(apple_mvs_stream_decode_full(&br, 15u, 25u, &st, NULL) == RFB_OK);
    // Post-DC is 8 bits in (n_sig 6 + 1 + 1). Atomic restore must leave the
    // 105-bit payload *and* the 2-bit EOB unconsumed.
    RFB_CHECK_EQ_UINT(apple_mvs_bit_reader_bits_left(&br), left_before - 8u);
    for (int i = 1; i < 64; i++) {
        RFB_CHECK_EQ_INT(st.cb[i], 0);
        RFB_CHECK_EQ_INT(st.cr[i], 0);
    }
}

// (-) Truncated chroma DC (cr DC small_diff hits EOF) is a hard PROTOCOL with
// NO writeback — the DC cannot be recovered, so AC soft-continue does not
// apply (only a failed AC *after* DC succeeds soft-continues). This guards the
// soft-continue change from accidentally swallowing a DC-side truncation.
RFB_TEST(apple_mvs_stream, chroma_dc_truncated_no_writeback)
{
    // 1 byte = 8 bits: n_sig(6) + cb DC "10" (+1, 2 bits) → cr DC has 0 bits.
    uint8_t buf[1] = {0x02u};
    apple_mvs_tile_state st;
    memset(&st, 0, sizeof st);
    st.y[1] = 42;       // sentinel — must survive (no writeback)
    st.cb[0] = 5;
    st.valid = true;

    apple_mvs_bit_reader br;
    apple_mvs_bit_reader_init(&br, buf, 1u);
    rfb_error e = apple_mvs_stream_decode_full(&br, 15u, 25u, &st, NULL);
    RFB_CHECK(e == RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(st.y[1], 42);
    RFB_CHECK_EQ_INT(st.cb[0], 5);
    RFB_CHECK(st.valid);
}

// An initialized framebuffer store maps each in-bounds tile coordinate to one slot.
RFB_TEST(apple_mvs_stream, coeff_store_fb_index)
{
    apple_mvs_coeff_store store;
    memset(&store, 0, sizeof store);
    RFB_CHECK(apple_mvs_coeff_store_ensure(&store, 32u, 16u)); // 4×2 tiles
    RFB_CHECK_EQ_UINT(store.tiles_x, 4u);
    RFB_CHECK_EQ_UINT(store.tiles_y, 2u);

    apple_mvs_tile_state *a = apple_mvs_coeff_store_at(&store, 8u, 0u);
    apple_mvs_tile_state *b = apple_mvs_coeff_store_at(&store, 8u, 0u);
    RFB_CHECK(a != NULL && a == b);
    a->y[1] = 99;
    a->valid = true;

    // A repeated lookup at the same framebuffer tile origin reuses the slot.
    apple_mvs_tile_state *c = apple_mvs_coeff_store_at(&store, 8u, 0u);
    RFB_CHECK_EQ_INT(c->y[1], 99);

    apple_mvs_coeff_store_clear(&store);
    RFB_CHECK(!store.tiles[0].valid);
    apple_mvs_coeff_store_free(&store);
    RFB_CHECK(store.tiles == NULL);
}

RFB_TEST(apple_mvs_stream, coeff_store_budget_resize_is_transactional)
{
    const size_t tile_bytes = sizeof(apple_mvs_tile_state);
    farsee_memory_budget budget;
    RFB_CHECK(farsee_memory_budget_init(&budget, rfb_default_allocator(),
                                        2u * tile_bytes));

    apple_mvs_coeff_store store;
    memset(&store, 0, sizeof store);
    RFB_CHECK(apple_mvs_coeff_store_ensure_with_allocator(
        &store, 8u, 8u, farsee_memory_budget_allocator(&budget)));
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&budget), tile_bytes);
    store.tiles[0].y[1] = 77;

    RFB_CHECK(!apple_mvs_coeff_store_ensure_with_allocator(
        &store, 16u, 8u, farsee_memory_budget_allocator(&budget)));
    RFB_CHECK_EQ_UINT(store.ntiles, 1u);
    RFB_CHECK_EQ_INT(store.tiles[0].y[1], 77);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&budget), tile_bytes);

    apple_mvs_coeff_store_free(&store);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&budget), 0u);
}

RFB_TEST(apple_mvs_stream, small_diff_rejects_invalid_and_truncated_inputs)
{
    int32_t value = 17;
    apple_mvs_bit_reader br;

    RFB_CHECK(!apple_mvs_stream_small_diff_get(NULL, &value));
    apple_mvs_bit_reader_init(&br, NULL, 0u);
    RFB_CHECK(!apple_mvs_stream_small_diff_get(&br, NULL));
    RFB_CHECK(!apple_mvs_stream_small_diff_get(&br, &value));

    /* One buffered one-bit prefix requires a second bit that is absent. */
    apple_mvs_bit_reader_init(&br, NULL, 0u);
    br.acc = 1u;
    br.free_bits = 1;
    RFB_CHECK(!apple_mvs_stream_small_diff_get(&br, &value));
    RFB_CHECK_EQ_INT(value, 17);
}

RFB_TEST(apple_mvs_stream, next_handles_trailer_eof_and_truncated_cache_id)
{
    static const uint8_t trailer[] = {0x6du, 0x76u, 0x73u};
    static const uint8_t not_a[] = {0x00u, 0x76u, 0x73u};
    static const uint8_t not_b[] = {0x6du, 0x00u, 0x73u};
    static const uint8_t not_c[] = {0x6du, 0x76u, 0x00u};
    static const uint8_t cache_id_truncated[] = {0xc0u};
    apple_mvs_bit_reader br;
    apple_mvs_tile_event event;

    RFB_CHECK(apple_mvs_stream_next(NULL, &event) == RFB_ERR_INTERNAL);
    apple_mvs_bit_reader_init(&br, NULL, 0u);
    RFB_CHECK(apple_mvs_stream_next(&br, NULL) == RFB_ERR_INTERNAL);
    RFB_CHECK(apple_mvs_stream_next(&br, &event) == RFB_OK);
    RFB_CHECK(event.kind == APPLE_MVS_KIND_EOF);

    apple_mvs_bit_reader_init(&br, trailer, sizeof trailer);
    RFB_CHECK(apple_mvs_stream_next(&br, &event) == RFB_OK);
    RFB_CHECK(event.kind == APPLE_MVS_KIND_TRAILER_MVS);
    RFB_CHECK_EQ_UINT(apple_mvs_bit_reader_bits_left(&br), 0u);

    apple_mvs_bit_reader_init(&br, not_a, sizeof not_a);
    RFB_CHECK(apple_mvs_stream_next(&br, &event) == RFB_OK);
    RFB_CHECK(event.kind == APPLE_MVS_KIND_WHITE);
    apple_mvs_bit_reader_init(&br, not_b, sizeof not_b);
    RFB_CHECK(apple_mvs_stream_next(&br, &event) == RFB_OK);
    RFB_CHECK(event.kind == APPLE_MVS_KIND_FULL);
    apple_mvs_bit_reader_init(&br, not_c, sizeof not_c);
    RFB_CHECK(apple_mvs_stream_next(&br, &event) == RFB_OK);
    RFB_CHECK(event.kind == APPLE_MVS_KIND_FULL);

    /* A buffered 11 prefix with no third bit is an incomplete cache prefix. */
    apple_mvs_bit_reader_init(&br, NULL, 0u);
    br.acc = 3u;
    br.free_bits = 2;
    RFB_CHECK(apple_mvs_stream_next(&br, &event) == RFB_ERR_PROTOCOL);

    apple_mvs_bit_reader_init(&br, cache_id_truncated,
                              sizeof cache_id_truncated);
    RFB_CHECK(apple_mvs_stream_next(&br, &event) == RFB_ERR_PROTOCOL);
}

RFB_TEST(apple_mvs_stream, low_first_form_decodes_mag_signed_and_clamps)
{
    uint8_t buf[16];
    apple_mvs_bit_writer bw;
    apple_mvs_bit_reader br;
    apple_mvs_tile_state state;
    apple_mvs_full_coeffs coeffs;

    apple_mvs_bit_writer_init(&bw, buf, sizeof buf);
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 1u, 6u));
    RFB_CHECK(apple_mvs_mag_put(&bw, 1));
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 0u, 1u));
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 0u, 1u));
    RFB_CHECK(apple_mvs_bit_writer_finish(&bw));
    memset(&state, 0, sizeof state);
    state.valid = true;
    state.y[1] = INT16_MAX;
    apple_mvs_bit_reader_init(&br, buf, bw.len);
    RFB_CHECK(apple_mvs_stream_decode_full(&br, 2u, 0u, &state, &coeffs) ==
              RFB_OK);
    RFB_CHECK_EQ_INT(state.y[1], INT16_MAX);

    apple_mvs_bit_writer_init(&bw, buf, sizeof buf);
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 1u, 6u));
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 7u, 3u));
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 0u, 1u));
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 0u, 1u));
    RFB_CHECK(apple_mvs_bit_writer_finish(&bw));
    memset(&state, 0, sizeof state);
    state.valid = true;
    state.y[1] = INT16_MIN;
    apple_mvs_bit_reader_init(&br, buf, bw.len);
    RFB_CHECK(apple_mvs_stream_decode_full(&br, 2u, 5u, &state, NULL) ==
              RFB_OK);
    RFB_CHECK_EQ_INT(state.y[1], INT16_MIN);

    apple_mvs_bit_writer_init(&bw, buf, sizeof buf);
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 1u, 6u));
    RFB_CHECK(apple_mvs_mag_put(&bw, 0));
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 0u, 1u));
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 0u, 1u));
    RFB_CHECK(apple_mvs_bit_writer_finish(&bw));
    memset(&state, 0, sizeof state);
    state.valid = true;
    state.y[1] = 42;
    apple_mvs_bit_reader_init(&br, buf, bw.len);
    RFB_CHECK(apple_mvs_stream_decode_full(&br, 2u, 5u, &state, NULL) ==
              RFB_OK);
    RFB_CHECK_EQ_INT(state.y[1], 42);

    apple_mvs_bit_writer_init(&bw, buf, sizeof buf);
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 1u, 6u));
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 15u, 4u));
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 0u, 1u));
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 0u, 1u));
    RFB_CHECK(apple_mvs_bit_writer_finish(&bw));
    memset(&state, 0, sizeof state);
    state.valid = true;
    state.y[1] = INT16_MIN;
    apple_mvs_bit_reader_init(&br, buf, bw.len);
    RFB_CHECK(apple_mvs_stream_decode_full(&br, 1u, 5u, &state, NULL) ==
              RFB_OK);
    RFB_CHECK_EQ_INT(state.y[1], INT16_MIN);
}

RFB_TEST(apple_mvs_stream, residual_forms_reject_each_truncation_boundary)
{
    apple_mvs_bit_reader br;
    apple_mvs_tile_state state;

    RFB_CHECK(apple_mvs_stream_decode_full(NULL, 15u, 25u, NULL, NULL) ==
              RFB_ERR_INTERNAL);

    apple_mvs_bit_reader_init(&br, NULL, 0u);
    RFB_CHECK(apple_mvs_stream_decode_full(&br, 15u, 25u, NULL, NULL) ==
              RFB_ERR_PROTOCOL);

    /* n_sig=2, fidelity=2: no residual bits remain for first-form peek. */
    memset(&state, 0, sizeof state);
    apple_mvs_bit_reader_init(&br, NULL, 0u);
    br.acc = 1u;
    br.free_bits = 6;
    RFB_CHECK(apple_mvs_stream_decode_full(&br, 2u, 5u, &state, NULL) ==
              RFB_ERR_PROTOCOL);

    /* The two-bit peek succeeds as 01, but the signed three-bit read fails. */
    apple_mvs_bit_reader_init(&br, NULL, 0u);
    br.acc = 5u;
    br.free_bits = 8;
    RFB_CHECK(apple_mvs_stream_decode_full(&br, 2u, 5u, &state, NULL) ==
              RFB_ERR_PROTOCOL);

    /* n_sig=2, fidelity=1: zero template cannot peek a second-form prefix. */
    apple_mvs_bit_reader_init(&br, NULL, 0u);
    br.acc = 1u;
    br.free_bits = 6;
    RFB_CHECK(apple_mvs_stream_decode_full(&br, 1u, 5u, &state, NULL) ==
              RFB_ERR_PROTOCOL);

    /* A nonzero template selects four signed bits, with only two available. */
    memset(&state, 0, sizeof state);
    state.valid = true;
    state.y[1] = 1;
    apple_mvs_bit_reader_init(&br, NULL, 0u);
    br.acc = 7u;
    br.free_bits = 8;
    RFB_CHECK(apple_mvs_stream_decode_full(&br, 1u, 5u, &state, NULL) ==
              RFB_ERR_PROTOCOL);

    /* n_sig=1 consumes six bits, then the first chroma DC is absent. */
    apple_mvs_bit_reader_init(&br, NULL, 0u);
    br.acc = 0u;
    br.free_bits = 6;
    RFB_CHECK(apple_mvs_stream_decode_full(&br, 1u, 5u, &state, NULL) ==
              RFB_ERR_PROTOCOL);
}

RFB_TEST(apple_mvs_stream, fidelity_defaults_and_caps_are_deterministic)
{
    static const uint8_t minimal[] = {0u};
    apple_mvs_bit_reader br;
    apple_mvs_full_coeffs coeffs;

    apple_mvs_bit_reader_init(&br, minimal, sizeof minimal);
    RFB_CHECK(apple_mvs_stream_decode_full(&br, 0u, 0u, NULL, &coeffs) ==
              RFB_OK);
    RFB_CHECK_EQ_UINT(coeffs.fidelity, 15u);

    apple_mvs_bit_reader_init(&br, minimal, sizeof minimal);
    RFB_CHECK(apple_mvs_stream_decode_full(&br, 65u, UINT32_MAX, NULL,
                                           &coeffs) == RFB_OK);
    RFB_CHECK_EQ_UINT(coeffs.fidelity, 15u);

    apple_mvs_bit_reader_init(&br, minimal, sizeof minimal);
    RFB_CHECK(apple_mvs_stream_decode_full(&br, 64u, UINT32_MAX, NULL,
                                           &coeffs) == RFB_OK);
    RFB_CHECK_EQ_UINT(coeffs.fidelity, 64u);
}

RFB_TEST(apple_mvs_stream, ac_failures_cover_zero_consumption_and_cr_rollback)
{
    apple_mvs_bit_reader br;
    apple_mvs_tile_state state;

    /* Exactly n_sig(6) + Cb DC(1) + Cr DC(1): Cb AC sees immediate EOF. */
    memset(&state, 0, sizeof state);
    state.valid = true;
    apple_mvs_bit_reader_init(&br, NULL, 0u);
    br.acc = 0u;
    br.free_bits = 8;
    RFB_CHECK(apple_mvs_stream_decode_full(&br, 15u, 25u, &state, NULL) ==
              RFB_OK);
    RFB_CHECK_EQ_UINT(apple_mvs_bit_reader_bits_left(&br), 0u);

    /* Cb EOB succeeds, then Cr AC sees EOF without consuming a bit. */
    memset(&state, 0, sizeof state);
    state.valid = true;
    apple_mvs_bit_reader_init(&br, NULL, 0u);
    br.acc = 0u;
    br.free_bits = 10;
    RFB_CHECK(apple_mvs_stream_decode_full(&br, 15u, 25u, &state, NULL) ==
              RFB_OK);
    RFB_CHECK_EQ_UINT(apple_mvs_bit_reader_bits_left(&br), 2u);
    RFB_CHECK_EQ_UINT(state.cb_count, 1u);
    RFB_CHECK_EQ_UINT(state.cr_count, 1u);
}

RFB_TEST(apple_mvs_stream, cr_over_budget_rolls_back_both_ac_planes)
{
    uint8_t buf[32];
    apple_mvs_bit_writer bw;
    apple_mvs_bit_reader br;
    apple_mvs_tile_state state;

    apple_mvs_bit_writer_init(&bw, buf, sizeof buf);
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 0u, 6u));
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 0u, 1u));
    RFB_CHECK(apple_mvs_bit_writer_put(&bw, 0u, 1u));
    put_ac_eob_only(&bw);
    for (int i = 0; i < 15; i++) {
        RFB_CHECK(apple_mvs_bit_writer_put(&bw, 0xau, 4u));
        RFB_CHECK(apple_mvs_bit_writer_put(&bw, 0u, 3u));
    }
    RFB_CHECK(apple_mvs_bit_writer_finish(&bw));

    memset(&state, 0, sizeof state);
    state.valid = true;
    state.cb[apple_mvs_zigzag[1]] = 19;
    state.cr[apple_mvs_zigzag[1]] = -23;
    apple_mvs_bit_reader_init(&br, buf, bw.len);
    const size_t left_before = apple_mvs_bit_reader_bits_left(&br);
    RFB_CHECK(apple_mvs_stream_decode_full(&br, 15u, 15u, &state, NULL) ==
              RFB_OK);
    RFB_CHECK_EQ_UINT(apple_mvs_bit_reader_bits_left(&br), left_before - 8u);
    RFB_CHECK_EQ_INT(state.cb[apple_mvs_zigzag[1]], 19);
    RFB_CHECK_EQ_INT(state.cr[apple_mvs_zigzag[1]], -23);
}

RFB_TEST(apple_mvs_stream, coeff_store_validates_geometry_and_callbacks)
{
    apple_mvs_coeff_store store;
    rfb_allocator invalid = *rfb_default_allocator();
    memset(&store, 0, sizeof store);

    RFB_CHECK(!apple_mvs_coeff_store_ensure(NULL, 8u, 8u));
    RFB_CHECK(!apple_mvs_coeff_store_ensure(&store, 0u, 8u));
    RFB_CHECK(!apple_mvs_coeff_store_ensure(&store, 8u, 0u));
    RFB_CHECK(!apple_mvs_coeff_store_ensure_with_allocator(
        &store, 8u, 8u, NULL));
    invalid.alloc = NULL;
    RFB_CHECK(!apple_mvs_coeff_store_ensure_with_allocator(
        &store, 8u, 8u, &invalid));
    invalid = *rfb_default_allocator();
    invalid.free = NULL;
    RFB_CHECK(!apple_mvs_coeff_store_ensure_with_allocator(
        &store, 8u, 8u, &invalid));
    RFB_CHECK(!apple_mvs_coeff_store_ensure(
        &store, UINT32_MAX, UINT32_MAX));

    RFB_CHECK(apple_mvs_coeff_store_at(NULL, 0u, 0u) == NULL);
    RFB_CHECK(apple_mvs_coeff_store_at(&store, 0u, 0u) == NULL);
    apple_mvs_coeff_store_clear(NULL);
    apple_mvs_coeff_store_clear(&store);
    apple_mvs_coeff_store_free(NULL);
    apple_mvs_coeff_store_free(&store);
}

RFB_TEST(apple_mvs_stream, coeff_store_reuses_resizes_and_rejects_oob)
{
    apple_mvs_coeff_store store;
    memset(&store, 0, sizeof store);

    RFB_CHECK(apple_mvs_coeff_store_ensure(&store, 9u, 9u));
    apple_mvs_tile_state *const first = store.tiles;
    RFB_CHECK(apple_mvs_coeff_store_ensure(&store, 9u, 9u));
    RFB_CHECK(store.tiles == first);
    RFB_CHECK_EQ_UINT(store.ntiles, 4u);

    RFB_CHECK(apple_mvs_coeff_store_at(&store, 15u, 15u) != NULL);
    RFB_CHECK(apple_mvs_coeff_store_at(&store, 16u, 0u) == NULL);
    RFB_CHECK(apple_mvs_coeff_store_at(&store, 0u, 16u) == NULL);

    const uint32_t saved_ntiles = store.ntiles;
    const uint32_t saved_tiles_x = store.tiles_x;
    store.ntiles = 1u;
    RFB_CHECK(apple_mvs_coeff_store_at(&store, 8u, 0u) == NULL);
    store.ntiles = saved_ntiles;
    store.tiles_x = 0u;
    RFB_CHECK(apple_mvs_coeff_store_at(&store, 0u, 0u) == NULL);
    store.tiles_x = saved_tiles_x;

    store.ntiles = 0u;
    apple_mvs_coeff_store_clear(&store);
    store.ntiles = saved_ntiles;

    store.tiles_y = 1u;
    RFB_CHECK(apple_mvs_coeff_store_ensure(&store, 9u, 9u));
    store.ntiles = 3u;
    RFB_CHECK(apple_mvs_coeff_store_ensure(&store, 9u, 9u));
    store.alloc = NULL;

    RFB_CHECK(apple_mvs_coeff_store_ensure(&store, 17u, 9u));
    RFB_CHECK_EQ_UINT(store.tiles_x, 3u);
    RFB_CHECK_EQ_UINT(store.tiles_y, 2u);
    store.tiles[0].valid = true;
    apple_mvs_coeff_store_clear(&store);
    RFB_CHECK(!store.tiles[0].valid);
    store.alloc = NULL;
    apple_mvs_coeff_store_free(&store);
    RFB_CHECK(store.tiles == NULL);
    RFB_CHECK_EQ_UINT(store.ntiles, 0u);
}
