// SPDX-License-Identifier: Apache-2.0
//
// Unit tests: MVS IDCT + YCbCr paint helpers.

#include "rfb_test.h"
#include "farsee/apple_mvs_bits.h"
#include "farsee/apple_mvs_dct.h"
#include "farsee/farsee_atomic.h"
#include "farsee/farsee_thread.h"

#include <string.h>

typedef struct ac_concurrent_arg {
    farsee_atomic_int *start;
    farsee_atomic_u64 *ready;
    bool ok;
} ac_concurrent_arg;

static void *decode_ac_concurrently(void *opaque)
{
    ac_concurrent_arg *arg = (ac_concurrent_arg *)opaque;
    (void)farsee_atomic_u64_fetch_add(arg->ready, 1u);
    while (!farsee_atomic_int_load_nonzero(arg->start)) {
        // Short test barrier. The main test releases all workers together.
    }
    arg->ok = true;
    for (size_t i = 0u; i < 10000u; i++) {
        const uint8_t buf[1] = { 0u };
        apple_mvs_bit_reader br;
        apple_mvs_bit_reader_init(&br, buf, sizeof buf);
        int16_t coeffs[64] = { 0 };
        apple_mvs_ac_end_reason reason = APPLE_MVS_AC_END_HUFF_FAIL;
        if (!apple_mvs_jpeg_ac_decode_reason(&br, coeffs, 1, 15, &reason) ||
            reason != APPLE_MVS_AC_END_EOB) {
            arg->ok = false;
            break;
        }
    }
    return NULL;
}

RFB_TEST(apple_mvs_dct, ac_first_use__concurrent_decoders_are_deterministic)
{
    enum { worker_count = 4 };
    farsee_atomic_int start = ATOMIC_VAR_INIT(0);
    farsee_atomic_u64 ready = ATOMIC_VAR_INIT(0u);
    ac_concurrent_arg args[worker_count];
    farsee_thread *threads[worker_count] = { NULL };
    size_t created = 0u;
    for (size_t i = 0u; i < worker_count; i++) {
        args[i] = (ac_concurrent_arg){
            .start = &start,
            .ready = &ready,
            .ok = false,
        };
        threads[i] = farsee_thread_create(decode_ac_concurrently, &args[i]);
        RFB_CHECK(threads[i] != NULL);
        if (threads[i] == NULL) {
            break;
        }
        created++;
    }
    while (farsee_atomic_u64_load(&ready) < created) {
        // Wait until every successfully created worker reaches the barrier.
    }
    farsee_atomic_int_store(&start, 1);
    for (size_t i = 0u; i < created; i++) {
        farsee_thread_join(&threads[i], NULL);
        RFB_CHECK(args[i].ok);
    }
}

RFB_TEST(apple_mvs_dct, ac_decode__invalid_arguments_report_huffman_failure)
{
    uint8_t bits[1] = { 0u };
    apple_mvs_bit_reader br;
    apple_mvs_bit_reader_init(&br, bits, sizeof bits);
    int16_t coeffs[64] = { 0 };
    apple_mvs_ac_end_reason reason = APPLE_MVS_AC_END_EOB;

    RFB_CHECK(!apple_mvs_jpeg_ac_decode_reason(
        NULL, coeffs, 0, 63, &reason));
    RFB_CHECK_EQ_INT(reason, APPLE_MVS_AC_END_HUFF_FAIL);
    RFB_CHECK(!apple_mvs_jpeg_ac_decode_reason(
        &br, NULL, 0, 63, NULL));
    RFB_CHECK(!apple_mvs_jpeg_ac_decode_reason(
        &br, coeffs, -1, 63, &reason));
    RFB_CHECK_EQ_INT(reason, APPLE_MVS_AC_END_HUFF_FAIL);
    RFB_CHECK(!apple_mvs_jpeg_ac_decode_reason(
        &br, coeffs, 0, 64, NULL));
}

RFB_TEST(apple_mvs_dct, idct_dc_only_is_constant)
{
    int16_t in[64];
    int16_t out[64];
    memset(in, 0, sizeof in);
    in[0] = 8 * 128; // strong DC
    apple_mvs_idct_8x8(in, out);
    // All spatial samples similar (DC block)
    int minv = out[0], maxv = out[0];
    for (int i = 1; i < 64; i++) {
        if (out[i] < minv) {
            minv = out[i];
        }
        if (out[i] > maxv) {
            maxv = out[i];
        }
    }
    RFB_CHECK(maxv - minv < 4);
}

RFB_TEST(apple_mvs_dct, ycbcr_tile_writes_rgba)
{
    int16_t y[64], cb[64], cr[64];
    memset(y, 0, sizeof y);
    memset(cb, 0, sizeof cb);
    memset(cr, 0, sizeof cr);
    // Y=0 → mid gray after +128
    uint8_t rgba[8 * 8 * 4];
    memset(rgba, 0xcd, sizeof rgba);
    apple_mvs_ycbcr_tile_to_rgba(y, cb, cr, rgba, 8 * 4, 8, 8);
    RFB_CHECK_EQ_UINT(rgba[0], 128u);
    RFB_CHECK_EQ_UINT(rgba[1], 128u);
    RFB_CHECK_EQ_UINT(rgba[2], 128u);
    RFB_CHECK_EQ_UINT(rgba[3], 255u);
}

RFB_TEST(apple_mvs_dct, zigzag_is_permutation)
{
    bool seen[64];
    memset(seen, 0, sizeof seen);
    for (int i = 0; i < 64; i++) {
        uint8_t z = apple_mvs_zigzag[i];
        RFB_CHECK(z < 64u);
        RFB_CHECK(!seen[z]);
        seen[z] = true;
    }
}

// AC end-reason out-param.
// It distinguishes EOB, max-band exit, and Huffman failure without re-parsing.
// The reason pointer may be NULL.

// EOB: chrominance EOB = 00 (2 bits) ends the loop at k=1.
RFB_TEST(apple_mvs_dct, ac_end_reason_eob)
{
    uint8_t buf[4];
    apple_mvs_bit_writer bw;
    apple_mvs_bit_writer_init(&bw, buf, sizeof buf);
    (void)apple_mvs_bit_writer_put(&bw, 0u, 2u); // chrominance EOB 00
    (void)apple_mvs_bit_writer_finish(&bw);

    apple_mvs_bit_reader br;
    apple_mvs_bit_reader_init(&br, buf, bw.len);
    int16_t coeffs[64];
    memset(coeffs, 0, sizeof coeffs);
    apple_mvs_ac_end_reason r = (apple_mvs_ac_end_reason)99;
    RFB_CHECK(apple_mvs_jpeg_ac_decode_reason(&br, coeffs, 1, 15, &r));
    RFB_CHECK_EQ_INT((int)r, (int)APPLE_MVS_AC_END_EOB);
    // A NULL reason pointer exercises the same decode path as the thin wrapper.
    apple_mvs_bit_reader_init(&br, buf, bw.len);
    memset(coeffs, 0, sizeof coeffs);
    RFB_CHECK(apple_mvs_jpeg_ac_decode_reason(&br, coeffs, 1, 15, NULL));
}

// max: loop exits because k > max_k (k0=1, max_k=1 → one EOB-free exit only
// after a coefficient lands at k=1, then k=2 > 1). Use sym0x01 (sz1,run0) so a
// coefficient lands at k=1, k becomes 2 > max_k=1 → exit via max.
RFB_TEST(apple_mvs_dct, ac_end_reason_max)
{
    uint8_t buf[4];
    apple_mvs_bit_writer bw;
    apple_mvs_bit_writer_init(&bw, buf, sizeof buf);
    (void)apple_mvs_bit_writer_put(&bw, 1u, 2u);  // sym0x01 (chroma code 01)
    (void)apple_mvs_bit_writer_put(&bw, 1u, 1u);  // sz1 value 1 → +1
    (void)apple_mvs_bit_writer_finish(&bw);

    apple_mvs_bit_reader br;
    apple_mvs_bit_reader_init(&br, buf, bw.len);
    int16_t coeffs[64];
    memset(coeffs, 0, sizeof coeffs);
    apple_mvs_ac_end_reason r = (apple_mvs_ac_end_reason)99;
    RFB_CHECK(apple_mvs_jpeg_ac_decode_reason(&br, coeffs, 1, 1, &r));
    RFB_CHECK_EQ_INT((int)r, (int)APPLE_MVS_AC_END_MAX);
    RFB_CHECK_EQ_INT(coeffs[apple_mvs_zigzag[1]], 1);
}

// JPEG receive-extend negative branch: sz1 value bit 0 decodes to -1 without
// shifting a negative value.
RFB_TEST(apple_mvs_dct, ac_negative_receive_extend_is_defined)
{
    uint8_t buf[4];
    apple_mvs_bit_writer bw;
    apple_mvs_bit_writer_init(&bw, buf, sizeof buf);
    (void)apple_mvs_bit_writer_put(&bw, 1u, 2u); // sym0x01 (chroma code 01)
    (void)apple_mvs_bit_writer_put(&bw, 0u, 1u); // sz1 value 0 -> -1
    (void)apple_mvs_bit_writer_finish(&bw);

    apple_mvs_bit_reader br;
    apple_mvs_bit_reader_init(&br, buf, bw.len);
    int16_t coeffs[64];
    memset(coeffs, 0, sizeof coeffs);
    apple_mvs_ac_end_reason r = (apple_mvs_ac_end_reason)99;
    RFB_CHECK(apple_mvs_jpeg_ac_decode_reason(&br, coeffs, 1, 1, &r));
    RFB_CHECK_EQ_INT((int)r, (int)APPLE_MVS_AC_END_MAX);
    RFB_CHECK_EQ_INT(coeffs[apple_mvs_zigzag[1]], -1);
}

// huff_fail: all-ones is not a chrominance Huffman code (longest is
// 1111111111111110) → deterministic Huffman failure.
RFB_TEST(apple_mvs_dct, ac_end_reason_huff_fail)
{
    uint8_t buf[4];
    apple_mvs_bit_writer bw;
    apple_mvs_bit_writer_init(&bw, buf, sizeof buf);
    for (int i = 0; i < 16; i++) {
        (void)apple_mvs_bit_writer_put(&bw, 1u, 1u);
    }
    (void)apple_mvs_bit_writer_finish(&bw);

    apple_mvs_bit_reader br;
    apple_mvs_bit_reader_init(&br, buf, bw.len);
    int16_t coeffs[64];
    memset(coeffs, 0, sizeof coeffs);
    apple_mvs_ac_end_reason r = (apple_mvs_ac_end_reason)99;
    RFB_CHECK(!apple_mvs_jpeg_ac_decode_reason(&br, coeffs, 1, 15, &r));
    RFB_CHECK_EQ_INT((int)r, (int)APPLE_MVS_AC_END_HUFF_FAIL);
}

// Exercise every coefficient position at INT16_MIN/INT16_MAX, including an
// alternating-sign pattern. The int64 intermediates keep these public inputs
// defined.
RFB_TEST(apple_mvs_dct, idct_extreme_coefficients_do_not_overflow)
{
    int16_t in[64];
    int16_t out[64];
    for (int pattern = 0; pattern < 3; pattern++) {
        for (int i = 0; i < 64; i++) {
            const int16_t big = (pattern == 0) ? INT16_MAX : INT16_MIN;
            in[i] = (pattern == 2) ? (int16_t)((i & 1) ? INT16_MIN : INT16_MAX)
                                   : big;
        }
        apple_mvs_idct_8x8(in, out);
        // This test has no value oracle; sanitizer-clean execution is the assertion.
        RFB_CHECK(out[0] == out[0]);
    }
}

// Check the horizontal and vertical basis functions for coefficient 1 at 64.
RFB_TEST(apple_mvs_dct, idct_single_basis_function_is_stable)
{
    int16_t in[64];
    int16_t out[64];
    memset(in, 0, sizeof in);
    in[1] = 64;   // horizontal frequency 1
    apple_mvs_idct_8x8(in, out);
    static const int16_t expect[8] = {11, 9, 6, 2, -2, -6, -9, -11};
    for (int y = 0; y < 8; y++) {
        for (int x = 0; x < 8; x++) {
            RFB_CHECK_EQ_INT(out[y * 8 + x], expect[x]);
        }
    }
    memset(in, 0, sizeof in);
    in[8] = 64;   // vertical frequency 1
    apple_mvs_idct_8x8(in, out);
    for (int y = 0; y < 8; y++) {
        for (int x = 0; x < 8; x++) {
            RFB_CHECK_EQ_INT(out[y * 8 + x], expect[y]);
        }
    }
}
