// SPDX-License-Identifier: Apache-2.0
//
// G8 — zlib adapter tests (plan.md §G8).
//
// Tests the zlib inflate wrapper: round-trip (compress→decompress),
// persistent stream across calls, output-cap enforcement, and reset.

#include "rfb_test.h"
#include "farsee/memory_budget.h"
#include "farsee/zlib_adapter.h"

#include <zlib.h>
#include <limits.h>
#include <string.h>

// Helper: compress data with zlib so we have something to inflate.
static size_t compress_data(const uint8_t *src, size_t src_len,
                            uint8_t *dst, size_t dst_cap)
{
    uLongf out_len = dst_cap;
    if (compress2(dst, &out_len, src, src_len, Z_DEFAULT_COMPRESSION) != Z_OK) {
        return 0;
    }
    return (size_t)out_len;
}

static size_t compress_sync_flush(const uint8_t *src, size_t src_len,
                                  uint8_t *dst, size_t dst_cap)
{
    z_stream zs;
    memset(&zs, 0, sizeof zs);
    if (deflateInit(&zs, Z_DEFAULT_COMPRESSION) != Z_OK) {
        return 0u;
    }
    zs.next_in = (Bytef *)(uintptr_t)src;
    zs.avail_in = (uInt)src_len;
    zs.next_out = dst;
    zs.avail_out = (uInt)dst_cap;
    const int rc = deflate(&zs, Z_SYNC_FLUSH);
    const size_t written = dst_cap - (size_t)zs.avail_out;
    (void)deflateEnd(&zs);
    return rc == Z_OK && zs.avail_in == 0u ? written : 0u;
}

typedef struct zlib_reject_allocator {
    size_t alloc_calls;
    size_t free_calls;
} zlib_reject_allocator;

static void *zlib_reject_alloc(rfb_allocator *allocator, size_t size)
{
    (void)size;
    zlib_reject_allocator *reject =
        (zlib_reject_allocator *)allocator->user;
    reject->alloc_calls += 1u;
    return NULL;
}

static void zlib_reject_free(rfb_allocator *allocator, void *allocation)
{
    (void)allocation;
    zlib_reject_allocator *reject =
        (zlib_reject_allocator *)allocator->user;
    reject->free_calls += 1u;
}

RFB_TEST(zlib, zlib__create_destroy__no_leak) {
    rfb_zlib_stream *s = rfb_zlib_create();
    RFB_CHECK(s != NULL);
    rfb_zlib_destroy(s);
    rfb_zlib_destroy(NULL);  // safe
}

RFB_TEST(zlib, budget_allocator_accounts_for_object_and_scratch)
{
    farsee_memory_budget budget;
    RFB_CHECK(farsee_memory_budget_init(&budget, rfb_default_allocator(),
                                        8192u));
    rfb_zlib_stream *s = rfb_zlib_create_with_allocator(
        farsee_memory_budget_allocator(&budget));
    RFB_CHECK(s != NULL);
    const size_t object_bytes = farsee_memory_budget_used(&budget);
    RFB_CHECK(object_bytes > 0u);
    RFB_CHECK(rfb_zlib_ensure_scratch(s, 1024u) != NULL);
    RFB_CHECK(farsee_memory_budget_used(&budget) > object_bytes);
    rfb_zlib_destroy(s);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&budget), 0u);
}

RFB_TEST(zlib, budget_rejects_scratch_growth_transactionally)
{
    farsee_memory_budget budget;
    RFB_CHECK(farsee_memory_budget_init(&budget, rfb_default_allocator(),
                                        4608u));
    rfb_zlib_stream *s = rfb_zlib_create_with_allocator(
        farsee_memory_budget_allocator(&budget));
    RFB_CHECK(s != NULL);
    uint8_t *original = rfb_zlib_ensure_scratch(s, 1024u);
    RFB_CHECK(original != NULL);
    original[0] = 0x5au;
    const size_t before = farsee_memory_budget_used(&budget);
    RFB_CHECK(rfb_zlib_ensure_scratch(s, 4097u) == NULL);
    RFB_CHECK_EQ_UINT(rfb_zlib_scratch_cap(s), 4096u);
    RFB_CHECK_EQ_UINT(original[0], 0x5au);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&budget), before);
    rfb_zlib_destroy(s);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&budget), 0u);
}

RFB_TEST(zlib, zlib__round_trip_short__matches_original) {
    static const uint8_t input[] = "Hello, ZRLE world! This is test data.";
    uint8_t compressed[256];
    size_t comp_len = compress_data(input, sizeof input - 1, compressed, sizeof compressed);
    RFB_CHECK(comp_len > 0);

    rfb_zlib_stream *s = rfb_zlib_create();
    RFB_CHECK(s != NULL);
    uint8_t output[256] = { 0 };
    size_t out_len = 0;
    RFB_CHECK_EQ_INT(
        rfb_zlib_inflate(s, compressed, comp_len, output, sizeof output, &out_len),
        RFB_OK);
    RFB_CHECK_EQ_UINT(out_len, sizeof input - 1);
    RFB_CHECK_MEM_EQ(output, input, sizeof input - 1);
    rfb_zlib_destroy(s);
}

RFB_TEST(zlib, zlib__output_cap_too_small__returns_limit) {
    static const uint8_t input[] = "This is longer than the output cap.";
    uint8_t compressed[256];
    size_t comp_len = compress_data(input, sizeof input - 1, compressed, sizeof compressed);
    RFB_CHECK(comp_len > 0);

    rfb_zlib_stream *s = rfb_zlib_create();
    uint8_t output[8] = { 0 };  // too small
    size_t out_len = 0;
    RFB_CHECK_EQ_INT(
        rfb_zlib_inflate(s, compressed, comp_len, output, sizeof output, &out_len),
        RFB_ERR_LIMIT);
    rfb_zlib_destroy(s);
}

RFB_TEST(zlib, zlib__persistent_stream__two_inflate_calls_share_context) {
    // ZRLE uses one persistent zlib stream across rectangles. Compress
    // two chunks separately (as flush-blocks) and inflate them through
    // the same stream; the result must be the concatenation.
    static const uint8_t chunk_a[] = "AAAAAAAABBBBBBBB";
    static const uint8_t chunk_b[] = "CCCCCCCCDDDDDDDD";

    // Compress both into one stream using Z_SYNC_FLUSH between them.
    z_stream zs;
    memset(&zs, 0, sizeof zs);
    deflateInit(&zs, Z_DEFAULT_COMPRESSION);
    uint8_t comp[256];
    zs.next_out = comp;
    zs.avail_out = sizeof comp;
    zs.next_in = (Bytef *)(uintptr_t)chunk_a;
    zs.avail_in = sizeof chunk_a - 1;
    deflate(&zs, Z_SYNC_FLUSH);
    zs.next_in = (Bytef *)(uintptr_t)chunk_b;
    zs.avail_in = sizeof chunk_b - 1;
    deflate(&zs, Z_FINISH);
    size_t comp_len = zs.total_out;
    deflateEnd(&zs);

    rfb_zlib_stream *s = rfb_zlib_create();
    uint8_t output[256] = { 0 };
    size_t out_len = 0;
    RFB_CHECK_EQ_INT(
        rfb_zlib_inflate(s, comp, comp_len, output, sizeof output, &out_len),
        RFB_OK);
    // Expected: concatenation of both chunks.
    RFB_CHECK_EQ_UINT(out_len, (sizeof chunk_a - 1) + (sizeof chunk_b - 1));
    RFB_CHECK_MEM_EQ(output, chunk_a, sizeof chunk_a - 1);
    RFB_CHECK_MEM_EQ(output + (sizeof chunk_a - 1), chunk_b, sizeof chunk_b - 1);
    rfb_zlib_destroy(s);
}

RFB_TEST(zlib, zlib__reset__starts_fresh) {
    static const uint8_t input[] = "reset test";
    uint8_t compressed[128];
    size_t comp_len = compress_data(input, sizeof input - 1, compressed, sizeof compressed);
    RFB_CHECK(comp_len > 0);

    rfb_zlib_stream *s = rfb_zlib_create();
    uint8_t output[128] = { 0 };
    size_t out_len = 0;
    // First inflate works.
    RFB_CHECK_EQ_INT(
        rfb_zlib_inflate(s, compressed, comp_len, output, sizeof output, &out_len),
        RFB_OK);
    RFB_CHECK_EQ_UINT(out_len, sizeof input - 1);
    // Reset, then inflate the same compressed data again.
    RFB_CHECK_EQ_INT(rfb_zlib_reset(s), RFB_OK);
    out_len = 0;
    memset(output, 0, sizeof output);
    RFB_CHECK_EQ_INT(
        rfb_zlib_inflate(s, compressed, comp_len, output, sizeof output, &out_len),
        RFB_OK);
    RFB_CHECK_EQ_UINT(out_len, sizeof input - 1);
    RFB_CHECK_MEM_EQ(output, input, sizeof input - 1);
    rfb_zlib_destroy(s);
}

RFB_TEST(zlib, zlib__corrupt_input__returns_protocol_error) {
    rfb_zlib_stream *s = rfb_zlib_create();
    static const uint8_t garbage[16] = { 0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0 };
    uint8_t output[64] = { 0 };
    size_t out_len = 0;
    RFB_CHECK_EQ_INT(
        rfb_zlib_inflate(s, garbage, sizeof garbage, output, sizeof output, &out_len),
        RFB_ERR_PROTOCOL);
    rfb_zlib_destroy(s);
}

RFB_TEST(zlib, create__rejects_invalid_and_failing_allocators)
{
    zlib_reject_allocator reject = { 0u, 0u };
    rfb_allocator missing_alloc = {
        .alloc = NULL,
        .free = zlib_reject_free,
        .user = &reject,
    };
    rfb_allocator missing_free = {
        .alloc = zlib_reject_alloc,
        .free = NULL,
        .user = &reject,
    };
    rfb_allocator rejecting = {
        .alloc = zlib_reject_alloc,
        .free = zlib_reject_free,
        .user = &reject,
    };

    RFB_CHECK(rfb_zlib_create_with_allocator(NULL) == NULL);
    RFB_CHECK(rfb_zlib_create_with_allocator(&missing_alloc) == NULL);
    RFB_CHECK(rfb_zlib_create_with_allocator(&missing_free) == NULL);
    RFB_CHECK_EQ_UINT(reject.alloc_calls, 0u);
    RFB_CHECK(rfb_zlib_create_with_allocator(&rejecting) == NULL);
    RFB_CHECK_EQ_UINT(reject.alloc_calls, 1u);
    RFB_CHECK_EQ_UINT(reject.free_calls, 0u);
}

RFB_TEST(zlib, scratch__covers_null_zero_reuse_and_geometric_growth)
{
    RFB_CHECK(rfb_zlib_ensure_scratch(NULL, 1u) == NULL);
    RFB_CHECK_EQ_UINT(rfb_zlib_scratch_cap(NULL), 0u);

    rfb_zlib_stream *s = rfb_zlib_create();
    RFB_CHECK(s != NULL);
    if (s == NULL) {
        return;
    }
    RFB_CHECK(rfb_zlib_ensure_scratch(s, 0u) == NULL);
    RFB_CHECK_EQ_UINT(rfb_zlib_scratch_cap(s), 0u);

    uint8_t *first = rfb_zlib_ensure_scratch(s, 1u);
    RFB_CHECK(first != NULL);
    RFB_CHECK_EQ_UINT(rfb_zlib_scratch_cap(s), 4096u);
    first[0] = 0x5au;
    RFB_CHECK(rfb_zlib_ensure_scratch(s, 4096u) == first);
    RFB_CHECK_EQ_UINT(first[0], 0x5au);

    uint8_t *grown = rfb_zlib_ensure_scratch(s, 4097u);
    RFB_CHECK(grown != NULL);
    RFB_CHECK_EQ_UINT(rfb_zlib_scratch_cap(s), 8192u);
    RFB_CHECK_EQ_UINT(grown[0], 0x5au);
    rfb_zlib_destroy(s);
}

RFB_TEST(zlib, inflate__rejects_null_arguments_and_empty_progress)
{
    static const uint8_t byte = 0u;
    uint8_t output[1] = { 0u };
    size_t out_len = 99u;
    rfb_zlib_stream *s = rfb_zlib_create();
    RFB_CHECK(s != NULL);
    if (s == NULL) {
        return;
    }

    RFB_CHECK_EQ_INT(rfb_zlib_inflate(NULL, &byte, 1u, output,
                                      sizeof output, &out_len),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(rfb_zlib_inflate(s, NULL, 1u, output, sizeof output,
                                      &out_len),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(rfb_zlib_inflate(s, &byte, 1u, NULL, sizeof output,
                                      &out_len),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(rfb_zlib_inflate(s, &byte, 1u, output, sizeof output,
                                      NULL),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_UINT(out_len, 99u);
    RFB_CHECK_EQ_INT(rfb_zlib_inflate(s, &byte, 0u, output, sizeof output,
                                      &out_len),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_UINT(out_len, 0u);
    RFB_CHECK_EQ_INT(rfb_zlib_reset(NULL), RFB_ERR_INTERNAL);
    rfb_zlib_destroy(s);
}

RFB_TEST(zlib, inflate__distinguishes_zero_exact_and_trailing_capacity)
{
    static const uint8_t input[] = "exact output";
    uint8_t compressed[128] = { 0u };
    const size_t input_len = sizeof input - 1u;
    const size_t compressed_len =
        compress_data(input, input_len, compressed, sizeof compressed - 1u);
    RFB_CHECK(compressed_len > 0u);
    compressed[compressed_len] = 0u;

    rfb_zlib_stream *s = rfb_zlib_create();
    RFB_CHECK(s != NULL);
    if (s == NULL) {
        return;
    }
    uint8_t output[sizeof input - 1u] = { 0u };
    size_t out_len = 99u;
    RFB_CHECK_EQ_INT(rfb_zlib_inflate(s, compressed, compressed_len, output,
                                      0u, &out_len),
                     RFB_ERR_LIMIT);
    RFB_CHECK_EQ_UINT(out_len, 0u);

    RFB_CHECK_EQ_INT(rfb_zlib_reset(s), RFB_OK);
    RFB_CHECK_EQ_INT(rfb_zlib_inflate(s, compressed, compressed_len, output,
                                      sizeof output, &out_len),
                     RFB_OK);
    RFB_CHECK_EQ_UINT(out_len, input_len);
    RFB_CHECK_MEM_EQ(output, input, input_len);

    RFB_CHECK_EQ_INT(rfb_zlib_inflate(s, compressed, compressed_len + 1u,
                                      output, sizeof output, &out_len),
                     RFB_ERR_LIMIT);
    RFB_CHECK_EQ_UINT(out_len, input_len);
    RFB_CHECK_EQ_INT(rfb_zlib_inflate(s, compressed, compressed_len, output,
                                      sizeof output, &out_len),
                     RFB_OK);
    RFB_CHECK_MEM_EQ(output, input, input_len);
    rfb_zlib_destroy(s);
}

RFB_TEST(zlib, validate_exact__covers_arguments_lengths_and_trailing_data)
{
    static const uint8_t input[] = "independent stream";
    static const uint8_t byte = 0u;
    uint8_t compressed[128] = { 0u };
    const size_t input_len = sizeof input - 1u;
    const size_t compressed_len =
        compress_data(input, input_len, compressed, sizeof compressed - 1u);
    RFB_CHECK(compressed_len > 0u);

    RFB_CHECK_EQ_INT(rfb_zlib_validate_independent_exact_output(
                         NULL, compressed_len, input_len),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(rfb_zlib_validate_independent_exact_output(
                         compressed, 0u, input_len),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(rfb_zlib_validate_independent_exact_output(
                         compressed, compressed_len, 0u),
                     RFB_ERR_INTERNAL);
#if SIZE_MAX > UINT_MAX
    RFB_CHECK_EQ_INT(rfb_zlib_validate_independent_exact_output(
                         &byte, (size_t)UINT_MAX + 1u, 1u),
                     RFB_ERR_LIMIT);
#else
    (void)byte;
#endif

    RFB_CHECK_EQ_INT(rfb_zlib_validate_independent_exact_output(
                         compressed, compressed_len, input_len),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_zlib_validate_independent_exact_output(
                         compressed, compressed_len, input_len - 1u),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(rfb_zlib_validate_independent_exact_output(
                         compressed, compressed_len, input_len + 1u),
                     RFB_ERR_PROTOCOL);
    compressed[compressed_len] = 0u;
    RFB_CHECK_EQ_INT(rfb_zlib_validate_independent_exact_output(
                         compressed, compressed_len + 1u, input_len),
                     RFB_ERR_PROTOCOL);
}

RFB_TEST(zlib, validate_exact__accepts_flush_stream_and_large_output)
{
    static const uint8_t flushed_input[] = "sync-flushed rectangle";
    uint8_t flushed[128] = { 0u };
    const size_t flushed_len = compress_sync_flush(
        flushed_input, sizeof flushed_input - 1u, flushed, sizeof flushed);
    RFB_CHECK(flushed_len > 0u);
    RFB_CHECK_EQ_INT(rfb_zlib_validate_independent_exact_output(
                         flushed, flushed_len, sizeof flushed_input - 1u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_zlib_validate_independent_exact_output(
                         flushed, flushed_len, sizeof flushed_input),
                     RFB_ERR_PROTOCOL);

    uint8_t large_input[5000];
    for (size_t i = 0u; i < sizeof large_input; i++) {
        large_input[i] = (uint8_t)(i & 0xffu);
    }
    uint8_t compressed[5500] = { 0u };
    const size_t compressed_len = compress_data(
        large_input, sizeof large_input, compressed, sizeof compressed);
    RFB_CHECK(compressed_len > 0u);
    RFB_CHECK_EQ_INT(rfb_zlib_validate_independent_exact_output(
                         compressed, compressed_len, sizeof large_input),
                     RFB_OK);
}

RFB_TEST(zlib, inflate_independent_exact__copies_only_exact_complete_output)
{
    static const uint8_t input[] = "independent output";
    uint8_t compressed[128] = {0u};
    const size_t input_len = sizeof input - 1u;
    const size_t compressed_len = compress_sync_flush(
        input, input_len, compressed, sizeof compressed - 1u);
    RFB_CHECK(compressed_len > 0u);

    uint8_t output[sizeof input];
    memset(output, 0xa5, sizeof output);
    RFB_CHECK_EQ_INT(rfb_zlib_inflate_independent_exact_output(
                         compressed, compressed_len, output, input_len),
                     RFB_OK);
    RFB_CHECK_MEM_EQ(output, input, input_len);
    RFB_CHECK_EQ_INT(rfb_zlib_inflate_independent_exact_output(
                         compressed, compressed_len, NULL, input_len),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(rfb_zlib_inflate_independent_exact_output(
                         compressed, compressed_len, output, input_len - 1u),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(rfb_zlib_inflate_independent_exact_output(
                         compressed, compressed_len, output, input_len + 1u),
                     RFB_ERR_PROTOCOL);
    compressed[0] = 0u;
    RFB_CHECK_EQ_INT(rfb_zlib_inflate_independent_exact_output(
                         compressed, compressed_len, output, input_len),
                     RFB_ERR_PROTOCOL);
}
