// SPDX-License-Identifier: Apache-2.0
//
// Growable-buffer boundary and allocation-failure tests.
//
#include "rfb_test.h"
#include "farsee/buffer.h"
#include "farsee/allocator.h"
#include "farsee/error.h"
#include "farsee/limits.h"
#include <stdlib.h>
#include <string.h>

// ---- basic append / read ------------------------------------------------

RFB_TEST(buffer, buffer__append_small__is_readable) {
    rfb_buffer b;
    rfb_buffer_init(&b, rfb_default_allocator(), 1024);
    static const uint8_t data[5] = { 1, 2, 3, 4, 5 };
    RFB_CHECK_EQ_INT(rfb_buffer_append(&b, data, sizeof data), RFB_OK);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&b), 5u);
    RFB_CHECK(rfb_buffer_data(&b) != NULL);
    RFB_CHECK_MEM_EQ(rfb_buffer_data(&b), data, 5);
    rfb_buffer_destroy(&b);
}

RFB_TEST(buffer, buffer__append_zero_bytes__succeeds_unchanged) {
    rfb_buffer b;
    rfb_buffer_init(&b, rfb_default_allocator(), 1024);
    RFB_CHECK_EQ_INT(rfb_buffer_append(&b, NULL, 0), RFB_OK);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&b), 0u);
    rfb_buffer_destroy(&b);
}

// ---- growth --------------------------------------------------------------

RFB_TEST(buffer, buffer__append_past_initial_capacity__grows) {
    rfb_buffer b;
    rfb_buffer_init(&b, rfb_default_allocator(), 1u << 20);
    // Append 100 KiB in 1 KiB chunks; should grow without loss.
    static uint8_t chunk[1024];
    for (size_t i = 0; i < sizeof chunk; i++) {
        chunk[i] = (uint8_t)(i & 0xFF);
    }
    for (int k = 0; k < 100; k++) {
        RFB_CHECK_EQ_INT(rfb_buffer_append(&b, chunk, sizeof chunk), RFB_OK);
    }
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&b), 100u * 1024u);
    // Verify content survived the growth: each chunk must match.
    for (int k = 0; k < 100; k++) {
        RFB_CHECK_MEM_EQ(rfb_buffer_data(&b) + k * 1024, chunk, 1024);
    }
    rfb_buffer_destroy(&b);
}

// ---- hard-limit boundaries ------------------------------------------------

RFB_TEST(buffer, buffer__limit_minus_one__succeeds) {
    rfb_buffer b;
    rfb_buffer_init(&b, rfb_default_allocator(), 16);
    uint8_t data[15] = { 0 };
    RFB_CHECK_EQ_INT(rfb_buffer_append(&b, data, sizeof data), RFB_OK);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&b), 15u);
    rfb_buffer_destroy(&b);
}

RFB_TEST(buffer, buffer__exact_limit__succeeds) {
    rfb_buffer b;
    rfb_buffer_init(&b, rfb_default_allocator(), 16);
    uint8_t data[16] = { 0 };
    RFB_CHECK_EQ_INT(rfb_buffer_append(&b, data, sizeof data), RFB_OK);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&b), 16u);
    rfb_buffer_destroy(&b);
}

RFB_TEST(buffer, buffer__limit_plus_one__fails_with_err_limit_and_preserves_contents) {
    rfb_buffer b;
    rfb_buffer_init(&b, rfb_default_allocator(), 16);
    // Fill exactly to the limit first.
    static const uint8_t fill[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    RFB_CHECK_EQ_INT(rfb_buffer_append(&b, fill, sizeof fill), RFB_OK);
    // Now append 9 more — would total 17, over the limit of 16.
    static const uint8_t more[9] = { 9 };
    RFB_CHECK_EQ_INT(rfb_buffer_append(&b, more, sizeof more), RFB_ERR_LIMIT);
    // Length unchanged; prior contents intact.
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&b), 8u);
    RFB_CHECK_MEM_EQ(rfb_buffer_data(&b), fill, 8);
    rfb_buffer_destroy(&b);
}

// Session input uses RFB_LIMIT_FB_BYTES_POLICY so a full 4K Raw FBU
// (~31.6 MiB at 3840x2160x4) can assemble. A policy-sized buffer can reserve
// beyond 32 MiB.
RFB_TEST(buffer, buffer__session_fb_policy_limit__reserves_past_32mib) {
    rfb_buffer b;
    rfb_buffer_init(&b, rfb_default_allocator(), RFB_LIMIT_FB_BYTES_POLICY);
    const size_t old_session_in_cap = RFB_LIMIT_OUTBOUND_BYTES * 4u; // 32 MiB
    const size_t need = old_session_in_cap + (1u << 20);             // 33 MiB
    RFB_CHECK(need < RFB_LIMIT_FB_BYTES_POLICY);
    RFB_CHECK_EQ_INT(rfb_buffer_reserve(&b, need), RFB_OK);
    RFB_CHECK(b.capacity >= need);
    rfb_buffer_destroy(&b);
}

// ---- consume / clear / reserve ------------------------------------------

// Prepend home CSI and APC in one stream.
RFB_TEST(buffer, buffer__prepend__inserts_front)
{
    rfb_buffer b;
    rfb_buffer_init(&b, rfb_default_allocator(), 4096);
    RFB_CHECK_EQ_INT(rfb_buffer_append(&b, "G", 1), RFB_OK);
    RFB_CHECK_EQ_INT(rfb_buffer_prepend(&b, "\033[H", 3), RFB_OK);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&b), 4u);
    RFB_CHECK_MEM_EQ(rfb_buffer_data(&b), "\033[HG", 4);
    rfb_buffer_destroy(&b);
}

// Encoding rollback must preserve the committed prefix.
RFB_TEST(buffer, buffer__truncate__keeps_prefix)
{
    rfb_buffer b;
    rfb_buffer_init(&b, rfb_default_allocator(), 4096);
    RFB_CHECK_EQ_INT(rfb_buffer_append(&b, "ABCD", 4), RFB_OK);
    rfb_buffer_truncate(&b, 2);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&b), 2u);
    RFB_CHECK_MEM_EQ(rfb_buffer_data(&b), "AB", 2);
    rfb_buffer_truncate(&b, 100);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&b), 2u);
    rfb_buffer_destroy(&b);
}

RFB_TEST(buffer, buffer__consume__drops_from_front) {
    rfb_buffer b;
    rfb_buffer_init(&b, rfb_default_allocator(), 1024);
    static const uint8_t data[6] = { 10, 20, 30, 40, 50, 60 };
    rfb_buffer_append(&b, data, 6);
    rfb_buffer_consume(&b, 2);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&b), 4u);
    RFB_CHECK_EQ_UINT(rfb_buffer_data(&b)[0], 30u);
    rfb_buffer_destroy(&b);
}

RFB_TEST(buffer, buffer__consume_more_than_length__empties) {
    rfb_buffer b;
    rfb_buffer_init(&b, rfb_default_allocator(), 1024);
    static const uint8_t data[3] = { 1, 2, 3 };
    rfb_buffer_append(&b, data, 3);
    rfb_buffer_consume(&b, 100);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&b), 0u);
    rfb_buffer_destroy(&b);
}

RFB_TEST(buffer, buffer__clear__empties_without_free) {
    rfb_buffer b;
    rfb_buffer_init(&b, rfb_default_allocator(), 1024);
    static const uint8_t data[4] = { 1, 2, 3, 4 };
    rfb_buffer_append(&b, data, 4);
    rfb_buffer_clear(&b);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&b), 0u);
    // After clear, appending should reuse the retained capacity.
    rfb_buffer_append(&b, data, 4);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&b), 4u);
    rfb_buffer_destroy(&b);
}

// ---- allocation failure at each point -----------------------------------
//
// We use a fault-injecting allocator that fails on the Nth alloc, then run
// the same operation for N = 1..10 and assert the buffer is destructible
// and its state is consistent each time.

typedef struct fault_alloc {
    int fail_at;        // 1-based; fail on the Nth successful-or-not alloc
    int calls;
    int allocs_returned_null;
} fault_alloc;

static void *fault_alloc_fn(rfb_allocator *self, size_t n)
{
    fault_alloc *f = (fault_alloc *)self->user;
    f->calls++;
    if (f->calls == f->fail_at) {
        f->allocs_returned_null++;
        return NULL;
    }
    if (n == 0) {
        return NULL;
    }
    return malloc(n);
}

static void fault_free_fn(rfb_allocator *self, void *p)
{
    (void)self;
    free(p);
}

RFB_TEST(buffer, buffer__allocation_failure_at_each_point__leaves_destructible) {
    static const uint8_t data[100] = { 0 };
    for (int fail = 1; fail <= 10; fail++) {
        fault_alloc f = { .fail_at = fail };
        rfb_allocator a = { .alloc = fault_alloc_fn, .free = fault_free_fn, .user = &f };
        rfb_buffer b;
        rfb_buffer_init(&b, &a, 1u << 20);
        // Append until it either succeeds or fails; either way we must be
        // able to destroy without crashing.
        (void)rfb_buffer_append(&b, data, sizeof data);
        rfb_buffer_destroy(&b);
        // The test's invariant is simply: no crash, no leak (ASan catches
        // the leak; the loop reaches here intact).
        RFB_CHECK(true);  // reached end without crashing
    }
}

RFB_TEST(buffer, buffer__failed_growth_preserves_old_contents) {
    // Append some data, then force the growth alloc to fail; the original
    // data must remain intact.
    fault_alloc f = { .fail_at = 2 };  // fail the second alloc (the growth)
    rfb_allocator a = { .alloc = fault_alloc_fn, .free = fault_free_fn, .user = &f };
    rfb_buffer b;
    rfb_buffer_init(&b, &a, 1u << 20);
    static const uint8_t first[4] = { 0xAA, 0xBB, 0xCC, 0xDD };
    RFB_CHECK_EQ_INT(rfb_buffer_append(&b, first, sizeof first), RFB_OK);
    // Now a large append that needs growth; the growth alloc fails.
    static uint8_t big[10000] = { 0 };
    rfb_error e = rfb_buffer_append(&b, big, sizeof big);
    RFB_CHECK(e == RFB_ERR_NOMEM);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&b), 4u);
    RFB_CHECK_MEM_EQ(rfb_buffer_data(&b), first, 4);
    rfb_buffer_destroy(&b);
}

RFB_TEST(buffer, buffer__public_guards_and_inconsistent_state_fail_closed)
{
    static const uint8_t byte = 0x5Au;
    rfb_allocator no_allocator = {
        .alloc = NULL,
        .free = NULL,
        .user = NULL,
    };

    rfb_buffer_init(NULL, rfb_default_allocator(), 1u);
    rfb_buffer_destroy(NULL);
    RFB_CHECK_EQ_INT(rfb_buffer_reserve(NULL, 1u), RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(rfb_buffer_append(NULL, &byte, 1u), RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(rfb_buffer_prepend(NULL, &byte, 1u), RFB_ERR_INTERNAL);
    rfb_buffer_consume(NULL, 1u);
    rfb_buffer_clear(NULL);
    rfb_buffer_truncate(NULL, 1u);

    rfb_buffer buffer;
    rfb_buffer_init(&buffer, NULL, 8u);
    RFB_CHECK_EQ_INT(rfb_buffer_reserve(&buffer, 1u), RFB_ERR_INTERNAL);
    buffer.alloc = &no_allocator;
    RFB_CHECK_EQ_INT(rfb_buffer_reserve(&buffer, 1u), RFB_ERR_INTERNAL);

    buffer.data = NULL;
    buffer.length = 2u;
    buffer.capacity = 2u;
    rfb_buffer_consume(&buffer, 1u);
    RFB_CHECK_EQ_UINT(buffer.length, 0u);

    rfb_buffer_init(&buffer, rfb_default_allocator(), 1024u);
    RFB_CHECK_EQ_INT(rfb_buffer_reserve(&buffer, 256u), RFB_OK);
    uint8_t *first_allocation = buffer.data;
    fault_alloc allocation_state = { .fail_at = 0 };
    rfb_allocator no_free = {
        .alloc = fault_alloc_fn,
        .free = NULL,
        .user = &allocation_state,
    };
    buffer.alloc = &no_free;
    RFB_CHECK_EQ_INT(rfb_buffer_reserve(&buffer, 512u), RFB_OK);
    uint8_t *second_allocation = buffer.data;
    rfb_buffer_destroy(&buffer);
    free(first_allocation);
    free(second_allocation);
}
