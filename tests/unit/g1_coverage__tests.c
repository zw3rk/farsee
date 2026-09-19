// SPDX-License-Identifier: Apache-2.0
//
// G1 — coverage completion tests for defensive NULL guards.
//
// These exercise the NULL-check branches in checked.c, bytes.c, allocator.c,
// and buffer.c so plan.md §G1's "100% line coverage for checked arithmetic
// and readers" is met. They are intentionally focused on the edge cases the
// main behavioral tests don't drive.

#include "rfb_test.h"
#include "farsee/checked.h"
#include "farsee/bytes.h"
#include "farsee/allocator.h"
#include "farsee/buffer.h"
#include "farsee/progress.h"
#include "farsee/log.h"
#include "farsee/secret.h"
#include "farsee/error.h"

#include <stdlib.h>
#include <string.h>

// ---- checked: NULL out pointers -----------------------------------------

RFB_TEST(checked_cov, checked_add__null_out__fails) {
    RFB_CHECK(!rfb_checked_add_size(1, 2, NULL));
    RFB_CHECK(!rfb_checked_mul_size(2, 3, NULL));
    RFB_CHECK(!rfb_checked_rect_bytes(1, 1, 4, NULL));
    RFB_CHECK(!rfb_checked_add_u32(1, 2, NULL));
}

RFB_TEST(checked_cov, checked_rect_bytes__pixels_times_bpp_overflows__fails) {
    // width*height fits in size_t, but * bpp overflows (exercises the
    // second-multiply guard in rfb_checked_rect_bytes). On 64-bit hosts
    // the first-multiply guard is not reachable with uint32 inputs
    // (documented in checked.c and the G1 report).
    size_t out = 0xDEAD;
    // 0xFFFFFFFF * 0xFFFFFFFF = 0xFFFFFFFE00000001 ≈ 1.8e19 (fits in 64-bit size_t)
    // * 4 = ~7.2e19 > SIZE_MAX (1.8e19) → overflow on the second multiply.
    RFB_CHECK(!rfb_checked_rect_bytes(0xFFFFFFFFu, 0xFFFFFFFFu, 4u, &out));
    RFB_CHECK_EQ_UINT(out, 0xDEADu);
}

// ---- bytes reader/writer: NULL pointer guards ----------------------------

RFB_TEST(bytes_cov, reader__null_self__returns_false) {
    RFB_CHECK_EQ_UINT(rfb_reader_remaining(NULL), 0u);
    uint8_t b = 0;
    RFB_CHECK(!rfb_read_u8(NULL, &b));
    uint16_t s = 0;
    RFB_CHECK(!rfb_read_u16(NULL, &s));
    uint32_t l = 0;
    RFB_CHECK(!rfb_read_u32(NULL, &l));
    RFB_CHECK(!rfb_read_bytes(NULL, &b, 1));
    RFB_CHECK(!rfb_reader_skip(NULL, 1));
    // NULL reader is safe to reset (no-op)
    rfb_reader_reset(NULL);
}

RFB_TEST(bytes_cov, reader__null_out__returns_false_offset_unchanged) {
    static const uint8_t buf[4] = { 1, 2, 3, 4 };
    rfb_reader r = rfb_reader_make(buf, sizeof buf);
    RFB_CHECK(!rfb_read_u8(&r, NULL));
    RFB_CHECK(!rfb_read_u16(&r, NULL));
    RFB_CHECK(!rfb_read_u32(&r, NULL));
    RFB_CHECK(!rfb_read_bytes(&r, NULL, 1));
    RFB_CHECK(!rfb_peek_u8(&r, 0, NULL));
    RFB_CHECK(!rfb_peek_u16(&r, 0, NULL));
    RFB_CHECK(!rfb_peek_u32(&r, 0, NULL));
    RFB_CHECK_EQ_UINT(r.offset, 0u);
}

RFB_TEST(bytes_cov, reader__peek_out_of_range__returns_false) {
    static const uint8_t buf[2] = { 1, 2 };
    rfb_reader r = rfb_reader_make(buf, sizeof buf);
    uint8_t b = 0;
    uint16_t s = 0;
    uint32_t l = 0;
    RFB_CHECK(!rfb_peek_u8(&r, 5, &b));
    RFB_CHECK(!rfb_peek_u16(&r, 1, &s));
    RFB_CHECK(!rfb_peek_u32(&r, 0, &l));
}

RFB_TEST(bytes_cov, reader__read_zero_bytes__succeeds_no_advance) {
    static const uint8_t buf[1] = { 7 };
    rfb_reader r = rfb_reader_make(buf, sizeof buf);
    uint8_t dst[1] = { 0xEE };
    RFB_CHECK(rfb_read_bytes(&r, dst, 0));
    RFB_CHECK_EQ_UINT(dst[0], 0xEEu);
    RFB_CHECK_EQ_UINT(r.offset, 0u);
}

RFB_TEST(bytes_cov, reader__peek_null_reader__returns_false) {
    uint8_t b = 0;
    uint16_t s = 0;
    uint32_t l = 0;
    RFB_CHECK(!rfb_peek_u8(NULL, 0, &b));
    RFB_CHECK(!rfb_peek_u16(NULL, 0, &s));
    RFB_CHECK(!rfb_peek_u32(NULL, 0, &l));
}

RFB_TEST(bytes_cov, writer__null_self__returns_false) {
    RFB_CHECK(!rfb_write_u8(NULL, 1));
    RFB_CHECK(!rfb_write_u16(NULL, 1));
    RFB_CHECK(!rfb_write_u32(NULL, 1));
    static const uint8_t src[1] = { 0 };
    RFB_CHECK(!rfb_write_bytes(NULL, src, 1));
}

RFB_TEST(bytes_cov, writer__zero_byte_write__succeeds) {
    uint8_t buf[1] = { 0 };
    rfb_writer w = rfb_writer_make(buf, sizeof buf);
    RFB_CHECK(rfb_write_bytes(&w, NULL, 0));
    RFB_CHECK_EQ_UINT(w.length, 0u);
}

RFB_TEST(bytes_cov, writer__nonzero_write_null_src__returns_false) {
    uint8_t buf[1] = { 0 };
    rfb_writer w = rfb_writer_make(buf, sizeof buf);
    RFB_CHECK(!rfb_write_bytes(&w, NULL, 1));
}

RFB_TEST(bytes_cov, writer__u8_overflow_capacity_zero__returns_false) {
    uint8_t buf[1] = { 0 };
    rfb_writer w = rfb_writer_make(buf, 0);  // zero-capacity
    RFB_CHECK(!rfb_write_u8(&w, 1));
    RFB_CHECK_EQ_UINT(w.length, 0u);
}

RFB_TEST(bytes_cov, writer__u32_overflow_room_for_three__returns_false) {
    uint8_t buf[3] = { 0 };
    rfb_writer w = rfb_writer_make(buf, sizeof buf);  // room for 3, need 4
    RFB_CHECK(!rfb_write_u32(&w, 0x01020304));
    RFB_CHECK_EQ_UINT(w.length, 0u);
}

// ---- allocator realloc edge cases ---------------------------------------

static void *cov_always_null_alloc(rfb_allocator *self, size_t n)
{
    (void)self; (void)n;
    return NULL;
}
static void cov_noop_free(rfb_allocator *self, void *p)
{
    (void)self; (void)p;
}

RFB_TEST(alloc_cov, allocator_realloc__null_allocator__returns_null) {
    RFB_CHECK(rfb_allocator_realloc(NULL, NULL, 0, 100) == NULL);
}

RFB_TEST(alloc_cov, allocator_realloc__alloc_failure__returns_null) {
    rfb_allocator a = { .alloc = cov_always_null_alloc, .free = cov_noop_free, .user = NULL };
    void *p = rfb_allocator_realloc(&a, NULL, 0, 100);
    RFB_CHECK(p == NULL);
}

RFB_TEST(alloc_cov, allocator_realloc__with_old_block__copies_and_frees) {
    rfb_allocator *a = rfb_default_allocator();
    // Allocate a small old block, grow it.
    uint8_t *old = (uint8_t *)a->alloc(a, 4);
    RFB_CHECK(old != NULL);
    for (int i = 0; i < 4; i++) old[i] = (uint8_t)(100 + i);
    uint8_t *p = (uint8_t *)rfb_allocator_realloc(a, old, 4, 8);
    RFB_CHECK(p != NULL);
    RFB_CHECK_EQ_UINT(p[0], 100u);
    RFB_CHECK_EQ_UINT(p[3], 103u);
    a->free(a, p);
}

RFB_TEST(alloc_cov, allocator_realloc__null_alloc_field__returns_null) {
    rfb_allocator a = { .alloc = NULL, .free = NULL, .user = NULL };
    RFB_CHECK(rfb_allocator_realloc(&a, NULL, 0, 1) == NULL);
}

RFB_TEST(alloc_cov, neutral_allocator__zero_and_compatibility_contracts) {
    farsee_allocator *allocator = farsee_default_allocator();
    RFB_CHECK(allocator != NULL);
    RFB_CHECK(allocator == rfb_default_allocator());
    RFB_CHECK(allocator->alloc(allocator, 0u) == NULL);

    uint8_t *fresh =
        (uint8_t *)farsee_allocator_realloc(allocator, NULL, 0u, 4u);
    RFB_CHECK(fresh != NULL);
    allocator->free(allocator, fresh);
}

RFB_TEST(alloc_cov, neutral_allocator__shrink_preserves_prefix) {
    farsee_allocator *allocator = farsee_default_allocator();
    uint8_t *original = (uint8_t *)allocator->alloc(allocator, 8u);
    RFB_CHECK(original != NULL);
    for (size_t i = 0u; i < 8u; i++) {
        original[i] = (uint8_t)(0x40u + i);
    }
    uint8_t *shrunk = (uint8_t *)farsee_allocator_realloc(
        allocator, original, 8u, 4u);
    RFB_CHECK(shrunk != NULL);
    for (size_t i = 0u; i < 4u; i++) {
        RFB_CHECK_EQ_UINT(shrunk[i], 0x40u + i);
    }
    allocator->free(allocator, shrunk);
}

// ---- buffer: NULL guards -------------------------------------------------

RFB_TEST(buffer_cov, buffer__null_self__returns_internal_error) {
    RFB_CHECK_EQ_INT(rfb_buffer_append(NULL, NULL, 0), RFB_ERR_INTERNAL);
    // reserve and destroy on NULL must not crash
    rfb_buffer_destroy(NULL);
    rfb_buffer_clear(NULL);
    rfb_buffer_consume(NULL, 1);
    rfb_buffer_init(NULL, NULL, 0);
}

RFB_TEST(buffer_cov, buffer__reserve_under_capacity__is_noop_ok) {
    rfb_buffer b;
    rfb_buffer_init(&b, rfb_default_allocator(), 1024);
    RFB_CHECK_EQ_INT(rfb_buffer_reserve(&b, 0), RFB_OK);  // 0 <= 0 capacity
    RFB_CHECK_EQ_INT(rfb_buffer_reserve(&b, 256), RFB_OK);
    RFB_CHECK_EQ_INT(rfb_buffer_reserve(&b, 100), RFB_OK);  // already have 256
    rfb_buffer_destroy(&b);
}

RFB_TEST(buffer_cov, buffer__reserve_over_limit__returns_err_limit) {
    rfb_buffer b;
    rfb_buffer_init(&b, rfb_default_allocator(), 64);
    RFB_CHECK_EQ_INT(rfb_buffer_reserve(&b, 128), RFB_ERR_LIMIT);
    rfb_buffer_destroy(&b);
}

RFB_TEST(buffer_cov, buffer__append_null_data_nonzero__returns_protocol) {
    rfb_buffer b;
    rfb_buffer_init(&b, rfb_default_allocator(), 1024);
    RFB_CHECK_EQ_INT(rfb_buffer_append(&b, NULL, 5), RFB_ERR_PROTOCOL);
    rfb_buffer_destroy(&b);
}

RFB_TEST(buffer_cov, buffer__null_allocator_in_reserve__returns_internal) {
    rfb_buffer b;
    rfb_buffer_init(&b, NULL, 1024);  // alloc is NULL
    RFB_CHECK_EQ_INT(rfb_buffer_reserve(&b, 16), RFB_ERR_INTERNAL);
    // append also routes through reserve when growing
    static const uint8_t d[1] = { 1 };
    RFB_CHECK_EQ_INT(rfb_buffer_append(&b, d, 1), RFB_ERR_INTERNAL);
}

RFB_TEST(buffer_cov, buffer__prepend_guards_and_empty_success) {
    static const uint8_t byte = 0x5au;
    RFB_CHECK_EQ_INT(rfb_buffer_prepend(NULL, &byte, 1u),
                     RFB_ERR_INTERNAL);

    rfb_buffer buffer;
    rfb_buffer_init(&buffer, rfb_default_allocator(), 1u);
    RFB_CHECK_EQ_INT(rfb_buffer_prepend(&buffer, NULL, 0u), RFB_OK);
    RFB_CHECK_EQ_INT(rfb_buffer_prepend(&buffer, NULL, 1u),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(rfb_buffer_prepend(&buffer, &byte, 1u), RFB_OK);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&buffer), 1u);
    RFB_CHECK_EQ_INT(rfb_buffer_prepend(&buffer, &byte, 1u),
                     RFB_ERR_LIMIT);
    rfb_buffer_destroy(&buffer);
}

RFB_TEST(buffer_cov, buffer__prepend_allocation_failure_is_transactional) {
    rfb_allocator allocator = {
        .alloc = cov_always_null_alloc,
        .free = cov_noop_free,
        .user = NULL,
    };
    rfb_buffer buffer;
    rfb_buffer_init(&buffer, &allocator, 64u);
    const uint8_t byte = 0xa5u;
    RFB_CHECK_EQ_INT(rfb_buffer_prepend(&buffer, &byte, 1u),
                     RFB_ERR_NOMEM);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&buffer), 0u);
    RFB_CHECK(rfb_buffer_data(&buffer) == NULL);
    rfb_buffer_destroy(&buffer);
}
