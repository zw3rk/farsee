// SPDX-License-Identifier: Apache-2.0
//
// Coordinated per-session memory budget tests.

#include "rfb_test.h"

#include "farsee/allocator.h"
#include "farsee/buffer.h"
#include "farsee/farsee_atomic.h"
#include "farsee/farsee_frame_slot.h"
#include "farsee/farsee_thread.h"
#include "farsee/memory_budget.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct budget_backing {
    rfb_allocator allocator;
    atomic_size_t calls;
    atomic_size_t frees;
    size_t fail_call;
} budget_backing;

static void *budget_backing_alloc(rfb_allocator *allocator, size_t size)
{
    budget_backing *backing = (budget_backing *)allocator->user;
    const size_t call =
        atomic_fetch_add_explicit(&backing->calls, 1u, memory_order_relaxed) +
        1u;
    if (backing->fail_call != 0u && call == backing->fail_call) {
        return NULL;
    }
    return malloc(size);
}

static void budget_backing_free(rfb_allocator *allocator, void *allocation)
{
    budget_backing *backing = (budget_backing *)allocator->user;
    (void)atomic_fetch_add_explicit(&backing->frees, 1u,
                                    memory_order_relaxed);
    free(allocation);
}

static void budget_backing_init(budget_backing *backing)
{
    *backing = (budget_backing){
        .allocator = {
            .alloc = budget_backing_alloc,
            .free = budget_backing_free,
            .user = backing,
        },
    };
    atomic_init(&backing->calls, 0u);
    atomic_init(&backing->frees, 0u);
}

static size_t budget_backing_calls(const budget_backing *backing)
{
    return atomic_load_explicit(&backing->calls, memory_order_relaxed);
}

static size_t budget_backing_frees(const budget_backing *backing)
{
    return atomic_load_explicit(&backing->frees, memory_order_relaxed);
}

typedef struct concurrent_budget_arg {
    rfb_allocator *allocator;
    farsee_atomic_int *start;
    atomic_int *attempted;
    farsee_atomic_int *release;
    void *allocation;
} concurrent_budget_arg;

static void *concurrent_budget_alloc(void *opaque)
{
    concurrent_budget_arg *arg = (concurrent_budget_arg *)opaque;
    while (!farsee_atomic_int_load_nonzero(arg->start)) {
    }
    arg->allocation = arg->allocator->alloc(arg->allocator, 8u);
    (void)atomic_fetch_add_explicit(arg->attempted, 1, memory_order_acq_rel);
    while (arg->allocation != NULL &&
           !farsee_atomic_int_load_nonzero(arg->release)) {
    }
    if (arg->allocation != NULL) {
        arg->allocator->free(arg->allocator, arg->allocation);
    }
    return NULL;
}

RFB_TEST(memory_budget, shared_buffer_and_frame_slot_reject_aggregate_overage)
{
    budget_backing backing;
    budget_backing_init(&backing);
    farsee_memory_budget budget;
    RFB_CHECK(farsee_memory_budget_init(&budget, &backing.allocator, 319u));
    rfb_allocator *allocator = farsee_memory_budget_allocator(&budget);

    rfb_buffer buffer;
    rfb_buffer_init(&buffer, allocator, 256u);
    const uint8_t byte = 0x5au;
    RFB_CHECK_EQ_INT(rfb_buffer_append(&buffer, &byte, 1u), RFB_OK);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&budget), 256u);

    farsee_frame_slot slot;
    RFB_CHECK(farsee_frame_slot_init_with_allocator(&slot, allocator));
    uint8_t frame[64] = {0};
    RFB_CHECK_EQ_INT(
        farsee_frame_slot_publish_ex(&slot, frame, 4u, 4u, 16u,
                                     FARSEE_PIXEL_RGBA8888),
        FARSEE_FRAME_PUBLISH_OUT_OF_MEMORY);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&budget), 256u);

    farsee_frame_slot_destroy(&slot);
    rfb_buffer_destroy(&buffer);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&budget), 0u);
}

RFB_TEST(memory_budget, shared_buffer_and_frame_slot_accept_exact_fit)
{
    budget_backing backing;
    budget_backing_init(&backing);
    farsee_memory_budget budget;
    RFB_CHECK(farsee_memory_budget_init(&budget, &backing.allocator, 320u));
    rfb_allocator *allocator = farsee_memory_budget_allocator(&budget);

    rfb_buffer buffer;
    rfb_buffer_init(&buffer, allocator, 256u);
    const uint8_t byte = 0xa5u;
    RFB_CHECK_EQ_INT(rfb_buffer_append(&buffer, &byte, 1u), RFB_OK);

    farsee_frame_slot slot;
    RFB_CHECK(farsee_frame_slot_init_with_allocator(&slot, allocator));
    uint8_t frame[64] = {0};
    RFB_CHECK_EQ_INT(
        farsee_frame_slot_publish_ex(&slot, frame, 4u, 4u, 16u,
                                     FARSEE_PIXEL_RGBA8888),
        FARSEE_FRAME_PUBLISH_OK);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&budget), 320u);

    farsee_frame_slot_destroy(&slot);
    rfb_buffer_destroy(&buffer);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&budget), 0u);
}

RFB_TEST(memory_budget, aggregate_limit_rejects_without_backing_allocation)
{
    budget_backing backing;
    budget_backing_init(&backing);
    farsee_memory_budget budget;
    RFB_CHECK(farsee_memory_budget_init(&budget, &backing.allocator, 12u));
    rfb_allocator *allocator = farsee_memory_budget_allocator(&budget);

    void *first = allocator->alloc(allocator, 8u);
    RFB_CHECK(first != NULL);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&budget), 8u);
    RFB_CHECK_EQ_UINT(budget_backing_calls(&backing), 1u);

    void *rejected = allocator->alloc(allocator, 5u);
    RFB_CHECK(rejected == NULL);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&budget), 8u);
    RFB_CHECK_EQ_UINT(budget_backing_calls(&backing), 1u);

    allocator->free(allocator, first);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&budget), 0u);
    RFB_CHECK_EQ_UINT(budget_backing_frees(&backing), 1u);
}

RFB_TEST(memory_budget, exact_fit_tracks_peak_and_releases_once)
{
    budget_backing backing;
    budget_backing_init(&backing);
    farsee_memory_budget budget;
    RFB_CHECK(farsee_memory_budget_init(&budget, &backing.allocator, 16u));
    rfb_allocator *allocator = farsee_memory_budget_allocator(&budget);

    void *a = allocator->alloc(allocator, 7u);
    void *b = allocator->alloc(allocator, 9u);
    RFB_CHECK(a != NULL);
    RFB_CHECK(b != NULL);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_limit(&budget), 16u);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&budget), 16u);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_peak(&budget), 16u);

    allocator->free(allocator, NULL);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&budget), 16u);
    allocator->free(allocator, a);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&budget), 9u);
    allocator->free(allocator, b);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&budget), 0u);
    RFB_CHECK_EQ_UINT(budget_backing_frees(&backing), 2u);
}

RFB_TEST(memory_budget, zero_limit_uses_default_policy)
{
    budget_backing backing;
    budget_backing_init(&backing);
    farsee_memory_budget budget;
    RFB_CHECK(farsee_memory_budget_init(&budget, &backing.allocator, 0u));
    RFB_CHECK_EQ_UINT(farsee_memory_budget_limit(&budget),
                      FARSEE_MEMORY_BUDGET_DEFAULT_BYTES);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&budget), 0u);
}

RFB_TEST(memory_budget, header_overflow_never_calls_backing_allocator)
{
    budget_backing backing;
    budget_backing_init(&backing);
    farsee_memory_budget budget;
    RFB_CHECK(farsee_memory_budget_init(&budget, &backing.allocator, SIZE_MAX));
    rfb_allocator *allocator = farsee_memory_budget_allocator(&budget);

    RFB_CHECK(allocator->alloc(allocator, SIZE_MAX) == NULL);
    RFB_CHECK_EQ_UINT(budget_backing_calls(&backing), 0u);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&budget), 0u);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_peak(&budget), 0u);
}

RFB_TEST(memory_budget, backing_failure_rolls_charge_back)
{
    budget_backing backing;
    budget_backing_init(&backing);
    backing.fail_call = 1u;
    farsee_memory_budget budget;
    RFB_CHECK(farsee_memory_budget_init(&budget, &backing.allocator, 32u));
    rfb_allocator *allocator = farsee_memory_budget_allocator(&budget);

    RFB_CHECK(allocator->alloc(allocator, 8u) == NULL);
    RFB_CHECK_EQ_UINT(budget_backing_calls(&backing), 1u);
    RFB_CHECK_EQ_UINT(budget_backing_frees(&backing), 0u);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&budget), 0u);

    backing.fail_call = 0u;
    void *allocation = allocator->alloc(allocator, 8u);
    RFB_CHECK(allocation != NULL);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&budget), 8u);
    allocator->free(allocator, allocation);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&budget), 0u);
}

RFB_TEST(memory_budget, returned_storage_has_max_align_t_alignment)
{
    budget_backing backing;
    budget_backing_init(&backing);
    farsee_memory_budget budget;
    RFB_CHECK(farsee_memory_budget_init(&budget, &backing.allocator, 64u));
    rfb_allocator *allocator = farsee_memory_budget_allocator(&budget);

    void *allocation = allocator->alloc(allocator, sizeof(max_align_t));
    RFB_CHECK(allocation != NULL);
    RFB_CHECK_EQ_UINT((uintptr_t)allocation % _Alignof(max_align_t), 0u);
    allocator->free(allocator, allocation);
}

RFB_TEST(memory_budget, allocator_realloc_observes_transactional_peak)
{
    budget_backing backing;
    budget_backing_init(&backing);
    farsee_memory_budget budget;
    RFB_CHECK(farsee_memory_budget_init(&budget, &backing.allocator, 767u));
    rfb_allocator *allocator = farsee_memory_budget_allocator(&budget);
    rfb_buffer buffer;
    rfb_buffer_init(&buffer, allocator, 1024u);

    uint8_t initial[256] = {0};
    uint8_t growth = 1u;
    RFB_CHECK_EQ_INT(rfb_buffer_append(&buffer, initial, sizeof initial),
                     RFB_OK);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&budget), 256u);
    RFB_CHECK_EQ_INT(rfb_buffer_append(&buffer, &growth, sizeof growth),
                     RFB_ERR_NOMEM);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&buffer), 256u);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&budget), 256u);

    rfb_buffer_destroy(&buffer);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&budget), 0u);

    farsee_memory_budget roomy;
    RFB_CHECK(farsee_memory_budget_init(&roomy, &backing.allocator, 768u));
    rfb_buffer_init(&buffer, farsee_memory_budget_allocator(&roomy), 1024u);
    RFB_CHECK_EQ_INT(rfb_buffer_append(&buffer, initial, sizeof initial),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_buffer_append(&buffer, &growth, sizeof growth),
                     RFB_OK);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&buffer), 257u);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&roomy), 512u);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_peak(&roomy), 768u);
    rfb_buffer_destroy(&buffer);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&roomy), 0u);
}

RFB_TEST(memory_budget, logical_reservation_is_checked_and_releasable)
{
    budget_backing backing;
    budget_backing_init(&backing);
    farsee_memory_budget budget;
    RFB_CHECK(farsee_memory_budget_init(&budget, &backing.allocator, 12u));

    RFB_CHECK(farsee_memory_budget_reserve(&budget, 10u));
    RFB_CHECK(!farsee_memory_budget_reserve(&budget, 3u));
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&budget), 10u);
    RFB_CHECK(!farsee_memory_budget_release(&budget, 11u));
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&budget), 10u);
    RFB_CHECK(farsee_memory_budget_release(&budget, 10u));
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&budget), 0u);
    RFB_CHECK(farsee_memory_budget_release(&budget, 0u));
}

RFB_TEST(memory_budget, logical_reservation_replace_is_transactional)
{
    budget_backing backing;
    budget_backing_init(&backing);
    farsee_memory_budget budget;
    RFB_CHECK(farsee_memory_budget_init(&budget, &backing.allocator, 12u));
    size_t held = 0u;

    RFB_CHECK(farsee_memory_budget_replace_reservation(&budget, &held, 8u));
    RFB_CHECK_EQ_UINT(held, 8u);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&budget), 8u);
    RFB_CHECK(!farsee_memory_budget_replace_reservation(&budget, &held, 13u));
    RFB_CHECK_EQ_UINT(held, 8u);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&budget), 8u);
    RFB_CHECK(farsee_memory_budget_replace_reservation(&budget, &held, 3u));
    RFB_CHECK_EQ_UINT(held, 3u);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&budget), 3u);
    RFB_CHECK(farsee_memory_budget_replace_reservation(&budget, &held, 0u));
    RFB_CHECK_EQ_UINT(held, 0u);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&budget), 0u);
}

RFB_TEST(memory_budget, invalid_and_uninitialized_contracts_fail_closed)
{
    farsee_memory_budget uninitialized = {0};
    size_t held = 0u;
    RFB_CHECK(!farsee_memory_budget_reserve(NULL, 1u));
    RFB_CHECK(!farsee_memory_budget_reserve(&uninitialized, 1u));
    RFB_CHECK(!farsee_memory_budget_release(NULL, 1u));
    RFB_CHECK(!farsee_memory_budget_release(&uninitialized, 1u));
    RFB_CHECK(!farsee_memory_budget_replace_reservation(NULL, &held, 1u));
    RFB_CHECK(!farsee_memory_budget_replace_reservation(
        &uninitialized, &held, 1u));
    RFB_CHECK(!farsee_memory_budget_replace_reservation(
        &uninitialized, NULL, 1u));
    RFB_CHECK(farsee_memory_budget_allocator(NULL) == NULL);
    RFB_CHECK(farsee_memory_budget_allocator(&uninitialized) == NULL);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_limit(NULL), 0u);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_limit(&uninitialized), 0u);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(NULL), 0u);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&uninitialized), 0u);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_peak(NULL), 0u);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_peak(&uninitialized), 0u);
}

RFB_TEST(memory_budget, init_rejects_invalid_backing_allocators)
{
    farsee_memory_budget budget = {0};
    RFB_CHECK(!farsee_memory_budget_init(
        NULL, rfb_default_allocator(), 1u));
    RFB_CHECK(!farsee_memory_budget_init(&budget, NULL, 1u));
    RFB_CHECK(!farsee_memory_budget_init(
        &budget, &budget.allocator, 1u));

    rfb_allocator missing_alloc = {
        .alloc = NULL,
        .free = budget_backing_free,
        .user = NULL,
    };
    RFB_CHECK(!farsee_memory_budget_init(&budget, &missing_alloc, 1u));
    rfb_allocator missing_free = {
        .alloc = budget_backing_alloc,
        .free = NULL,
        .user = NULL,
    };
    RFB_CHECK(!farsee_memory_budget_init(&budget, &missing_free, 1u));
}

RFB_TEST(memory_budget, allocator_and_replace_edge_contracts_are_bounded)
{
    budget_backing backing;
    budget_backing_init(&backing);
    farsee_memory_budget budget;
    RFB_CHECK(farsee_memory_budget_init(&budget, &backing.allocator, 16u));
    rfb_allocator *allocator = farsee_memory_budget_allocator(&budget);
    RFB_CHECK(allocator != NULL);
    RFB_CHECK(allocator->alloc(NULL, 1u) == NULL);
    RFB_CHECK(allocator->alloc(allocator, 0u) == NULL);
    allocator->free(NULL, NULL);
    allocator->free(allocator, NULL);

    size_t held = 0u;
    RFB_CHECK(farsee_memory_budget_replace_reservation(
        &budget, &held, 0u));
    held = 1u;
    RFB_CHECK(!farsee_memory_budget_replace_reservation(
        &budget, &held, 0u));
    RFB_CHECK_EQ_UINT(held, 1u);
}

RFB_TEST(memory_budget, allocator_owner_views__reject_invalid_ownership)
{
    budget_backing backing;
    budget_backing_init(&backing);
    farsee_memory_budget budget;
    RFB_CHECK(farsee_memory_budget_init(&budget, &backing.allocator, 16u));
    rfb_allocator *allocator = farsee_memory_budget_allocator(&budget);
    RFB_CHECK(allocator != NULL);

    rfb_allocator view = *allocator;
    view.user = NULL;
    RFB_CHECK(view.alloc(&view, 1u) == NULL);

    farsee_memory_budget uninitialized = {0};
    view.user = &uninitialized;
    RFB_CHECK(view.alloc(&view, 1u) == NULL);

    farsee_memory_budget no_backing = {0};
    no_backing.initialized = true;
    view.user = &no_backing;
    RFB_CHECK(view.alloc(&view, 1u) == NULL);

    void *allocation = allocator->alloc(allocator, 8u);
    RFB_CHECK(allocation != NULL);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&budget), 8u);

    view.user = NULL;
    view.free(&view, allocation);
    view.user = &uninitialized;
    view.free(&view, allocation);

    farsee_memory_budget other;
    RFB_CHECK(farsee_memory_budget_init(&other, &backing.allocator, 16u));
    view.user = &other;
    view.free(&view, allocation);

    rfb_allocator *saved_backing = budget.backing;
    budget.backing = NULL;
    allocator->free(allocator, allocation);
    budget.backing = saved_backing;

    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&budget), 8u);
    allocator->free(allocator, allocation);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&budget), 0u);
}

RFB_TEST(memory_budget, allocator_realloc_preserves_bytes_and_accounting)
{
    budget_backing backing;
    budget_backing_init(&backing);
    farsee_memory_budget budget;
    RFB_CHECK(farsee_memory_budget_init(&budget, &backing.allocator, 20u));
    rfb_allocator *allocator = farsee_memory_budget_allocator(&budget);

    uint8_t *first = (uint8_t *)allocator->alloc(allocator, 8u);
    RFB_CHECK(first != NULL);
    for (size_t i = 0u; i < 8u; i++) {
        first[i] = (uint8_t)(i + 1u);
    }
    uint8_t *grown =
        (uint8_t *)rfb_allocator_realloc(allocator, first, 8u, 12u);
    RFB_CHECK(grown != NULL);
    for (size_t i = 0u; i < 8u; i++) {
        RFB_CHECK_EQ_UINT(grown[i], i + 1u);
    }
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&budget), 12u);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_peak(&budget), 20u);
    allocator->free(allocator, grown);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&budget), 0u);
}

RFB_TEST(memory_budget, concurrent_first_failure_never_overcharges_limit)
{
    enum { thread_count = 8 };
    budget_backing backing;
    budget_backing_init(&backing);
    farsee_memory_budget budget;
    RFB_CHECK(farsee_memory_budget_init(&budget, &backing.allocator, 32u));
    rfb_allocator *allocator = farsee_memory_budget_allocator(&budget);
    farsee_atomic_int start = ATOMIC_VAR_INIT(0);
    farsee_atomic_int release = ATOMIC_VAR_INIT(0);
    atomic_int attempted = ATOMIC_VAR_INIT(0);
    concurrent_budget_arg args[thread_count];
    farsee_thread *threads[thread_count] = {NULL};
    size_t created = 0u;

    for (size_t i = 0u; i < thread_count; i++) {
        args[i] = (concurrent_budget_arg){
            .allocator = allocator,
            .start = &start,
            .attempted = &attempted,
            .release = &release,
            .allocation = NULL,
        };
        threads[i] = farsee_thread_create(concurrent_budget_alloc, &args[i]);
        RFB_CHECK(threads[i] != NULL);
        if (threads[i] == NULL) {
            break;
        }
        created++;
    }

    farsee_atomic_int_store(&start, 1);
    const uint64_t deadline = farsee_thread_monotonic_ms() + 5000u;
    while ((size_t)atomic_load_explicit(&attempted, memory_order_acquire) <
               created &&
           farsee_thread_monotonic_ms() < deadline) {
    }
    RFB_CHECK_EQ_UINT(
        (size_t)atomic_load_explicit(&attempted, memory_order_acquire), created);
    const size_t expected_successes = created < 4u ? created : 4u;
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&budget),
                      expected_successes * 8u);
    RFB_CHECK_EQ_UINT(budget_backing_calls(&backing), expected_successes);
    RFB_CHECK_EQ_UINT(farsee_memory_budget_peak(&budget),
                      expected_successes * 8u);

    farsee_atomic_int_store(&release, 1);
    for (size_t i = 0u; i < created; i++) {
        farsee_thread_join(&threads[i], NULL);
    }
    RFB_CHECK_EQ_UINT(farsee_memory_budget_used(&budget), 0u);
    RFB_CHECK_EQ_UINT(budget_backing_frees(&backing), expected_successes);
}
