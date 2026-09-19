// SPDX-License-Identifier: Apache-2.0
//
// Coordinated memory accounting for one live session.

#include "farsee/memory_budget.h"

#include "farsee/checked.h"

#include <stdint.h>

typedef union farsee_memory_allocation_header {
    max_align_t alignment;
    struct {
        farsee_memory_budget *budget;
        size_t charge;
    } fields;
} farsee_memory_allocation_header;

_Static_assert(
    sizeof(farsee_memory_allocation_header) % _Alignof(max_align_t) == 0u,
    "budget allocation payload must retain max_align_t alignment");

static void update_peak(farsee_memory_budget *budget, size_t candidate)
{
    size_t peak = atomic_load_explicit(&budget->peak, memory_order_relaxed);
    while (peak < candidate &&
           !atomic_compare_exchange_weak_explicit(
               &budget->peak, &peak, candidate,
               memory_order_relaxed, memory_order_relaxed)) {
    }
}

bool farsee_memory_budget_reserve(farsee_memory_budget *budget, size_t bytes)
{
    if (budget == NULL || !budget->initialized) {
        return false;
    }
    size_t used = atomic_load_explicit(&budget->used, memory_order_relaxed);
    for (;;) {
        if (used > budget->limit || bytes > budget->limit - used) {
            return false;
        }
        const size_t next = used + bytes;
        if (atomic_compare_exchange_weak_explicit(
                &budget->used, &used, next,
                memory_order_acq_rel, memory_order_relaxed)) {
            update_peak(budget, next);
            return true;
        }
    }
}

bool farsee_memory_budget_release(farsee_memory_budget *budget, size_t bytes)
{
    if (budget == NULL || !budget->initialized) {
        return false;
    }
    size_t used = atomic_load_explicit(&budget->used, memory_order_relaxed);
    for (;;) {
        if (bytes > used) {
            return false;
        }
        if (atomic_compare_exchange_weak_explicit(
                &budget->used, &used, used - bytes,
                memory_order_acq_rel, memory_order_relaxed)) {
            return true;
        }
    }
}

bool farsee_memory_budget_replace_reservation(farsee_memory_budget *budget,
                                              size_t *held, size_t bytes)
{
    if (budget == NULL || held == NULL || !budget->initialized) {
        return false;
    }
    const size_t old = *held;
    if (bytes == old) {
        return true;
    }
    if (bytes > old) {
        const size_t increase = bytes - old;
        if (!farsee_memory_budget_reserve(budget, increase)) {
            return false;
        }
        *held = bytes;
        return true;
    }
    const size_t decrease = old - bytes;
    if (!farsee_memory_budget_release(budget, decrease)) {
        return false;
    }
    *held = bytes;
    return true;
}

static void *budget_alloc(rfb_allocator *allocator, size_t bytes)
{
    if (allocator == NULL || bytes == 0u) {
        return NULL;
    }
    farsee_memory_budget *budget = (farsee_memory_budget *)allocator->user;
    if (budget == NULL || !budget->initialized || budget->backing == NULL) {
        return NULL;
    }
    size_t total = 0u;
    if (!rfb_checked_add_size(sizeof(farsee_memory_allocation_header), bytes,
                              &total)) {
        return NULL;
    }
    if (!farsee_memory_budget_reserve(budget, bytes)) {
        return NULL;
    }
    farsee_memory_allocation_header *header =
        (farsee_memory_allocation_header *)budget->backing->alloc(
            budget->backing, total);
    if (header == NULL) {
        (void)farsee_memory_budget_release(budget, bytes);
        return NULL;
    }
    header->fields.budget = budget;
    header->fields.charge = bytes;
    return (void *)(header + 1);
}

static void budget_free(rfb_allocator *allocator, void *allocation)
{
    if (allocator == NULL || allocation == NULL) {
        return;
    }
    farsee_memory_budget *budget = (farsee_memory_budget *)allocator->user;
    farsee_memory_allocation_header *header =
        ((farsee_memory_allocation_header *)allocation) - 1;
    if (budget == NULL || !budget->initialized ||
        header->fields.budget != budget || budget->backing == NULL) {
        return;
    }
    const size_t charge = header->fields.charge;
    budget->backing->free(budget->backing, header);
    (void)farsee_memory_budget_release(budget, charge);
}

bool farsee_memory_budget_init(farsee_memory_budget *budget,
                               rfb_allocator *backing, size_t limit)
{
    if (budget == NULL || backing == NULL || backing == &budget->allocator ||
        backing->alloc == NULL || backing->free == NULL) {
        return false;
    }
    budget->allocator.alloc = budget_alloc;
    budget->allocator.free = budget_free;
    budget->allocator.user = budget;
    budget->backing = backing;
    budget->limit = limit == 0u ? FARSEE_MEMORY_BUDGET_DEFAULT_BYTES : limit;
    atomic_init(&budget->used, 0u);
    atomic_init(&budget->peak, 0u);
    budget->initialized = true;
    return true;
}

rfb_allocator *farsee_memory_budget_allocator(farsee_memory_budget *budget)
{
    return budget != NULL && budget->initialized ? &budget->allocator : NULL;
}

size_t farsee_memory_budget_limit(const farsee_memory_budget *budget)
{
    return budget != NULL && budget->initialized ? budget->limit : 0u;
}

size_t farsee_memory_budget_used(const farsee_memory_budget *budget)
{
    return budget != NULL && budget->initialized
               ? atomic_load_explicit(&budget->used, memory_order_relaxed)
               : 0u;
}

size_t farsee_memory_budget_peak(const farsee_memory_budget *budget)
{
    return budget != NULL && budget->initialized
               ? atomic_load_explicit(&budget->peak, memory_order_relaxed)
               : 0u;
}
