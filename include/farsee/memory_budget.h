// SPDX-License-Identifier: Apache-2.0
//
// Coordinated memory accounting for one live session.

#ifndef FARSEE_INCLUDE_FARSEE_MEMORY_BUDGET_H
#define FARSEE_INCLUDE_FARSEE_MEMORY_BUDGET_H

#include "farsee/allocator.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdatomic.h>

#ifdef __cplusplus
extern "C" {
#endif

// Default aggregate budget for all first-party allocations owned by one
// live session. Passing zero to farsee_memory_budget_init selects this value.
#define FARSEE_MEMORY_BUDGET_DEFAULT_BYTES \
    ((size_t)512u * (size_t)1024u * (size_t)1024u)

typedef struct farsee_memory_budget {
    rfb_allocator allocator;
    rfb_allocator *backing;
    size_t limit;
    atomic_size_t used;
    atomic_size_t peak;
    bool initialized;
} farsee_memory_budget;

// Initialize fresh budget storage. `backing` and `budget` must outlive every
// allocation returned by the budget allocator. Reinitializing a budget with
// live allocations is invalid. The backing allocator must not be the budget's
// own wrapper.
bool farsee_memory_budget_init(farsee_memory_budget *budget,
                               rfb_allocator *backing, size_t limit);

// Borrow the allocator wrapper. Returns NULL for an uninitialized budget.
// Allocations charge their requested payload bytes, not the private header.
rfb_allocator *farsee_memory_budget_allocator(farsee_memory_budget *budget);

// Account memory owned by a dependency or another allocator. The release
// operation rejects an amount larger than the current charge, so counters do
// not wrap on an invalid release. Zero-byte reserve/release operations succeed.
bool farsee_memory_budget_reserve(farsee_memory_budget *budget, size_t bytes);
bool farsee_memory_budget_release(farsee_memory_budget *budget, size_t bytes);

// Replace one caller-owned logical reservation. Growth charges before the
// caller-visible value changes; failure leaves both unchanged. Shrink and
// release cannot underflow when *held was maintained by this function.
bool farsee_memory_budget_replace_reservation(farsee_memory_budget *budget,
                                              size_t *held, size_t bytes);

size_t farsee_memory_budget_limit(const farsee_memory_budget *budget);
size_t farsee_memory_budget_used(const farsee_memory_budget *budget);
size_t farsee_memory_budget_peak(const farsee_memory_budget *budget);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_MEMORY_BUDGET_H
