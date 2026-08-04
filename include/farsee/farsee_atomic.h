// SPDX-License-Identifier: Apache-2.0
//
// C11 <stdatomic.h> wrappers for cross-thread flags and counters.
//
// Prefer these over bare volatile / sig_atomic_t for ordinary shared data
// between protocol, present, and input threads. Signal handlers may still
// store into a lock-free farsee_atomic_int (stop flags).
//
// No pthread in this header. Header-only.

#ifndef FARSEE_INCLUDE_FARSEE_FARSEE_ATOMIC_H
#define FARSEE_INCLUDE_FARSEE_FARSEE_ATOMIC_H

#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Integer flag / small counter (stop, force_repaint, cursor coords, …).
typedef atomic_int farsee_atomic_int;

// Generation counters shared across threads when needed.
typedef atomic_uint_least64_t farsee_atomic_u64;

// Stop flag storage type (alias; same representation as farsee_atomic_int).
typedef farsee_atomic_int farsee_stop_flag;

// --- farsee_atomic_int -----------------------------------------------------

static inline int farsee_atomic_int_load(const farsee_atomic_int *p)
{
    if (p == NULL) {
        return 0;
    }
    // C11 atomic_load takes a non-const atomic*; cast is intentional.
    return atomic_load_explicit((farsee_atomic_int *)(uintptr_t)p,
                                memory_order_acquire);
}

static inline void farsee_atomic_int_store(farsee_atomic_int *p, int v)
{
    if (p == NULL) {
        return;
    }
    atomic_store_explicit(p, v, memory_order_release);
}

// Read previous value and replace with `v` (acq_rel). Used to clear
// force_repaint: exchange(p, 0) returns 1 if a repaint was requested.
static inline int farsee_atomic_int_exchange(farsee_atomic_int *p, int v)
{
    if (p == NULL) {
        return 0;
    }
    return atomic_exchange_explicit(p, v, memory_order_acq_rel);
}

static inline bool farsee_atomic_int_load_nonzero(const farsee_atomic_int *p)
{
    return farsee_atomic_int_load(p) != 0;
}

// --- farsee_atomic_u64 -----------------------------------------------------

static inline uint64_t farsee_atomic_u64_load(const farsee_atomic_u64 *p)
{
    if (p == NULL) {
        return 0u;
    }
    return atomic_load_explicit((farsee_atomic_u64 *)(uintptr_t)p,
                                memory_order_acquire);
}

static inline void farsee_atomic_u64_store(farsee_atomic_u64 *p, uint64_t v)
{
    if (p == NULL) {
        return;
    }
    atomic_store_explicit(p, v, memory_order_release);
}

// Exchange (returns previous value). Used for pending_desk claim (T5).
static inline uint64_t farsee_atomic_u64_exchange(farsee_atomic_u64 *p,
                                                 uint64_t v)
{
    if (p == NULL) {
        return 0u;
    }
    return atomic_exchange_explicit(p, v, memory_order_acq_rel);
}

// Compare-exchange strong: if *p == expected, set to desired and return true;
// else write *p into *expected and return false.
static inline bool farsee_atomic_u64_compare_exchange(farsee_atomic_u64 *p,
                                                      uint64_t *expected,
                                                      uint64_t desired)
{
    if (p == NULL || expected == NULL) {
        return false;
    }
    return atomic_compare_exchange_strong_explicit(
        p, expected, desired, memory_order_acq_rel, memory_order_acquire);
}

// Fetch-add (returns previous value). Used for frame/paint counters.
static inline uint64_t farsee_atomic_u64_fetch_add(farsee_atomic_u64 *p,
                                                   uint64_t v)
{
    if (p == NULL) {
        return 0u;
    }
    return atomic_fetch_add_explicit(p, v, memory_order_acq_rel);
}

// --- stop flag convenience (signal-handler safe when lock-free) ------------

static inline void farsee_stop_flag_set(farsee_stop_flag *flag)
{
    farsee_atomic_int_store(flag, 1);
}

static inline bool farsee_stop_flag_is_set(const farsee_stop_flag *flag)
{
    return farsee_atomic_int_load_nonzero(flag);
}

static inline void farsee_stop_flag_clear(farsee_stop_flag *flag)
{
    farsee_atomic_int_store(flag, 0);
}

#ifdef __cplusplus
}
#endif

#endif /* FARSEE_INCLUDE_FARSEE_FARSEE_ATOMIC_H */
