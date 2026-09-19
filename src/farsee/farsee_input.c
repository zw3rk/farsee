// SPDX-License-Identifier: Apache-2.0
//
// Farsee key-state ledger implementation.
//
// Tracks accepted physical key-down events for later release enumeration.
// The ledger has fixed capacity and no heap; a new press can be refused.

#include "farsee/farsee_input.h"

#include <stdbool.h>
#include <stddef.h>

void farsee_key_ledger_init(farsee_key_ledger *l)
{
    if (l == NULL) {
        return;
    }
    l->count = 0;
    for (size_t i = 0; i < FARSEE_KEY_LEDGER_MAX; ++i) {
        l->down[i] = 0;
    }
}

static size_t ledger_find(const farsee_key_ledger *l, farsee_physical_key k)
{
    for (size_t i = 0; i < l->count; ++i) {
        if (l->down[i] == k) {
            return i;
        }
    }
    return FARSEE_KEY_LEDGER_MAX;  // not found
}

bool farsee_key_ledger_apply(farsee_key_ledger *l, const farsee_key_event *e)
{
    if (l == NULL || e == NULL || e->physical == 0) {
        return true;  // nothing to track (no physical identity)
    }
    // Reject a corrupted count before indexing the ledger.
    if (l->count > FARSEE_KEY_LEDGER_MAX) {
        l->count = FARSEE_KEY_LEDGER_MAX;
    }
    if (e->action == FARSEE_KEY_PRESS || e->action == FARSEE_KEY_REPEAT) {
        if (ledger_find(l, e->physical) != FARSEE_KEY_LEDGER_MAX) {
            return true;  // already down; idempotent
        }
        if (l->count >= FARSEE_KEY_LEDGER_MAX) {
            return false;  // overflow; caller should release all
        }
        l->down[l->count++] = e->physical;
        return true;
    }
    // Release: remove the key if present (compact the array).
    size_t idx = ledger_find(l, e->physical);
    if (idx != FARSEE_KEY_LEDGER_MAX) {
        l->down[idx] = l->down[l->count - 1];
        l->down[l->count - 1] = 0;
        --l->count;
    }
    return true;
}

size_t farsee_key_ledger_release_all(farsee_key_ledger *l,
                                     farsee_physical_key *out, size_t out_cap)
{
    if (l == NULL) {
        return 0;
    }
    if (l->count > FARSEE_KEY_LEDGER_MAX) {
        l->count = FARSEE_KEY_LEDGER_MAX;
    }
    size_t n = 0;
    for (size_t i = 0; i < l->count && n < out_cap; ++i) {
        if (out != NULL) {
            out[n] = l->down[i];
        }
        ++n;
    }
    l->count = 0;
    for (size_t i = 0; i < FARSEE_KEY_LEDGER_MAX; ++i) {
        l->down[i] = 0;
    }
    return n;
}
