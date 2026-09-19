// SPDX-License-Identifier: Apache-2.0
//
// farsee — SHM in-flight tracking table (plan.md §G10).
//
// Bounded table of in-flight SHM names and image IDs. An add to a full table
// returns false; callers decide whether to reclaim an entry or use direct
// transfer. The table stores names for deferred cleanup after acknowledgement
// or timeout handling.

#ifndef FARSEE_INCLUDE_FARSEE_KITTY_SHM_TABLE_H
#define FARSEE_INCLUDE_FARSEE_KITTY_SHM_TABLE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#define KITTY_SHM_MAX_INFLIGHT 8u
#define KITTY_SHM_NAME_MAX 64u

typedef struct rfb_shm_entry {
    char name[KITTY_SHM_NAME_MAX];  // the shm object name
    uint32_t image_id;               // kitty image ID for ack correlation
    bool in_use;                     // true if this slot is occupied
} rfb_shm_entry;

typedef struct rfb_shm_table {
    rfb_shm_entry entries[KITTY_SHM_MAX_INFLIGHT];
    size_t count;  // number of in-use entries
} rfb_shm_table;

void rfb_shm_table_init(rfb_shm_table *t);

// Try to add a new in-flight entry; return false if the table is full.
// On success, copy the name and image_id into one free table slot. The caller
// selects its recovery after a false return.
bool rfb_shm_table_add(rfb_shm_table *t, const char *name, uint32_t image_id);

// Mark an entry as acknowledged (by image_id) and remove it. Returns
// true if found and removed.
bool rfb_shm_table_ack(rfb_shm_table *t, uint32_t image_id);

// Get the count of in-flight entries.
static inline size_t rfb_shm_table_count(const rfb_shm_table *t)
{
    return t != NULL ? t->count : 0;
}

// True if the table reached its fixed capacity.
static inline bool rfb_shm_table_full(const rfb_shm_table *t)
{
    return t != NULL && t->count >= KITTY_SHM_MAX_INFLIGHT;
}

// Remove all entries (e.g. on session reset / cancellation). Does NOT
// unlink the shm objects — the caller must do that via the stored names.
void rfb_shm_table_clear(rfb_shm_table *t);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_KITTY_SHM_TABLE_H
