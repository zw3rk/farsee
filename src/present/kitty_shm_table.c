// SPDX-License-Identifier: Apache-2.0
//
// farsee — SHM in-flight tracking table implementation (plan.md §G10).

#include "farsee/kitty_shm_table.h"

#include <string.h>

void rfb_shm_table_init(rfb_shm_table *t)
{
    if (t == NULL) return;
    memset(t, 0, sizeof *t);
}

bool rfb_shm_table_add(rfb_shm_table *t, const char *name, uint32_t image_id)
{
    if (t == NULL || name == NULL) return false;
    if (t->count >= KITTY_SHM_MAX_INFLIGHT) return false;  // full
    // Find a free slot.
    for (size_t i = 0; i < KITTY_SHM_MAX_INFLIGHT; i++) {
        if (!t->entries[i].in_use) {
            strncpy(t->entries[i].name, name, KITTY_SHM_NAME_MAX - 1);
            t->entries[i].name[KITTY_SHM_NAME_MAX - 1] = '\0';
            t->entries[i].image_id = image_id;
            t->entries[i].in_use = true;
            t->count++;
            return true;
        }
    }
    return false;  // shouldn't happen (count < MAX guarantees a free slot)
}

bool rfb_shm_table_ack(rfb_shm_table *t, uint32_t image_id)
{
    if (t == NULL) return false;
    for (size_t i = 0; i < KITTY_SHM_MAX_INFLIGHT; i++) {
        if (t->entries[i].in_use && t->entries[i].image_id == image_id) {
            t->entries[i].in_use = false;
            t->entries[i].name[0] = '\0';
            t->count--;
            return true;
        }
    }
    return false;  // not found
}

void rfb_shm_table_clear(rfb_shm_table *t)
{
    if (t == NULL) return;
    memset(t, 0, sizeof *t);
}
