// SPDX-License-Identifier: Apache-2.0
//
// Farsee transport set implementation (F7 gate, §9).
//
// Owns a fixed-capacity array of lanes with per-lane metrics (§9.8). The
// concrete TCP/UDP/TLS lane backends are added by later subgates; this
// delivers the set container, engine-owned lane registration (for FreeRDP),
// and metrics storage — all bounded, all destructible.

#include "farsee/farsee_transport.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    farsee_lane_semantics semantics;
    bool present;
    farsee_transport_metrics metrics;
} lane_slot;

struct farsee_transport_set {
    lane_slot *lanes;
    size_t max_lanes;
    size_t count;
};

farsee_transport_set *farsee_transport_set_create(size_t max_lanes)
{
    if (max_lanes == 0) {
        return NULL;
    }
    farsee_transport_set *s = calloc(1, sizeof(*s));
    if (s == NULL) {
        return NULL;
    }
    s->lanes = calloc(max_lanes, sizeof(lane_slot));
    if (s->lanes == NULL) {
        free(s);
        return NULL;
    }
    s->max_lanes = max_lanes;
    s->count = 0;
    return s;
}

void farsee_transport_set_destroy(farsee_transport_set **sp)
{
    if (sp == NULL || *sp == NULL) {
        return;
    }
    free((*sp)->lanes);
    free(*sp);
    *sp = NULL;
}

size_t farsee_transport_set_count(const farsee_transport_set *s)
{
    return (s != NULL) ? s->count : 0;
}

size_t farsee_transport_set_add_engine_owned(farsee_transport_set *s)
{
    if (s == NULL) {
        return SIZE_MAX;
    }
    for (size_t i = 0; i < s->max_lanes; ++i) {
        if (!s->lanes[i].present) {
            s->lanes[i].present = true;
            s->lanes[i].semantics = FARSEE_LANE_ENGINE_OWNED;
            memset(&s->lanes[i].metrics, 0, sizeof(farsee_transport_metrics));
            s->count++;
            return i;
        }
    }
    return SIZE_MAX;  // full
}

static const lane_slot *lane_at(const farsee_transport_set *s, size_t i)
{
    if (s == NULL || i >= s->max_lanes || !s->lanes[i].present) {
        return NULL;
    }
    return &s->lanes[i];
}

farsee_lane_semantics farsee_transport_lane_semantics(const farsee_transport_set *s,
                                                      size_t lane_index)
{
    const lane_slot *l = lane_at(s, lane_index);
    return (l != NULL) ? l->semantics : FARSEE_LANE_RELIABLE_ORDERED_STREAM;
}

const farsee_transport_metrics *farsee_transport_lane_metrics(const farsee_transport_set *s,
                                                              size_t lane_index)
{
    const lane_slot *l = lane_at(s, lane_index);
    return (l != NULL) ? &l->metrics : NULL;
}
