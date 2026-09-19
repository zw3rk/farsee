// SPDX-License-Identifier: Apache-2.0
//
// Farsee bounded-queue implementation.
//
// A mutex-protected FIFO is bounded by item count and aggregate payload bytes.
// A terminal-tagged push bypasses those caps; if admitted, it closes the queue
// to later pushes. Invalid input and allocation failure can still reject it.
//
// Priority entries are delivered ahead of normal entries. A terminal entry is
// delivered after the entries already queued, or immediately when empty.

#include "farsee/farsee_queue.h"
#include "farsee/farsee_thread.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

typedef struct entry {
    farsee_queue_tag tag;
    void  *buf;            // owned copy of payload (NULL if payload_bytes==0)
    size_t buf_bytes;
    void (*dtor)(void *);
    void  *user;
    struct entry *next;
} entry;

struct farsee_queue {
    farsee_mutex *mtx;
    entry *head;           // oldest normal/priority
    entry *tail;           // newest normal/priority
    entry *priority_head;  // priority queue (delivered first)
    entry *priority_tail;
    entry *terminal;       // at most one (NULL until pushed)
    entry *last_delivered; // retained so out_payload stays valid until next pop
    bool   terminal_delivered;
    size_t count;          // non-terminal entries currently queued
    size_t bytes;          // non-terminal payload bytes currently queued
    size_t high_water;
    farsee_queue_config cfg;
};

farsee_queue *farsee_queue_create(farsee_queue_config cfg)
{
    if (cfg.max_items == 0 || cfg.max_bytes == 0) {
        return NULL;
    }
    farsee_queue *q = calloc(1, sizeof(*q));
    if (q == NULL) {
        return NULL;
    }
    q->mtx = farsee_mutex_create();
    if (q->mtx == NULL) {
        free(q);
        return NULL;
    }
    q->cfg = cfg;
    return q;
}

// Release only the entry's owned buffer + struct, NOT the user destructor.
// The destructor for `user` fires at logical-consume time (pop/destroy);
// this helper frees the queue-owned payload buffer and the entry node.
static void free_entry_buffer(entry *e)
{
    if (e == NULL) {
        return;
    }
    free(e->buf);
    free(e);
}

// Fire the user destructor (caller-owned `user`) and free the buffer/struct.
static void destroy_entry(entry *e)
{
    if (e == NULL) {
        return;
    }
    if (e->dtor != NULL) {
        e->dtor(e->user);
    }
    free(e->buf);
    free(e);
}

void farsee_queue_destroy(farsee_queue **qp)
{
    if (qp == NULL || *qp == NULL) {
        return;
    }
    farsee_queue *q = *qp;
    entry *e = q->priority_head;
    while (e != NULL) {
        entry *next = e->next;
        destroy_entry(e);
        e = next;
    }
    e = q->head;
    while (e != NULL) {
        entry *next = e->next;
        destroy_entry(e);
        e = next;
    }
    destroy_entry(q->terminal);
    // last_delivered's user destructor already fired at its pop time; only
    // its buffer remains to be freed.
    free_entry_buffer(q->last_delivered);
    farsee_mutex_destroy(&q->mtx);
    free(q);
    *qp = NULL;
}

static bool would_exceed(farsee_queue *q, size_t add_bytes)
{
    if (q->count + 1 > q->cfg.max_items) {
        return true;
    }
    if (q->bytes + add_bytes > q->cfg.max_bytes) {
        return true;
    }
    return false;
}

bool farsee_queue_push(farsee_queue *q, farsee_queue_tag tag,
                       const void *payload, size_t payload_bytes,
                       void (*user_destructor)(void *user), void *user)
{
    if (q == NULL) {
        return false;
    }
    // Reject a NULL payload with positive length before reaching memcpy.
    if (payload == NULL && payload_bytes > 0) {
        return false;
    }
    farsee_mutex_lock(q->mtx);
    // After a terminal entry, the queue is locked.
    if (q->terminal != NULL) {
        farsee_mutex_unlock(q->mtx);
        return false;
    }
    if (tag == FARSEE_QUEUE_TAG_TERMINAL) {
        // Terminal bypasses caps; admitted exactly once.
        entry *e = calloc(1, sizeof(*e));
        if (e == NULL) {
            farsee_mutex_unlock(q->mtx);
            return false;
        }
        e->tag = tag;
        e->buf_bytes = payload_bytes;
        e->dtor = user_destructor;
        e->user = user;
        if (payload_bytes > 0) {
            e->buf = malloc(payload_bytes);
            if (e->buf == NULL) {
                free(e);
                farsee_mutex_unlock(q->mtx);
                return false;
            }
            memcpy(e->buf, payload, payload_bytes);
        }
        q->terminal = e;
        q->terminal_delivered = false;
        farsee_mutex_unlock(q->mtx);
        return true;
    }
    // Normal/priority: enforce caps. The per-entry byte cap is checked
    // here — AFTER the TERMINAL exemption above — so terminal payloads
    // bypass it entirely; would_exceed guards the aggregate.
    if (payload_bytes > q->cfg.max_bytes || would_exceed(q, payload_bytes)) {
        farsee_mutex_unlock(q->mtx);
        return false;
    }
    entry *e = calloc(1, sizeof(*e));
    if (e == NULL) {
        farsee_mutex_unlock(q->mtx);
        return false;
    }
    e->tag = tag;
    e->buf_bytes = payload_bytes;
    e->dtor = user_destructor;
    e->user = user;
    if (payload_bytes > 0) {
        e->buf = malloc(payload_bytes);
        if (e->buf == NULL) {
            free(e);
            farsee_mutex_unlock(q->mtx);
            return false;
        }
        memcpy(e->buf, payload, payload_bytes);
    }
    if (tag == FARSEE_QUEUE_TAG_PRIORITY) {
        if (q->priority_tail != NULL) {
            q->priority_tail->next = e;
        } else {
            q->priority_head = e;
        }
        q->priority_tail = e;
    } else {
        if (q->tail != NULL) {
            q->tail->next = e;
        } else {
            q->head = e;
        }
        q->tail = e;
    }
    q->count += 1;
    q->bytes += payload_bytes;
    if (q->count > q->high_water) {
        q->high_water = q->count;
    }
    farsee_mutex_unlock(q->mtx);
    return true;
}

// Select the next entry to deliver: priority first, then normal, then the
// (at-most-once) terminal after the queue is otherwise empty.
static entry *select_next(farsee_queue *q)
{
    if (q->priority_head != NULL) {
        entry *e = q->priority_head;
        q->priority_head = e->next;
        if (q->priority_head == NULL) {
            q->priority_tail = NULL;
        }
        q->count -= 1;
        q->bytes -= e->buf_bytes;
        return e;
    }
    if (q->head != NULL) {
        entry *e = q->head;
        q->head = e->next;
        if (q->head == NULL) {
            q->tail = NULL;
        }
        q->count -= 1;
        q->bytes -= e->buf_bytes;
        return e;
    }
    // Normal and priority queues are empty: deliver the retained terminal once.
    if (q->terminal != NULL && !q->terminal_delivered) {
        q->terminal_delivered = true;
        return q->terminal;  // retained by the queue until destroy
    }
    return NULL;
}

bool farsee_queue_pop(farsee_queue *q,
                      const void **out_payload, size_t *out_bytes,
                      farsee_queue_tag *out_tag, void **out_user)
{
    if (q == NULL) {
        return false;
    }
    farsee_mutex_lock(q->mtx);
    entry *e = select_next(q);
    if (e == NULL) {
        farsee_mutex_unlock(q->mtx);
        return false;
    }
    if (out_payload != NULL) {
        *out_payload = e->buf;
    }
    if (out_bytes != NULL) {
        *out_bytes = e->buf_bytes;
    }
    if (out_tag != NULL) {
        *out_tag = e->tag;
    }
    if (out_user != NULL) {
        *out_user = e->user;
    }
    if (e == q->terminal) {
        // Terminal: it is the queue's final state. select_next never
        // returns it again. Its user destructor fires now (logical
        // consume); the buffer stays valid for the caller until destroy.
        if (e->dtor != NULL) {
            e->dtor(e->user);
        }
        e->dtor = NULL;  // don't fire again on destroy
        farsee_mutex_unlock(q->mtx);
        return true;
    }
    // Normal/priority: the caller's out_payload points into e->buf, which
    // must remain valid until the next pop/destroy. Fire the user
    // destructor now (logical consume); retain only the buffer.
    if (e->dtor != NULL) {
        e->dtor(e->user);
    }
    // Free the previously-retained buffer, then retain this entry's buffer.
    if (q->last_delivered != NULL) {
        free_entry_buffer(q->last_delivered);
    }
    q->last_delivered = e;  // e->dtor already NULL-ed implicitly by consume
    farsee_mutex_unlock(q->mtx);
    return true;
}

size_t farsee_queue_count(const farsee_queue *q)
{
    if (q == NULL) {
        return 0;
    }
    farsee_mutex *m = q->mtx;
    farsee_mutex_lock(m);
    size_t n = q->count;
    farsee_mutex_unlock(m);
    return n;
}

size_t farsee_queue_bytes(const farsee_queue *q)
{
    if (q == NULL) {
        return 0;
    }
    farsee_mutex *m = q->mtx;
    farsee_mutex_lock(m);
    size_t n = q->bytes;
    farsee_mutex_unlock(m);
    return n;
}

bool farsee_queue_is_terminal(const farsee_queue *q)
{
    if (q == NULL) {
        return false;
    }
    farsee_mutex *m = q->mtx;
    farsee_mutex_lock(m);
    bool t = (q->terminal != NULL);
    farsee_mutex_unlock(m);
    return t;
}

size_t farsee_queue_high_water_items(const farsee_queue *q)
{
    if (q == NULL) {
        return 0;
    }
    farsee_mutex *m = q->mtx;
    farsee_mutex_lock(m);
    size_t n = q->high_water;
    farsee_mutex_unlock(m);
    return n;
}
