// SPDX-License-Identifier: Apache-2.0
//
// Latest-wins triple buffer (see farsee_frame_slot.h).

#include "farsee/farsee_frame_slot.h"
#include "farsee/checked.h"
#include "farsee/farsee_display.h"

#include <stdlib.h>
#include <string.h>

bool farsee_frame_slot_init(farsee_frame_slot *s)
{
    if (s == NULL) {
        return false;
    }
    memset(s, 0, sizeof(*s));
    s->publish_idx = -1;
    s->display_idx = -1;
    s->mu = farsee_mutex_create();
    s->cv = farsee_cond_create();
    if (s->mu == NULL || s->cv == NULL) {
        farsee_frame_slot_destroy(s);
        return false;
    }
    return true;
}

void farsee_frame_slot_destroy(farsee_frame_slot *s)
{
    if (s == NULL) {
        return;
    }
    for (unsigned i = 0; i < FARSEE_FRAME_SLOT_N; i++) {
        free(s->buf[i]);
        s->buf[i] = NULL;
        s->cap[i] = 0;
    }
    farsee_cond_destroy(&s->cv);
    farsee_mutex_destroy(&s->mu);
    memset(s, 0, sizeof(*s));
    s->publish_idx = -1;
    s->display_idx = -1;
}

static bool ensure_cap(farsee_frame_slot *s, int idx, size_t need)
{
    if (idx < 0 || (unsigned)idx >= FARSEE_FRAME_SLOT_N) {
        return false;
    }
    if (s->cap[(unsigned)idx] >= need && s->buf[(unsigned)idx] != NULL) {
        return true;
    }
    uint8_t *nbuf = (uint8_t *)realloc(s->buf[(unsigned)idx], need);
    if (nbuf == NULL) {
        return false;
    }
    s->buf[(unsigned)idx] = nbuf;
    s->cap[(unsigned)idx] = need;
    return true;
}

// Pick a free write index: not publish_idx, not display_idx.
static int pick_write_idx(const farsee_frame_slot *s)
{
    for (int i = 0; i < (int)FARSEE_FRAME_SLOT_N; i++) {
        if (i != s->publish_idx && i != s->display_idx) {
            return i;
        }
    }
    // All busy: overwrite a non-display slot (drop unshown publish).
    for (int i = 0; i < (int)FARSEE_FRAME_SLOT_N; i++) {
        if (i != s->display_idx) {
            return i;
        }
    }
    return 0;
}

bool farsee_frame_slot_publish(farsee_frame_slot *s, const uint8_t *pixels,
                               uint32_t w, uint32_t h, uint32_t stride,
                               farsee_pixel_format_kind format)
{
    if (s == NULL || pixels == NULL || w == 0 || h == 0) {
        return false;
    }
    const size_t bpp = farsee_pixel_format_bytes(format);
    if (bpp == 0) {
        return false;
    }
    size_t row_bytes = 0;
    if (!rfb_checked_mul_size((size_t)w, bpp, &row_bytes) ||
        (size_t)stride < row_bytes) {
        return false;
    }
    size_t need = 0;
    if (!rfb_checked_mul_size((size_t)stride, (size_t)h, &need)) {
        return false;
    }
    // Cap allocation even when size_t mul does not wrap (e.g. UINT32_MAX²
    // fits in 64-bit size_t but is multi-exabyte). Align with plan hard
    // limits so ASan does not abort on intentional overflow tests / bugs.
    if (need == 0u || need > (size_t)(1ull << 30)) {  // 1 GiB absolute
        return false;
    }
    farsee_mutex_lock(s->mu);
    const int wi = pick_write_idx(s);
    if (s->publish_idx >= 0 && s->publish_idx != s->display_idx &&
        s->publish_idx != wi) {
        // Overwriting a ready frame that present never took.
        s->dropped++;
    }
    if (!ensure_cap(s, wi, need)) {
        farsee_mutex_unlock(s->mu);
        return false;
    }
    // Copy row-by-row if stride may exceed tight packing.
    uint8_t *dst = s->buf[(unsigned)wi];
    const uint8_t *src = pixels;
    for (uint32_t y = 0; y < h; y++) {
        memcpy(dst + (size_t)y * (size_t)stride,
               src + (size_t)y * (size_t)stride, row_bytes);
    }
    s->w = w;
    s->h = h;
    s->stride = stride;
    s->format = format;
    s->publish_idx = wi;
    s->gen++;
    s->has_frame = true;
    farsee_cond_broadcast(s->cv);
    farsee_mutex_unlock(s->mu);
    return true;
}

bool farsee_frame_slot_acquire(farsee_frame_slot *s, farsee_frame_view *out)
{
    if (s == NULL || out == NULL) {
        return false;
    }
    memset(out, 0, sizeof(*out));
    farsee_mutex_lock(s->mu);
    if (!s->has_frame || s->publish_idx < 0) {
        farsee_mutex_unlock(s->mu);
        return false;
    }
    // If present still holds the same slot, allow re-read (same gen).
    // If present holds another slot, free it when we switch.
    const int pi = s->publish_idx;
    s->display_idx = pi;
    out->pixels = s->buf[(unsigned)pi];
    out->w = s->w;
    out->h = s->h;
    out->stride = s->stride;
    out->format = s->format;
    out->gen = s->gen;
    out->slot_idx = pi;
    farsee_mutex_unlock(s->mu);
    return out->pixels != NULL;
}

bool farsee_frame_slot_acquire_wait(farsee_frame_slot *s, uint64_t after_gen,
                                    uint64_t deadline_monotonic_ms,
                                    farsee_atomic_int *stop,
                                    farsee_frame_view *out)
{
    if (s == NULL || out == NULL) {
        return false;
    }
    memset(out, 0, sizeof(*out));
    farsee_mutex_lock(s->mu);
    for (;;) {
        if (farsee_atomic_int_load_nonzero(stop)) {
            farsee_mutex_unlock(s->mu);
            return false;
        }
        if (s->has_frame && s->publish_idx >= 0 && s->gen > after_gen) {
            const int pi = s->publish_idx;
            s->display_idx = pi;
            out->pixels = s->buf[(unsigned)pi];
            out->w = s->w;
            out->h = s->h;
            out->stride = s->stride;
            out->format = s->format;
            out->gen = s->gen;
            out->slot_idx = pi;
            farsee_mutex_unlock(s->mu);
            return out->pixels != NULL;
        }
        if (!farsee_cond_timedwait(s->cv, s->mu, deadline_monotonic_ms)) {
            // Timeout: do not force-acquire same gen; return false.
            farsee_mutex_unlock(s->mu);
            return false;
        }
    }
}

void farsee_frame_slot_release(farsee_frame_slot *s, const farsee_frame_view *v)
{
    if (s == NULL || v == NULL) {
        return;
    }
    farsee_mutex_lock(s->mu);
    if (s->display_idx == v->slot_idx) {
        s->display_idx = -1;
    }
    farsee_mutex_unlock(s->mu);
}

void farsee_frame_slot_kick(farsee_frame_slot *s)
{
    if (s == NULL || s->cv == NULL) {
        return;
    }
    farsee_mutex_lock(s->mu);
    farsee_cond_broadcast(s->cv);
    farsee_mutex_unlock(s->mu);
}
