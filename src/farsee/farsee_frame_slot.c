// SPDX-License-Identifier: Apache-2.0
//
// Latest-wins triple buffer (see farsee_frame_slot.h).

#include "farsee/farsee_frame_slot.h"
#include "farsee/checked.h"
#include "farsee/farsee_display.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

bool farsee_frame_slot_init(farsee_frame_slot *s)
{
    return farsee_frame_slot_init_with_allocator(s,
                                                 farsee_default_allocator());
}

bool farsee_frame_slot_init_with_allocator(farsee_frame_slot *s,
                                           farsee_allocator *alloc)
{
    if (s == NULL || alloc == NULL || alloc->alloc == NULL ||
        alloc->free == NULL) {
        return false;
    }
    memset(s, 0, sizeof(*s));
    s->alloc = alloc;
    s->publish_idx = -1;
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
        if (s->buf[i] != NULL && s->alloc != NULL && s->alloc->free != NULL) {
            s->alloc->free(s->alloc, s->buf[i]);
        }
        s->buf[i] = NULL;
        s->cap[i] = 0;
    }
    farsee_cond_destroy(&s->cv);
    farsee_mutex_destroy(&s->mu);
    memset(s, 0, sizeof(*s));
    s->publish_idx = -1;
}

static bool ensure_cap(farsee_frame_slot *s, int idx, size_t need)
{
    if (idx < 0 || (unsigned)idx >= FARSEE_FRAME_SLOT_N) {
        return false;
    }
    if (s->cap[(unsigned)idx] >= need && s->buf[(unsigned)idx] != NULL) {
        return true;
    }
    if (s->alloc == NULL || s->alloc->alloc == NULL ||
        s->alloc->free == NULL) {
        return false;
    }
    uint8_t *nbuf = (uint8_t *)farsee_allocator_realloc(
        s->alloc, s->buf[(unsigned)idx], s->cap[(unsigned)idx], need);
    if (nbuf == NULL) {
        return false;
    }
    s->buf[(unsigned)idx] = nbuf;
    s->cap[(unsigned)idx] = need;
    return true;
}

// Pick storage that is neither visible as the latest complete frame, held by
// a reader, nor reserved by another publisher.
static int pick_write_idx(const farsee_frame_slot *s)
{
    for (int i = 0; i < (int)FARSEE_FRAME_SLOT_N; i++) {
        if (i != s->publish_idx && s->readers[(unsigned)i] == 0u &&
            !s->writing[(unsigned)i]) {
            return i;
        }
    }
    return -1;
}

static uint8_t blend_channel(uint8_t foreground, uint8_t background,
                             uint8_t alpha)
{
    const uint32_t value = (uint32_t)foreground * (uint32_t)alpha +
                           (uint32_t)background * (uint32_t)(255u - alpha);
    return (uint8_t)((value + 127u) / 255u);
}

static void composite_cursor(uint8_t *frame, uint32_t frame_w,
                             uint32_t frame_h, uint32_t frame_stride,
                             const farsee_cursor *cursor)
{
    const int64_t left = (int64_t)cursor->pos_x -
                         (int64_t)cursor->hotspot_x;
    const int64_t top = (int64_t)cursor->pos_y -
                        (int64_t)cursor->hotspot_y;
    for (uint32_t cy = 0u; cy < cursor->height; cy++) {
        const int64_t dy = top + (int64_t)cy;
        if (dy < 0 || (uint64_t)dy >= (uint64_t)frame_h) {
            continue;
        }
        for (uint32_t cx = 0u; cx < cursor->width; cx++) {
            const int64_t dx = left + (int64_t)cx;
            if (dx < 0 || (uint64_t)dx >= (uint64_t)frame_w) {
                continue;
            }
            const size_t cursor_offset =
                ((size_t)cy * (size_t)cursor->width + (size_t)cx) * 4u;
            const uint8_t alpha = cursor->data[cursor_offset + 3u];
            if (alpha == 0u) {
                continue;
            }
            const size_t frame_offset = (size_t)dy * (size_t)frame_stride +
                                        (size_t)dx * 4u;
            for (size_t channel = 0u; channel < 3u; channel++) {
                frame[frame_offset + channel] = blend_channel(
                    cursor->data[cursor_offset + channel],
                    frame[frame_offset + channel], alpha);
            }
            frame[frame_offset + 3u] = 255u;
        }
    }
}

farsee_frame_publish_result farsee_frame_slot_publish_composited_ex(
    farsee_frame_slot *s, const uint8_t *pixels, uint32_t w, uint32_t h,
    uint32_t stride, farsee_pixel_format_kind format,
    const farsee_cursor *cursor)
{
    if (s == NULL || pixels == NULL || w == 0 || h == 0) {
        return FARSEE_FRAME_PUBLISH_INVALID;
    }
    const size_t bpp = farsee_pixel_format_bytes(format);
    if (bpp == 0) {
        return FARSEE_FRAME_PUBLISH_INVALID;
    }
    size_t row_bytes = 0;
    if (!rfb_checked_mul_size((size_t)w, bpp, &row_bytes) ||
        (size_t)stride < row_bytes) {
        return FARSEE_FRAME_PUBLISH_INVALID;
    }
    const bool cursor_visible = cursor != NULL && cursor->visible;
    if (cursor_visible) {
        size_t cursor_pixels = 0u;
        size_t cursor_bytes = 0u;
        if (format != FARSEE_PIXEL_RGBA8888 || cursor->data == NULL ||
            cursor->format != FARSEE_PIXEL_RGBA8888 || cursor->width == 0u ||
            cursor->height == 0u ||
            !rfb_checked_mul_size((size_t)cursor->width,
                                  (size_t)cursor->height, &cursor_pixels) ||
            !rfb_checked_mul_size(cursor_pixels, 4u, &cursor_bytes) ||
            cursor_bytes > (size_t)(1ull << 30)) {
            return FARSEE_FRAME_PUBLISH_INVALID;
        }
    }
    size_t need = 0;
    if (!rfb_checked_mul_size((size_t)stride, (size_t)h, &need)) {
        return FARSEE_FRAME_PUBLISH_INVALID;
    }
    // Cap allocation even when size_t multiplication does not wrap. For example,
    // UINT32_MAX squared fits in 64-bit size_t but exceeds this allocation cap.
    if (need == 0u || need > (size_t)(1ull << 30)) {  // 1 GiB absolute
        return FARSEE_FRAME_PUBLISH_INVALID;
    }
    farsee_mutex_lock(s->mu);
    const int wi = pick_write_idx(s);
    if (wi < 0) {
        farsee_mutex_unlock(s->mu);
        return FARSEE_FRAME_PUBLISH_RESOURCE_BUSY;
    }
    if (!ensure_cap(s, wi, need)) {
        farsee_mutex_unlock(s->mu);
        return FARSEE_FRAME_PUBLISH_OUT_OF_MEMORY;
    }
    s->writing[(unsigned)wi] = true;
    uint8_t *dst = s->buf[(unsigned)wi];
    farsee_mutex_unlock(s->mu);

    const uint8_t *src = pixels;
    for (uint32_t y = 0; y < h; y++) {
        memcpy(dst + (size_t)y * (size_t)stride,
               src + (size_t)y * (size_t)stride, row_bytes);
    }
    if (cursor_visible) {
        composite_cursor(dst, w, h, stride, cursor);
    }

    farsee_mutex_lock(s->mu);
    s->writing[(unsigned)wi] = false;
    if (s->publish_idx >= 0 && !s->publish_seen) {
        // A complete ready frame was superseded before any reader acquired it.
        s->dropped++;
    }
    s->w = w;
    s->h = h;
    s->stride = stride;
    s->format = format;
    s->publish_idx = wi;
    s->gen++;
    s->slot_gen[(unsigned)wi] = s->gen;
    s->publish_seen = false;
    s->has_frame = true;
    farsee_cond_broadcast(s->cv);
    farsee_mutex_unlock(s->mu);
    return FARSEE_FRAME_PUBLISH_OK;
}

farsee_frame_publish_result farsee_frame_slot_publish_ex(
    farsee_frame_slot *s, const uint8_t *pixels, uint32_t w, uint32_t h,
    uint32_t stride, farsee_pixel_format_kind format)
{
    return farsee_frame_slot_publish_composited_ex(
        s, pixels, w, h, stride, format, NULL);
}

bool farsee_frame_slot_publish(farsee_frame_slot *s, const uint8_t *pixels,
                               uint32_t w, uint32_t h, uint32_t stride,
                               farsee_pixel_format_kind format)
{
    return farsee_frame_slot_publish_ex(s, pixels, w, h, stride, format) ==
           FARSEE_FRAME_PUBLISH_OK;
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
    const int pi = s->publish_idx;
    if (s->readers[(unsigned)pi] == UINT_MAX) {
        farsee_mutex_unlock(s->mu);
        return false;
    }
    s->readers[(unsigned)pi]++;
    s->publish_seen = true;
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
            if (s->readers[(unsigned)pi] == UINT_MAX) {
                farsee_mutex_unlock(s->mu);
                return false;
            }
            s->readers[(unsigned)pi]++;
            s->publish_seen = true;
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
    if (v->slot_idx >= 0 && (unsigned)v->slot_idx < FARSEE_FRAME_SLOT_N &&
        s->slot_gen[(unsigned)v->slot_idx] == v->gen &&
        s->readers[(unsigned)v->slot_idx] > 0u) {
        s->readers[(unsigned)v->slot_idx]--;
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
