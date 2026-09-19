// SPDX-License-Identifier: Apache-2.0
//
// farsee — presenter wrappers and null presenter.

#include "farsee/presenter.h"

#include <stddef.h>
#include <stdio.h>

int rfb_presenter_open(rfb_presenter *p, const rfb_framebuffer *fb)
{
    if (p == NULL || p->ops == NULL || p->ops->open == NULL) {
        return 0;
    }
    return p->ops->open(p->ctx, fb);
}

int rfb_presenter_resize(rfb_presenter *p, const rfb_framebuffer *fb)
{
    if (p == NULL || p->ops == NULL || p->ops->resize == NULL) {
        return 0;
    }
    return p->ops->resize(p->ctx, fb);
}

int rfb_presenter_present(rfb_presenter *p, const rfb_framebuffer *fb,
                          const rfb_damage_batch *damage)
{
    if (p == NULL || p->ops == NULL || p->ops->present == NULL) {
        return 0;
    }
    return p->ops->present(p->ctx, fb, damage);
}

void rfb_presenter_close(rfb_presenter *p)
{
    if (p == NULL || p->ops == NULL || p->ops->close == NULL) {
        return;
    }
    p->ops->close(p->ctx);
}

// --- Null presenter ------------------------------------------------------

void rfb_presenter_null_init(rfb_presenter_null *n)
{
    if (n != NULL) {
        n->present_count = 0;
    }
}

static int null_open(void *ctx, const rfb_framebuffer *fb)
{
    (void)ctx; (void)fb;
    return 0;
}

static int null_resize(void *ctx, const rfb_framebuffer *fb)
{
    (void)ctx; (void)fb;
    return 0;
}

static int null_present(void *ctx, const rfb_framebuffer *fb,
                        const rfb_damage_batch *damage)
{
    rfb_presenter_null *n = (rfb_presenter_null *)ctx;
    if (n != NULL) {
        n->present_count++;
    }
    (void)fb; (void)damage;
    return 0;
}

static void null_close(void *ctx)
{
    (void)ctx;
}

const rfb_presenter_ops rfb_presenter_null_ops = {
    .open    = null_open,
    .resize  = null_resize,
    .present = null_present,
    .close   = null_close,
};
