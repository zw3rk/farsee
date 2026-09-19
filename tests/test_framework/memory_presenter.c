// SPDX-License-Identifier: Apache-2.0

#include "memory_presenter.h"
#include "farsee/checked.h"

#include <string.h>

void rfb_test_memory_presenter_init(rfb_test_memory_presenter *presenter,
                                    uint8_t *storage, size_t capacity)
{
    if (presenter == NULL) {
        return;
    }
    memset(presenter, 0, sizeof *presenter);
    presenter->storage = storage;
    presenter->capacity = capacity;
}

static int memory_open(void *context, const rfb_framebuffer *framebuffer)
{
    rfb_test_memory_presenter *presenter =
        (rfb_test_memory_presenter *)context;
    if (presenter == NULL || framebuffer == NULL) {
        return -1;
    }
    presenter->open_count++;
    return 0;
}

static int memory_resize(void *context, const rfb_framebuffer *framebuffer)
{
    rfb_test_memory_presenter *presenter =
        (rfb_test_memory_presenter *)context;
    if (presenter == NULL || framebuffer == NULL) {
        return -1;
    }
    presenter->resize_count++;
    return 0;
}

static int memory_present(void *context, const rfb_framebuffer *framebuffer,
                          const rfb_damage_batch *damage)
{
    (void)damage;
    rfb_test_memory_presenter *presenter =
        (rfb_test_memory_presenter *)context;
    if (presenter == NULL || framebuffer == NULL ||
        framebuffer->rgba == NULL || framebuffer->width == 0u ||
        framebuffer->height == 0u) {
        return -1;
    }
    size_t row_size = 0u;
    size_t size = 0u;
    if (!rfb_checked_mul_size(
            (size_t)framebuffer->width, 4u, &row_size) ||
        framebuffer->stride < row_size ||
        !rfb_checked_mul_size(
            row_size, (size_t)framebuffer->height, &size)) {
        return -1;
    }
    if (size > presenter->capacity ||
        (size > 0u && presenter->storage == NULL)) {
        return -1;
    }
    for (uint32_t y = 0u; y < framebuffer->height; y++) {
        memcpy(presenter->storage + (size_t)y * row_size,
               framebuffer->rgba + (size_t)y * framebuffer->stride,
               row_size);
    }
    presenter->size = size;
    presenter->width = framebuffer->width;
    presenter->height = framebuffer->height;
    presenter->stride = (uint32_t)row_size;
    presenter->present_count++;
    return 0;
}

static void memory_close(void *context)
{
    rfb_test_memory_presenter *presenter =
        (rfb_test_memory_presenter *)context;
    if (presenter != NULL) {
        presenter->close_count++;
    }
}

const rfb_presenter_ops rfb_test_memory_presenter_ops = {
    .open = memory_open,
    .resize = memory_resize,
    .present = memory_present,
    .close = memory_close,
};
