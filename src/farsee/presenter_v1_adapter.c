// SPDX-License-Identifier: Apache-2.0
//
// Farsee presenter v1 compatibility adapter (F4 gate, §11.8).
//
// Maps a common-scene frame commit into the existing v1 presenter contract
// (rfb_presenter_ops on rfb_framebuffer + rfb_damage_batch). The adapter
// owns a scratch RGBA8 framebuffer; on each present it copies the surface
// view's pixels into the scratch (converting BGRA/RGB to RGBA8) and
// forwards the damage. This preserves the existing null/dump/kitty
// presenters and RFB output byte-for-byte.

#include "farsee/presenter_v1_adapter.h"

#include "farsee/allocator.h"  // rfb_default_allocator
#include "farsee/farsee_display.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

// Byte-copy a single surface view into a canonical RGBA8 scratch framebuffer.
// Only RGBA8888/BGRA8888/RGBX8888/BGRX8888/RGB888 sources are converted;
// RGBA8888 is a direct copy. Returns false if the scratch is mis-sized or
// the format is unsupported (fail closed).
//
// Hot path: RDP software-GDI is BGRA8888. Convert with a tight per-pixel
// loop (R/B swap) — not a nested switch on every pixel, which crushed live
// frame rates even when Kitty itself can play full-HD smoothly via SHM.
static bool copy_surface_to_scratch(rfb_framebuffer *scratch,
                                    const farsee_surface_view *v)
{
    if (scratch->width != v->width || scratch->height != v->height) {
        return false;
    }
    size_t bpp = farsee_pixel_format_bytes(v->format);
    if (bpp == 0) {
        return false;
    }
    const uint32_t w = v->width;
    const uint32_t h = v->height;
    const size_t src_stride = v->stride;
    const size_t dst_stride = scratch->stride;

    if (v->format == FARSEE_PIXEL_RGBA8888) {
        for (uint32_t y = 0; y < h; ++y) {
            memcpy(scratch->rgba + (size_t)y * dst_stride,
                   v->data + (size_t)y * src_stride,
                   (size_t)w * 4u);
        }
        return true;
    }

    if (v->format == FARSEE_PIXEL_BGRA8888) {
        for (uint32_t y = 0; y < h; ++y) {
            const uint8_t *src = v->data + (size_t)y * src_stride;
            uint8_t *dst = scratch->rgba + (size_t)y * dst_stride;
            for (uint32_t x = 0; x < w; ++x) {
                const uint8_t *s = src + (size_t)x * 4u;
                uint8_t *d = dst + (size_t)x * 4u;
                d[0] = s[2];
                d[1] = s[1];
                d[2] = s[0];
                d[3] = s[3];
            }
        }
        return true;
    }

    for (uint32_t y = 0; y < h; ++y) {
        const uint8_t *src = v->data + (size_t)y * src_stride;
        uint8_t *dst = scratch->rgba + (size_t)y * dst_stride;
        for (uint32_t x = 0; x < w; ++x) {
            const uint8_t *s = src + (size_t)x * bpp;
            uint8_t *d = dst + (size_t)x * 4u;
            switch (v->format) {
            case FARSEE_PIXEL_RGBA8888:
            case FARSEE_PIXEL_BGRA8888:
                // Handled in fast paths above.
                return false;
            case FARSEE_PIXEL_RGBX8888:
                d[0] = s[0]; d[1] = s[1]; d[2] = s[2]; d[3] = 255u;
                break;
            case FARSEE_PIXEL_BGRX8888:
                d[0] = s[2]; d[1] = s[1]; d[2] = s[0]; d[3] = 255u;
                break;
            case FARSEE_PIXEL_RGB888:
                d[0] = s[0]; d[1] = s[1]; d[2] = s[2]; d[3] = 255u;
                break;
            }
        }
    }
    return true;
}

static farsee_error_code adapter_open(farsee_presenter *p,
                                      farsee_presenter_caps *out_caps)
{
    farsee_presenter_v1_adapter *a = (farsee_presenter_v1_adapter *)(void *)p;
    if (a->opened) {
        return FARSEE_ERR_STATE;
    }
    // Open the wrapped v1 presenter with a 1x1 scratch; the first present
    // resizes it to the real surface.
    rfb_error re = rfb_framebuffer_resize(&a->scratch, 1, 1, a->byte_limit);
    if (re != RFB_OK) {
        return FARSEE_ERR_OUT_OF_MEMORY;
    }
    if (rfb_presenter_open(&a->v1, &a->scratch) != 0) {
        return FARSEE_ERR_PRESENTER_FAILURE;
    }
    a->opened = true;
    if (out_caps != NULL) {
        // The v1 contract is a single canonical RGBA8 framebuffer with
        // damage rects and no cursor plane. BGRA8888 is also accepted:
        // copy_surface_to_scratch converts BGRA->RGBA8, so the RDP engine
        // can publish FreeRDP's software-GDI output directly (§11.7).
        *out_caps = (farsee_presenter_caps){
            .accepts_rgba8888 = true,
            .accepts_bgra8888 = true,
            .supports_partial_update = true,
            .max_dimension = 16384,
            .max_in_flight_frames = 1,
            .preferred_frame_rate = 30,
        };
    }
    return FARSEE_E_OK;
}

static farsee_error_code adapter_present(farsee_presenter *p,
                                         const farsee_frame_commit *frame)
{
    farsee_presenter_v1_adapter *a = (farsee_presenter_v1_adapter *)(void *)p;
    if (!a->opened || frame == NULL || frame->update_count == 0) {
        return FARSEE_ERR_STATE;
    }
    // The v1 contract models one root surface; take the first update.
    const farsee_surface_update *u = &frame->updates[0];
    if (!farsee_surface_view_valid(&u->view, 16384u)) {
        return FARSEE_ERR_PROTOCOL_VIOLATION;
    }
    // Resize scratch if needed (transactional, preserves contents on failure).
    if (a->scratch.width != u->view.width || a->scratch.height != u->view.height) {
        rfb_error re = rfb_framebuffer_resize(&a->scratch, u->view.width,
                                              u->view.height, a->byte_limit);
        if (re != RFB_OK) {
            return (re == RFB_ERR_LIMIT) ? FARSEE_ERR_RESOURCE_LIMIT
                                         : FARSEE_ERR_OUT_OF_MEMORY;
        }
        if (rfb_presenter_resize(&a->v1, &a->scratch) != 0) {
            return FARSEE_ERR_PRESENTER_FAILURE;
        }
    }
    if (!copy_surface_to_scratch(&a->scratch, &u->view)) {
        return FARSEE_ERR_PROTOCOL_VIOLATION;
    }
    a->scratch.generation = u->view.generation;

    // Build the v1 damage batch.
    rfb_damage_batch batch;
    batch.framebuffer_generation = u->view.generation;
    if (frame->complete_snapshot || u->damage_count == 0) {
        batch.rects = NULL;
        batch.count = 0;
        batch.full_frame = true;
    } else {
        // Forward the damage rects (already validated against the surface
        // by the engine; farsee_rect_within is the engine's responsibility).
        batch.rects = (const rfb_rect *)u->damage;
        batch.count = u->damage_count;
        batch.full_frame = false;
    }
    if (rfb_presenter_present(&a->v1, &a->scratch, &batch) != 0) {
        return FARSEE_ERR_PRESENTER_FAILURE;
    }
    return FARSEE_E_OK;
}

static farsee_error_code adapter_flush(farsee_presenter *p)
{
    (void)p;
    return FARSEE_E_OK;  // v1 presenters are synchronous
}

static void adapter_close(farsee_presenter **pp)
{
    if (pp == NULL || *pp == NULL) {
        return;
    }
    farsee_presenter_v1_adapter *a = (farsee_presenter_v1_adapter *)(void *)*pp;
    if (a->opened) {
        rfb_presenter_close(&a->v1);
        a->opened = false;
    }
    rfb_framebuffer_destroy(&a->scratch);
    // The adapter does not own its own allocation (it's embedded); the
    // caller frees the enclosing storage.
    *pp = NULL;
}

static const farsee_presenter_ops_v2 ADAPTER_OPS = {
    .open = adapter_open,
    .present = adapter_present,
    .flush = adapter_flush,
    .close = adapter_close,
};

const farsee_presenter_ops_v2 *farsee_presenter_v1_adapter_ops(void)
{
    return &ADAPTER_OPS;
}

void farsee_presenter_v1_adapter_init(farsee_presenter_v1_adapter *a,
                                      rfb_presenter v1, uint32_t byte_limit)
{
    if (a == NULL) {
        return;
    }
    a->v2_ops = &ADAPTER_OPS;
    a->v1 = v1;
    a->byte_limit = (byte_limit == 0) ? (uint32_t)256u * 1024u * 1024u : byte_limit;
    a->opened = false;
    rfb_framebuffer_init(&a->scratch, rfb_default_allocator());
}
