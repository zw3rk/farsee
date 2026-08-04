// SPDX-License-Identifier: Apache-2.0
//
// farsee — presenter abstraction (plan.md §10.5, §G3).
//
// Presenters display the framebuffer. The authoritative framebuffer is
// never mutated by a presenter (plan.md §8 principle 4). Implementations:
//   - null:   no-op (used by automated tests);
//   - dump:   write RGBA/PPM to a file (debug + golden-image tests);
//   - kitty direct / kitty shm (G7, G10).

#ifndef FARSEE_INCLUDE_FARSEE_PRESENTER_H
#define FARSEE_INCLUDE_FARSEE_PRESENTER_H

#include "farsee/error.h"
#include "farsee/framebuffer.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// A damage rectangle (plan.md §10.4).
typedef struct rfb_rect {
    uint32_t x;
    uint32_t y;
    uint32_t width;
    uint32_t height;
} rfb_rect;

// A batch of damage rectangles produced by a single FramebufferUpdate.
typedef struct rfb_damage_batch {
    const rfb_rect *rects;
    size_t count;
    bool full_frame;            // true when the whole framebuffer changed
    uint64_t framebuffer_generation;
} rfb_damage_batch;

// Presenter operations (plan.md §10.5). Each implementation fills in the
// ops it supports; unsupported ops are NULL and the caller treats them as
// no-ops. The presenter holds its own context (e.g. file handle, Kitty
// state) in a concrete struct that the ops dereference via `ctx`.
typedef struct rfb_presenter_ops {
    int  (*open)(void *ctx, const rfb_framebuffer *fb);
    int  (*resize)(void *ctx, const rfb_framebuffer *fb);
    int  (*present)(void *ctx, const rfb_framebuffer *fb,
                    const rfb_damage_batch *damage);
    void (*close)(void *ctx);
} rfb_presenter_ops;

// A presenter instance binds ops to its context.
typedef struct rfb_presenter {
    const rfb_presenter_ops *ops;
    void *ctx;
} rfb_presenter;

// Convenience wrappers that tolerate NULL ops.
int  rfb_presenter_open(rfb_presenter *p, const rfb_framebuffer *fb);
int  rfb_presenter_resize(rfb_presenter *p, const rfb_framebuffer *fb);
int  rfb_presenter_present(rfb_presenter *p, const rfb_framebuffer *fb,
                           const rfb_damage_batch *damage);
void rfb_presenter_close(rfb_presenter *p);

// --- Null presenter ------------------------------------------------------
// No-op; used by tests that drive the full pipeline without display.
typedef struct rfb_presenter_null {
    int present_count;  // bumped on each present call (test hook)
} rfb_presenter_null;

extern const rfb_presenter_ops rfb_presenter_null_ops;
void rfb_presenter_null_init(rfb_presenter_null *n);

// --- Dump presenter ------------------------------------------------------
// Writes the framebuffer as raw RGBA to a file on each present. Optionally
// also writes a PPM (P6) header for human inspection. Used by golden-image
// tests and `--dump-frame`.
typedef struct rfb_presenter_dump {
    const char *path;       // output file path (RGBA)
    bool        write_ppm;  // also write <path>.ppm
    int         present_count;
} rfb_presenter_dump;

extern const rfb_presenter_ops rfb_presenter_dump_ops;
void rfb_presenter_dump_init(rfb_presenter_dump *d, const char *path,
                             bool write_ppm);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_PRESENTER_H
