// SPDX-License-Identifier: Apache-2.0
//
// Farsee common display scene: pixel formats, rectangles, surfaces, damage,
// cursor, frame commits.
//
// The common layer models committed display state WITHOUT dictating
// protocol-internal storage. RFB keeps its canonical RGBA8 framebuffer
// inside the RFB engine; RDP/SPICE may use protocol-native caches. Every
// engine publishes display state as frame commits into this scene.
//
// Checked image arithmetic (§11.4): every allocation validates dimensions,
// strides, and byte budgets. "32-bit RGB" is not a sufficient type — pixel
// formats carry explicit channel order, alpha semantics, and endianness.

#ifndef FARSEE_INCLUDE_FARSEE_FARSEE_DISPLAY_H
#define FARSEE_INCLUDE_FARSEE_FARSEE_DISPLAY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// --- Pixel formats (§11.3) -------------------------------------------------

typedef enum {
    FARSEE_PIXEL_RGBA8888 = 1,  // 8R 8G 8B 8A, alpha meaningful
    FARSEE_PIXEL_BGRA8888 = 2,  // 8B 8G 8R 8A (common RDP output)
    FARSEE_PIXEL_RGBX8888 = 3,  // 8R 8G 8B, alpha ignored (opaque)
    FARSEE_PIXEL_BGRX8888 = 4,
    FARSEE_PIXEL_RGB888   = 5,  // 3 bytes/pixel, packed
} farsee_pixel_format_kind;

// Bytes per pixel for a format (0 if not a fixed-stride format).
size_t farsee_pixel_format_bytes(farsee_pixel_format_kind fmt);

// --- Rectangles (checked) --------------------------------------------------

// A rectangle in surface coordinates. Coordinates are non-negative and fit
// the surface; the scene validates intersections with checked arithmetic.
typedef struct farsee_rect {
    uint32_t x;
    uint32_t y;
    uint32_t width;
    uint32_t height;
} farsee_rect;

// Checked: does `r` lie wholly within [0,w)x[0,h)? False on overflow.
bool farsee_rect_within(const farsee_rect *r, uint32_t w, uint32_t h);

// --- Surfaces (§11.2) ------------------------------------------------------

typedef uint64_t farsee_surface_id;
typedef uint64_t farsee_frame_id;

// A read-only view of a surface's pixels, published in a frame commit. The
// caller (engine) owns the backing store. `data` is borrowed only for the
// synchronous farsee_presenter_present() call; a presenter that needs pixels
// after return must copy them before it returns. There is no release callback.
typedef struct farsee_surface_view {
    farsee_surface_id id;
    uint32_t width;
    uint32_t height;
    size_t   stride;                 // bytes per row
    farsee_pixel_format_kind format;
    const uint8_t *data;             // stride * height bytes
    size_t   data_size;              // total bytes (stride * height)
    uint64_t generation;             // engine-defined content version
} farsee_surface_view;

// A surface update carried in a frame commit: the new view of a region.
typedef struct farsee_surface_update {
    farsee_surface_view view;        // the post-update pixel content
    const farsee_rect  *damage;      // dirty rects in surface coords (may be NULL)
    size_t              damage_count;
} farsee_surface_update;

// --- Cursor (§11.2) --------------------------------------------------------

typedef struct farsee_cursor {
    uint32_t hotspot_x;
    uint32_t hotspot_y;
    uint32_t width;
    uint32_t height;
    farsee_pixel_format_kind format; // typically RGBA8888
    const uint8_t *data;             // cursor pixels, stride = width*bpp
    bool     visible;
    int32_t  pos_x;                  // display coords when visible
    int32_t  pos_y;
} farsee_cursor;

// --- Frame commit (§11.2) --------------------------------------------------
//
// Atomically makes a set of surface + cursor changes visible. The latest
// committed state must always remain reconstructible (§11.5).
// The commit and all pointers reachable from it (updates, surface data, damage,
// and cursor data) are borrowed only for the synchronous present call. The
// presenter must finish reading or copy them before it returns.

typedef struct farsee_frame_commit {
    farsee_frame_id frame_id;
    const farsee_surface_update *updates;   // surface changes this frame
    size_t update_count;
    const farsee_cursor *cursor;            // NULL if unchanged
    uint64_t presentation_time_ns;
    bool complete_snapshot;                 // true = full-frame resync
} farsee_frame_commit;

// --- Checked image arithmetic (§11.4) --------------------------------------
//
// Validate a surface view's geometry. Returns true iff:
//   width > 0, height > 0, width <= max_dim, height <= max_dim,
//   stride >= minimum stride for the format, and
//   stride * height does not overflow size_t.
bool farsee_surface_view_valid(const farsee_surface_view *v,
                               uint32_t max_dim);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_FARSEE_DISPLAY_H
