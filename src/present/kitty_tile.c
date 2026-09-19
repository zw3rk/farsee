// SPDX-License-Identifier: Apache-2.0
//
// farsee — tile/damage-aware Kitty presenter (plan.md §G22, §G7, §G10).
//
// Implements a damage-aware presenter that preserves stable Kitty
// image/placement IDs per tile and retransmits only the tiles intersecting
// the current damage. The authoritative framebuffer is read-only.
//
// See include/farsee/kitty_tile.h for the full invariant list.

#include "farsee/kitty_tile.h"
#include "farsee/kitty_protocol.h"
#include "farsee/kitty_shm.h"

#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

// --- Tile-grid geometry (pure helpers) -----------------------------------

bool rfb_kitty_tile_grid(uint32_t w, uint32_t h, uint32_t tile_edge,
                         uint32_t *cols, uint32_t *rows)
{
    if (cols == NULL || rows == NULL || tile_edge == 0) return false;
    if (w == 0 || h == 0) return false;
    // cols = ceil(w / tile_edge), rows = ceil(h / tile_edge). Use wide
    // arithmetic so a valid uint32_t dimension cannot wrap before the cap.
    const uint64_t c = ((uint64_t)w + (uint64_t)tile_edge - 1u) /
                       (uint64_t)tile_edge;
    const uint64_t r = ((uint64_t)h + (uint64_t)tile_edge - 1u) /
                       (uint64_t)tile_edge;
    // Check against the cap.
    if (c > RFB_KITTY_TILE_MAX_TILES || r > RFB_KITTY_TILE_MAX_TILES) {
        return false;
    }
    // Total tile count cap.
    if ((uint64_t)c * (uint64_t)r > (uint64_t)RFB_KITTY_TILE_MAX_TILES) {
        return false;
    }
    *cols = (uint32_t)c;
    *rows = (uint32_t)r;
    return true;
}

size_t rfb_kitty_tile_rect_tile_count(uint32_t rect_w, uint32_t rect_h,
                                      uint32_t tile_edge,
                                      uint32_t cols, uint32_t rows)
{
    if (tile_edge == 0 || cols == 0 || rows == 0) return 0;
    // tiles spanned horizontally: ceil(min(rect_w, cols*edge) / edge).
    const uint64_t full_w = (uint64_t)cols * (uint64_t)tile_edge;
    const uint64_t w = (uint64_t)rect_w > full_w
                           ? full_w
                           : (uint64_t)rect_w;
    const uint64_t full_h = (uint64_t)rows * (uint64_t)tile_edge;
    const uint64_t h = (uint64_t)rect_h > full_h
                           ? full_h
                           : (uint64_t)rect_h;
    uint64_t tc = (w + (uint64_t)tile_edge - 1u) / (uint64_t)tile_edge;
    uint64_t tr = (h + (uint64_t)tile_edge - 1u) / (uint64_t)tile_edge;
    if (tc == 0) tc = 1;
    if (tr == 0) tr = 1;
    return (size_t)tc * (size_t)tr;
}

size_t rfb_kitty_tile_rect_to_tiles(uint32_t rect_x, uint32_t rect_y,
                                    uint32_t rect_w, uint32_t rect_h,
                                    uint32_t fb_w, uint32_t fb_h,
                                    uint32_t tile_edge,
                                    uint32_t cols, uint32_t rows,
                                    size_t *out_indices)
{
    if (out_indices == NULL || tile_edge == 0) return 0;
    if (cols == 0 || rows == 0) return 0;
    if (rect_w == 0 || rect_h == 0) return 0;
    // Use 64-bit intermediates to avoid overflow on rect_x+rect_w.
    uint64_t xe = (uint64_t)rect_x + (uint64_t)rect_w;
    uint64_t ye = (uint64_t)rect_y + (uint64_t)rect_h;
    if (xe > fb_w) xe = fb_w;
    if (ye > fb_h) ye = fb_h;
    if (xe <= rect_x || ye <= rect_y) return 0;
    // First/last tile column and row (clamped to the grid).
    uint32_t col_lo = rect_x / tile_edge;
    uint32_t col_hi = (uint32_t)((xe - 1u) / tile_edge);
    uint32_t row_lo = rect_y / tile_edge;
    uint32_t row_hi = (uint32_t)((ye - 1u) / tile_edge);
    if (col_hi >= cols) col_hi = cols - 1u;
    if (row_hi >= rows) row_hi = rows - 1u;
    size_t count = 0;
    for (uint32_t row = row_lo; row <= row_hi; row++) {
        for (uint32_t col = col_lo; col <= col_hi; col++) {
            out_indices[count++] = (size_t)row * (size_t)cols + (size_t)col;
        }
    }
    return count;
}

// --- Lifecycle: init / open / destroy ------------------------------------

void rfb_kitty_tile_init(rfb_kitty_tile *kt,
                         rfb_allocator *alloc,
                         rfb_buffer *out,
                         uint32_t tile_edge,
                         bool use_shm,
                         bool request_ack)
{
    if (kt == NULL) return;
    memset(kt, 0, sizeof *kt);
    kt->alloc = (alloc != NULL) ? alloc : rfb_default_allocator();
    kt->out = out;
    kt->tile_edge = (tile_edge == 0) ? RFB_KITTY_TILE_DEFAULT_EDGE : tile_edge;
    kt->use_shm = use_shm;
    kt->request_ack = request_ack;
    kt->ack_timeout_ms = RFB_KITTY_TILE_ACK_TIMEOUT_MS;
    kt->high_water_bytes = RFB_KITTY_TILE_HIGH_WATER_BYTES;
    farsee_atomic_u64_store(&kt->place_cells, 0u);
    rfb_shm_table_init(&kt->shm_table);
}

void rfb_kitty_tile_set_place_cells(rfb_kitty_tile *kt,
                                    uint32_t cols, uint32_t rows)
{
    if (kt == NULL) {
        return;
    }
    // Single release store: cols in high 32, rows in low 32 (never torn).
    const uint64_t pack =
        ((uint64_t)cols << 32) | (uint64_t)(rows & 0xffffffffu);
    farsee_atomic_u64_store(&kt->place_cells, pack);
}

// Unlink all in-flight SHM objects (best-effort). Tolerates ENOENT — the
// terminal may have already unlinked, or the object may have been acked and
// cleaned up by the session loop. After this call, no SHM objects remain.
static void kt_unlink_shm_objects(rfb_kitty_tile *kt)
{
    if (kt == NULL) return;
    for (size_t i = 0; i < KITTY_SHM_MAX_INFLIGHT; i++) {
        if (kt->shm_table.entries[i].in_use &&
            kt->shm_table.entries[i].name[0] != '\0') {
            shm_unlink(kt->shm_table.entries[i].name);
        }
        kt->shm_send_time[i] = 0;
    }
}

void rfb_kitty_tile_destroy(rfb_kitty_tile *kt)
{
    if (kt == NULL) return;
    // Unlink any in-flight SHM objects before clearing the table (no leak).
    kt_unlink_shm_objects(kt);
    if (kt->dirty != NULL) {
        kt->alloc->free(kt->alloc, kt->dirty);
        kt->dirty = NULL;
    }
    kt->tile_count = 0;
    kt->cols = 0;
    kt->rows = 0;
    rfb_shm_table_clear(&kt->shm_table);
}

// Allocate (or reallocate) the dirty bitmap for the current grid and mark
// every tile dirty. Returns RFB_ERR_NOMEM on allocation failure (the prior
// grid state is left intact — transactional).
static rfb_error kt_alloc_grid(rfb_kitty_tile *kt, uint32_t w, uint32_t h)
{
    uint32_t cols, rows;
    if (!rfb_kitty_tile_grid(w, h, kt->tile_edge, &cols, &rows)) {
        // Grid too large: whole-frame mode, no bitmap.
        kt->whole_frame_mode = true;
        kt->cols = 0;
        kt->rows = 0;
        kt->tile_count = 0;
        if (kt->dirty != NULL) {
            kt->alloc->free(kt->alloc, kt->dirty);
            kt->dirty = NULL;
        }
        kt->full_frame_dirty = true;
        return RFB_OK;
    }
    size_t count = (size_t)cols * (size_t)rows;
    uint8_t *bitmap = (uint8_t *)kt->alloc->alloc(kt->alloc, count);
    if (bitmap == NULL) {
        return RFB_ERR_NOMEM;
    }
    // Mark all tiles dirty (first paint / after resize is a full repaint).
    memset(bitmap, 1, count);
    if (kt->dirty != NULL) {
        kt->alloc->free(kt->alloc, kt->dirty);
    }
    kt->dirty = bitmap;
    kt->cols = cols;
    kt->rows = rows;
    kt->tile_count = count;
    kt->whole_frame_mode = false;
    kt->full_frame_dirty = true;  // first paint of this grid is full
    return RFB_OK;
}

rfb_error rfb_kitty_tile_open(rfb_kitty_tile *kt, const rfb_framebuffer *fb)
{
    if (kt == NULL || fb == NULL) return RFB_ERR_INTERNAL;
    kt->fb_width = fb->width;
    kt->fb_height = fb->height;
    kt->base_image_id = 1u;  // Kitty image IDs must be nonzero
    return kt_alloc_grid(kt, fb->width, fb->height);
}

// --- Damage marking + coalescing -----------------------------------------

void rfb_kitty_tile_mark_damage(rfb_kitty_tile *kt,
                                const rfb_damage_batch *damage)
{
    if (kt == NULL || damage == NULL) return;
    if (kt->whole_frame_mode || damage->full_frame) {
        kt->full_frame_dirty = true;
        return;
    }
    if (kt->dirty == NULL) return;
    // Map each rect to its tile set and mark them dirty. Idempotent: a tile
    // already dirty stays dirty; superseded damage in the same tile is
    // absorbed. The final committed state is preserved because every dirty
    // tile is retransmitted at present time.
    //
    // We compute the tile column/row range inline (O(1) stack) rather than
    // collecting indices into a large stack array.
    for (size_t i = 0; i < damage->count; i++) {
        const rfb_rect *r = &damage->rects[i];
        // Clamp the rect to the framebuffer (64-bit to avoid overflow).
        uint64_t xe = (uint64_t)r->x + (uint64_t)r->width;
        uint64_t ye = (uint64_t)r->y + (uint64_t)r->height;
        if (xe > kt->fb_width) xe = kt->fb_width;
        if (ye > kt->fb_height) ye = kt->fb_height;
        if (xe <= r->x || ye <= r->y) continue;
        uint32_t col_lo = r->x / kt->tile_edge;
        uint32_t col_hi = (uint32_t)((xe - 1u) / kt->tile_edge);
        uint32_t row_lo = r->y / kt->tile_edge;
        uint32_t row_hi = (uint32_t)((ye - 1u) / kt->tile_edge);
        if (col_hi >= kt->cols) col_hi = kt->cols - 1u;
        if (row_hi >= kt->rows) row_hi = kt->rows - 1u;
        for (uint32_t row = row_lo; row <= row_hi; row++) {
            for (uint32_t col = col_lo; col <= col_hi; col++) {
                size_t idx = (size_t)row * (size_t)kt->cols + (size_t)col;
                kt->dirty[idx] = 1;
                kt->metrics.damage_tiles_touched++;
            }
        }
    }
}

// --- close / resize / delete_all / present (filled in by later cycles) --

void rfb_kitty_tile_delete_all(rfb_kitty_tile *kt)
{
    if (kt == NULL) return;
    // Emit delete-image commands for the whole grid range (best-effort).
    // The terminal removes all placements of these image IDs.
    if (kt->out != NULL && kt->tile_count > 0 && !kt->whole_frame_mode) {
        for (size_t i = 0; i < kt->tile_count; i++) {
            uint32_t iid = kt->base_image_id + (uint32_t)i;
            if (kitty_encode_delete_image(kt->out, iid) != RFB_OK) {
                break; // Stop stacking partial deletes.
            }
        }
    }
}

bool rfb_kitty_tile_ack_shm(rfb_kitty_tile *kt, uint32_t image_id)
{
    if (kt == NULL) return false;
    for (size_t i = 0; i < KITTY_SHM_MAX_INFLIGHT; i++) {
        if (kt->shm_table.entries[i].in_use &&
            kt->shm_table.entries[i].image_id == image_id) {
            // Unlink the SHM object (terminal has consumed it).
            if (kt->shm_table.entries[i].name[0] != '\0') {
                shm_unlink(kt->shm_table.entries[i].name);
            }
            rfb_shm_table_ack(&kt->shm_table, image_id);
            kt->shm_send_time[i] = 0;
            return true;
        }
    }
    return false;
}

size_t rfb_kitty_tile_reclaim_expired_shm(rfb_kitty_tile *kt, uint64_t now_ms)
{
    if (kt == NULL) return 0;
    size_t reclaimed = 0;
    for (size_t i = 0; i < KITTY_SHM_MAX_INFLIGHT; i++) {
        if (!kt->shm_table.entries[i].in_use) continue;
        uint64_t sent = kt->shm_send_time[i];
        if (sent == 0) continue;  // no timestamp (shouldn't happen)
        if (now_ms - sent >= kt->ack_timeout_ms) {
            // Timed out: unlink and free the slot.
            if (kt->shm_table.entries[i].name[0] != '\0') {
                shm_unlink(kt->shm_table.entries[i].name);
            }
            rfb_shm_table_ack(&kt->shm_table,
                              kt->shm_table.entries[i].image_id);
            kt->shm_send_time[i] = 0;
            reclaimed++;
        }
    }
    return reclaimed;
}

void rfb_kitty_tile_close(rfb_kitty_tile *kt)
{
    if (kt == NULL) return;
    rfb_kitty_tile_delete_all(kt);
    rfb_kitty_tile_destroy(kt);
    kt->fb_width = 0;
    kt->fb_height = 0;
}

rfb_error rfb_kitty_tile_resize(rfb_kitty_tile *kt, const rfb_framebuffer *fb)
{
    if (kt == NULL || fb == NULL) return RFB_ERR_INTERNAL;
    // No-op when geometry is unchanged — callers (MT present loop) may
    // invoke resize every frame; deleting then re-uploading blanks Kitty.
    if (kt->fb_width == fb->width && kt->fb_height == fb->height &&
        (kt->dirty != NULL || kt->whole_frame_mode)) {
        return RFB_OK;
    }
    // Delete the old images so the terminal does not keep stale tiles
    // (plan.md §G22: "no stale tiles after resize/reconnect").
    rfb_kitty_tile_delete_all(kt);
    rfb_kitty_tile_destroy(kt);
    kt->fb_width = fb->width;
    kt->fb_height = fb->height;
    return kt_alloc_grid(kt, fb->width, fb->height);
}

// Encode a single tile into the output buffer via the direct base64 path.
// Reads only the tile's pixel rows from the framebuffer (crop reconstruction:
// no full-frame copy). Allocates a staging buffer of exactly tile_w*tile_h*4
// bytes. Updates the copy/alloc counters. Returns RFB_OK / RFB_ERR_NOMEM /
// RFB_ERR_LIMIT.
static rfb_error kt_encode_tile_direct(rfb_kitty_tile *kt,
                                       const rfb_framebuffer *fb,
                                       uint32_t origin_x, uint32_t origin_y,
                                       uint32_t tile_w, uint32_t tile_h,
                                       uint32_t image_id)
{
    // Staging buffer: exactly the tile's pixel bytes, NOT the whole frame.
    // This is the headline G22 invariant — measurable via bytes_allocated.
    size_t tile_bytes = (size_t)tile_w * (size_t)tile_h * RFB_BPP_CANONICAL;
    uint8_t *staging = (uint8_t *)kt->alloc->alloc(kt->alloc, tile_bytes);
    if (staging == NULL) {
        return RFB_ERR_NOMEM;
    }
    kt->metrics.bytes_allocated += tile_bytes;

    // Copy only this tile's rows from the framebuffer. The framebuffer may
    // have a stride != width*4 in general, so we copy row by row.
    for (uint32_t row = 0; row < tile_h; row++) {
        const uint8_t *src = rfb_framebuffer_pixel_c(fb, origin_x,
                                                     origin_y + row);
        memcpy(staging + (size_t)row * tile_w * RFB_BPP_CANONICAL,
               src, (size_t)tile_w * RFB_BPP_CANONICAL);
    }
    kt->metrics.bytes_copied += tile_bytes;

    // Encode with the tile's stable image ID. Retransmitting the same ID
    // updates the placement in place (no stacking). placement_id equals
    // image_id (1:1 placement per image).
    uint32_t place_c = 0u;
    uint32_t place_r = 0u;
    rfb_kitty_tile_place_pair(kt, &place_c, &place_r);
    rfb_error e = kitty_encode_direct_framebuffer(
        kt->out, staging, tile_w, tile_h, KITTY_FMT_RGBA32,
        image_id, image_id, kt->request_ack, place_c, place_r);

    kt->alloc->free(kt->alloc, staging);
    return e;
}

// Present a single tile (computes geometry, encodes, clears dirty bit).
static rfb_error kt_present_tile(rfb_kitty_tile *kt,
                                 const rfb_framebuffer *fb,
                                 size_t tile_index)
{
    uint32_t col = (uint32_t)(tile_index % kt->cols);
    uint32_t row = (uint32_t)(tile_index / kt->cols);
    uint32_t origin_x = col * kt->tile_edge;
    uint32_t origin_y = row * kt->tile_edge;
    // Tile dimensions: full edge, or the remainder on the right/bottom edge.
    uint32_t tile_w = kt->tile_edge;
    if (origin_x + tile_w > fb->width) {
        tile_w = fb->width - origin_x;
    }
    uint32_t tile_h = kt->tile_edge;
    if (origin_y + tile_h > fb->height) {
        tile_h = fb->height - origin_y;
    }
    uint32_t image_id = kt->base_image_id + (uint32_t)tile_index;

    rfb_error e;
    if (kt->use_shm) {
        // Free any prior in-flight entry for this image_id so re-presenting
        // the same whole-frame ID at 30+ fps does not fill the table and
        // silently fall back to multi-MB base64 (the live RDP pathology).
        (void)rfb_kitty_tile_ack_shm(kt, image_id);
        // If still full, evict the oldest in-use slot.
        if (rfb_shm_table_full(&kt->shm_table)) {
            for (size_t s = 0; s < KITTY_SHM_MAX_INFLIGHT; s++) {
                if (kt->shm_table.entries[s].in_use) {
                    (void)rfb_kitty_tile_ack_shm(
                        kt, kt->shm_table.entries[s].image_id);
                    break;
                }
            }
        }

        // SHM one-shot: contiguous RGBA staging for this tile/frame.
        size_t tile_bytes = (size_t)tile_w * (size_t)tile_h * RFB_BPP_CANONICAL;
        uint8_t *staging = (uint8_t *)kt->alloc->alloc(kt->alloc, tile_bytes);
        if (staging == NULL) {
            return RFB_ERR_NOMEM;
        }
        kt->metrics.bytes_allocated += tile_bytes;
        for (uint32_t r = 0; r < tile_h; r++) {
            const uint8_t *src = rfb_framebuffer_pixel_c(fb, origin_x,
                                                         origin_y + r);
            memcpy(staging + (size_t)r * tile_w * RFB_BPP_CANONICAL,
                   src, (size_t)tile_w * RFB_BPP_CANONICAL);
        }
        kt->metrics.bytes_copied += tile_bytes;

        uint32_t place_c = 0u;
        uint32_t place_r = 0u;
        rfb_kitty_tile_place_pair(kt, &place_c, &place_r);
        e = rfb_shm_transfer(kt->out, staging, tile_w, tile_h,
                             KITTY_FMT_RGBA32, image_id, image_id,
                             kt->request_ack, &kt->shm_table,
                             place_c, place_r);
        if (e == RFB_OK) {
            kt->metrics.shm_transfers++;
            for (size_t s = 0; s < KITTY_SHM_MAX_INFLIGHT; s++) {
                if (kt->shm_table.entries[s].in_use &&
                    kt->shm_table.entries[s].image_id == image_id &&
                    kt->shm_send_time[s] == 0) {
                    kt->shm_send_time[s] = kt->logical_clock_ms;
                    break;
                }
            }
            // Without terminal acks, keep only the newest frame in flight
            // so the table never caps us into the base64 fallback.
            if (!kt->request_ack) {
                // Leave the just-added entry; next present will replace it.
            }
        } else {
            // SHM failed (shm_open/mmap error, etc.): fall back to direct.
            kt->metrics.shm_fallbacks++;
            e = kitty_encode_direct_framebuffer(
                kt->out, staging, tile_w, tile_h, KITTY_FMT_RGBA32,
                image_id, image_id, kt->request_ack, place_c, place_r);
        }
        kt->alloc->free(kt->alloc, staging);
    } else {
        e = kt_encode_tile_direct(kt, fb, origin_x, origin_y,
                                  tile_w, tile_h, image_id);
    }
    return e;
}

rfb_error rfb_kitty_tile_present(rfb_kitty_tile *kt,
                                 const rfb_framebuffer *fb,
                                 const rfb_damage_batch *damage)
{
    if (kt == NULL || fb == NULL) return RFB_ERR_INTERNAL;
    if (kt->out == NULL) {
        // No output sink: just clear the dirty state (tests that inspect
        // metrics pass NULL output and don't expect encoding).
        kt->full_frame_dirty = false;
        if (kt->dirty != NULL) {
            memset(kt->dirty, 0, kt->tile_count);
        }
        kt->metrics.presents++;
        return RFB_OK;
    }

    // Fold the incoming damage into the dirty bitmap before presenting, so
    // that a single present() call handles both "mark then present" and
    // "present with damage" usage. This is idempotent coalescing: tiles
    // already dirty stay dirty; the final state is never lost.
    if (damage != NULL) {
        rfb_kitty_tile_mark_damage(kt, damage);
    }

    kt->metrics.presents++;

    // Advance the logical clock (frame-rate granularity; deterministic).
    kt->logical_clock_ms += 16;  // ~60fps nominal

    // Decide what to send: full frame, or only dirty tiles.
    bool send_full = kt->full_frame_dirty || kt->whole_frame_mode;

    if (send_full) {
        if (kt->whole_frame_mode || kt->dirty == NULL) {
            // Whole-frame mode: one image for the entire framebuffer.
            // Prefer SHM when configured — pixels never cross the PTY
            // (same path full-HD terminal video players use).
            kt->metrics.full_frame_presents++;
            rfb_error e;
            // Always stage tightly: rfb_shm_transfer / direct assume
            // width*height*4 contiguous bytes, but MT frame views may
            // use a larger stride. Row-copy into a tight buffer.
            const size_t frame_bytes =
                (size_t)fb->width * (size_t)fb->height * RFB_BPP_CANONICAL;
            uint8_t *staging =
                (uint8_t *)kt->alloc->alloc(kt->alloc, frame_bytes);
            if (staging == NULL) {
                return RFB_ERR_NOMEM;
            }
            if (fb->stride == (size_t)fb->width * RFB_BPP_CANONICAL) {
                memcpy(staging, fb->rgba, frame_bytes);
            } else {
                for (uint32_t r = 0; r < fb->height; r++) {
                    const uint8_t *src = rfb_framebuffer_pixel_c(fb, 0, r);
                    memcpy(staging + (size_t)r * (size_t)fb->width *
                                         RFB_BPP_CANONICAL,
                           src, (size_t)fb->width * RFB_BPP_CANONICAL);
                }
            }
            uint32_t place_c = 0u;
            uint32_t place_r = 0u;
            rfb_kitty_tile_place_pair(kt, &place_c, &place_r);
            if (kt->use_shm) {
                (void)rfb_kitty_tile_ack_shm(kt, kt->base_image_id);
                e = rfb_shm_transfer(kt->out, staging, fb->width, fb->height,
                                     KITTY_FMT_RGBA32, kt->base_image_id,
                                     kt->base_image_id, kt->request_ack,
                                     &kt->shm_table, place_c, place_r);
                if (e == RFB_OK) {
                    kt->metrics.shm_transfers++;
                } else {
                    kt->metrics.shm_fallbacks++;
                    e = kitty_encode_direct_framebuffer(
                        kt->out, staging, fb->width, fb->height,
                        KITTY_FMT_RGBA32, kt->base_image_id, kt->base_image_id,
                        kt->request_ack, place_c, place_r);
                }
            } else {
                e = kitty_encode_direct_framebuffer(
                    kt->out, staging, fb->width, fb->height,
                    KITTY_FMT_RGBA32, kt->base_image_id, kt->base_image_id,
                    kt->request_ack, place_c, place_r);
            }
            kt->alloc->free(kt->alloc, staging);
            if (e != RFB_OK) {
                // encoder rolls back its own suffix via truncate-to-mark
                return e;
            }
            kt->metrics.bytes_copied += frame_bytes;
            kt->metrics.bytes_allocated += frame_bytes;
            kt->metrics.tiles_encoded++;
        } else {
            // Tile mode but full-frame dirty: send every tile.
            for (size_t i = 0; i < kt->tile_count; i++) {
                rfb_error e = kt_present_tile(kt, fb, i);
                if (e != RFB_OK) return e;
                kt->metrics.tiles_encoded++;
                kt->dirty[i] = 0;
            }
        }
        kt->full_frame_dirty = false;
    } else {
        // Send only the dirty tiles (the common small-damage path).
        for (size_t i = 0; i < kt->tile_count; i++) {
            if (kt->dirty[i] == 0) continue;
            rfb_error e = kt_present_tile(kt, fb, i);
            if (e != RFB_OK) return e;
            kt->metrics.tiles_encoded++;
            kt->metrics.damage_tiles_sent++;
            kt->dirty[i] = 0;
        }
    }

    // Update backpressure state based on the output buffer level.
    if (rfb_buffer_length(kt->out) > kt->high_water_bytes) {
        if (!kt->backpressure) {
            kt->metrics.backpressure_events++;
        }
        kt->backpressure = true;
    } else {
        kt->backpressure = false;
    }

    return RFB_OK;
}

// --- Presenter ops table (rfb_presenter_ops interface) -------------------

static int kt_ops_open(void *ctx, const rfb_framebuffer *fb)
{
    return (int)rfb_kitty_tile_open((rfb_kitty_tile *)ctx, fb);
}

static int kt_ops_resize(void *ctx, const rfb_framebuffer *fb)
{
    return (int)rfb_kitty_tile_resize((rfb_kitty_tile *)ctx, fb);
}

static int kt_ops_present(void *ctx, const rfb_framebuffer *fb,
                          const rfb_damage_batch *damage)
{
    return (int)rfb_kitty_tile_present((rfb_kitty_tile *)ctx, fb, damage);
}

static void kt_ops_close(void *ctx)
{
    rfb_kitty_tile_close((rfb_kitty_tile *)ctx);
}

const rfb_presenter_ops rfb_kitty_tile_ops = {
    .open    = kt_ops_open,
    .resize  = kt_ops_resize,
    .present = kt_ops_present,
    .close   = kt_ops_close,
};
