// SPDX-License-Identifier: Apache-2.0
//
// Tile-aware, damage-aware Kitty presenter tests.
//
// These tests cover tile-grid geometry, the dirty bitmap and coalescing,
// crop reconstruction, SHM fallback, resize, teardown, and allocation counts.

#include "rfb_test.h"
#include "farsee/kitty_tile.h"
#include "farsee/allocator.h"
#include "farsee/buffer.h"
#include "farsee/framebuffer.h"
#include "farsee/kitty_shm_table.h"
#include "farsee/presenter.h"

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

// =========================================================================
// Tile-grid geometry (pure helpers)
// =========================================================================

RFB_TEST(kt_grid, grid__exact_multiple__no_partial_tiles) {
    // 512x512 with 256 edge -> 2x2 = 4 tiles, no partials.
    uint32_t cols = 0, rows = 0;
    bool ok = rfb_kitty_tile_grid(512, 512, 256, &cols, &rows);
    RFB_CHECK(ok);
    RFB_CHECK_EQ_UINT(cols, 2u);
    RFB_CHECK_EQ_UINT(rows, 2u);
}

RFB_TEST(kt_grid, grid__non_multiple__has_partial_edge_tiles) {
    // 300x100 with 256 edge -> cols=2 (256 + 44), rows=1.
    uint32_t cols = 0, rows = 0;
    bool ok = rfb_kitty_tile_grid(300, 100, 256, &cols, &rows);
    RFB_CHECK(ok);
    RFB_CHECK_EQ_UINT(cols, 2u);
    RFB_CHECK_EQ_UINT(rows, 1u);
}

RFB_TEST(kt_grid, grid__smaller_than_tile__single_tile) {
    // 100x50 with 256 edge -> 1x1.
    uint32_t cols = 0, rows = 0;
    bool ok = rfb_kitty_tile_grid(100, 50, 256, &cols, &rows);
    RFB_CHECK(ok);
    RFB_CHECK_EQ_UINT(cols, 1u);
    RFB_CHECK_EQ_UINT(rows, 1u);
}

RFB_TEST(kt_grid, grid__too_many_tiles__returns_false) {
    // A framebuffer so large the grid would exceed the cap.
    // 65536x65536 with 256 edge -> 256*256 = 65536 tiles > 4096 cap.
    uint32_t cols = 0, rows = 0;
    bool ok = rfb_kitty_tile_grid(65536u, 65536u, 256, &cols, &rows);
    RFB_CHECK(!ok);
}

RFB_TEST(kt_rect, rect_to_tiles__single_tile_interior) {
    // 512x512 grid, 256 edge, 2x2 tiles (row-major: 0,1 / 2,3).
    // A rect fully inside tile 0 (top-left): x=10,y=10,w=20,h=20.
    size_t idx[16];
    size_t n = rfb_kitty_tile_rect_to_tiles(10, 10, 20, 20,
                                            512, 512, 256, 2, 2, idx);
    RFB_CHECK_EQ_UINT(n, 1u);
    RFB_CHECK_EQ_UINT(idx[0], 0u);
}

RFB_TEST(kt_rect, rect_to_tiles__spans_two_horizontal_tiles) {
    // Rect crossing the vertical boundary at x=256: tiles 0 and 1.
    size_t idx[16];
    size_t n = rfb_kitty_tile_rect_to_tiles(200, 10, 100, 20,
                                            512, 512, 256, 2, 2, idx);
    RFB_CHECK_EQ_UINT(n, 2u);
    RFB_CHECK_EQ_UINT(idx[0], 0u);
    RFB_CHECK_EQ_UINT(idx[1], 1u);
}

RFB_TEST(kt_rect, rect_to_tiles__spans_four_tiles_at_center) {
    // Rect straddling the center crossing: touches all 4 tiles.
    size_t idx[16];
    size_t n = rfb_kitty_tile_rect_to_tiles(250, 250, 12, 12,
                                            512, 512, 256, 2, 2, idx);
    RFB_CHECK_EQ_UINT(n, 4u);
    // Expect 0,1,2,3 in some order; sort and check.
    bool seen[4] = { false, false, false, false };
    for (size_t i = 0; i < n; i++) {
        RFB_CHECK(idx[i] < 4u);
        seen[idx[i]] = true;
    }
    for (size_t i = 0; i < 4u; i++) {
        RFB_CHECK(seen[i]);
    }
}

RFB_TEST(kt_rect, rect_to_tiles__no_duplicates) {
    // A wide rect spanning many tiles must not list any tile twice.
    size_t idx[64];
    size_t n = rfb_kitty_tile_rect_to_tiles(0, 0, 512, 256,
                                            512, 512, 256, 2, 2, idx);
    RFB_CHECK_EQ_UINT(n, 2u);  // top row: tiles 0,1
    RFB_CHECK_EQ_UINT(idx[0], 0u);
    RFB_CHECK_EQ_UINT(idx[1], 1u);
}

// =========================================================================
// init / open / destroy + dirty bitmap
// =========================================================================
//
// A helper framebuffer: 512x512, 2x2 tiles (256 edge). Tiles row-major:
//   0 (0,0)     1 (256,0)
//   2 (0,256)   3 (256,256)

static void kt_setup_fb(rfb_framebuffer *fb)
{
    rfb_framebuffer_init(fb, rfb_default_allocator());
    rfb_framebuffer_resize(fb, 512, 512, 1u << 20);
}

RFB_TEST(kt_open, open__marks_whole_grid_dirty) {
    rfb_kitty_tile kt;
    rfb_kitty_tile_init(&kt, rfb_default_allocator(), NULL, 256, false, false);
    rfb_framebuffer fb;
    kt_setup_fb(&fb);
    RFB_CHECK_EQ_INT(rfb_kitty_tile_open(&kt, &fb), RFB_OK);
    // 2x2 = 4 tiles.
    RFB_CHECK_EQ_UINT(kt.cols, 2u);
    RFB_CHECK_EQ_UINT(kt.rows, 2u);
    RFB_CHECK_EQ_UINT(kt.tile_count, 4u);
    RFB_CHECK(kt.dirty != NULL);
    // First frame is a full paint: all tiles dirty.
    for (size_t i = 0; i < kt.tile_count; i++) {
        RFB_CHECK(kt.dirty[i] != 0);
    }
    rfb_kitty_tile_close(&kt);
    rfb_framebuffer_destroy(&fb);
}

RFB_TEST(kt_open, open__whole_frame_mode_when_grid_too_large) {
    rfb_kitty_tile kt;
    rfb_kitty_tile_init(&kt, rfb_default_allocator(), NULL, 256, false, false);
    rfb_framebuffer fb;
    rfb_framebuffer_init(&fb, rfb_default_allocator());
    // 65536x1 -> 256 cols x 1 row = 256 tiles, OK. Use 65536x65536 -> too many.
    rfb_framebuffer_resize(&fb, 65536u, 65536u, 1u << 30);
    // open should not fail; it falls back to whole-frame mode.
    RFB_CHECK_EQ_INT(rfb_kitty_tile_open(&kt, &fb), RFB_OK);
    RFB_CHECK(kt.whole_frame_mode);
    RFB_CHECK(kt.dirty == NULL);
    rfb_kitty_tile_close(&kt);
    rfb_framebuffer_destroy(&fb);
}

RFB_TEST(kt_coalesce, mark_damage__single_rect__marks_intersecting_tiles) {
    rfb_kitty_tile kt;
    rfb_kitty_tile_init(&kt, rfb_default_allocator(), NULL, 256, false, false);
    rfb_framebuffer fb;
    kt_setup_fb(&fb);
    rfb_kitty_tile_open(&kt, &fb);
    // Clear the dirty bitmap (simulate a clean state after first paint).
    memset(kt.dirty, 0, kt.tile_count);
    kt.full_frame_dirty = false;

    // Damage rect fully in tile 1 (top-right): x=300,y=10,w=20,h=20.
    rfb_rect r = { .x = 300, .y = 10, .width = 20, .height = 20 };
    rfb_damage_batch b = { .rects = &r, .count = 1, .full_frame = false };
    rfb_kitty_tile_mark_damage(&kt, &b);
    RFB_CHECK_EQ_UINT(kt.dirty[0], 0u);
    RFB_CHECK(kt.dirty[1] != 0);
    RFB_CHECK_EQ_UINT(kt.dirty[2], 0u);
    RFB_CHECK_EQ_UINT(kt.dirty[3], 0u);
    rfb_kitty_tile_close(&kt);
    rfb_framebuffer_destroy(&fb);
}

RFB_TEST(kt_coalesce, mark_damage__two_batches__coalesces_keeps_both) {
    rfb_kitty_tile kt;
    rfb_kitty_tile_init(&kt, rfb_default_allocator(), NULL, 256, false, false);
    rfb_framebuffer fb;
    kt_setup_fb(&fb);
    rfb_kitty_tile_open(&kt, &fb);
    memset(kt.dirty, 0, kt.tile_count);
    kt.full_frame_dirty = false;

    // Batch 1: tile 0.
    rfb_rect r0 = { .x = 10, .y = 10, .width = 5, .height = 5 };
    rfb_damage_batch b0 = { .rects = &r0, .count = 1, .full_frame = false };
    rfb_kitty_tile_mark_damage(&kt, &b0);
    // Batch 2: tile 3 (different region).
    rfb_rect r3 = { .x = 300, .y = 300, .width = 5, .height = 5 };
    rfb_damage_batch b3 = { .rects = &r3, .count = 1, .full_frame = false };
    rfb_kitty_tile_mark_damage(&kt, &b3);
    // Both tiles remain dirty (final state preserved).
    RFB_CHECK(kt.dirty[0] != 0);
    RFB_CHECK_EQ_UINT(kt.dirty[1], 0u);
    RFB_CHECK_EQ_UINT(kt.dirty[2], 0u);
    RFB_CHECK(kt.dirty[3] != 0);
    rfb_kitty_tile_close(&kt);
    rfb_framebuffer_destroy(&fb);
}

RFB_TEST(kt_coalesce, mark_damage__superseded_rect__re_marks_idempotently) {
    rfb_kitty_tile kt;
    rfb_kitty_tile_init(&kt, rfb_default_allocator(), NULL, 256, false, false);
    rfb_framebuffer fb;
    kt_setup_fb(&fb);
    rfb_kitty_tile_open(&kt, &fb);
    memset(kt.dirty, 0, kt.tile_count);
    kt.full_frame_dirty = false;

    // First rect marks tile 0.
    rfb_rect r0 = { .x = 10, .y = 10, .width = 5, .height = 5 };
    rfb_damage_batch b0 = { .rects = &r0, .count = 1, .full_frame = false };
    rfb_kitty_tile_mark_damage(&kt, &b0);
    // A superseding rect in the SAME tile just re-marks it (no duplication,
    // no clearing). The final committed state is tile 0 dirty.
    rfb_rect r1 = { .x = 20, .y = 20, .width = 5, .height = 5 };
    rfb_damage_batch b1 = { .rects = &r1, .count = 1, .full_frame = false };
    rfb_kitty_tile_mark_damage(&kt, &b1);
    RFB_CHECK(kt.dirty[0] != 0);
    RFB_CHECK_EQ_UINT(kt.dirty[1], 0u);
    rfb_kitty_tile_close(&kt);
    rfb_framebuffer_destroy(&fb);
}

RFB_TEST(kt_coalesce, mark_damage__full_frame_batch__sets_full_frame_dirty) {
    rfb_kitty_tile kt;
    rfb_kitty_tile_init(&kt, rfb_default_allocator(), NULL, 256, false, false);
    rfb_framebuffer fb;
    kt_setup_fb(&fb);
    rfb_kitty_tile_open(&kt, &fb);
    memset(kt.dirty, 0, kt.tile_count);
    kt.full_frame_dirty = false;

    rfb_damage_batch b = { .rects = NULL, .count = 0, .full_frame = true };
    rfb_kitty_tile_mark_damage(&kt, &b);
    RFB_CHECK(kt.full_frame_dirty);
    rfb_kitty_tile_close(&kt);
    rfb_framebuffer_destroy(&fb);
}

// =========================================================================
// present(): tile selection, crop reconstruction, counters
// =========================================================================
//
// A helper to count distinct Kitty image transmissions in the output. The
// encoder chunks a single image across multiple APC sequences (m=1 more-
// follows); only the FIRST chunk of each image contains the "f=" format
// field. So counting "f=" occurrences counts distinct images/tiles.

static size_t kt_count_image_transmissions(const rfb_buffer *out)
{
    const uint8_t *d = rfb_buffer_data(out);
    size_t len = rfb_buffer_length(out);
    size_t count = 0;
    for (size_t i = 0; i + 1 < len; i++) {
        // First chunk of an image contains "f=" (the format field).
        if (d[i] == 'f' && d[i + 1] == '=') {
            count++;
        }
    }
    return count;
}

RFB_TEST(kt_present, present__first_paint__sends_all_tiles) {
    rfb_buffer out;
    rfb_buffer_init(&out, rfb_default_allocator(), 1u << 23);
    rfb_kitty_tile kt;
    rfb_kitty_tile_init(&kt, rfb_default_allocator(), &out, 256, false, false);
    rfb_framebuffer fb;
    kt_setup_fb(&fb);
    rfb_kitty_tile_open(&kt, &fb);
    // First present: full paint (open marks everything dirty).
    RFB_CHECK_EQ_INT(rfb_kitty_tile_present(&kt, &fb, NULL), RFB_OK);
    // 2x2 grid => 4 tile image transmissions.
    RFB_CHECK_EQ_UINT(kt_count_image_transmissions(&out), 4u);
    RFB_CHECK_EQ_UINT(kt.metrics.tiles_encoded, 4u);
    RFB_CHECK_EQ_UINT(kt.metrics.presents, 1u);
    // After present, nothing is dirty.
    for (size_t i = 0; i < kt.tile_count; i++) {
        RFB_CHECK_EQ_UINT(kt.dirty[i], 0u);
    }
    RFB_CHECK(!kt.full_frame_dirty);
    rfb_kitty_tile_close(&kt);
    rfb_framebuffer_destroy(&fb);
    rfb_buffer_destroy(&out);
}

RFB_TEST(kt_present, present__small_damage__sends_only_one_tile) {
    rfb_buffer out;
    rfb_buffer_init(&out, rfb_default_allocator(), 1u << 23);
    rfb_kitty_tile kt;
    rfb_kitty_tile_init(&kt, rfb_default_allocator(), &out, 256, false, false);
    rfb_framebuffer fb;
    kt_setup_fb(&fb);
    rfb_kitty_tile_open(&kt, &fb);
    // Paint once to clear the initial full-frame dirty state.
    rfb_kitty_tile_present(&kt, &fb, NULL);
    rfb_buffer_clear(&out);

    // Damage a small rect entirely within tile 3 (bottom-right).
    rfb_rect r = { .x = 300, .y = 300, .width = 10, .height = 10 };
    rfb_damage_batch b = { .rects = &r, .count = 1, .full_frame = false };
    RFB_CHECK_EQ_INT(rfb_kitty_tile_present(&kt, &fb, &b), RFB_OK);
    // Only ONE tile image transmission should be emitted.
    RFB_CHECK_EQ_UINT(kt_count_image_transmissions(&out), 1u);
    // tiles_encoded for this present = 1 (total counter accumulates).
    RFB_CHECK_EQ_UINT(kt.metrics.tiles_encoded, 4u + 1u);
    rfb_kitty_tile_close(&kt);
    rfb_framebuffer_destroy(&fb);
    rfb_buffer_destroy(&out);
}

RFB_TEST(kt_present, present__small_damage__no_full_frame_copy) {
    // A small damage must not copy or allocate
    // whole-frame bytes. For a 512x512x4 = 1MiB framebuffer, a 10x10 damage
    // touching one 256x256 tile copies only that tile's pixels.
    rfb_buffer out;
    rfb_buffer_init(&out, rfb_default_allocator(), 1u << 23);
    rfb_kitty_tile kt;
    rfb_kitty_tile_init(&kt, rfb_default_allocator(), &out, 256, false, false);
    rfb_framebuffer fb;
    kt_setup_fb(&fb);
    rfb_kitty_tile_open(&kt, &fb);
    rfb_kitty_tile_present(&kt, &fb, NULL);  // clear initial dirty
    rfb_buffer_clear(&out);

    uint64_t copied_before = kt.metrics.bytes_copied;
    uint64_t alloc_before = kt.metrics.bytes_allocated;
    rfb_rect r = { .x = 300, .y = 300, .width = 10, .height = 10 };
    rfb_damage_batch b = { .rects = &r, .count = 1, .full_frame = false };
    rfb_kitty_tile_present(&kt, &fb, &b);
    uint64_t copied_now = kt.metrics.bytes_copied - copied_before;
    uint64_t alloc_now = kt.metrics.bytes_allocated - alloc_before;
    // One 256x256x4 = 262144 bytes tile. Whole frame = 1048576 bytes.
    RFB_CHECK_EQ_UINT(copied_now, 262144u);
    RFB_CHECK_EQ_UINT(alloc_now, 262144u);
    // Strictly less than the full frame.
    RFB_CHECK(copied_now < 1048576u);
    rfb_kitty_tile_close(&kt);
    rfb_framebuffer_destroy(&fb);
    rfb_buffer_destroy(&out);
}

RFB_TEST(kt_present, present__does_not_mutate_framebuffer) {
    // Presenters never mutate the framebuffer.
    rfb_buffer out;
    rfb_buffer_init(&out, rfb_default_allocator(), 1u << 23);
    rfb_kitty_tile kt;
    rfb_kitty_tile_init(&kt, rfb_default_allocator(), &out, 256, false, false);
    rfb_framebuffer fb;
    kt_setup_fb(&fb);
    // Fill with a known pattern.
    rfb_framebuffer_fill(&fb, 0xAA, 0xBB, 0xCC, 0xDD);
    // Snapshot the whole framebuffer.
    size_t fb_bytes = fb.width * fb.height * 4u;
    uint8_t *snap = (uint8_t *)rfb_default_allocator()->alloc(
        rfb_default_allocator(), fb_bytes);
    RFB_CHECK(snap != NULL);
    memcpy(snap, fb.rgba, fb_bytes);

    rfb_kitty_tile_open(&kt, &fb);
    rfb_rect r = { .x = 100, .y = 100, .width = 50, .height = 50 };
    rfb_damage_batch b = { .rects = &r, .count = 1, .full_frame = false };
    rfb_kitty_tile_present(&kt, &fb, &b);
    rfb_kitty_tile_present(&kt, &fb, NULL);

    RFB_CHECK_MEM_EQ(fb.rgba, snap, fb_bytes);
    rfb_default_allocator()->free(rfb_default_allocator(), snap);
    rfb_kitty_tile_close(&kt);
    rfb_framebuffer_destroy(&fb);
    rfb_buffer_destroy(&out);
}

// =========================================================================
// SHM transport + fallback
// =========================================================================
//
// A helper: count occurrences of a 3-byte substring "t=X" in the output.
// t=s = shared-memory transfer; t=d = direct base64 transfer.

static bool kt_output_contains(const rfb_buffer *out, const char *needle)
{
    const uint8_t *d = rfb_buffer_data(out);
    size_t len = rfb_buffer_length(out);
    size_t nl = strlen(needle);
    if (nl == 0 || nl > len) return false;
    for (size_t i = 0; i + nl <= len; i++) {
        if (memcmp(d + i, needle, nl) == 0) return true;
    }
    return false;
}

RFB_TEST(kt_shm, present__use_shm__emits_shm_transfer) {
    rfb_buffer out;
    rfb_buffer_init(&out, rfb_default_allocator(), 1u << 23);
    rfb_kitty_tile kt;
    rfb_kitty_tile_init(&kt, rfb_default_allocator(), &out, 256, true, false);
    rfb_framebuffer fb;
    kt_setup_fb(&fb);
    rfb_kitty_tile_open(&kt, &fb);

    // First paint with use_shm: should emit t=s commands.
    RFB_CHECK_EQ_INT(rfb_kitty_tile_present(&kt, &fb, NULL), RFB_OK);
    RFB_CHECK(kt_output_contains(&out, "t=s"));
    RFB_CHECK_EQ_UINT(kt.metrics.shm_transfers, 4u);  // 2x2 grid
    RFB_CHECK_EQ_UINT(kt.metrics.shm_fallbacks, 0u);
    // SHM objects are now in-flight (deferred unlink).
    RFB_CHECK_EQ_UINT(rfb_shm_table_count(&kt.shm_table), 4u);
    rfb_kitty_tile_close(&kt);
    rfb_framebuffer_destroy(&fb);
    rfb_buffer_destroy(&out);
}

RFB_TEST(kt_shm, present__same_ids_replace_not_fill_table) {
    // Re-presenting the same tile image IDs must replace prior SHM slots
    // instead of stacking until KITTY_SHM_MAX_INFLIGHT and falling back to
    // base64 under sustained high-rate presentation.
    rfb_buffer out;
    rfb_buffer_init(&out, rfb_default_allocator(), 1u << 24);
    rfb_kitty_tile kt;
    rfb_kitty_tile_init(&kt, rfb_default_allocator(), &out, 256, true, false);
    rfb_framebuffer fb;
    kt_setup_fb(&fb);
    rfb_kitty_tile_open(&kt, &fb);

    // Present once (4 tiles via SHM). Table has 4 entries.
    rfb_kitty_tile_present(&kt, &fb, NULL);
    RFB_CHECK_EQ_UINT(rfb_shm_table_count(&kt.shm_table), 4u);
    RFB_CHECK_EQ_UINT(kt.metrics.shm_transfers, 4u);
    rfb_buffer_clear(&out);

    // Second and third presents: same IDs → table stays at 4, still SHM.
    for (int round = 0; round < 2; round++) {
        kt.full_frame_dirty = true;
        RFB_CHECK_EQ_INT(rfb_kitty_tile_present(&kt, &fb, NULL), RFB_OK);
        RFB_CHECK_EQ_UINT(rfb_shm_table_count(&kt.shm_table), 4u);
        RFB_CHECK(kt_output_contains(&out, "t=s"));
        RFB_CHECK_EQ_UINT(kt.metrics.shm_fallbacks, 0u);
        rfb_buffer_clear(&out);
    }
    RFB_CHECK_EQ_UINT(kt.metrics.shm_transfers, 12u);  // 3 × 4 tiles
    rfb_kitty_tile_close(&kt);
    rfb_framebuffer_destroy(&fb);
    rfb_buffer_destroy(&out);
}

RFB_TEST(kt_shm, close__unlinks_inflight_shm_objects) {
    // After close, the in-flight SHM table must be empty AND the shm objects
    // must have been unlinked (no leak). We verify by checking the table is
    // cleared and that shm_open on the old names fails with ENOENT.
    rfb_buffer out;
    rfb_buffer_init(&out, rfb_default_allocator(), 1u << 23);
    rfb_kitty_tile kt;
    rfb_kitty_tile_init(&kt, rfb_default_allocator(), &out, 256, true, false);
    rfb_framebuffer fb;
    kt_setup_fb(&fb);
    rfb_kitty_tile_open(&kt, &fb);
    rfb_kitty_tile_present(&kt, &fb, NULL);
    RFB_CHECK(rfb_shm_table_count(&kt.shm_table) > 0);

    // Snapshot the names so we can verify they are gone after close.
    char saved_names[KITTY_SHM_MAX_INFLIGHT][KITTY_SHM_NAME_MAX];
    size_t saved_count = 0;
    for (size_t i = 0; i < KITTY_SHM_MAX_INFLIGHT; i++) {
        if (kt.shm_table.entries[i].in_use) {
            strncpy(saved_names[saved_count], kt.shm_table.entries[i].name,
                    KITTY_SHM_NAME_MAX - 1);
            saved_names[saved_count][KITTY_SHM_NAME_MAX - 1] = '\0';
            saved_count++;
        }
    }
    RFB_CHECK(saved_count > 0);

    rfb_kitty_tile_close(&kt);
    // Table is cleared.
    RFB_CHECK_EQ_UINT(rfb_shm_table_count(&kt.shm_table), 0u);
    // Each saved shm name is now gone (shm_open without O_CREAT fails).
    for (size_t i = 0; i < saved_count; i++) {
        int fd = shm_open(saved_names[i], O_RDONLY, 0);
        RFB_CHECK_EQ_INT(fd, -1);
    }
    rfb_framebuffer_destroy(&fb);
    rfb_buffer_destroy(&out);
}

// =========================================================================
// resize: stale tile cleanup + grid reallocation
// =========================================================================

RFB_TEST(kt_resize, resize__emits_delete_for_old_tiles) {
    // resize must emit delete-image commands for the OLD tiles so the
    // terminal does not keep stale images after resize or reconnect.
    rfb_buffer out;
    rfb_buffer_init(&out, rfb_default_allocator(), 1u << 23);
    rfb_kitty_tile kt;
    rfb_kitty_tile_init(&kt, rfb_default_allocator(), &out, 256, false, false);
    rfb_framebuffer fb;
    kt_setup_fb(&fb);  // 512x512 = 2x2 = 4 tiles
    rfb_kitty_tile_open(&kt, &fb);
    rfb_kitty_tile_present(&kt, &fb, NULL);
    rfb_buffer_clear(&out);

    // Resize to 256x256 = 1x1 = 1 tile. The old 4 tiles must be deleted.
    rfb_framebuffer_resize(&fb, 256, 256, 1u << 20);
    RFB_CHECK_EQ_INT(rfb_kitty_tile_resize(&kt, &fb), RFB_OK);
    // Output should contain 4 delete commands (a=d,d=I,i=<id>).
    size_t del_count = 0;
    const char *needle = "a=d,d=I,i=";
    const uint8_t *d = rfb_buffer_data(&out);
    size_t len = rfb_buffer_length(&out);
    size_t nl = strlen(needle);
    for (size_t i = 0; i + nl <= len; i++) {
        if (memcmp(d + i, needle, nl) == 0) del_count++;
    }
    RFB_CHECK_EQ_UINT(del_count, 4u);
    // New grid is 1x1.
    RFB_CHECK_EQ_UINT(kt.cols, 1u);
    RFB_CHECK_EQ_UINT(kt.rows, 1u);
    RFB_CHECK_EQ_UINT(kt.tile_count, 1u);
    rfb_kitty_tile_close(&kt);
    rfb_framebuffer_destroy(&fb);
    rfb_buffer_destroy(&out);
}

RFB_TEST(kt_resize, resize__new_grid_fully_dirty) {
    rfb_buffer out;
    rfb_buffer_init(&out, rfb_default_allocator(), 1u << 23);
    rfb_kitty_tile kt;
    rfb_kitty_tile_init(&kt, rfb_default_allocator(), &out, 256, false, false);
    rfb_framebuffer fb;
    kt_setup_fb(&fb);
    rfb_kitty_tile_open(&kt, &fb);
    rfb_kitty_tile_present(&kt, &fb, NULL);  // clear dirty

    // Resize to 768x256 = 3x1 = 3 tiles.
    rfb_framebuffer_resize(&fb, 768, 256, 1u << 22);
    RFB_CHECK_EQ_INT(rfb_kitty_tile_resize(&kt, &fb), RFB_OK);
    RFB_CHECK_EQ_UINT(kt.tile_count, 3u);
    // All 3 new tiles must be dirty (first paint of new geometry).
    for (size_t i = 0; i < kt.tile_count; i++) {
        RFB_CHECK(kt.dirty[i] != 0);
    }
    RFB_CHECK(kt.full_frame_dirty);
    // Presenting the new grid sends 3 tiles.
    rfb_buffer_clear(&out);
    RFB_CHECK_EQ_INT(rfb_kitty_tile_present(&kt, &fb, NULL), RFB_OK);
    RFB_CHECK_EQ_UINT(kt_count_image_transmissions(&out), 3u);
    rfb_kitty_tile_close(&kt);
    rfb_framebuffer_destroy(&fb);
    rfb_buffer_destroy(&out);
}

RFB_TEST(kt_resize, resize__to_whole_frame_mode_and_back) {
    rfb_buffer out;
    rfb_buffer_init(&out, rfb_default_allocator(), 1u << 25);
    rfb_kitty_tile kt;
    rfb_kitty_tile_init(&kt, rfb_default_allocator(), &out, 256, false, false);
    rfb_framebuffer fb;
    kt_setup_fb(&fb);
    rfb_kitty_tile_open(&kt, &fb);
    RFB_CHECK(!kt.whole_frame_mode);

    // Resize to something huge -> whole-frame mode.
    // 4097 cols * 1 row = 4097 tiles > 4096 cap.
    rfb_framebuffer_resize(&fb, 4097u * 256u, 1u, 1u << 24);
    RFB_CHECK_EQ_INT(rfb_kitty_tile_resize(&kt, &fb), RFB_OK);
    RFB_CHECK(kt.whole_frame_mode);
    RFB_CHECK(kt.dirty == NULL);

    // Resize back to small -> tiled mode restored.
    rfb_framebuffer_resize(&fb, 256, 256, 1u << 20);
    RFB_CHECK_EQ_INT(rfb_kitty_tile_resize(&kt, &fb), RFB_OK);
    RFB_CHECK(!kt.whole_frame_mode);
    RFB_CHECK(kt.dirty != NULL);
    RFB_CHECK_EQ_UINT(kt.tile_count, 1u);
    rfb_kitty_tile_close(&kt);
    rfb_framebuffer_destroy(&fb);
    rfb_buffer_destroy(&out);
}

// =========================================================================
// backpressure: high-water mark on output buffer
// =========================================================================

RFB_TEST(kt_bp, present__exceeds_high_water__reports_backpressure) {
    rfb_buffer out;
    rfb_buffer_init(&out, rfb_default_allocator(), 1u << 23);
    rfb_kitty_tile kt;
    rfb_kitty_tile_init(&kt, rfb_default_allocator(), &out, 256, false, false);
    // Set a tiny high-water mark so a single present exceeds it.
    kt.high_water_bytes = 1024;
    rfb_framebuffer fb;
    kt_setup_fb(&fb);
    rfb_kitty_tile_open(&kt, &fb);
    RFB_CHECK(!rfb_kitty_tile_in_backpressure(&kt));
    rfb_kitty_tile_present(&kt, &fb, NULL);
    RFB_CHECK(rfb_kitty_tile_in_backpressure(&kt));
    RFB_CHECK_EQ_UINT(kt.metrics.backpressure_events, 1u);
    rfb_kitty_tile_close(&kt);
    rfb_framebuffer_destroy(&fb);
    rfb_buffer_destroy(&out);
}

RFB_TEST(kt_bp, present__under_high_water__no_backpressure) {
    rfb_buffer out;
    rfb_buffer_init(&out, rfb_default_allocator(), 1u << 23);
    rfb_kitty_tile kt;
    rfb_kitty_tile_init(&kt, rfb_default_allocator(), &out, 256, false, false);
    // High-water mark large enough that a full paint doesn't exceed it.
    kt.high_water_bytes = 1u << 24;  // 16 MiB
    rfb_framebuffer fb;
    kt_setup_fb(&fb);
    rfb_kitty_tile_open(&kt, &fb);
    rfb_kitty_tile_present(&kt, &fb, NULL);  // full paint (4 tiles)
    RFB_CHECK(!rfb_kitty_tile_in_backpressure(&kt));
    RFB_CHECK_EQ_UINT(kt.metrics.backpressure_events, 0u);
    rfb_kitty_tile_close(&kt);
    rfb_framebuffer_destroy(&fb);
    rfb_buffer_destroy(&out);
}

// =========================================================================
// bounded memory: update flood does not grow unboundedly
// =========================================================================

RFB_TEST(kt_bound, present__update_flood__bounded_output_and_dirty) {
    // Simulate an update flood: many small damage rects across many tiles.
    // The output buffer has a hard limit; the dirty bitmap is bounded by
    // tile_count. Verify present() never exceeds the buffer limit and the
    // dirty bitmap is always cleared after each present.
    rfb_buffer out;
    rfb_buffer_init(&out, rfb_default_allocator(), 1u << 23);
    rfb_kitty_tile kt;
    rfb_kitty_tile_init(&kt, rfb_default_allocator(), &out, 256, false, false);
    rfb_framebuffer fb;
    kt_setup_fb(&fb);
    rfb_kitty_tile_open(&kt, &fb);
    rfb_kitty_tile_present(&kt, &fb, NULL);  // initial paint

    // Flood: 100 presents, each with a small damage rect.
    for (int i = 0; i < 100; i++) {
        rfb_buffer_clear(&out);
        rfb_rect r = { .x = (uint32_t)(10 + i % 500),
                       .y = (uint32_t)(10 + i % 500),
                       .width = 5, .height = 5 };
        rfb_damage_batch b = { .rects = &r, .count = 1, .full_frame = false };
        rfb_kitty_tile_present(&kt, &fb, &b);
        // After each present, the dirty bitmap must be fully cleared.
        for (size_t t = 0; t < kt.tile_count; t++) {
            RFB_CHECK_EQ_UINT(kt.dirty[t], 0u);
        }
        // Output never exceeds the hard limit.
        RFB_CHECK(rfb_buffer_length(&out) <= (1u << 23));
    }
    RFB_CHECK_EQ_UINT(kt.metrics.presents, 101u);  // 1 initial + 100 flood
    rfb_kitty_tile_close(&kt);
    rfb_framebuffer_destroy(&fb);
    rfb_buffer_destroy(&out);
}

// =========================================================================
// SHM ack + timeout reclamation
// =========================================================================

RFB_TEST(kt_ack, ack_shm__frees_table_entry_and_unlinks) {
    rfb_buffer out;
    rfb_buffer_init(&out, rfb_default_allocator(), 1u << 23);
    rfb_kitty_tile kt;
    rfb_kitty_tile_init(&kt, rfb_default_allocator(), &out, 256, true, false);
    rfb_framebuffer fb;
    kt_setup_fb(&fb);
    rfb_kitty_tile_open(&kt, &fb);
    rfb_kitty_tile_present(&kt, &fb, NULL);  // 4 SHM transfers
    RFB_CHECK_EQ_UINT(rfb_shm_table_count(&kt.shm_table), 4u);

    // Snapshot the name of image_id 1 (first tile) to verify unlink.
    char name0[KITTY_SHM_NAME_MAX] = { 0 };
    for (size_t i = 0; i < KITTY_SHM_MAX_INFLIGHT; i++) {
        if (kt.shm_table.entries[i].in_use &&
            kt.shm_table.entries[i].image_id == 1u) {
            strncpy(name0, kt.shm_table.entries[i].name, KITTY_SHM_NAME_MAX - 1);
            break;
        }
    }
    RFB_CHECK(name0[0] != '\0');

    // Acknowledge image_id 1.
    RFB_CHECK(rfb_kitty_tile_ack_shm(&kt, 1u));
    RFB_CHECK_EQ_UINT(rfb_shm_table_count(&kt.shm_table), 3u);
    // The SHM object is unlinked: shm_open without O_CREAT fails.
    RFB_CHECK_EQ_INT(shm_open(name0, O_RDONLY, 0), -1);
    // Acking again returns false (already removed).
    RFB_CHECK(!rfb_kitty_tile_ack_shm(&kt, 1u));
    rfb_kitty_tile_close(&kt);
    rfb_framebuffer_destroy(&fb);
    rfb_buffer_destroy(&out);
}

RFB_TEST(kt_ack, reclaim_expired__frees_timed_out_entries) {
    rfb_buffer out;
    rfb_buffer_init(&out, rfb_default_allocator(), 1u << 23);
    rfb_kitty_tile kt;
    rfb_kitty_tile_init(&kt, rfb_default_allocator(), &out, 256, true, false);
    // Short timeout for the test.
    kt.ack_timeout_ms = 100;
    rfb_framebuffer fb;
    kt_setup_fb(&fb);
    rfb_kitty_tile_open(&kt, &fb);
    rfb_kitty_tile_present(&kt, &fb, NULL);  // 4 SHM transfers, clock=16ms
    RFB_CHECK_EQ_UINT(rfb_shm_table_count(&kt.shm_table), 4u);

    // Reclaim with now_ms far in the future: all 4 should time out.
    size_t reclaimed = rfb_kitty_tile_reclaim_expired_shm(&kt, 1000);
    RFB_CHECK_EQ_UINT(reclaimed, 4u);
    RFB_CHECK_EQ_UINT(rfb_shm_table_count(&kt.shm_table), 0u);

    // Table is now empty: SHM transfers can proceed again (no backpressure).
    rfb_kitty_tile_close(&kt);
    rfb_framebuffer_destroy(&fb);
    rfb_buffer_destroy(&out);
}

RFB_TEST(kt_ack, reclaim_expired__keeps_recent_entries) {
    rfb_buffer out;
    rfb_buffer_init(&out, rfb_default_allocator(), 1u << 23);
    rfb_kitty_tile kt;
    rfb_kitty_tile_init(&kt, rfb_default_allocator(), &out, 256, true, false);
    kt.ack_timeout_ms = 2000;
    rfb_framebuffer fb;
    kt_setup_fb(&fb);
    rfb_kitty_tile_open(&kt, &fb);
    rfb_kitty_tile_present(&kt, &fb, NULL);  // clock=16ms, entries stamped at 16
    RFB_CHECK_EQ_UINT(rfb_shm_table_count(&kt.shm_table), 4u);

    // Reclaim with now_ms only 50ms after send (well under 2000ms timeout).
    size_t reclaimed = rfb_kitty_tile_reclaim_expired_shm(&kt, 66);
    RFB_CHECK_EQ_UINT(reclaimed, 0u);
    RFB_CHECK_EQ_UINT(rfb_shm_table_count(&kt.shm_table), 4u);
    rfb_kitty_tile_close(&kt);
    rfb_framebuffer_destroy(&fb);
    rfb_buffer_destroy(&out);
}

// =========================================================================
// ops table: rfb_presenter_ops interface
// =========================================================================

RFB_TEST(kt_ops, ops__present_through_standard_interface) {
    rfb_buffer out;
    rfb_buffer_init(&out, rfb_default_allocator(), 1u << 23);
    rfb_kitty_tile kt;
    rfb_kitty_tile_init(&kt, rfb_default_allocator(), &out, 256, false, false);
    rfb_framebuffer fb;
    kt_setup_fb(&fb);
    rfb_presenter p = { .ops = &rfb_kitty_tile_ops, .ctx = &kt };

    RFB_CHECK_EQ_INT(rfb_presenter_open(&p, &fb), RFB_OK);
    RFB_CHECK_EQ_INT(rfb_presenter_present(&p, &fb, NULL), RFB_OK);
    RFB_CHECK_EQ_UINT(kt.metrics.presents, 1u);
    RFB_CHECK_EQ_UINT(kt_count_image_transmissions(&out), 4u);

    rfb_presenter_close(&p);
    RFB_CHECK_EQ_UINT(kt.tile_count, 0u);
    rfb_framebuffer_destroy(&fb);
    rfb_buffer_destroy(&out);
}

RFB_TEST(kt_ops, ops__resize_through_standard_interface) {
    rfb_buffer out;
    rfb_buffer_init(&out, rfb_default_allocator(), 1u << 23);
    rfb_kitty_tile kt;
    rfb_kitty_tile_init(&kt, rfb_default_allocator(), &out, 256, false, false);
    rfb_framebuffer fb;
    kt_setup_fb(&fb);
    rfb_presenter p = { .ops = &rfb_kitty_tile_ops, .ctx = &kt };

    rfb_presenter_open(&p, &fb);
    rfb_presenter_present(&p, &fb, NULL);
    rfb_framebuffer_resize(&fb, 256, 256, 1u << 20);
    RFB_CHECK_EQ_INT(rfb_presenter_resize(&p, &fb), RFB_OK);
    RFB_CHECK_EQ_UINT(kt.tile_count, 1u);
    rfb_presenter_close(&p);
    rfb_framebuffer_destroy(&fb);
    rfb_buffer_destroy(&out);
}

// =========================================================================
// output overflow: present when the output buffer is at its hard limit
// =========================================================================

RFB_TEST(kt_overflow, present__output_overflow__returns_err_limit) {
    // The output buffer has a tiny hard limit. Presenting a full grid that
    // would overflow must return RFB_ERR_LIMIT without corrupting state.
    rfb_buffer out;
    rfb_buffer_init(&out, rfb_default_allocator(), 4096);  // tiny
    rfb_kitty_tile kt;
    rfb_kitty_tile_init(&kt, rfb_default_allocator(), &out, 256, false, false);
    rfb_framebuffer fb;
    kt_setup_fb(&fb);
    rfb_kitty_tile_open(&kt, &fb);
    rfb_error e = rfb_kitty_tile_present(&kt, &fb, NULL);
    // Should fail with LIMIT (the 4 tiles can't fit in 4096 bytes).
    RFB_CHECK_EQ_INT(e, RFB_ERR_LIMIT);
    // The dirty bitmap state is preserved (the committed state is not lost
    // — the tiles that failed to send remain dirty for the next attempt).
    // Note: present() clears dirty only for tiles it successfully encoded.
    rfb_kitty_tile_close(&kt);
    rfb_framebuffer_destroy(&fb);
    rfb_buffer_destroy(&out);
}

// Place cells form an atomic snapshot: set/load round-trips without races
// on the storage itself (TSan coverage is optional; correctness unit here).
RFB_TEST(kt_place, set_place_cells__atomic_snapshot)
{
    rfb_kitty_tile kt;
    rfb_kitty_tile_init(&kt, rfb_default_allocator(), NULL, 256, false, false);
    RFB_CHECK_EQ_UINT(rfb_kitty_tile_place_cols(&kt), 0u);
    RFB_CHECK_EQ_UINT(rfb_kitty_tile_place_rows(&kt), 0u);
    rfb_kitty_tile_set_place_cells(&kt, 80u, 24u);
    RFB_CHECK_EQ_UINT(rfb_kitty_tile_place_cols(&kt), 80u);
    RFB_CHECK_EQ_UINT(rfb_kitty_tile_place_rows(&kt), 24u);
    rfb_kitty_tile_set_place_cells(&kt, 40u, 12u);
    RFB_CHECK_EQ_UINT(rfb_kitty_tile_place_cols(&kt), 40u);
    RFB_CHECK_EQ_UINT(rfb_kitty_tile_place_rows(&kt), 12u);
    rfb_kitty_tile_destroy(&kt);
}
