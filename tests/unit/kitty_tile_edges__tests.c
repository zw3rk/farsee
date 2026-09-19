// SPDX-License-Identifier: Apache-2.0
//
// Boundary and whole-frame contracts for the Kitty tile presenter.

#include "rfb_test.h"

#include "farsee/allocator.h"
#include "farsee/buffer.h"
#include "farsee/framebuffer.h"
#include "farsee/kitty_tile.h"

#include <stdint.h>
#include <string.h>

RFB_TEST(kitty_tile_edges,
         grid__uint32_ceiling_overflow_is_rejected)
{
    uint32_t cols = 99u;
    uint32_t rows = 99u;
    RFB_CHECK(!rfb_kitty_tile_grid(UINT32_MAX, 1u, 2u, &cols, &rows));
    RFB_CHECK_EQ_UINT(cols, 99u);
    RFB_CHECK_EQ_UINT(rows, 99u);
}

RFB_TEST(kitty_tile_edges,
         geometry_helpers__invalid_caps_clamps_and_overflow_are_bounded)
{
    uint32_t cols = 0u;
    uint32_t rows = 0u;
    RFB_CHECK(!rfb_kitty_tile_grid(1u, 1u, 0u, &cols, &rows));
    RFB_CHECK(!rfb_kitty_tile_grid(0u, 1u, 1u, &cols, &rows));
    RFB_CHECK(!rfb_kitty_tile_grid(1u, 0u, 1u, &cols, &rows));
    RFB_CHECK(!rfb_kitty_tile_grid(1u, 1u, 1u, NULL, &rows));
    RFB_CHECK(!rfb_kitty_tile_grid(1u, 1u, 1u, &cols, NULL));
    RFB_CHECK(!rfb_kitty_tile_grid(RFB_KITTY_TILE_MAX_TILES + 1u,
                                   1u, 1u, &cols, &rows));
    RFB_CHECK(!rfb_kitty_tile_grid(1u,
                                   RFB_KITTY_TILE_MAX_TILES + 1u,
                                   1u, &cols, &rows));
    RFB_CHECK(!rfb_kitty_tile_grid(65u, 65u, 1u, &cols, &rows));

    RFB_CHECK_EQ_UINT(rfb_kitty_tile_rect_tile_count(1u, 1u, 0u, 1u, 1u),
                      0u);
    RFB_CHECK_EQ_UINT(rfb_kitty_tile_rect_tile_count(1u, 1u, 1u, 0u, 1u),
                      0u);
    RFB_CHECK_EQ_UINT(rfb_kitty_tile_rect_tile_count(1u, 1u, 1u, 1u, 0u),
                      0u);
    RFB_CHECK_EQ_UINT(rfb_kitty_tile_rect_tile_count(
                          UINT32_MAX, 1u, 2u, UINT32_MAX, 1u),
                      2147483648ull);
    RFB_CHECK_EQ_UINT(rfb_kitty_tile_rect_tile_count(0u, 0u, 2u, 2u, 2u),
                      1u);
}

RFB_TEST(kitty_tile_edges,
         rect_to_tiles__invalid_and_clipped_rectangles_are_bounded)
{
    size_t indices[4] = {99u, 99u, 99u, 99u};
    RFB_CHECK_EQ_UINT(rfb_kitty_tile_rect_to_tiles(
                          0u, 0u, 1u, 1u, 2u, 2u, 1u, 2u, 2u, NULL), 0u);
    RFB_CHECK_EQ_UINT(rfb_kitty_tile_rect_to_tiles(
                          0u, 0u, 1u, 1u, 2u, 2u, 0u, 2u, 2u, indices), 0u);
    RFB_CHECK_EQ_UINT(rfb_kitty_tile_rect_to_tiles(
                          0u, 0u, 1u, 1u, 2u, 2u, 1u, 0u, 2u, indices), 0u);
    RFB_CHECK_EQ_UINT(rfb_kitty_tile_rect_to_tiles(
                          0u, 0u, 0u, 1u, 2u, 2u, 1u, 2u, 2u, indices), 0u);
    RFB_CHECK_EQ_UINT(rfb_kitty_tile_rect_to_tiles(
                          2u, 0u, UINT32_MAX, 1u, 2u, 2u, 1u, 2u, 2u,
                          indices), 0u);
    RFB_CHECK_EQ_UINT(rfb_kitty_tile_rect_to_tiles(
                          1u, 1u, UINT32_MAX, UINT32_MAX,
                          2u, 2u, 1u, 2u, 2u, indices), 1u);
    RFB_CHECK_EQ_UINT(indices[0], 3u);
}

static void *fail_alloc(rfb_allocator *allocator, size_t size)
{
    (void)allocator;
    (void)size;
    return NULL;
}

static void fail_free(rfb_allocator *allocator, void *allocation)
{
    (void)allocator;
    rfb_default_allocator()->free(rfb_default_allocator(), allocation);
}

RFB_TEST(kitty_tile_edges,
         lifecycle__null_defaults_and_grid_allocation_failure_are_safe)
{
    rfb_kitty_tile_init(NULL, NULL, NULL, 0u, false, false);
    rfb_kitty_tile tile;
    rfb_kitty_tile_init(&tile, NULL, NULL, 0u, false, false);
    RFB_CHECK(tile.alloc == rfb_default_allocator());
    RFB_CHECK_EQ_UINT(tile.tile_edge, RFB_KITTY_TILE_DEFAULT_EDGE);
    rfb_kitty_tile_set_place_cells(NULL, 1u, 1u);
    rfb_kitty_tile_destroy(NULL);
    rfb_kitty_tile_close(NULL);
    RFB_CHECK_EQ_INT(rfb_kitty_tile_open(NULL, NULL), RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(rfb_kitty_tile_resize(NULL, NULL), RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(rfb_kitty_tile_present(NULL, NULL, NULL),
                     RFB_ERR_INTERNAL);

    rfb_allocator failing = {
        .alloc = fail_alloc,
        .free = fail_free,
        .user = NULL,
    };
    rfb_kitty_tile_init(&tile, &failing, NULL, 1u, false, false);
    uint8_t pixels[4] = {0u, 0u, 0u, 255u};
    rfb_framebuffer framebuffer = {
        .rgba = pixels,
        .stride = 4u,
        .width = 1u,
        .height = 1u,
        .generation = 0u,
        .alloc = rfb_default_allocator(),
    };
    RFB_CHECK_EQ_INT(rfb_kitty_tile_open(&tile, &framebuffer),
                     RFB_ERR_NOMEM);
    RFB_CHECK(tile.dirty == NULL);
    rfb_kitty_tile_destroy(&tile);
}

RFB_TEST(kitty_tile_edges,
         damage_and_tracking__empty_outside_and_missing_entries_are_safe)
{
    rfb_kitty_tile tile;
    rfb_kitty_tile_init(&tile, NULL, NULL, 1u, false, false);
    rfb_kitty_tile_mark_damage(NULL, NULL);
    rfb_kitty_tile_mark_damage(&tile, NULL);
    tile.whole_frame_mode = true;
    rfb_damage_batch damage;
    memset(&damage, 0, sizeof damage);
    rfb_kitty_tile_mark_damage(&tile, &damage);
    RFB_CHECK(tile.full_frame_dirty);

    tile.whole_frame_mode = false;
    tile.full_frame_dirty = false;
    rfb_kitty_tile_mark_damage(&tile, &damage);
    RFB_CHECK(!tile.full_frame_dirty);
    damage.full_frame = true;
    rfb_kitty_tile_mark_damage(&tile, &damage);
    RFB_CHECK(tile.full_frame_dirty);

    rfb_kitty_tile_delete_all(NULL);
    rfb_kitty_tile_delete_all(&tile);
    RFB_CHECK(!rfb_kitty_tile_ack_shm(NULL, 1u));
    RFB_CHECK(!rfb_kitty_tile_ack_shm(&tile, 1u));
    RFB_CHECK_EQ_UINT(rfb_kitty_tile_reclaim_expired_shm(NULL, 1u), 0u);
    rfb_kitty_tile_destroy(&tile);
}

RFB_TEST(kitty_tile_edges,
         present__null_output_clears_tiled_dirty_state)
{
    rfb_framebuffer framebuffer;
    rfb_framebuffer_init(&framebuffer, rfb_default_allocator());
    RFB_CHECK_EQ_INT(rfb_framebuffer_resize(&framebuffer, 2u, 2u, 64u),
                     RFB_OK);
    rfb_kitty_tile tile;
    rfb_kitty_tile_init(&tile, NULL, NULL, 1u, false, false);
    RFB_CHECK_EQ_INT(rfb_kitty_tile_open(&tile, &framebuffer), RFB_OK);
    RFB_CHECK_EQ_INT(rfb_kitty_tile_present(&tile, &framebuffer, NULL), RFB_OK);
    RFB_CHECK(!tile.full_frame_dirty);
    for (size_t i = 0u; i < tile.tile_count; i++) {
        RFB_CHECK_EQ_UINT(tile.dirty[i], 0u);
    }
    RFB_CHECK_EQ_UINT(tile.metrics.presents, 1u);
    RFB_CHECK_EQ_INT(rfb_kitty_tile_resize(&tile, &framebuffer), RFB_OK);
    rfb_kitty_tile_close(&tile);
    rfb_framebuffer_destroy(&framebuffer);
}

RFB_TEST(kitty_tile_edges,
         present__small_oversized_grid_uses_direct_whole_frame_image)
{
    rfb_framebuffer framebuffer;
    rfb_framebuffer_init(&framebuffer, rfb_default_allocator());
    RFB_CHECK_EQ_INT(rfb_framebuffer_resize(
                         &framebuffer, 65u, 65u, 65u * 65u * 4u), RFB_OK);
    rfb_buffer output;
    rfb_buffer_init(&output, rfb_default_allocator(), 1u << 20);
    rfb_kitty_tile tile;
    rfb_kitty_tile_init(&tile, NULL, &output, 1u, false, false);
    RFB_CHECK_EQ_INT(rfb_kitty_tile_open(&tile, &framebuffer), RFB_OK);
    RFB_CHECK(tile.whole_frame_mode);
    RFB_CHECK_EQ_UINT(tile.tile_count, 0u);
    RFB_CHECK_EQ_INT(rfb_kitty_tile_present(&tile, &framebuffer, NULL), RFB_OK);
    RFB_CHECK_EQ_UINT(tile.metrics.full_frame_presents, 1u);
    RFB_CHECK_EQ_UINT(tile.metrics.tiles_encoded, 1u);
    RFB_CHECK_EQ_UINT(tile.metrics.bytes_copied, 65u * 65u * 4u);
    RFB_CHECK(rfb_buffer_length(&output) > 0u);
    rfb_kitty_tile_close(&tile);
    rfb_buffer_destroy(&output);
    rfb_framebuffer_destroy(&framebuffer);
}

RFB_TEST(kitty_tile_edges, geometry__clamps_both_axes_and_empty_ranges)
{
    RFB_CHECK_EQ_UINT(rfb_kitty_tile_rect_tile_count(
                          UINT32_MAX, UINT32_MAX, 2u, 2u, 3u),
                      6u);

    size_t indices[4] = {99u, 99u, 99u, 99u};
    RFB_CHECK_EQ_UINT(rfb_kitty_tile_rect_to_tiles(
                          0u, 0u, 1u, 1u, 2u, 2u, 1u, 1u, 0u, indices),
                      0u);
    RFB_CHECK_EQ_UINT(rfb_kitty_tile_rect_to_tiles(
                          0u, 0u, 1u, 0u, 2u, 2u, 1u, 2u, 2u, indices),
                      0u);
    RFB_CHECK_EQ_UINT(rfb_kitty_tile_rect_to_tiles(
                          0u, 2u, 1u, UINT32_MAX, 2u, 2u, 1u, 2u, 2u,
                          indices),
                      0u);
    RFB_CHECK_EQ_UINT(rfb_kitty_tile_rect_to_tiles(
                          3u, 3u, 7u, 7u, 10u, 10u, 2u, 2u, 2u, indices),
                      1u);
    RFB_CHECK_EQ_UINT(indices[0], 3u);
}

RFB_TEST(kitty_tile_edges, lifecycle__replacement_and_whole_frame_are_clean)
{
    uint8_t pixels[4] = {0u, 0u, 0u, 255u};
    rfb_framebuffer framebuffer = {
        .rgba = pixels,
        .stride = sizeof pixels,
        .width = 2u,
        .height = 2u,
        .generation = 0u,
        .alloc = rfb_default_allocator(),
    };
    rfb_kitty_tile tile;
    rfb_kitty_tile_init(&tile, NULL, NULL, 1u, false, false);
    RFB_CHECK_EQ_INT(rfb_kitty_tile_open(&tile, NULL), RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(rfb_kitty_tile_resize(&tile, NULL), RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(rfb_kitty_tile_open(&tile, &framebuffer), RFB_OK);
    RFB_CHECK_EQ_UINT(tile.tile_count, 4u);

    framebuffer.width = 3u;
    RFB_CHECK_EQ_INT(rfb_kitty_tile_resize(&tile, &framebuffer), RFB_OK);
    RFB_CHECK_EQ_UINT(tile.tile_count, 6u);
    RFB_CHECK(!tile.whole_frame_mode);

    framebuffer.width = 65u;
    framebuffer.height = 65u;
    RFB_CHECK_EQ_INT(rfb_kitty_tile_resize(&tile, &framebuffer), RFB_OK);
    RFB_CHECK(tile.whole_frame_mode);
    RFB_CHECK(tile.dirty == NULL);
    RFB_CHECK_EQ_UINT(tile.tile_count, 0u);
    rfb_kitty_tile_destroy(&tile);
}

RFB_TEST(kitty_tile_edges, damage__empty_outside_clipped_and_clamped_batches)
{
    uint8_t pixels[4] = {0};
    rfb_framebuffer framebuffer = {
        .rgba = pixels,
        .stride = sizeof pixels,
        .width = 4u,
        .height = 4u,
        .generation = 0u,
        .alloc = rfb_default_allocator(),
    };
    rfb_kitty_tile tile;
    rfb_kitty_tile_init(&tile, NULL, NULL, 2u, false, false);
    RFB_CHECK_EQ_INT(rfb_kitty_tile_open(&tile, &framebuffer), RFB_OK);
    memset(tile.dirty, 0, tile.tile_count);
    tile.full_frame_dirty = false;

    rfb_damage_batch empty = {.rects = NULL, .count = 0u,
                              .full_frame = false};
    rfb_kitty_tile_mark_damage(&tile, &empty);
    RFB_CHECK_EQ_UINT(tile.metrics.damage_tiles_touched, 0u);

    static const rfb_rect rects[] = {
        {.x = 4u, .y = 0u, .width = UINT32_MAX, .height = 1u},
        {.x = 0u, .y = 4u, .width = 1u, .height = UINT32_MAX},
        {.x = 3u, .y = 3u, .width = UINT32_MAX, .height = UINT32_MAX},
    };
    rfb_damage_batch batch = {
        .rects = rects,
        .count = sizeof rects / sizeof rects[0],
        .full_frame = false,
    };
    rfb_kitty_tile_mark_damage(&tile, &batch);
    RFB_CHECK_EQ_UINT(tile.dirty[0], 0u);
    RFB_CHECK_EQ_UINT(tile.dirty[1], 0u);
    RFB_CHECK_EQ_UINT(tile.dirty[2], 0u);
    RFB_CHECK_EQ_UINT(tile.dirty[3], 1u);
    RFB_CHECK_EQ_UINT(tile.metrics.damage_tiles_touched, 1u);

    memset(tile.dirty, 0, tile.tile_count);
    tile.cols = 1u;
    tile.rows = 1u;
    static const rfb_rect grid_clamp = {
        .x = 0u, .y = 0u, .width = 4u, .height = 4u,
    };
    batch.rects = &grid_clamp;
    batch.count = 1u;
    rfb_kitty_tile_mark_damage(&tile, &batch);
    RFB_CHECK_EQ_UINT(tile.dirty[0], 1u);
    rfb_kitty_tile_destroy(&tile);
}

RFB_TEST(kitty_tile_edges, delete_all__stops_after_output_limit)
{
    rfb_buffer output;
    rfb_buffer_init(&output, rfb_default_allocator(), 1u);
    rfb_kitty_tile tile;
    rfb_kitty_tile_init(&tile, NULL, &output, 1u, false, false);
    tile.base_image_id = 1u;
    tile.tile_count = 2u;
    rfb_kitty_tile_delete_all(&tile);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&output), 0u);
    rfb_kitty_tile_destroy(&tile);
    rfb_buffer_destroy(&output);
}

RFB_TEST(kitty_tile_edges, shm_tracking__empty_names_and_timeout_boundaries)
{
    rfb_kitty_tile tile;
    rfb_kitty_tile_init(&tile, NULL, NULL, 1u, true, true);
    RFB_CHECK(rfb_shm_table_add(&tile.shm_table, "", 11u));
    tile.shm_send_time[0] = 10u;
    RFB_CHECK(rfb_kitty_tile_ack_shm(&tile, 11u));
    RFB_CHECK_EQ_UINT(tile.shm_send_time[0], 0u);

    RFB_CHECK(rfb_shm_table_add(&tile.shm_table, "", 12u));
    RFB_CHECK(rfb_shm_table_add(&tile.shm_table,
                                "/farsee-kitty-tile-does-not-exist", 13u));
    RFB_CHECK(rfb_shm_table_add(&tile.shm_table, "", 14u));
    tile.shm_send_time[0] = 0u;
    tile.shm_send_time[1] = 100u;
    tile.shm_send_time[2] = 101u;
    tile.ack_timeout_ms = 10u;
    RFB_CHECK_EQ_UINT(rfb_kitty_tile_reclaim_expired_shm(&tile, 109u), 0u);
    RFB_CHECK_EQ_UINT(rfb_kitty_tile_reclaim_expired_shm(&tile, 110u), 1u);
    RFB_CHECK_EQ_UINT(rfb_kitty_tile_reclaim_expired_shm(&tile, 111u), 1u);
    RFB_CHECK_EQ_UINT(rfb_shm_table_count(&tile.shm_table), 1u);
    rfb_kitty_tile_destroy(&tile);
}

RFB_TEST(kitty_tile_edges, present__allocator_failures_preserve_dirty_state)
{
    uint8_t pixels[4] = {0u, 0u, 0u, 255u};
    rfb_framebuffer framebuffer = {
        .rgba = pixels,
        .stride = sizeof pixels,
        .width = 1u,
        .height = 1u,
        .generation = 0u,
        .alloc = rfb_default_allocator(),
    };
    rfb_buffer output;
    rfb_buffer_init(&output, rfb_default_allocator(), 4096u);
    rfb_allocator failing = {
        .alloc = fail_alloc,
        .free = fail_free,
        .user = NULL,
    };

    rfb_kitty_tile tile;
    rfb_kitty_tile_init(&tile, &failing, &output, 1u, true, false);
    uint8_t dirty = 1u;
    tile.cols = 1u;
    tile.rows = 1u;
    tile.tile_count = 1u;
    tile.dirty = &dirty;
    tile.full_frame_dirty = true;
    tile.base_image_id = 1u;
    RFB_CHECK_EQ_INT(rfb_kitty_tile_present(&tile, &framebuffer, NULL),
                     RFB_ERR_NOMEM);
    RFB_CHECK_EQ_UINT(dirty, 1u);
    tile.dirty = NULL;
    rfb_kitty_tile_destroy(&tile);

    rfb_kitty_tile_init(&tile, &failing, &output, 1u, false, false);
    tile.whole_frame_mode = true;
    tile.full_frame_dirty = true;
    tile.base_image_id = 1u;
    RFB_CHECK_EQ_INT(rfb_kitty_tile_present(&tile, &framebuffer, NULL),
                     RFB_ERR_NOMEM);
    RFB_CHECK(tile.full_frame_dirty);
    rfb_kitty_tile_destroy(&tile);
    rfb_buffer_destroy(&output);
}

RFB_TEST(kitty_tile_edges,
         present__padded_whole_frame_falls_back_from_full_shm_table)
{
    uint8_t pixels[16] = {
        1u, 2u, 3u, 4u, 0u, 0u, 0u, 0u,
        5u, 6u, 7u, 8u, 0u, 0u, 0u, 0u,
    };
    rfb_framebuffer framebuffer = {
        .rgba = pixels,
        .stride = 8u,
        .width = 1u,
        .height = 2u,
        .generation = 0u,
        .alloc = rfb_default_allocator(),
    };
    rfb_buffer output;
    rfb_buffer_init(&output, rfb_default_allocator(), 4096u);
    rfb_kitty_tile tile;
    rfb_kitty_tile_init(&tile, NULL, &output, 1u, true, true);
    tile.whole_frame_mode = true;
    tile.full_frame_dirty = true;
    tile.base_image_id = 1u;
    for (size_t i = 0u; i < KITTY_SHM_MAX_INFLIGHT; i++) {
        RFB_CHECK(rfb_shm_table_add(&tile.shm_table, "", 100u + (uint32_t)i));
    }
    RFB_CHECK_EQ_INT(rfb_kitty_tile_present(&tile, &framebuffer, NULL), RFB_OK);
    RFB_CHECK_EQ_UINT(tile.metrics.full_frame_presents, 1u);
    RFB_CHECK_EQ_UINT(tile.metrics.shm_fallbacks, 1u);
    RFB_CHECK_EQ_UINT(tile.metrics.shm_transfers, 0u);
    RFB_CHECK_EQ_UINT(tile.metrics.bytes_copied, 8u);
    RFB_CHECK_EQ_UINT(tile.metrics.bytes_allocated, 8u);
    RFB_CHECK_EQ_UINT(tile.metrics.tiles_encoded, 1u);
    RFB_CHECK(rfb_buffer_length(&output) > 0u);
    rfb_kitty_tile_destroy(&tile);
    rfb_buffer_destroy(&output);
}

RFB_TEST(kitty_tile_edges, present__backpressure_counts_only_transitions)
{
    uint8_t pixels[4] = {0u, 0u, 0u, 255u};
    rfb_framebuffer framebuffer = {
        .rgba = pixels,
        .stride = sizeof pixels,
        .width = 1u,
        .height = 1u,
        .generation = 0u,
        .alloc = rfb_default_allocator(),
    };
    rfb_buffer output;
    rfb_buffer_init(&output, rfb_default_allocator(), 4096u);
    rfb_kitty_tile tile;
    rfb_kitty_tile_init(&tile, NULL, &output, 1u, false, false);
    tile.high_water_bytes = 0u;
    RFB_CHECK_EQ_INT(rfb_kitty_tile_open(&tile, &framebuffer), RFB_OK);
    RFB_CHECK_EQ_INT(rfb_kitty_tile_present(&tile, &framebuffer, NULL), RFB_OK);
    RFB_CHECK(tile.backpressure);
    RFB_CHECK_EQ_UINT(tile.metrics.backpressure_events, 1u);
    RFB_CHECK_EQ_INT(rfb_kitty_tile_present(&tile, &framebuffer, NULL), RFB_OK);
    RFB_CHECK_EQ_UINT(tile.metrics.backpressure_events, 1u);
    rfb_buffer_clear(&output);
    RFB_CHECK_EQ_INT(rfb_kitty_tile_present(&tile, &framebuffer, NULL), RFB_OK);
    RFB_CHECK(!tile.backpressure);
    rfb_kitty_tile_destroy(&tile);
    rfb_buffer_destroy(&output);
}
