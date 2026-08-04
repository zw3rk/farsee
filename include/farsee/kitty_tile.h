// SPDX-License-Identifier: Apache-2.0
//
// farsee — tile/damage-aware Kitty presenter (plan.md §G22, §G7, §G10).
//
// A damage-aware presenter that preserves stable Kitty image/placement IDs
// per tile and retransmits only the tiles intersecting the current damage.
// It supports both direct base64 transfer (plan.md §G7) and the one-shot
// POSIX SHM transport (plan.md §G10), falling back to direct on SHM
// failure or when the in-flight table is full.
//
// Key invariants (plan.md §G22):
//   - the authoritative framebuffer is NEVER mutated (read-only);
//   - a tile's image/placement ID is stable across frames, so the terminal
//     updates the placement in place rather than stacking new images;
//   - only the dirty tiles are encoded — no full-frame RGBA copy when the
//     damage is small (provable via the copy/alloc counters);
//   - the tile cache, image IDs, outstanding SHM acks, and write queue are
//     all bounded;
//   - damage is coalesced: superseded damage is dropped, but the final
//     committed state is never lost (every dirty tile at present time is
//     retransmitted);
//   - resize clears the tile grid and deletes the old images on the
//     terminal (no stale tiles after resize/reconnect);
//   - close deletes all images and restores deterministic state.
//
// The Kitty graphics protocol reference is the official Kitty graphics
// protocol specification (clean-room; no Kitty source consulted).

#ifndef FARSEE_INCLUDE_FARSEE_KITTY_TILE_H
#define FARSEE_INCLUDE_FARSEE_KITTY_TILE_H

#include "farsee/allocator.h"
#include "farsee/buffer.h"
#include "farsee/error.h"
#include "farsee/farsee_atomic.h"
#include "farsee/framebuffer.h"
#include "farsee/kitty_protocol.h"
#include "farsee/kitty_shm_table.h"
#include "farsee/presenter.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Default tile edge length in pixels. Tiles are square. 256 is a balance
// between per-tile Kitty command overhead and the cost of re-encoding a
// tile when only a few pixels changed.
#define RFB_KITTY_TILE_DEFAULT_EDGE 256u

// Hard cap on the number of tiles in the grid. If a framebuffer would need
// more tiles than this, the presenter falls back to a single whole-frame
// image (still damage-aware only in that it always retransmits the frame).
#define RFB_KITTY_TILE_MAX_TILES 4096u

// High-water mark (bytes) on the output buffer. When the pending output
// exceeds this, the presenter reports backpressure so the session loop can
// pause FramebufferUpdateRequests until the terminal drains.
#define RFB_KITTY_TILE_HIGH_WATER_BYTES ((size_t)8u * 1024u * 1024u)

// Default acknowledgement timeout in milliseconds. A tile transfer that has
// not been acknowledged within this window is considered lost; the in-flight
// SHM entry is reclaimed and a future present retransmits via direct path.
#define RFB_KITTY_TILE_ACK_TIMEOUT_MS 2000u

// Performance/counting metrics (plan.md §G22: "prove with allocation/copy
// counters"). These let tests assert that a small-damage present does NOT
// copy or allocate whole-frame bytes.
typedef struct rfb_kitty_tile_metrics {
    uint64_t presents;             // present() calls
    uint64_t tiles_encoded;        // tiles actually emitted
    uint64_t full_frame_presents;  // presents that fell back to whole-frame
    uint64_t shm_transfers;        // tiles sent via SHM
    uint64_t shm_fallbacks;        // SHM attempts that fell back to direct
    uint64_t bytes_copied;         // pixel bytes copied from fb to staging
    uint64_t bytes_allocated;      // pixel bytes allocated for staging
    uint64_t damage_tiles_touched; // tiles marked dirty (pre-coalescing raw)
    uint64_t damage_tiles_sent;    // tiles actually sent (post-coalescing)
    uint64_t backpressure_events;  // times high-water was reached
} rfb_kitty_tile_metrics;

// The tile/damage-aware Kitty presenter. One instance per session.
typedef struct rfb_kitty_tile {
    // --- Configuration (set at init, immutable thereafter) ---
    rfb_allocator *alloc;
    uint32_t tile_edge;        // pixels per tile edge
    bool use_shm;              // attempt SHM transport before direct
    bool request_ack;          // request Kitty acknowledgements
    uint32_t ack_timeout_ms;   // SHM ack reclamation timeout
    size_t high_water_bytes;   // output backpressure threshold
    // Optional Kitty placement size in cells (c/r). 0 = native pixel size.
    // Live RDP/RFB set these so the image leaves a status row free below.
    // Packed as one atomic u64 (cols high 32, rows low 32) so present never
    // observes a torn (new_cols, old_rows) pair under concurrent zoom.
    farsee_atomic_u64 place_cells;

    // --- Output sink ---
    // The presenter appends Kitty escape sequences here. The session loop
    // drains this buffer to the PTY. NULL means output is dropped (used by
    // tests that only inspect metrics).
    rfb_buffer *out;

    // --- Tile grid (current framebuffer geometry) ---
    uint32_t fb_width;
    uint32_t fb_height;
    uint32_t cols;             // tiles across
    uint32_t rows;             // tiles down
    size_t tile_count;         // cols * rows (<= RFB_KITTY_TILE_MAX_TILES)
    uint32_t base_image_id;    // first tile's Kitty image ID
    bool whole_frame_mode;     // true when grid exceeds the tile cap

    // --- Dirty bitmap + coalescing ---
    // `dirty[i]` is true when tile i has unsent damage. Multiple damage
    // batches between presents simply re-mark tiles (idempotent coalescing):
    // superseded damage is dropped, the final state is preserved because
    // every dirty tile is retransmitted at present time.
    uint8_t *dirty;            // tile_count bytes (owned); NULL in whole-frame
    bool full_frame_dirty;     // whole-frame damage pending

    // --- SHM in-flight tracking (plan.md §G10) ---
    rfb_shm_table shm_table;
    // Send timestamps (ms) parallel to shm_table.entries, for ack-timeout
    // reclamation. Index i corresponds to shm_table.entries[i]. Zero means
    // "not sent" (entry unused). Indexed by slot, NOT by image_id.
    uint64_t shm_send_time[KITTY_SHM_MAX_INFLIGHT];

    // --- Backpressure ---
    bool backpressure;         // true while out exceeds high_water_bytes

    // --- Logical clock for ack-timeout (plan.md §G22) ---
    // Advanced by present(); stamped into shm_send_time when an SHM transfer
    // is registered. reclaim_expired_shm() compares against this. Deterministic
    // (no system clock) so tests can drive timeout scenarios exactly.
    uint64_t logical_clock_ms;

    // --- Metrics ---
    rfb_kitty_tile_metrics metrics;
} rfb_kitty_tile;

// Snapshot place cells as one pair (acquire). Safe from any thread.
static inline void rfb_kitty_tile_place_pair(const rfb_kitty_tile *kt,
                                             uint32_t *out_cols,
                                             uint32_t *out_rows)
{
    uint32_t c = 0u;
    uint32_t r = 0u;
    if (kt != NULL) {
        uint64_t v = farsee_atomic_u64_load(&kt->place_cells);
        c = (uint32_t)(v >> 32);
        r = (uint32_t)(v & 0xffffffffu);
    }
    if (out_cols != NULL) {
        *out_cols = c;
    }
    if (out_rows != NULL) {
        *out_rows = r;
    }
}

static inline uint32_t rfb_kitty_tile_place_cols(const rfb_kitty_tile *kt)
{
    uint32_t c = 0u;
    rfb_kitty_tile_place_pair(kt, &c, NULL);
    return c;
}

static inline uint32_t rfb_kitty_tile_place_rows(const rfb_kitty_tile *kt)
{
    uint32_t r = 0u;
    rfb_kitty_tile_place_pair(kt, NULL, &r);
    return r;
}

// Initialize the presenter with the given configuration. Does NOT allocate
// the grid; the grid is (re)allocated on open/resize when the framebuffer
// dimensions are known. `out` may be NULL (output dropped). The presenter
// does not take ownership of `out` or `alloc`.
void rfb_kitty_tile_init(rfb_kitty_tile *kt,
                         rfb_allocator *alloc,
                         rfb_buffer *out,
                         uint32_t tile_edge,
                         bool use_shm,
                         bool request_ack);

// Set Kitty placement rectangle in cells (c/r). Pass 0,0 for native size.
void rfb_kitty_tile_set_place_cells(rfb_kitty_tile *kt,
                                    uint32_t cols, uint32_t rows);

// --- Tile-grid geometry helpers (pure, testable without a presenter) ----

// Compute the grid dimensions for a framebuffer of `w`x`h` with `tile_edge`.
// Sets *cols and *rows. Returns false if the grid would exceed
// RFB_KITTY_TILE_MAX_TILES (caller should use whole-frame mode).
bool rfb_kitty_tile_grid(uint32_t w, uint32_t h, uint32_t tile_edge,
                         uint32_t *cols, uint32_t *rows);

// Map a damage rectangle to the set of tiles it intersects. Writes the
// tile indices into `out_indices` (which must have room for at least
// cols*rows entries, or use rfb_kitty_tile_rect_tile_count to size it).
// Returns the number of tile indices written. Tiles are in row-major order.
size_t rfb_kitty_tile_rect_to_tiles(uint32_t rect_x, uint32_t rect_y,
                                    uint32_t rect_w, uint32_t rect_h,
                                    uint32_t fb_w, uint32_t fb_h,
                                    uint32_t tile_edge,
                                    uint32_t cols, uint32_t rows,
                                    size_t *out_indices);

// Upper bound on the number of tiles a rectangle can intersect (for
// sizing caller buffers).
size_t rfb_kitty_tile_rect_tile_count(uint32_t rect_w, uint32_t rect_h,
                                      uint32_t tile_edge,
                                      uint32_t cols, uint32_t rows);

// --- Presenter ops -------------------------------------------------------

// open: record the framebuffer geometry, allocate the dirty bitmap, and
// mark the whole grid dirty (first frame is always a full paint).
// Returns RFB_OK or RFB_ERR_NOMEM.
rfb_error rfb_kitty_tile_open(rfb_kitty_tile *kt, const rfb_framebuffer *fb);

// resize: the framebuffer changed size. Deletes the old images on the
// terminal, frees and reallocates the grid for the new geometry, and marks
// everything dirty. Never leaves stale tiles (plan.md §G22).
// Returns RFB_OK or RFB_ERR_NOMEM.
rfb_error rfb_kitty_tile_resize(rfb_kitty_tile *kt, const rfb_framebuffer *fb);

// present: encode the dirty tiles into the output buffer. Reads the
// framebuffer read-only. Clears the dirty bitmap after encoding (the
// committed state is now on the wire). If `damage` is NULL or full_frame,
// retransmits the whole grid. Coalescing is implicit: tiles dirty from
// multiple damage batches are sent exactly once.
// Returns RFB_OK, RFB_ERR_NOMEM, or RFB_ERR_LIMIT (output overflow).
rfb_error rfb_kitty_tile_present(rfb_kitty_tile *kt,
                                 const rfb_framebuffer *fb,
                                 const rfb_damage_batch *damage);

// Mark damage from a batch into the dirty bitmap WITHOUT presenting. Used
// by the session loop between presents so that multiple FramebufferUpdates
// coalesce into one present. Never drops the final state: every dirty tile
// is retained until the next present().
void rfb_kitty_tile_mark_damage(rfb_kitty_tile *kt,
                                const rfb_damage_batch *damage);

// Encode the delete-image commands for all live tiles into the output
// buffer and clear the grid. Used by close() and resize(). Safe to call
// when the grid is empty (no-op).
void rfb_kitty_tile_delete_all(rfb_kitty_tile *kt);

// Acknowledge an in-flight SHM transfer by image_id. The terminal received
// and processed the transfer; the SHM object is unlinked and the table entry
// freed. Returns true if the entry was found and removed.
bool rfb_kitty_tile_ack_shm(rfb_kitty_tile *kt, uint32_t image_id);

// Reclaim in-flight SHM transfers that have not been acknowledged within
// ack_timeout_ms of their send time. `now_ms` is the current monotonic time.
// Each reclaimed entry's SHM object is unlinked and the table entry freed.
// Returns the number of entries reclaimed. After reclamation, those slots
// are available for new SHM transfers (relieving backpressure).
size_t rfb_kitty_tile_reclaim_expired_shm(rfb_kitty_tile *kt, uint64_t now_ms);

// close: delete all images, free the grid, clear SHM table. Restores
// deterministic state (the struct is safe to re-init).
void rfb_kitty_tile_close(rfb_kitty_tile *kt);

// The presenter ops table. ctx must point at a rfb_kitty_tile.
extern const rfb_presenter_ops rfb_kitty_tile_ops;

// True when the output buffer is above the high-water mark (backpressure).
static inline bool rfb_kitty_tile_in_backpressure(const rfb_kitty_tile *kt)
{
    return kt != NULL && kt->backpressure;
}

// Release any grid storage (does not emit delete commands). Used by tests
// and by close().
void rfb_kitty_tile_destroy(rfb_kitty_tile *kt);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_KITTY_TILE_H
