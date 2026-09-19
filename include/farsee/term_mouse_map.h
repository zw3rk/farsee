// SPDX-License-Identifier: Apache-2.0
//
// Terminal SGR mouse → desktop pixel mapping (aspect-fit Kitty placement).
// Shared pure math for RFB and RDP live. No I/O.

#ifndef FARSEE_INCLUDE_FARSEE_TERM_MOUSE_MAP_H
#define FARSEE_INCLUDE_FARSEE_TERM_MOUSE_MAP_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Default view scale: half of max aspect-fit (operator can raise with
// leader +/- or --view-scale). Makes 4K less dominant; zoom in to click.
#define FARSEE_VIEW_SCALE_DEFAULT_PCT 50u
#define FARSEE_VIEW_SCALE_MIN_PCT     20u
#define FARSEE_VIEW_SCALE_MAX_PCT     100u
#define FARSEE_VIEW_SCALE_STEP_PCT    10u

// Layout of a remote desktop image placed at terminal top-left after home.
// Cell size is terminal font metrics (from TIOCGWINSZ xpixel/ypixel, or a
// fallback). place_* describe the Kitty c/r rectangle. disp_* is the
// aspect-fit pixel size before cell rounding; hit-testing uses the place
// cell box (Kitty stretches the full framebuffer into c×r).
typedef struct farsee_term_layout {
    int32_t cell_w;       // terminal cell width in pixels (>=1)
    int32_t cell_h;       // terminal cell height in pixels (>=1)
    uint16_t term_cols;   // terminal columns (for SGR cell vs pixel detect)
    uint16_t term_rows;   // terminal rows
    uint16_t term_pw;     // terminal width in pixels (0 if unknown)
    uint16_t term_ph;     // terminal height in pixels (0 if unknown)
    uint32_t desk_w;      // remote desktop width
    uint32_t desk_h;      // remote desktop height
    uint16_t avail_cols;  // columns reserved for the image (status band excluded)
    uint16_t avail_rows;  // rows reserved for the image
    // View scale as percent of max aspect-fit (20..100). 0 → treat as 100.
    uint32_t scale_pct;
    // Outputs of farsee_term_layout_aspect_fit:
    int32_t disp_w_px;    // aspect-fit display width in terminal pixels
    int32_t disp_h_px;    // aspect-fit display height in terminal pixels
    uint32_t place_cols;  // Kitty c=
    uint32_t place_rows;  // Kitty r=
    int32_t origin_x;     // image top-left in terminal pixels (0 after home)
    int32_t origin_y;
    // When true (DECSET 1016 armed), SGR reports are always terminal pixels —
    // even when mx/my are small enough to look like cell indices. Without
    // this, top-left menu-bar clicks (e.g. Apple logo) mis-map as cells.
    bool sgr_pixel_coords;
} farsee_term_layout;

// Clamp scale_pct into [MIN, MAX]. 0 → MAX (100% fit).
uint32_t farsee_view_scale_clamp(uint32_t scale_pct);

// Resolve cell size from winsize-style fields. Prefer term_pw/term_ph when
// non-zero; otherwise fall back to 8×16 (macOS often reports 0 xpixel).
void farsee_term_layout_set_cell_size(farsee_term_layout *L);

// Compute aspect-preserving fit of desk_* into avail_cols × avail_rows,
// then apply scale_pct. Fills place_*, disp_*, origin_*=0. Safe for NULL.
void farsee_term_layout_aspect_fit(farsee_term_layout *L);

// Map one SGR report (1-based cell or pixel coords) to desktop pixels.
// Hit-tests against the Kitty place box (place_cols×cell × place_rows×cell),
// which matches stretch-to-c/r placement. Returns false if invalid.
bool farsee_term_mouse_to_desktop(const farsee_term_layout *L,
                                  int32_t mx, int32_t my,
                                  int32_t *out_x, int32_t *out_y,
                                  bool *out_pixel_mode);

#ifdef __cplusplus
}
#endif

#endif /* FARSEE_INCLUDE_FARSEE_TERM_MOUSE_MAP_H */
