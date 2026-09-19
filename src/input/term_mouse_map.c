// SPDX-License-Identifier: Apache-2.0
//
// Terminal SGR mouse → desktop pixel mapping (aspect-fit Kitty placement).

#include "farsee/term_mouse_map.h"

#include <stddef.h>

uint32_t farsee_view_scale_clamp(uint32_t scale_pct)
{
    if (scale_pct == 0u) {
        return FARSEE_VIEW_SCALE_MAX_PCT;
    }
    if (scale_pct < FARSEE_VIEW_SCALE_MIN_PCT) {
        return FARSEE_VIEW_SCALE_MIN_PCT;
    }
    if (scale_pct > FARSEE_VIEW_SCALE_MAX_PCT) {
        return FARSEE_VIEW_SCALE_MAX_PCT;
    }
    return scale_pct;
}

void farsee_term_layout_set_cell_size(farsee_term_layout *L)
{
    if (L == NULL) {
        return;
    }
    int32_t cw = 8;
    int32_t ch = 16;
    if (L->term_cols > 0u && L->term_pw > 0u) {
        cw = (int32_t)L->term_pw / (int32_t)L->term_cols;
        if (cw < 1) {
            cw = 8;
        }
    }
    if (L->term_rows > 0u && L->term_ph > 0u) {
        ch = (int32_t)L->term_ph / (int32_t)L->term_rows;
        if (ch < 1) {
            ch = 16;
        }
    }
    L->cell_w = cw;
    L->cell_h = ch;
}

void farsee_term_layout_aspect_fit(farsee_term_layout *L)
{
    if (L == NULL) {
        return;
    }
    farsee_term_layout_set_cell_size(L);
    int32_t cw = L->cell_w > 0 ? L->cell_w : 8;
    int32_t ch = L->cell_h > 0 ? L->cell_h : 16;
    uint16_t cols = L->avail_cols > 0u ? L->avail_cols
                                       : (L->term_cols > 0u ? L->term_cols : 80u);
    uint16_t rows = L->avail_rows > 0u ? L->avail_rows
                                       : (L->term_rows > 0u ? L->term_rows : 24u);
    if (cols < 1u) {
        cols = 1u;
    }
    if (rows < 1u) {
        rows = 1u;
    }
    const int32_t max_w = (int32_t)cols * cw;
    const int32_t max_h = (int32_t)rows * ch;
    int32_t desk_w = L->desk_w > 0u ? (int32_t)L->desk_w : max_w;
    int32_t desk_h = L->desk_h > 0u ? (int32_t)L->desk_h : max_h;
    if (desk_w < 1) {
        desk_w = 1;
    }
    if (desk_h < 1) {
        desk_h = 1;
    }
    // Max aspect-fit into the available terminal area.
    int32_t fit_w = desk_w;
    int32_t fit_h = desk_h;
    if (fit_w > max_w || fit_h > max_h) {
        const int64_t sx = ((int64_t)max_w * 10000) / desk_w;
        const int64_t sy = ((int64_t)max_h * 10000) / desk_h;
        const int64_t s = sx < sy ? sx : sy;
        fit_w = (int32_t)((desk_w * s) / 10000);
        fit_h = (int32_t)((desk_h * s) / 10000);
        if (fit_w < 1) {
            fit_w = 1;
        }
        if (fit_h < 1) {
            fit_h = 1;
        }
    }
    // Apply operator view scale (percent of max fit).
    const uint32_t pct = farsee_view_scale_clamp(L->scale_pct);
    int32_t disp_w = (int32_t)(((int64_t)fit_w * (int64_t)pct) / 100);
    int32_t disp_h = (int32_t)(((int64_t)fit_h * (int64_t)pct) / 100);
    if (disp_w < 1) {
        disp_w = 1;
    }
    if (disp_h < 1) {
        disp_h = 1;
    }
    if (disp_w > max_w) {
        disp_w = max_w;
    }
    if (disp_h > max_h) {
        disp_h = max_h;
    }
    L->disp_w_px = disp_w;
    L->disp_h_px = disp_h;
    L->place_cols = (uint32_t)((disp_w + cw - 1) / cw);
    L->place_rows = (uint32_t)((disp_h + ch - 1) / ch);
    if (L->place_cols < 1u) {
        L->place_cols = 1u;
    }
    if (L->place_rows < 1u) {
        L->place_rows = 1u;
    }
    if (L->place_cols > cols) {
        L->place_cols = cols;
    }
    if (L->place_rows > rows) {
        L->place_rows = rows;
    }
    // Image at home (0,0); RFB/RDP clear+home before Kitty place.
    L->origin_x = 0;
    L->origin_y = 0;
}

bool farsee_term_mouse_to_desktop(const farsee_term_layout *L,
                                  int32_t mx, int32_t my,
                                  int32_t *out_x, int32_t *out_y,
                                  bool *out_pixel_mode)
{
    if (L == NULL || L->desk_w == 0u || L->desk_h == 0u) {
        return false;
    }
    int32_t cw = L->cell_w > 0 ? L->cell_w : 8;
    int32_t ch = L->cell_h > 0 ? L->cell_h : 16;

    // Heuristic (legacy, no 1016): coords larger than the cell grid are
    // pixels. With DECSET 1016, reports are *always* 1-based terminal
    // pixels — including the top-left band where mx/my are small and would
    // otherwise be mistaken for cell indices (Apple menu / title clicks).
    const bool pixel_mode =
        L->sgr_pixel_coords ||
        (L->term_cols > 0u && mx > (int32_t)L->term_cols + 1) ||
        (L->term_rows > 0u && my > (int32_t)L->term_rows + 1);
    if (out_pixel_mode != NULL) {
        *out_pixel_mode = pixel_mode;
    }

    int32_t term_x;
    int32_t term_y;
    if (pixel_mode) {
        term_x = mx > 0 ? mx - 1 : 0;
        term_y = my > 0 ? my - 1 : 0;
    } else {
        // Cell mode: map to the cell's top-left + a small inset (not centre).
        // Centre mapping pushed row-0 clicks below the macOS menu bar.
        const int32_t col = mx > 0 ? mx - 1 : 0;
        const int32_t row = my > 0 ? my - 1 : 0;
        const int32_t inset_x = cw > 2 ? 1 : 0;
        const int32_t inset_y = ch > 2 ? 1 : 0;
        term_x = col * cw + inset_x;
        term_y = row * ch + inset_y;
    }

    // Kitty stretches the full framebuffer into the c×r place box. Hit-test
    // against that box (not the pre-ceil aspect-fit pixel size), or the
    // menu bar / corners systematically miss.
    int32_t place_w = cw * (L->place_cols > 0u ? (int32_t)L->place_cols : 1);
    int32_t place_h = ch * (L->place_rows > 0u ? (int32_t)L->place_rows : 1);
    if (place_w < 1) {
        place_w = 1;
    }
    if (place_h < 1) {
        place_h = 1;
    }

    int32_t lx = term_x - L->origin_x;
    int32_t ly = term_y - L->origin_y;
    // Outside the Kitty place box (status band, margins, etc.): refuse.
    // Clamping to the edge would inject real clicks on the desk border
    // (e.g. Windows Start / sign-out risk). Callers may drop presses.
    if (lx < 0 || ly < 0 || lx >= place_w || ly >= place_h) {
        return false;
    }
    int32_t x =
        (int32_t)(((int64_t)lx * (int64_t)L->desk_w) / (int64_t)place_w);
    int32_t y =
        (int32_t)(((int64_t)ly * (int64_t)L->desk_h) / (int64_t)place_h);
    if (x < 0) {
        x = 0;
    }
    if (y < 0) {
        y = 0;
    }
    if (x >= (int32_t)L->desk_w) {
        x = (int32_t)L->desk_w - 1;
    }
    if (y >= (int32_t)L->desk_h) {
        y = (int32_t)L->desk_h - 1;
    }
    if (out_x != NULL) {
        *out_x = x;
    }
    if (out_y != NULL) {
        *out_y = y;
    }
    return true;
}
