// SPDX-License-Identifier: Apache-2.0
//
// Aspect-fit terminal mouse map (SGR → desktop).

#include "rfb_test.h"
#include "farsee/term_mouse_map.h"

#include <string.h>

RFB_TEST(term_mouse_map, aspect_fit__16x9_into_wide_term) {
    farsee_term_layout L;
    memset(&L, 0, sizeof L);
    L.cell_w = 10;
    L.cell_h = 20;
    L.term_cols = 200;
    L.term_rows = 60;
    L.term_pw = 2000;
    L.term_ph = 1200;
    L.desk_w = 3840;
    L.desk_h = 2160;
    L.avail_cols = 200;
    L.avail_rows = 59;
    L.scale_pct = 100u;
    farsee_term_layout_aspect_fit(&L);
    // max = 2000×1180; scale = min(2000/3840, 1180/2160) ≈ 0.5208 (width-limited).
    // Fixed-point (×10000) truncates: disp ≈ 1999×1124.
    RFB_CHECK(L.disp_w_px >= 1990 && L.disp_w_px <= 2000);
    RFB_CHECK(L.disp_h_px >= 1115 && L.disp_h_px <= 1125);
    RFB_CHECK(L.place_cols > 0u);
    RFB_CHECK(L.place_rows > 0u);
    RFB_CHECK(L.place_cols <= 200u);
    RFB_CHECK(L.place_rows <= 59u);
}

RFB_TEST(term_mouse_map, aspect_fit__50pct_half_of_full_fit) {
    farsee_term_layout full;
    farsee_term_layout half;
    memset(&full, 0, sizeof full);
    memset(&half, 0, sizeof half);
    full.cell_w = half.cell_w = 10;
    full.cell_h = half.cell_h = 20;
    full.term_cols = half.term_cols = 200;
    full.term_rows = half.term_rows = 60;
    full.term_pw = half.term_pw = 2000;
    full.term_ph = half.term_ph = 1200;
    full.desk_w = half.desk_w = 3840;
    full.desk_h = half.desk_h = 2160;
    full.avail_cols = half.avail_cols = 200;
    full.avail_rows = half.avail_rows = 59;
    full.scale_pct = 100u;
    half.scale_pct = 50u;
    farsee_term_layout_aspect_fit(&full);
    farsee_term_layout_aspect_fit(&half);
    RFB_CHECK(half.disp_w_px * 2 >= full.disp_w_px - 2);
    RFB_CHECK(half.disp_w_px * 2 <= full.disp_w_px + 2);
    RFB_CHECK(half.place_cols < full.place_cols ||
              half.place_rows < full.place_rows);
}

RFB_TEST(term_mouse_map, view_scale_clamp__bounds) {
    RFB_CHECK_EQ_UINT(farsee_view_scale_clamp(0u), 100u);
    RFB_CHECK_EQ_UINT(farsee_view_scale_clamp(10u), 20u);
    RFB_CHECK_EQ_UINT(farsee_view_scale_clamp(50u), 50u);
    RFB_CHECK_EQ_UINT(farsee_view_scale_clamp(100u), 100u);
    RFB_CHECK_EQ_UINT(farsee_view_scale_clamp(200u), 100u);
}

RFB_TEST(term_mouse_map, mouse_center_pixel_mode__maps_near_desk_center) {
    farsee_term_layout L;
    memset(&L, 0, sizeof L);
    L.cell_w = 10;
    L.cell_h = 20;
    L.term_cols = 200;
    L.term_rows = 60;
    L.term_pw = 2000;
    L.term_ph = 1200;
    L.desk_w = 3840;
    L.desk_h = 2160;
    L.avail_cols = 200;
    L.avail_rows = 59;
    L.scale_pct = 100u;
    farsee_term_layout_aspect_fit(&L);

    // SGR 1016: centre of place box → near desktop centre.
    const int32_t place_w = 10 * (int32_t)L.place_cols;
    const int32_t place_h = 20 * (int32_t)L.place_rows;
    const int32_t cx = place_w / 2 + 1; // 1-based SGR
    const int32_t cy = place_h / 2 + 1;
    int32_t x = -1;
    int32_t y = -1;
    bool px = false;
    RFB_CHECK(farsee_term_mouse_to_desktop(&L, cx, cy, &x, &y, &px));
    RFB_CHECK(px);
    RFB_CHECK(x > 1700 && x < 2140);
    RFB_CHECK(y > 900 && y < 1260);
}

RFB_TEST(term_mouse_map, mouse_top_left_cell__near_origin) {
    farsee_term_layout L;
    memset(&L, 0, sizeof L);
    L.cell_w = 8;
    L.cell_h = 16;
    L.term_cols = 80;
    L.term_rows = 24;
    L.desk_w = 800;
    L.desk_h = 600;
    L.avail_cols = 80;
    L.avail_rows = 23;
    L.scale_pct = 100u;
    farsee_term_layout_aspect_fit(&L);

    int32_t x = -1;
    int32_t y = -1;
    bool px = false;
    // Cell mode: col=1,row=1 → near top-left of desktop (cell centre).
    RFB_CHECK(farsee_term_mouse_to_desktop(&L, 1, 1, &x, &y, &px));
    RFB_CHECK(!px);
    RFB_CHECK(x >= 0 && x < 40);
    RFB_CHECK(y >= 0 && y < 40);
}

// Regression: DECSET 1016 reports small terminal pixels near the origin
// (Apple menu). Without sgr_pixel_coords those look like cell (5,3) and
// map far below the menu bar.
RFB_TEST(term_mouse_map, mouse_sgr1016_small_pixel__maps_near_origin) {
    farsee_term_layout L;
    memset(&L, 0, sizeof L);
    L.term_cols = 120;
    L.term_rows = 40;
    L.term_pw = 1920;
    L.term_ph = 1080;
    L.desk_w = 1440;
    L.desk_h = 900;
    L.avail_cols = 120;
    L.avail_rows = 38;
    L.scale_pct = 100u;
    L.sgr_pixel_coords = true;
    farsee_term_layout_aspect_fit(&L);

    int32_t x = -1;
    int32_t y = -1;
    bool px = false;
    // Terminal pixel ~ (12, 8) — under term_cols/rows, looks "cell-like".
    RFB_CHECK(farsee_term_mouse_to_desktop(&L, 12, 8, &x, &y, &px));
    RFB_CHECK(px);
    // Must land in the menu-bar band (top ~5% of a typical desktop), not
    // deep into the content area as cell-mode would produce.
    RFB_CHECK(x >= 0 && x < (int32_t)L.desk_w / 10);
    RFB_CHECK(y >= 0 && y < (int32_t)L.desk_h / 20);

    // Same coords without the flag → cell mode (wrong for 1016).
    L.sgr_pixel_coords = false;
    int32_t xc = -1;
    int32_t yc = -1;
    RFB_CHECK(farsee_term_mouse_to_desktop(&L, 12, 8, &xc, &yc, &px));
    RFB_CHECK(!px);
    // Cell mapping of "row 8" is much lower than true pixel row 8.
    RFB_CHECK(yc > y);
}

RFB_TEST(term_mouse_map, mouse_top_left_pixel__near_desk_origin) {
    farsee_term_layout L;
    memset(&L, 0, sizeof L);
    L.cell_w = 10;
    L.cell_h = 20;
    L.term_cols = 100;
    L.term_rows = 40;
    L.term_pw = 1000;
    L.term_ph = 800;
    L.desk_w = 3840;
    L.desk_h = 2160;
    L.avail_cols = 100;
    L.avail_rows = 39;
    L.scale_pct = 100u;
    farsee_term_layout_aspect_fit(&L);
    int32_t x0 = -1;
    int32_t y0 = -1;
    int32_t x1 = -1;
    int32_t y1 = -1;
    bool px = false;
    // SGR 1016: pixel coords exceed cell grid (term_cols=100).
    // Upper-left of place maps closer to desk origin than place centre.
    RFB_CHECK(farsee_term_mouse_to_desktop(&L, 110, 50, &x0, &y0, &px));
    RFB_CHECK(px);
    RFB_CHECK(farsee_term_mouse_to_desktop(
        &L, 110 + (int32_t)L.place_cols * 5,
        50 + (int32_t)L.place_rows * 10, &x1, &y1, &px));
    RFB_CHECK(px);
    RFB_CHECK(x0 < x1);
    RFB_CHECK(y0 < y1);
    RFB_CHECK(x0 < (int32_t)L.desk_w / 2);
    RFB_CHECK(y0 < (int32_t)L.desk_h / 2);
}

RFB_TEST(term_mouse_map, null_and_invalid__fail_closed) {
    RFB_CHECK(!farsee_term_mouse_to_desktop(NULL, 1, 1, NULL, NULL, NULL));
    farsee_term_layout L;
    memset(&L, 0, sizeof L);
    // desk 0 → invalid
    RFB_CHECK(!farsee_term_mouse_to_desktop(&L, 1, 1, NULL, NULL, NULL));
    farsee_term_layout_aspect_fit(NULL); // must not crash
    farsee_term_layout_set_cell_size(NULL);
}

// T12: clicks on the status band / outside place must not clamp to desk edge.
RFB_TEST(term_mouse_map, outside_place__returns_false)
{
    farsee_term_layout L;
    memset(&L, 0, sizeof L);
    L.term_cols = 80;
    L.term_rows = 24;
    L.term_pw = 800;
    L.term_ph = 480;
    L.desk_w = 1920;
    L.desk_h = 1080;
    L.avail_cols = 80;
    L.avail_rows = 22; // leave 2 status rows
    L.scale_pct = 100u;
    L.sgr_pixel_coords = true;
    farsee_term_layout_aspect_fit(&L);
    farsee_term_layout_set_cell_size(&L);
    RFB_CHECK(L.place_cols > 0u);
    RFB_CHECK(L.place_rows > 0u);

    const int32_t cw = L.cell_w > 0 ? L.cell_w : 8;
    const int32_t ch = L.cell_h > 0 ? L.cell_h : 16;
    const int32_t place_h = ch * (int32_t)L.place_rows;

    int32_t x = 0;
    int32_t y = 0;
    bool px = false;
    // Pixel just below the place box (status row band), 1-based SGR 1016.
    const int32_t status_my = place_h + ch + 1;
    RFB_CHECK(!farsee_term_mouse_to_desktop(&L, /*mx=*/cw, status_my, &x, &y,
                                            &px));

    // Far right of place still maps (bottom-right image pixel → desk edge).
    const int32_t br_mx = (int32_t)L.place_cols * cw; // last col inside
    const int32_t br_my = (int32_t)L.place_rows * ch;
    RFB_CHECK(farsee_term_mouse_to_desktop(&L, br_mx, br_my, &x, &y, &px));
    RFB_CHECK(x >= 0);
    RFB_CHECK(y >= 0);
    RFB_CHECK(x < (int32_t)L.desk_w);
    RFB_CHECK(y < (int32_t)L.desk_h);
}
