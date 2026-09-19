// SPDX-License-Identifier: Apache-2.0
//
// Shared live-session shell: TTY quiet/raw lifecycle (crash atexit guard),
// leader demux feed, status band, aspect-fit layout, SGR→desktop packing.
// Protocol paths (RFB/RDP) supply inject ops + present/connect glue only.
//
// Layout field ownership (cross-thread):
//   place_cells, log_row, view_scale_pct, term_cells, term_px are atomics
//   (input/setup writes; present/status may load). Plain place_cols/rows
//   and disp_*/origin_* are same-thread caches under io_mu in refresh_layout.
//   force_repaint is an atomic: input/zoom stores 1, present loop clears.

#ifndef FARSEE_SRC_APP_LIVE_SHELL_H
#define FARSEE_SRC_APP_LIVE_SHELL_H

#include "farsee/cli_target.h"
#include "farsee/farsee_atomic.h"
#include "farsee/farsee_thread.h"
#include "farsee/live_demux.h"
#include "farsee/normalized_input.h"
#include "farsee/sgr_mouse.h"
#include "farsee/socket_posix.h" // FARSEE_LINK_RATE_WINDOW_MS, farsee_link_rate
#include "farsee/term_mouse_map.h"
#include "app/live_shell_tty_guard.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <termios.h>

#ifdef __cplusplus
extern "C" {
#endif

// Forward — optional place updates; shell does not own the tile.
struct rfb_kitty_tile;

// Protocol product hooks. Any pointer may be NULL (no-op).
typedef struct farsee_live_shell_ops {
    void (*inject_key)(void *u, const rfb_norm_key *nk);
    // Returns true when the inject was accepted (queued / sent). Shell only
    // advances last_buttons / last_desk_* on success.
    bool (*inject_pointer)(void *u, int32_t x, int32_t y, uint8_t buttons,
                           int wheel_v, int wheel_h);
    void (*request_quit)(void *u);
    // View scale (Kitty place). RFB and RDP both supply this for C-] +/-.
    // Leave NULL only when a protocol has no view-scale (status redraw only).
    void (*zoom)(void *u, int delta_pct);
    // RDP: job-control suspend. RFB: may map to quit (named decision).
    void (*suspend)(void *u);
    // Optional suffix for status line (scale %, FPS strip). Cap includes NUL.
    // Called from draw_status under s->io_mu when the mutex is non-NULL.
    // Implementations that mutate non-atomic state require a live io_mu
    // (RFB/RDP live paths treat mutex alloc failure as fatal).
    void (*status_extra)(void *u, char *buf, size_t cap);
    // After apply_kitty layout change (RFB: kick frame slot).
    void (*on_layout_applied)(void *u);
} farsee_live_shell_ops;

typedef struct farsee_live_shell {
    // --- TTY quiet/raw ---
    int            tty_fd;
    bool           tty_fd_owned;
    bool           tty_attrs_saved;
    struct termios tty_saved;
    bool           mouse_enabled;
    bool           want_mouse;
    bool           want_kitty_kb;

    // --- demux (leader / residual / APC / SGR / keyboard) ---
    farsee_live_demux demux;
    farsee_cli_leader leader;
    bool              view_only;

    // --- layout (see file header ownership note) ---
    // term_cells: cols high 32, rows low 32; term_px: pw high, ph low.
    farsee_atomic_u64 term_cells;
    farsee_atomic_u64 term_px;
    // Same-thread convenience caches (input/setup under io_mu in refresh).
    uint16_t term_cols;
    uint16_t term_rows;
    uint16_t term_pw;
    uint16_t term_ph;
    uint32_t desk_w;
    uint32_t desk_h;
    // place_cols/rows: packed as one atomic u64 (cols high 32, rows low 32).
    farsee_atomic_u64 place_cells;
    uint32_t place_cols; // cache of place_cells high (input thread)
    uint32_t place_rows; // cache of place_cells low (input thread)
    int32_t  disp_w_px;
    int32_t  disp_h_px;
    int32_t  img_origin_x;
    int32_t  img_origin_y;
    farsee_atomic_int view_scale_pct; // 20..100; cross-thread safe
    farsee_atomic_int log_row; // 1-based status row (place_rows+1); present reads
    bool     layout_active;
    uint16_t status_rows;    // RFB=2 (status+log), RDP=1
    // Status band short-write recovery: next draw prefixes CAN (0x18).
    bool     status_resync;

    // --- status identity / help text ---
    char     status_proto[8]; // "vnc" / "rdp"
    char     status_host[128];
    uint16_t status_port;
    bool     show_zoom;    // RFB: C-] +/- zoom in help
    bool     show_suspend; // RDP: C-] z suspend in help

    // --- input activity (status band) ---
    // Bumped by feed path on each inject; status_extra / draw can show it so
    // operators can tell demux is alive without FARSEE_*_INPUT_DEBUG.
    farsee_atomic_u64 input_events;
    // Last successful SGR→desktop map (for release-outside-place inject).
    int32_t  last_desk_x;
    int32_t  last_desk_y;
    uint8_t  last_buttons; // FARSEE_BUTTON_* mask last *successfully* injected

    // Present thread may only *note* desk geometry. Packed w<<32|h; 0 = none.
    // Input/setup applies via farsee_live_shell_apply_pending_desk.
    farsee_atomic_u64 pending_desk;

    // --- optional present hooks ---
    struct rfb_kitty_tile *kitty;          // may be NULL
    farsee_atomic_int     *force_repaint;  // may be NULL (atomic)
    farsee_mutex          *io_mu;          // may be NULL (RDP MT stdout)

    const farsee_live_shell_ops *ops;
    void                        *ops_user;
} farsee_live_shell;

// Init demux + defaults. status_rows: 2 RFB / 1 RDP. leader NULL → C-].
void farsee_live_shell_init(farsee_live_shell *s,
                            const farsee_cli_leader *leader,
                            uint16_t status_rows);

// View scale get/set (atomic; 20..100 clamped on set).
uint32_t farsee_live_shell_view_scale(const farsee_live_shell *s);
void farsee_live_shell_set_view_scale(farsee_live_shell *s, uint32_t pct);

// Publish terminal geometry atomics + same-thread caches (cross-thread safe).
void farsee_live_shell_set_term_geom(farsee_live_shell *s, uint16_t cols,
                                     uint16_t rows, uint16_t pw, uint16_t ph);
// Load published geometry into out params (atomics). Returns false if s NULL.
bool farsee_live_shell_get_term_geom(const farsee_live_shell *s, uint16_t *cols,
                                     uint16_t *rows, uint16_t *pw,
                                     uint16_t *ph);

// Quiet/raw enter (ISIG off so leader/Ctrl-C reach userspace). Re-enter safe.
bool farsee_live_shell_quiet_enter(farsee_live_shell *s);
void farsee_live_shell_quiet_restore(farsee_live_shell *s);

// Enable/disable SGR mouse + Kitty CSI-u on stdout and input TTY.
void farsee_live_shell_input_enable(farsee_live_shell *s);
void farsee_live_shell_input_disable(farsee_live_shell *s);

// Cursor / status band helpers (stdout).
void farsee_live_shell_home_cursor(void);
void farsee_live_shell_fix_status_rows(farsee_live_shell *s);
// May set status_resync on short write (next draw_status prefixes CAN).
void farsee_live_shell_park_status_cursor(farsee_live_shell *s);
void farsee_live_shell_park_log_cursor(farsee_live_shell *s);
void farsee_live_shell_draw_status(farsee_live_shell *s);

// farsee_link_rate / farsee_link_rate_sample live in farsee/socket_posix.h
// (pure; protocol thread latches and publishes via farsee_link_rate_pack).

// Pure status suffix: "  50%  14ms  340KiB/s" (no I/O).
// Units: RTT in ms; rate is kibibytes/s labelled KiB/s.
void farsee_live_shell_format_link_extra(char *buf, size_t cap,
                                         uint32_t scale_pct, uint32_t rtt_ms,
                                         bool have_rtt, uint32_t rate_kib_s,
                                         bool have_rate);

// Clamp snprintf return values for fixed-buffer writes.
// Returns 0 when n <= 0; otherwise min((size_t)n, cap-1) so callers never
// pass an oversize length to write() past the initialized region.
size_t farsee_live_shell_clamp_snprintf_len(int n, size_t cap);

// If *inout_len == cap-1 (real snprintf truncation), stamp trailing "\033[0m".
// If *inout_len >= cap (out-of-contract), set *inout_len = 0 and do not write
// (fail closed — never emit uninitialized bytes).
void farsee_live_shell_ensure_ansi_reset(char *buf, size_t *inout_len,
                                         size_t cap);

// Probe terminal geometry for layout. Prefer src_fd when >= 0, else STDOUT
// if a TTY. Returns true and writes cols/rows/pw/ph when a probe succeeds.
// Merges non-zero pixel dims when available (tmux may report 0 xpixel).
bool farsee_live_shell_probe_winsize(int src_fd, uint16_t *out_cols,
                                     uint16_t *out_rows, uint16_t *out_pw,
                                     uint16_t *out_ph);

// Aspect-fit packing. apply_kitty: place cells + optional erase + force_repaint.
// Returns true when place_cols/rows changed.
// Acquires s->io_mu when non-NULL — caller must NOT already hold io_mu
// The mutex is non-recursive; a nested lock deadlocks.
bool farsee_live_shell_refresh_layout(farsee_live_shell *s, bool apply_kitty);

// True when Kitty out buffer still has unflushed bytes (do not emit CSI).
// Safe with NULL shell / no kitty (false).
bool farsee_live_shell_kitty_pending(const farsee_live_shell *s);

// Present-safe: note peer desktop size for later apply on the layout writer
// thread. Does not mutate desk_w/h or refresh layout.
void farsee_live_shell_note_desk_size(farsee_live_shell *s, uint32_t w,
                                      uint32_t h);

// Input/setup: if pending desk differs from current, store desk_w/h and
// refresh_layout. Returns true when geometry was applied.
bool farsee_live_shell_apply_pending_desk(farsee_live_shell *s,
                                          bool apply_kitty);

// SGR terminal coords → desktop pixels (shared term_mouse_map rules).
bool farsee_live_shell_mouse_to_desktop(const farsee_live_shell *s, int32_t mx,
                                        int32_t my, int32_t *out_x,
                                        int32_t *out_y, bool *out_pixel_mode);

// Feed TTY bytes: demux + desktop map + ops dispatch.
void farsee_live_shell_feed_tty(farsee_live_shell *s, const uint8_t *data,
                                size_t n, uint64_t now_ms);

// Leader-arm timeout without new bytes (idle poll loop).
void farsee_live_shell_tick_timeout(farsee_live_shell *s, uint64_t now_ms);

// Leader second-chord product actions (also used from demux callback).
void farsee_live_shell_do_leader_cmd(farsee_live_shell *s, rfb_leader_cmd cmd);

// Zoom: if ops.zoom set, call it (protocol owns scale + layout). If ops set
// but zoom NULL, status redraw only — no view_scale mutation. If ops NULL,
// adjust local scale (unit/default path).
void farsee_live_shell_zoom(farsee_live_shell *s, int delta_pct);

#ifdef __cplusplus
}
#endif

#endif /* FARSEE_SRC_APP_LIVE_SHELL_H */
