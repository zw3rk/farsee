// SPDX-License-Identifier: Apache-2.0
//
// farsee — xterm SGR mouse protocol parser (CSI < Pb ; Px ; Py M/m).
//
// Pure, incremental parser for terminal mouse reporting used by RDP live
// mouse and classic RFB pointer paths. No sockets, no FreeRDP, no I/O.
//
// Spec sources (clean-room):
//   - xterm control sequences: DECSET 1000/1002/1006 (SGR mouse)
//   - Coordinates are 1-based cells or pixels, as selected by the terminal.
//
// Button encoding (Pb):
//   bits 0-1: button 0=left, 1=middle, 2=right; 3=release/no-button (motion)
//   bit 5 (32): motion
//   bit 6 (64): wheel; (Pb&3)==0 up, 1 down, 2 left, 3 right
// Final 'M' = press/move/wheel; final 'm' = release.

#ifndef FARSEE_INCLUDE_FARSEE_SGR_MOUSE_H
#define FARSEE_INCLUDE_FARSEE_SGR_MOUSE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Enable/disable sequences (write to stdout to enable terminal mouse).
// CSI ?1000h ?1002h ?1003h ?1006h ?1016h
// (1003 = any-event motion; 1016 = pixel coords when supported)
const char *rfb_sgr_mouse_enable_seq(void);   // returns static string
const char *rfb_sgr_mouse_disable_seq(void);

typedef enum {
    RFB_SGR_EV_NONE = 0,
    RFB_SGR_EV_PRESS,
    RFB_SGR_EV_RELEASE,
    RFB_SGR_EV_MOVE,      // motion with button held or hover if reported
    RFB_SGR_EV_WHEEL,     // vertical/horizontal wheel
} rfb_sgr_ev_kind;

typedef struct rfb_sgr_event {
    rfb_sgr_ev_kind kind;
    int32_t x;            // 1-based SGR x coordinate (cell or pixel)
    int32_t y;            // 1-based SGR y coordinate (cell or pixel)
    uint8_t button;       // 0=left,1=middle,2=right, 64=wheel-up,65=wheel-down
    bool down;            // true for press/move-with-button
    int32_t wheel_v;      // +120 or -120 per notch when kind==WHEEL, else 0
    int32_t wheel_h;
} rfb_sgr_event;

typedef struct rfb_sgr_mouse {
    // partial CSI buffer for resync
    uint8_t buf[64];
    size_t len;
    // state
    uint8_t buttons;      // current mask: bit0=left, bit1=middle, bit2=right
} rfb_sgr_mouse;

void rfb_sgr_mouse_init(rfb_sgr_mouse *m);

// Feed bytes. Writes up to out_cap events. Returns number of events.
// Incomplete sequences retained in m->buf. Malformed: reset and continue.
size_t rfb_sgr_mouse_feed(rfb_sgr_mouse *m, const uint8_t *data, size_t n,
                          rfb_sgr_event *out, size_t out_cap);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_SGR_MOUSE_H
