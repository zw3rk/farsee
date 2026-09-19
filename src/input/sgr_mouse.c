// SPDX-License-Identifier: Apache-2.0
//
// farsee — xterm SGR mouse protocol parser (CSI < Pb ; Px ; Py M/m).
//
// Incremental, bounded, fail-closed. Derived from public xterm control
// sequence documentation only (clean-room; no GPL/AGPL implementation).

#include "farsee/sgr_mouse.h"

#include <string.h>

// Enable: private modes 1000 (click), 1002 (drag), 1003 (any-event motion
// so the remote cursor tracks without a button held — required for VNC
// pointer movement), 1006 (SGR coords), 1016 (SGR *pixel* coordinates when
// the terminal supports it — Ghostty, recent xterm, Kitty). Disable clears
// the same set. With 1016, Pb;Px;Py are 1-based pixels from the terminal
// top-left; map through aspect-fit place (see term_mouse_map).
static const char k_enable[] =
    "\033[?1000h\033[?1002h\033[?1003h\033[?1006h\033[?1016h";
static const char k_disable[] =
    "\033[?1000l\033[?1002l\033[?1003l\033[?1006l\033[?1016l";

const char *rfb_sgr_mouse_enable_seq(void)
{
    return k_enable;
}

const char *rfb_sgr_mouse_disable_seq(void)
{
    return k_disable;
}

void rfb_sgr_mouse_init(rfb_sgr_mouse *m)
{
    if (m == NULL) {
        return;
    }
    m->len = 0;
    m->buttons = 0;
    // buf contents irrelevant when len==0; zero for determinism.
    memset(m->buf, 0, sizeof m->buf);
}

// Button mask bits matching FARSEE / RFB-style left/middle/right.
#define SGR_BTN_LEFT   0x01u
#define SGR_BTN_MIDDLE 0x02u
#define SGR_BTN_RIGHT  0x04u

static uint8_t sgr_mask_for_button(uint8_t btn)
{
    switch (btn) {
    case 0: return SGR_BTN_LEFT;
    case 1: return SGR_BTN_MIDDLE;
    case 2: return SGR_BTN_RIGHT;
    default: return 0;
    }
}

// Decode one complete Pb/Px/Py/final into an event and update button mask.
static void sgr_decode_event(rfb_sgr_mouse *m, unsigned pb,
                             int32_t px, int32_t py, char final,
                             rfb_sgr_event *ev)
{
    memset(ev, 0, sizeof *ev);
    ev->x = px;
    ev->y = py;

    const unsigned low = pb & 3u;
    const bool is_wheel = (pb & 64u) != 0u;
    const bool is_motion = (pb & 32u) != 0u;

    if (is_wheel) {
        ev->kind = RFB_SGR_EV_WHEEL;
        ev->button = (uint8_t)(64u + low);  // 64=up, 65=down, 66=left, 67=right
        ev->down = false;
        switch (low) {
        case 0: ev->wheel_v = 120; break;   // up
        case 1: ev->wheel_v = -120; break;  // down
        case 2: ev->wheel_h = -120; break;  // left
        case 3: ev->wheel_h = 120; break;   // right
        default: break;
        }
        return;
    }

    if (final == 'm') {
        ev->kind = RFB_SGR_EV_RELEASE;
        ev->button = (uint8_t)low;
        ev->down = false;
        if (low < 3u) {
            m->buttons = (uint8_t)(m->buttons & (uint8_t)~sgr_mask_for_button(
                (uint8_t)low));
        }
        return;
    }

    // Final 'M' (or anything else treated as press/move).
    if (is_motion) {
        ev->kind = RFB_SGR_EV_MOVE;
        if (low < 3u) {
            ev->button = (uint8_t)low;
            ev->down = true;
        } else {
            // No button (hover / motion without held button).
            ev->button = 3u;
            ev->down = false;
        }
        return;
    }

    // Press.
    ev->kind = RFB_SGR_EV_PRESS;
    ev->button = (uint8_t)low;
    ev->down = true;
    if (low < 3u) {
        m->buttons = (uint8_t)(m->buttons | sgr_mask_for_button((uint8_t)low));
    }
}

// Try to parse one SGR mouse sequence starting at buf[0..len).
// Returns:
//   >0  number of bytes consumed on success (event filled)
//    0  incomplete (need more data); *ev_out unchanged
//   -1  not a valid SGR start / malformed — caller should skip one byte
static int sgr_try_parse(rfb_sgr_mouse *m, const uint8_t *buf, size_t len,
                         rfb_sgr_event *ev_out)
{
    // Minimum: ESC [ < 0 ; 1 ; 1 M  → 9 bytes.
    if (len < 3u) {
        // Need at least ESC [ < to identify the sequence; if we have ESC
        // alone or ESC [, hold for more unless the second byte is already
        // wrong.
        if (len == 0u) {
            return 0;
        }
        if (buf[0] != 0x1bu) {
            return -1;
        }
        if (len == 1u) {
            return 0;  // wait for '['
        }
        if (buf[1] != (uint8_t)'[') {
            return -1;
        }
        return 0;  // wait for '<'
    }

    if (buf[0] != 0x1bu) {
        return -1;
    }
    if (buf[1] != (uint8_t)'[') {
        return -1;
    }
    if (buf[2] != (uint8_t)'<') {
        return -1;
    }

    // Parse Pb ; Px ; Py final  after the '<' (index 3).
    size_t i = 3;
    unsigned fields[3];
    unsigned field_count = 0;
    unsigned acc = 0;
    bool in_num = false;

    while (i < len) {
        uint8_t c = buf[i];
        if (c >= (uint8_t)'0' && c <= (uint8_t)'9') {
            // Bound accumulation to avoid wrap on garbage long numbers.
            if (acc > 100000u) {
                return -1;
            }
            acc = acc * 10u + (unsigned)(c - (uint8_t)'0');
            in_num = true;
            i++;
            continue;
        }
        if (c == (uint8_t)';') {
            if (field_count >= 3u) {
                return -1;
            }
            // Empty field (;; or leading ;) is allowed as 0.
            fields[field_count++] = acc;
            acc = 0;
            in_num = false;
            i++;
            continue;
        }
        if (c == (uint8_t)'M' || c == (uint8_t)'m') {
            // Final: require exactly 2 semicolons so far → 2 complete
            // fields, and the third field is `acc` (may be empty → 0).
            if (field_count != 2u) {
                return -1;
            }
            fields[2] = acc;
            (void)in_num;
            // Decode.
            sgr_decode_event(m, fields[0],
                             (int32_t)fields[1], (int32_t)fields[2],
                             (char)c, ev_out);
            return (int)(i + 1u);
        }
        // Any other character ends the attempt (malformed).
        return -1;
    }

    // Exhausted buffer without final → incomplete.
    // Cap buffer growth: if already full of non-final garbage, reject.
    if (len >= sizeof(((rfb_sgr_mouse *)0)->buf)) {
        return -1;
    }
    return 0;
}

size_t rfb_sgr_mouse_feed(rfb_sgr_mouse *m, const uint8_t *data, size_t n,
                          rfb_sgr_event *out, size_t out_cap)
{
    if (m == NULL || out == NULL || out_cap == 0u) {
        return 0;
    }
    if (data == NULL && n > 0u) {
        return 0;
    }

    size_t produced = 0;

    // Append new bytes into the residual buffer, then scan.
    // Process in a streaming fashion: if residual + new exceeds buf,
    // process what we can and drop excess carefully.
    size_t data_off = 0;
    while (produced < out_cap) {
        // Fill residual from remaining input when residual is empty-ish
        // or we need more bytes.
        if (data != NULL && data_off < n) {
            // Append as much as fits.
            size_t space = sizeof m->buf - m->len;
            size_t take = n - data_off;
            if (take > space) {
                take = space;
            }
            if (take > 0u) {
                memcpy(m->buf + m->len, data + data_off, take);
                m->len += take;
                data_off += take;
            }
        }

        if (m->len == 0u) {
            break;
        }

        rfb_sgr_event ev;
        int r = sgr_try_parse(m, m->buf, m->len, &ev);
        if (r > 0) {
            // Consumed r bytes; emit event.
            out[produced++] = ev;
            size_t consumed = (size_t)r;
            if (consumed < m->len) {
                memmove(m->buf, m->buf + consumed, m->len - consumed);
                m->len -= consumed;
            } else {
                m->len = 0;
            }
            continue;
        }
        if (r == 0) {
            // Incomplete. If there is more input that did not fit, we
            // cannot grow — treat as malformed overflow and resync.
            if (data != NULL && data_off < n && m->len >= sizeof m->buf) {
                // Drop one byte and retry.
                memmove(m->buf, m->buf + 1, m->len - 1);
                m->len -= 1;
                continue;
            }
            // Wait for more data. If no more input pending, stop.
            if (data == NULL || data_off >= n) {
                break;
            }
            // Space became available only if we would have taken more —
            // loop will append.
            continue;
        }

        // r < 0: skip one byte (resync).
        if (m->len > 0u) {
            memmove(m->buf, m->buf + 1, m->len - 1);
            m->len -= 1;
        }
    }

    // If we stopped early due to out_cap but still have unread input,
    // append what fits into residual for a later feed. Prefer keeping
    // complete residual sequences when possible.
    if (data != NULL && data_off < n && m->len < sizeof m->buf) {
        size_t space = sizeof m->buf - m->len;
        size_t take = n - data_off;
        if (take > space) {
            take = space;
        }
        if (take > 0u) {
            memcpy(m->buf + m->len, data + data_off, take);
            m->len += take;
        }
    }

    return produced;
}
