// SPDX-License-Identifier: Apache-2.0
//
// RFB session input ownership: command drain, wire formatting, and release.

#include "rfb/rfb_session_internal.h"
#include "rfb/rfb_session_math.h"

#include "farsee/bytes.h"
#include "farsee/input.h"
#include "farsee/rfb_io_pump.h"

#include <string.h>

static uint8_t pointer_held_mask(unsigned buttons)
{
    uint8_t mask = 0;
    if ((buttons & FARSEE_BUTTON_LEFT) != 0u) {
        mask = (uint8_t)(mask | RFB_BUTTON_LEFT);
    }
    if ((buttons & FARSEE_BUTTON_MIDDLE) != 0u) {
        mask = (uint8_t)(mask | RFB_BUTTON_MIDDLE);
    }
    if ((buttons & FARSEE_BUTTON_RIGHT) != 0u) {
        mask = (uint8_t)(mask | RFB_BUTTON_RIGHT);
    }
    return mask;
}

size_t rfb_session_format_pointer_events(const farsee_pointer_event *pe,
                                         uint8_t *out, size_t out_cap)
{
    if (pe == NULL || out == NULL) {
        return 0;
    }
    const uint16_t x = pe->abs_x < 0 ? 0u
        : (pe->abs_x > 0xFFFF ? (uint16_t)0xFFFFu : (uint16_t)pe->abs_x);
    const uint16_t y = pe->abs_y < 0 ? 0u
        : (pe->abs_y > 0xFFFF ? (uint16_t)0xFFFFu : (uint16_t)pe->abs_y);
    const uint8_t held = pointer_held_mask(pe->buttons);

    int32_t v_notches = rfb_session_wheel_notches(pe->wheel_v);
    int32_t h_notches = rfb_session_wheel_notches(pe->wheel_h);
    // Cap multi-notch flood so one command cannot exhaust the output buffer.
    if (v_notches > 32) {
        v_notches = 32;
    } else if (v_notches < -32) {
        v_notches = -32;
    }
    if (h_notches > 32) {
        h_notches = 32;
    } else if (h_notches < -32) {
        h_notches = -32;
    }

    const int32_t v_abs = v_notches >= 0 ? v_notches : -v_notches;
    const int32_t h_abs = h_notches >= 0 ? h_notches : -h_notches;
    // Each wheel notch emits a press and release at the event coordinates.
    // With no wheel notch, emit one event containing only held-button state.
    const size_t n_msgs =
        (v_abs == 0 && h_abs == 0)
            ? 1u
            : (size_t)(2 * v_abs + 2 * h_abs);
    const size_t need = n_msgs * 6u;
    if (need > out_cap) {
        return 0;
    }

    size_t off = 0;
    if (v_abs == 0 && h_abs == 0) {
        rfb_writer w = rfb_writer_make(out + off, 6u);
        if (rfb_format_pointer_event(&w, held, x, y) != RFB_OK) {
            return 0;
        }
        return 6u;
    }

    const uint8_t v_bit = (v_notches > 0)   ? RFB_BUTTON_WHEEL_UP
                          : (v_notches < 0) ? RFB_BUTTON_WHEEL_DN
                                            : 0u;
    const uint8_t h_bit = (h_notches > 0)   ? RFB_BUTTON_WHEEL_RIGHT
                          : (h_notches < 0) ? RFB_BUTTON_WHEEL_LEFT
                                            : 0u;

    for (int32_t i = 0; i < v_abs; i++) {
        rfb_writer wp = rfb_writer_make(out + off, 6u);
        if (rfb_format_pointer_event(&wp, (uint8_t)(held | v_bit), x, y) !=
            RFB_OK) {
            return 0;
        }
        off += 6u;
        rfb_writer wr = rfb_writer_make(out + off, 6u);
        if (rfb_format_pointer_event(&wr, held, x, y) != RFB_OK) {
            return 0;
        }
        off += 6u;
    }
    for (int32_t i = 0; i < h_abs; i++) {
        rfb_writer wp = rfb_writer_make(out + off, 6u);
        if (rfb_format_pointer_event(&wp, (uint8_t)(held | h_bit), x, y) !=
            RFB_OK) {
            return 0;
        }
        off += 6u;
        rfb_writer wr = rfb_writer_make(out + off, 6u);
        if (rfb_format_pointer_event(&wr, held, x, y) != RFB_OK) {
            return 0;
        }
        off += 6u;
    }
    return off;
}

static bool ledger_has_key(const farsee_key_ledger *ledger,
                           farsee_physical_key key)
{
    const size_t count = ledger->count <= FARSEE_KEY_LEDGER_MAX
                             ? ledger->count
                             : FARSEE_KEY_LEDGER_MAX;
    for (size_t i = 0u; i < count; i++) {
        if (ledger->down[i] == key) {
            return true;
        }
    }
    return false;
}

static rfb_error release_ledger_keys(rfb_session *session)
{
    if (session->key_ledger.count > FARSEE_KEY_LEDGER_MAX) {
        session->key_ledger.count = FARSEE_KEY_LEDGER_MAX;
    }
    farsee_physical_key keys[FARSEE_KEY_LEDGER_MAX];
    const size_t count = session->key_ledger.count;
    memcpy(keys, session->key_ledger.down, count * sizeof keys[0]);

    for (size_t i = 0u; i < count; i++) {
        if (keys[i] == 0u) {
            continue;
        }
        uint8_t message[8];
        rfb_writer writer = rfb_writer_make(message, sizeof message);
        rfb_error error =
            rfb_format_key_event(&writer, false, keys[i]);
        if (error != RFB_OK) {
            session->last_error = error;
            return error;
        }
        error = session_queue_bytes(session, message, writer.length);
        if (error != RFB_OK) {
            return error;
        }

        farsee_key_event release;
        memset(&release, 0, sizeof release);
        release.physical = keys[i];
        release.action = FARSEE_KEY_RELEASE;
        (void)farsee_key_ledger_apply(&session->key_ledger, &release);
    }
    return RFB_OK;
}

rfb_error rfb_session_internal_drain_cmds(rfb_session *s)
{
    if (s == NULL) {
        return RFB_ERR_INTERNAL;
    }
    if (s->cfg.cmds == NULL || s->cfg.view_only) {
        return RFB_OK;
    }
    // Use the current monotonic time as the deadline for nonblocking pops.
    const uint64_t now = rfb_io_mono_ms();
    farsee_cmd cmd;
    // Cap commands per tick so a mouse flood cannot starve the socket poll.
    unsigned n = 0;
    while (n < 32u &&
           farsee_cmd_queue_pop(s->cfg.cmds, &cmd, now, s->cfg.stop_flag)) {
        n++;
        uint8_t msg[16];
        rfb_writer w = rfb_writer_make(msg, sizeof msg);
        rfb_error e = RFB_OK;
        size_t ptr_bytes = 0;
        // Up to 4 notches x 2 axes x press+release = 16 messages x 6 bytes.
        uint8_t ptr_buf[6u * 16u];
        // Stash the keysym for a post-queue ledger update after success only.
        bool key_down = false;
        uint32_t key_sym = 0u;
        unsigned pending_buttons = s->held_buttons;
        bool update_buttons = false;
        switch (cmd.kind) {
        case FARSEE_CMD_KEY: {
            key_down = (cmd.key.action != FARSEE_KEY_RELEASE);
            key_sym = cmd.key.logical != 0u ? cmd.key.logical : cmd.key.unicode;
            e = rfb_format_key_event(&w, key_down, key_sym);
            if (e == RFB_OK && key_down && key_sym != 0u &&
                s->key_ledger.count >= FARSEE_KEY_LEDGER_MAX &&
                !ledger_has_key(&s->key_ledger, key_sym)) {
                e = release_ledger_keys(s);
            }
            break;
        }
        case FARSEE_CMD_POINTER: {
            // Wheel can expand to multiple press+release messages. Use a
            // dedicated buffer and cap the drain path at four notches.
            farsee_pointer_event pe = cmd.pe;
            int32_t vn = rfb_session_wheel_notches(pe.wheel_v);
            int32_t hn = rfb_session_wheel_notches(pe.wheel_h);
            if (vn > 4) {
                pe.wheel_v = 4 * 120;
            } else if (vn < -4) {
                pe.wheel_v = -4 * 120;
            }
            if (hn > 4) {
                pe.wheel_h = 4 * 120;
            } else if (hn < -4) {
                pe.wheel_h = -4 * 120;
            }
            ptr_bytes = rfb_session_format_pointer_events(&pe, ptr_buf,
                                                          sizeof ptr_buf);
            if (ptr_bytes == 0u) {
                e = RFB_ERR_INTERNAL;
            } else {
                pending_buttons = pe.buttons;
                update_buttons = true;
            }
            break;
        }
        case FARSEE_CMD_RELEASE_ALL: {
            // Emit key-ups for every tracked key + pointer mask 0.
            // Remove each ledger entry only after its release is admitted.
            e = release_ledger_keys(s);
            if (e != RFB_OK) {
                return e;
            }
            // Mask 0 at the last coordinates. Do not warp to (0,0).
            e = rfb_format_pointer_event(&w, 0, s->last_ptr_x, s->last_ptr_y);
            pending_buttons = 0u;
            update_buttons = true;
            break;
        }
        default:
            continue;
        }
        if (e != RFB_OK) {
            s->last_error = e;
            return e;
        }
        if (cmd.kind == FARSEE_CMD_POINTER && ptr_bytes > 0u && e == RFB_OK) {
            rfb_error queue_error =
                session_queue_bytes(s, ptr_buf, ptr_bytes);
            if (queue_error != RFB_OK) {
                return queue_error;
            }
            if (update_buttons) {
                s->held_buttons = pending_buttons;
            }
            if (cmd.pe.abs_x >= 0 && cmd.pe.abs_x <= 0xFFFF &&
                cmd.pe.abs_y >= 0 && cmd.pe.abs_y <= 0xFFFF) {
                s->last_ptr_x = (uint16_t)cmd.pe.abs_x;
                s->last_ptr_y = (uint16_t)cmd.pe.abs_y;
            }
        } else if (e == RFB_OK) {
            rfb_error queue_error = session_queue_bytes(s, msg, w.length);
            if (queue_error != RFB_OK) {
                return queue_error;
            }
            if (cmd.kind == FARSEE_CMD_KEY && key_sym != 0u) {
                farsee_key_event ke;
                memset(&ke, 0, sizeof ke);
                ke.physical = key_sym;
                ke.logical = key_sym;
                ke.action = key_down ? FARSEE_KEY_PRESS : FARSEE_KEY_RELEASE;
                if (!farsee_key_ledger_apply(&s->key_ledger, &ke)) {
                    s->last_error = RFB_ERR_STATE;
                    return RFB_ERR_STATE;
                }
            }
            if (update_buttons) {
                s->held_buttons = pending_buttons;
            }
        }
    }
    return RFB_OK;
}

void rfb_session_release_held_inputs(rfb_session *s)
{
    if (s == NULL || !s->active || s->cfg.view_only || !s->io_open) {
        return;
    }
    // Snapshot without clearing. Keep ledger entries after an append failure.
    farsee_physical_key keys[FARSEE_KEY_LEDGER_MAX];
    size_t nk = 0;
    if (s->key_ledger.count > FARSEE_KEY_LEDGER_MAX) {
        s->key_ledger.count = FARSEE_KEY_LEDGER_MAX;
    }
    for (size_t i = 0; i < s->key_ledger.count && nk < FARSEE_KEY_LEDGER_MAX;
         i++) {
        if (s->key_ledger.down[i] != 0u) {
            keys[nk++] = s->key_ledger.down[i];
        }
    }
    for (size_t i = 0; i < nk; i++) {
        if (keys[i] == 0u) {
            continue;
        }
        uint8_t msg[8];
        rfb_writer w = rfb_writer_make(msg, sizeof msg);
        if (rfb_format_key_event(&w, false, keys[i]) != RFB_OK) {
            continue;
        }
        // Use the session queue path. It seals records when active.
        if (session_queue_bytes(s, msg, w.length) == RFB_OK) {
            farsee_key_event ke;
            memset(&ke, 0, sizeof ke);
            ke.physical = keys[i];
            ke.action = FARSEE_KEY_RELEASE;
            (void)farsee_key_ledger_apply(&s->key_ledger, &ke);
        }
    }
    if (s->held_buttons != 0u || nk > 0u) {
        // Mask 0 at the last coordinates. Do not warp to (0,0).
        uint8_t msg[8];
        rfb_writer w = rfb_writer_make(msg, sizeof msg);
        if (rfb_format_pointer_event(&w, 0, s->last_ptr_x, s->last_ptr_y) ==
                RFB_OK &&
            session_queue_bytes(s, msg, w.length) == RFB_OK) {
            s->held_buttons = 0u;
        }
    }
    rfb_session_internal_flush_output(s, 200);
}
