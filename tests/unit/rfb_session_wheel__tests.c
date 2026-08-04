// SPDX-License-Identifier: Apache-2.0
//
// T25 — RFB wheel: press then release per notch; horizontal buttons 6/7.
// Pure encoder tests (no session I/O).
// Also T5 key-up / mask-0 wire format for release-held path.

#include "rfb_test.h"
#include "farsee/rfb_session.h"
#include "farsee/farsee_input.h"
#include "farsee/input.h"
#include "farsee/bytes.h"
#include "farsee/error.h"

#include <string.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <errno.h>

// multi-review 2026-07-31 T5: real release_held_inputs path → wire bytes.
// Seeds held key + buttons on an active session over socketpair; release
// must emit KeyEvent(up) + PointerEvent(mask=0). Would fail if release
// path were deleted.
RFB_TEST(session_wheel, release_held_inputs__writes_keyup_and_mask0_on_wire)
{
    int sp[2];
    RFB_CHECK_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, sp), 0);

    unsigned char storage[16384];
    RFB_CHECK(rfb_session_size() <= sizeof storage);
    rfb_session *s = (rfb_session *)(void *)storage;
    rfb_session_clear(s);
    RFB_CHECK(rfb_session_test_attach_connected_fd(s, sp[0]));

    // Hold keysym 'a' and left button as if inject succeeded.
    rfb_session_test_seed_held_key(s, 0x61u);
    rfb_session_test_seed_held_buttons(s, 1u);

    rfb_session_release_held_inputs(s);

    // Nonblocking peer read with short budget (never hang the suite).
    {
        int fl = fcntl(sp[1], F_GETFL, 0);
        RFB_CHECK(fl >= 0);
        RFB_CHECK(fcntl(sp[1], F_SETFL, fl | O_NONBLOCK) == 0);
    }
    uint8_t buf[64];
    memset(buf, 0, sizeof buf);
    size_t got = 0;
    for (int i = 0; i < 50 && got < sizeof buf; i++) {
        ssize_t r = recv(sp[1], buf + got, sizeof buf - got, 0);
        if (r > 0) {
            got += (size_t)r;
            if (got >= 8u + 6u) {
                break; // key(8) + ptr(6)
            }
            continue;
        }
        if (r == 0) {
            break;
        }
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            break;
        }
        { struct timespec ts = {0, 2000 * 1000}; (void)nanosleep(&ts, NULL); }
    }
    RFB_CHECK(got >= 14u);

    // Find KeyEvent type=4 down=0 keysym=0x61 and PointerEvent type=5 mask=0.
    bool saw_key_up = false;
    bool saw_mask0 = false;
    for (size_t i = 0; i + 8u <= got; i++) {
        if (buf[i] == 4u && buf[i + 1] == 0u && buf[i + 7] == 0x61u &&
            buf[i + 4] == 0u && buf[i + 5] == 0u && buf[i + 6] == 0u) {
            saw_key_up = true;
        }
    }
    for (size_t i = 0; i + 6u <= got; i++) {
        if (buf[i] == 5u && buf[i + 1] == 0u) {
            saw_mask0 = true;
        }
    }
    RFB_CHECK(saw_key_up);
    RFB_CHECK(saw_mask0);

    // Second release is idempotent (no crash; ledger empty).
    rfb_session_release_held_inputs(s);

    rfb_session_destroy(s); // closes sp[0]
    close(sp[1]);
}

// −: inactive session must not write (no attach).
RFB_TEST(session_wheel, release_held_inputs__inactive__no_wire)
{
    int sp[2];
    RFB_CHECK_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, sp), 0);
    unsigned char storage[8192];
    RFB_CHECK(rfb_session_size() <= sizeof storage);
    rfb_session *s = (rfb_session *)(void *)storage;
    rfb_session_clear(s);
    rfb_session_test_seed_held_key(s, 0x61u); // ignored: not active
    rfb_session_release_held_inputs(s);
    uint8_t b = 0;
    ssize_t r = recv(sp[1], &b, 1, MSG_DONTWAIT);
    RFB_CHECK(r <= 0); // nothing on the wire
    close(sp[0]);
    close(sp[1]);
    rfb_session_destroy(s);
}

static void check_ptr_msg(const uint8_t *m, uint8_t mask, uint16_t x, uint16_t y)
{
    RFB_CHECK_EQ_UINT(m[0], 5u);  // PointerEvent
    RFB_CHECK_EQ_UINT(m[1], mask);
    RFB_CHECK_EQ_UINT(m[2], (uint8_t)((x >> 8) & 0xffu));
    RFB_CHECK_EQ_UINT(m[3], (uint8_t)(x & 0xffu));
    RFB_CHECK_EQ_UINT(m[4], (uint8_t)((y >> 8) & 0xffu));
    RFB_CHECK_EQ_UINT(m[5], (uint8_t)(y & 0xffu));
}

// Motion / held buttons only: single message, no wheel bits.
RFB_TEST(session_wheel, motion_only__single_message)
{
    farsee_pointer_event pe;
    memset(&pe, 0, sizeof pe);
    pe.abs_x = 10;
    pe.abs_y = 20;
    pe.buttons = FARSEE_BUTTON_LEFT;
    uint8_t out[64];
    size_t n = rfb_session_format_pointer_events(&pe, out, sizeof out);
    RFB_CHECK_EQ_UINT(n, 6u);
    check_ptr_msg(out, RFB_BUTTON_LEFT, 10, 20);
}

// + one vertical notch up → press (bit3) then release
RFB_TEST(session_wheel, vertical_up_one_notch__press_then_release)
{
    farsee_pointer_event pe;
    memset(&pe, 0, sizeof pe);
    pe.abs_x = 5;
    pe.abs_y = 6;
    pe.wheel_v = 120;
    uint8_t out[64];
    size_t n = rfb_session_format_pointer_events(&pe, out, sizeof out);
    RFB_CHECK_EQ_UINT(n, 12u);
    check_ptr_msg(out, RFB_BUTTON_WHEEL_UP, 5, 6);
    check_ptr_msg(out + 6, 0u, 5, 6);
}

// + multi-notch down
RFB_TEST(session_wheel, vertical_down_three_notches__six_messages)
{
    farsee_pointer_event pe;
    memset(&pe, 0, sizeof pe);
    pe.abs_x = 1;
    pe.abs_y = 2;
    pe.wheel_v = -360;  // 3 notches down
    uint8_t out[64];
    size_t n = rfb_session_format_pointer_events(&pe, out, sizeof out);
    RFB_CHECK_EQ_UINT(n, 36u);
    for (int i = 0; i < 3; i++) {
        check_ptr_msg(out + (size_t)i * 12u, RFB_BUTTON_WHEEL_DN, 1, 2);
        check_ptr_msg(out + (size_t)i * 12u + 6u, 0u, 1, 2);
    }
}

// + held left button preserved across wheel press/release
RFB_TEST(session_wheel, held_left_plus_wheel__preserves_button)
{
    farsee_pointer_event pe;
    memset(&pe, 0, sizeof pe);
    pe.abs_x = 100;
    pe.abs_y = 200;
    pe.buttons = FARSEE_BUTTON_LEFT;
    pe.wheel_v = 120;
    uint8_t out[64];
    size_t n = rfb_session_format_pointer_events(&pe, out, sizeof out);
    RFB_CHECK_EQ_UINT(n, 12u);
    check_ptr_msg(out,
                  (uint8_t)(RFB_BUTTON_LEFT | RFB_BUTTON_WHEEL_UP), 100, 200);
    check_ptr_msg(out + 6, RFB_BUTTON_LEFT, 100, 200);
}

// + horizontal right / left (buttons 7 / 6)
RFB_TEST(session_wheel, horizontal_right_one_notch__press_release)
{
    farsee_pointer_event pe;
    memset(&pe, 0, sizeof pe);
    pe.abs_x = 3;
    pe.abs_y = 4;
    pe.wheel_h = 120;
    uint8_t out[64];
    size_t n = rfb_session_format_pointer_events(&pe, out, sizeof out);
    RFB_CHECK_EQ_UINT(n, 12u);
    check_ptr_msg(out, RFB_BUTTON_WHEEL_RIGHT, 3, 4);
    check_ptr_msg(out + 6, 0u, 3, 4);
}

RFB_TEST(session_wheel, horizontal_left_one_notch__press_release)
{
    farsee_pointer_event pe;
    memset(&pe, 0, sizeof pe);
    pe.abs_x = 3;
    pe.abs_y = 4;
    pe.wheel_h = -120;
    uint8_t out[64];
    size_t n = rfb_session_format_pointer_events(&pe, out, sizeof out);
    RFB_CHECK_EQ_UINT(n, 12u);
    check_ptr_msg(out, RFB_BUTTON_WHEEL_LEFT, 3, 4);
    check_ptr_msg(out + 6, 0u, 3, 4);
}

// Direction change in one event: vertical then horizontal
RFB_TEST(session_wheel, vertical_and_horizontal__both_axes)
{
    farsee_pointer_event pe;
    memset(&pe, 0, sizeof pe);
    pe.abs_x = 0;
    pe.abs_y = 0;
    pe.wheel_v = 120;
    pe.wheel_h = -120;
    uint8_t out[64];
    size_t n = rfb_session_format_pointer_events(&pe, out, sizeof out);
    RFB_CHECK_EQ_UINT(n, 24u);
    check_ptr_msg(out, RFB_BUTTON_WHEEL_UP, 0, 0);
    check_ptr_msg(out + 6, 0u, 0, 0);
    check_ptr_msg(out + 12, RFB_BUTTON_WHEEL_LEFT, 0, 0);
    check_ptr_msg(out + 18, 0u, 0, 0);
}

// − sub-notch high-res does not emit wheel
RFB_TEST(session_wheel, sub_notch_delta__motion_only)
{
    farsee_pointer_event pe;
    memset(&pe, 0, sizeof pe);
    pe.abs_x = 1;
    pe.abs_y = 1;
    pe.wheel_v = 119;
    pe.wheel_h = -119;
    uint8_t out[64];
    size_t n = rfb_session_format_pointer_events(&pe, out, sizeof out);
    RFB_CHECK_EQ_UINT(n, 6u);
    check_ptr_msg(out, 0u, 1, 1);
}

// − null / undersized out
RFB_TEST(session_wheel, null_or_small_out__returns_zero)
{
    farsee_pointer_event pe;
    memset(&pe, 0, sizeof pe);
    pe.wheel_v = 120;
    uint8_t out[4];
    RFB_CHECK_EQ_UINT(rfb_session_format_pointer_events(NULL, out, 64), 0u);
    RFB_CHECK_EQ_UINT(rfb_session_format_pointer_events(&pe, NULL, 64), 0u);
    RFB_CHECK_EQ_UINT(rfb_session_format_pointer_events(&pe, out, sizeof out),
                      0u);
}
