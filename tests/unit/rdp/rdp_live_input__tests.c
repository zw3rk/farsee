// SPDX-License-Identifier: Apache-2.0
//
// Private RDP live input-owner boundary tests.

#ifdef FARSEE_WITH_RDP

#include "app/rdp_live_input_internal.h"
#include "farsee/normalized_input.h"
#include "farsee/socket_posix.h"
#include "tests/test_framework/rfb_test.h"

#include <freerdp/freerdp.h>
#include <freerdp/input.h>

#include <errno.h>
#include <poll.h>
#include <string.h>
#include <unistd.h>

#define INPUT_FAKE_STEP_CAP 8u
#define INPUT_FAKE_DATA_CAP 16u

typedef struct input_poll_step {
    int result;
    short revents;
    int error_number;
    bool request_stop;
} input_poll_step;

typedef struct input_read_step {
    ssize_t result;
    int error_number;
    uint8_t data[INPUT_FAKE_DATA_CAP];
} input_read_step;

typedef struct input_fake {
    uint64_t now_ms;
    uint64_t monotonic_step_ms;
    bool probe_ok;
    uint16_t cols;
    uint16_t rows;
    uint16_t pixel_width;
    uint16_t pixel_height;
    farsee_atomic_int *stop;
    input_poll_step polls[INPUT_FAKE_STEP_CAP];
    size_t poll_count;
    size_t poll_index;
    input_read_step reads[INPUT_FAKE_STEP_CAP];
    size_t read_count;
    size_t read_index;
    unsigned probe_calls;
    unsigned refresh_calls;
    unsigned draw_calls;
    unsigned poll_calls;
    unsigned read_calls;
    int last_poll_fd;
    int last_poll_timeout_ms;
} input_fake;

typedef struct input_fixture {
    rdp_live_tick tick;
    rdp_inj_queue queue;
    farsee_atomic_int process_stop;
    farsee_atomic_int worker_stop;
    farsee_mt_terminal terminal;
    input_fake fake;
    rdp_live_input_ops ops;
} input_fixture;

static uint64_t input_fake_monotonic_ms(void *user)
{
    input_fake *fake = (input_fake *)user;
    RFB_CHECK(fake != NULL);
    if (fake == NULL) {
        return 0u;
    }
    const uint64_t now_ms = fake->now_ms;
    fake->now_ms += fake->monotonic_step_ms;
    return now_ms;
}

static bool input_fake_probe_winsize(
    void *user, int fd, uint16_t *cols, uint16_t *rows,
    uint16_t *pixel_width, uint16_t *pixel_height)
{
    input_fake *fake = (input_fake *)user;
    RFB_CHECK(fake != NULL);
    RFB_CHECK(fd == 17 || fd == -1);
    if (fake == NULL) {
        return false;
    }
    fake->probe_calls++;
    if (!fake->probe_ok) {
        return false;
    }
    RFB_CHECK(cols != NULL);
    RFB_CHECK(rows != NULL);
    RFB_CHECK(pixel_width != NULL);
    RFB_CHECK(pixel_height != NULL);
    if (cols == NULL || rows == NULL || pixel_width == NULL ||
        pixel_height == NULL) {
        return false;
    }
    *cols = fake->cols;
    *rows = fake->rows;
    *pixel_width = fake->pixel_width;
    *pixel_height = fake->pixel_height;
    return true;
}

static bool input_fake_refresh_layout(void *user, farsee_live_shell *shell,
                                      bool apply_kitty)
{
    input_fake *fake = (input_fake *)user;
    RFB_CHECK(fake != NULL);
    RFB_CHECK(shell != NULL);
    RFB_CHECK(apply_kitty);
    if (fake == NULL) {
        return false;
    }
    fake->refresh_calls++;
    return true;
}

static void input_fake_draw_status(void *user, farsee_live_shell *shell)
{
    input_fake *fake = (input_fake *)user;
    RFB_CHECK(fake != NULL);
    RFB_CHECK(shell != NULL);
    if (fake != NULL) {
        fake->draw_calls++;
    }
}

static int input_fake_poll(void *user, int fd, int timeout_ms,
                           short *out_revents, int *out_error)
{
    input_fake *fake = (input_fake *)user;
    RFB_CHECK(fake != NULL);
    RFB_CHECK(out_revents != NULL);
    RFB_CHECK(out_error != NULL);
    if (fake == NULL || out_revents == NULL || out_error == NULL) {
        return -1;
    }
    fake->poll_calls++;
    fake->last_poll_fd = fd;
    fake->last_poll_timeout_ms = timeout_ms;
    if (fake->poll_index >= fake->poll_count) {
        RFB_FAIL("input fake poll script exhausted");
        if (fake->stop != NULL) {
            farsee_atomic_int_store(fake->stop, 1);
        }
        *out_revents = 0;
        *out_error = 0;
        return 0;
    }
    const input_poll_step step = fake->polls[fake->poll_index++];
    *out_revents = step.revents;
    *out_error = step.error_number;
    if (step.request_stop && fake->stop != NULL) {
        farsee_atomic_int_store(fake->stop, 1);
    }
    return step.result;
}

static ssize_t input_fake_read(void *user, int fd, uint8_t *buffer,
                               size_t capacity, int *out_error)
{
    input_fake *fake = (input_fake *)user;
    RFB_CHECK(fake != NULL);
    RFB_CHECK_EQ_INT(fd, 17);
    RFB_CHECK(buffer != NULL);
    RFB_CHECK(out_error != NULL);
    if (fake == NULL || buffer == NULL || out_error == NULL) {
        return -1;
    }
    fake->read_calls++;
    if (fake->read_index >= fake->read_count) {
        RFB_FAIL("input fake read script exhausted");
        *out_error = EIO;
        return -1;
    }
    const input_read_step *step = &fake->reads[fake->read_index++];
    *out_error = step->error_number;
    if (step->result > 0) {
        RFB_CHECK((size_t)step->result <= capacity);
        RFB_CHECK((size_t)step->result <= sizeof step->data);
        if ((size_t)step->result > capacity ||
            (size_t)step->result > sizeof step->data) {
            return -1;
        }
        memcpy(buffer, step->data, (size_t)step->result);
    }
    return step->result;
}

static bool input_fixture_init(input_fixture *fixture)
{
    if (fixture == NULL) {
        return false;
    }
    memset(fixture, 0, sizeof *fixture);
    if (!rdp_inj_queue_init(&fixture->queue)) {
        return false;
    }
    farsee_live_shell_init(&fixture->tick.shell, NULL, 1u);
    fixture->tick.shell.tty_fd = 17;
    farsee_modifier_synth_init(&fixture->tick.synth_mods);
    farsee_atomic_int_store(&fixture->process_stop, 0);
    farsee_atomic_int_store(&fixture->worker_stop, 0);
    fixture->tick.process_stop = &fixture->process_stop;
    farsee_mt_terminal_init(&fixture->terminal);
    fixture->fake.now_ms = 1000u;
    fixture->fake.stop = &fixture->worker_stop;
    fixture->ops.user = &fixture->fake;
    fixture->ops.monotonic_ms = input_fake_monotonic_ms;
    fixture->ops.probe_winsize = input_fake_probe_winsize;
    fixture->ops.refresh_layout = input_fake_refresh_layout;
    fixture->ops.draw_status = input_fake_draw_status;
    fixture->ops.poll_input = input_fake_poll;
    fixture->ops.read_input = input_fake_read;
    return true;
}

static void input_fixture_reset_run(input_fixture *fixture)
{
    farsee_atomic_int_store(&fixture->worker_stop, 0);
    farsee_mt_terminal_init(&fixture->terminal);
}

static farsee_mt_terminal_kind input_fixture_run(input_fixture *fixture)
{
    return rdp_live_input_run(
        &fixture->tick, &fixture->queue, &fixture->worker_stop,
        &fixture->terminal, &fixture->ops);
}

static void input_fixture_destroy(input_fixture *fixture)
{
    rdp_inj_queue_destroy(&fixture->queue);
}

typedef struct direct_input_fixture {
    rdp_freerdp_ctx *ctx;
    rdpInput *input;
    void *saved_param1;
    pKeyboardEvent saved_keyboard;
    pMouseEvent saved_mouse;
    unsigned keyboard_calls;
    unsigned mouse_calls;
    bool keyboard_ok;
    bool mouse_ok;
    UINT16 last_mouse_flags;
    UINT16 last_mouse_x;
    UINT16 last_mouse_y;
} direct_input_fixture;

static direct_input_fixture *direct_input_from(rdpInput *input)
{
    return input != NULL ? (direct_input_fixture *)input->param1 : NULL;
}

static BOOL direct_input_keyboard(rdpInput *input, UINT16 flags, UINT8 code)
{
    (void)flags;
    (void)code;
    direct_input_fixture *fixture = direct_input_from(input);
    if (fixture == NULL) {
        return FALSE;
    }
    fixture->keyboard_calls++;
    return fixture->keyboard_ok ? TRUE : FALSE;
}

static BOOL direct_input_mouse(rdpInput *input, UINT16 flags,
                               UINT16 x, UINT16 y)
{
    direct_input_fixture *fixture = direct_input_from(input);
    if (fixture == NULL) {
        return FALSE;
    }
    fixture->mouse_calls++;
    fixture->last_mouse_flags = flags;
    fixture->last_mouse_x = x;
    fixture->last_mouse_y = y;
    return fixture->mouse_ok ? TRUE : FALSE;
}

static bool direct_input_fixture_init(direct_input_fixture *fixture)
{
    if (fixture == NULL) {
        return false;
    }
    memset(fixture, 0, sizeof *fixture);
    fixture->ctx = rdp_freerdp_create();
    if (fixture->ctx == NULL) {
        return false;
    }
    freerdp *instance =
        (freerdp *)rdp_freerdp_instance_opaque(fixture->ctx);
    if (instance == NULL || instance->context == NULL ||
        instance->context->input == NULL) {
        rdp_freerdp_destroy(&fixture->ctx);
        return false;
    }
    fixture->input = instance->context->input;
    fixture->saved_param1 = fixture->input->param1;
    fixture->saved_keyboard = fixture->input->KeyboardEvent;
    fixture->saved_mouse = fixture->input->MouseEvent;
    fixture->keyboard_ok = true;
    fixture->mouse_ok = true;
    fixture->input->param1 = fixture;
    fixture->input->KeyboardEvent = direct_input_keyboard;
    fixture->input->MouseEvent = direct_input_mouse;
    return true;
}

static void direct_input_fixture_destroy(direct_input_fixture *fixture)
{
    if (fixture == NULL || fixture->ctx == NULL) {
        return;
    }
    fixture->input->param1 = fixture->saved_param1;
    fixture->input->KeyboardEvent = fixture->saved_keyboard;
    fixture->input->MouseEvent = fixture->saved_mouse;
    rdp_freerdp_destroy(&fixture->ctx);
}

RFB_TEST(rdp_live_input, pointer_accept__queues_exact_state_and_quit_stops)
{
    rdp_inj_queue queue;
    if (!rdp_inj_queue_init(&queue)) {
        RFB_CHECK(false);
        return;
    }

    rdp_live_tick tick;
    memset(&tick, 0, sizeof tick);
    rdp_display_sink sink;
    rdp_display_sink_init(&sink);
    farsee_atomic_int process_stop;
    farsee_atomic_int_store(&process_stop, 0);
    tick.inj = &queue;
    tick.sink = &sink;
    tick.process_stop = &process_stop;
    tick.prev_buttons = 1u;
    rdp_live_bind_shell_ops(&tick);

    RFB_CHECK(tick.shell.ops == &tick.shell_ops);
    RFB_CHECK(tick.shell.ops_user == &tick);
    RFB_CHECK(tick.shell.ops->inject_pointer(
        tick.shell.ops_user, 23, 47, 5u, -120, 120));

    rdp_inj_cmd command;
    memset(&command, 0, sizeof command);
    RFB_CHECK(rdp_inj_queue_pop(
        &queue, &command, farsee_thread_monotonic_ms(), NULL));
    RFB_CHECK(command.kind == RDP_INJ_POINTER);
    RFB_CHECK_EQ_INT(command.pe.abs_x, 23);
    RFB_CHECK_EQ_INT(command.pe.abs_y, 47);
    RFB_CHECK_EQ_INT(command.pe.wheel_v, -120);
    RFB_CHECK_EQ_INT(command.pe.wheel_h, 120);
    RFB_CHECK_EQ_UINT(command.pe.buttons, 5u);
    RFB_CHECK_EQ_UINT(command.prev_buttons, 1u);
    RFB_CHECK_EQ_UINT(tick.prev_buttons, 5u);
    RFB_CHECK_EQ_INT(farsee_atomic_int_load(&sink.cursor_x), 23);
    RFB_CHECK_EQ_INT(farsee_atomic_int_load(&sink.cursor_y), 47);
    RFB_CHECK_EQ_INT(farsee_atomic_int_load(&sink.cursor_visible), 1);

    tick.shell.ops->request_quit(tick.shell.ops_user);
    RFB_CHECK(farsee_atomic_int_load_nonzero(&process_stop));
    rdp_inj_queue_destroy(&queue);
}

RFB_TEST(rdp_live_input, full_queue__rejects_pointer_without_advancing_state)
{
    rdp_inj_queue queue;
    if (!rdp_inj_queue_init(&queue)) {
        RFB_CHECK(false);
        return;
    }
    for (size_t i = 0u; i < RDP_INJ_QUEUE_CAP; i++) {
        rdp_inj_cmd key;
        memset(&key, 0, sizeof key);
        key.kind = RDP_INJ_KEY;
        key.keysym = (uint32_t)('a' + (i % 26u));
        key.down = true;
        RFB_CHECK(rdp_inj_queue_push(&queue, &key));
    }

    rdp_live_tick tick;
    memset(&tick, 0, sizeof tick);
    tick.inj = &queue;
    tick.prev_buttons = 4u;
    rdp_live_bind_shell_ops(&tick);

    RFB_CHECK(!tick.shell.ops->inject_pointer(
        tick.shell.ops_user, 8, 9, 1u, 0, 0));
    RFB_CHECK_EQ_UINT(tick.prev_buttons, 4u);
    rdp_inj_queue_destroy(&queue);
}

RFB_TEST(rdp_live_input,
         direct_input__updates_ledger_pointer_and_overflow_recovery)
{
    direct_input_fixture fixture;
    if (!direct_input_fixture_init(&fixture)) {
        RFB_FAIL("cannot initialize direct FreeRDP input fixture");
        return;
    }
    rdp_live_tick tick;
    memset(&tick, 0, sizeof tick);
    farsee_live_shell_init(&tick.shell, NULL, 1u);
    farsee_modifier_synth_init(&tick.synth_mods);
    farsee_key_ledger_init(&tick.ledger);
    rdp_display_sink sink;
    rdp_display_sink_init(&sink);
    tick.ctx = fixture.ctx;
    tick.sink = &sink;
    rdp_live_bind_shell_ops(&tick);

    rfb_norm_key key = {
        .keysym = (uint32_t)'a',
        .text = (uint32_t)'a',
        .down = true,
        .source = RFB_NORM_SOURCE_KITTY,
    };
    const unsigned before_press = fixture.keyboard_calls;
    tick.shell.ops->inject_key(tick.shell.ops_user, &key);
    RFB_CHECK(fixture.keyboard_calls > before_press);
    RFB_CHECK_EQ_UINT(tick.ledger.count, 1u);
    key.down = false;
    const unsigned before_release = fixture.keyboard_calls;
    tick.shell.ops->inject_key(tick.shell.ops_user, &key);
    RFB_CHECK(fixture.keyboard_calls > before_release);
    RFB_CHECK_EQ_UINT(tick.ledger.count, 0u);

    for (size_t i = 0u; i < FARSEE_KEY_LEDGER_MAX; i++) {
        tick.ledger.down[i] = (farsee_physical_key)(0x1000u + i);
    }
    tick.ledger.count = FARSEE_KEY_LEDGER_MAX;
    key.keysym = (uint32_t)'b';
    key.text = (uint32_t)'b';
    key.down = true;
    const unsigned before_overflow = fixture.keyboard_calls;
    tick.shell.ops->inject_key(tick.shell.ops_user, &key);
    RFB_CHECK(fixture.keyboard_calls >=
              before_overflow + FARSEE_KEY_LEDGER_MAX + 1u);
    RFB_CHECK_EQ_UINT(tick.ledger.count, 1u);
    key.down = false;
    tick.shell.ops->inject_key(tick.shell.ops_user, &key);
    RFB_CHECK_EQ_UINT(tick.ledger.count, 0u);

    RFB_CHECK(tick.shell.ops->inject_pointer(
        tick.shell.ops_user, 23, 47, FARSEE_BUTTON_LEFT, 0, 0));
    RFB_CHECK_EQ_UINT(fixture.mouse_calls, 2u);
    RFB_CHECK_EQ_UINT(tick.prev_buttons, FARSEE_BUTTON_LEFT);
    RFB_CHECK_EQ_UINT(fixture.last_mouse_x, 23u);
    RFB_CHECK_EQ_UINT(fixture.last_mouse_y, 47u);
    RFB_CHECK_EQ_INT(farsee_atomic_int_load(&sink.cursor_x), 23);
    RFB_CHECK_EQ_INT(farsee_atomic_int_load(&sink.cursor_y), 47);

    fixture.mouse_ok = false;
    RFB_CHECK(!tick.shell.ops->inject_pointer(
        tick.shell.ops_user, -1, -1, 0u, 0, 0));
    RFB_CHECK_EQ_UINT(tick.prev_buttons, FARSEE_BUTTON_LEFT);
    fixture.mouse_ok = true;
    RFB_CHECK(tick.shell.ops->inject_pointer(
        tick.shell.ops_user, -1, -1, 0u, 0, 0));
    RFB_CHECK_EQ_UINT(tick.prev_buttons, 0u);

    direct_input_fixture_destroy(&fixture);
}

RFB_TEST(rdp_live_input,
         direct_key_failure__distinguishes_recovery_from_required_stop)
{
    direct_input_fixture fixture;
    if (!direct_input_fixture_init(&fixture)) {
        RFB_FAIL("cannot initialize direct FreeRDP input fixture");
        return;
    }
    rdp_live_tick tick;
    memset(&tick, 0, sizeof tick);
    farsee_live_shell_init(&tick.shell, NULL, 1u);
    farsee_modifier_synth_init(&tick.synth_mods);
    farsee_key_ledger_init(&tick.ledger);
    farsee_atomic_int process_stop;
    farsee_atomic_int_store(&process_stop, 0);
    tick.process_stop = &process_stop;
    tick.ctx = fixture.ctx;
    rdp_live_bind_shell_ops(&tick);
    fixture.keyboard_ok = false;

    rfb_norm_key key = {
        .keysym = (uint32_t)'x',
        .text = (uint32_t)'x',
        .down = true,
        .source = RFB_NORM_SOURCE_LEGACY,
    };
    tick.shell.ops->inject_key(tick.shell.ops_user, &key);
    RFB_CHECK(!farsee_atomic_int_load_nonzero(&process_stop));
    RFB_CHECK(!farsee_modifier_synth_requires_stop(&tick.synth_mods));

    farsee_modifier_synth_init(&tick.synth_mods);
    key.keysym = XK_Shift_L;
    key.text = 0u;
    tick.shell.ops->inject_key(tick.shell.ops_user, &key);
    RFB_CHECK(farsee_atomic_int_load_nonzero(&process_stop));
    RFB_CHECK(farsee_modifier_synth_requires_stop(&tick.synth_mods));
    RFB_CHECK_EQ_UINT(fixture.keyboard_calls, 2u);

    direct_input_fixture_destroy(&fixture);
}

RFB_TEST(rdp_live_input, closed_input__reports_failure_and_releases_queue)
{
    int pfd[2];
    if (pipe(pfd) != 0) {
        RFB_CHECK(false);
        return;
    }
    close(pfd[1]);

    rdp_inj_queue queue;
    if (!rdp_inj_queue_init(&queue)) {
        RFB_CHECK(false);
        close(pfd[0]);
        return;
    }
    rdp_live_tick tick;
    memset(&tick, 0, sizeof tick);
    tick.shell.tty_fd = pfd[0];
    farsee_atomic_int process_stop;
    farsee_atomic_int worker_stop;
    farsee_atomic_int_store(&process_stop, 0);
    farsee_atomic_int_store(&worker_stop, 0);
    tick.process_stop = &process_stop;
    farsee_mt_terminal terminal;
    farsee_mt_terminal_init(&terminal);

    RFB_CHECK(rdp_live_input_fn(
                  &tick, &queue, &worker_stop, &terminal) ==
              FARSEE_MT_TERMINAL_INPUT_FAILURE);
    RFB_CHECK(farsee_mt_terminal_load(&terminal) ==
              FARSEE_MT_TERMINAL_INPUT_FAILURE);
    RFB_CHECK(tick.inj == NULL);

    rdp_inj_queue_destroy(&queue);
    close(pfd[0]);
}

RFB_TEST(rdp_live_input,
         incomplete_private_ops__fail_closed_without_claiming_queue)
{
    input_fixture fixture;
    if (!input_fixture_init(&fixture)) {
        RFB_CHECK(false);
        return;
    }

    rdp_live_input_ops incomplete = fixture.ops;
    incomplete.read_input = NULL;
    RFB_CHECK(rdp_live_input_run(
                  &fixture.tick, &fixture.queue, &fixture.worker_stop,
                  &fixture.terminal, &incomplete) ==
              FARSEE_MT_TERMINAL_INTERNAL_FAILURE);
    RFB_CHECK(farsee_mt_terminal_load(&fixture.terminal) ==
              FARSEE_MT_TERMINAL_INTERNAL_FAILURE);
    RFB_CHECK(fixture.tick.inj == NULL);
    RFB_CHECK_EQ_UINT(fixture.fake.poll_calls, 0u);

    input_fixture_destroy(&fixture);
}

RFB_TEST(rdp_live_input,
         each_private_dependency__fails_before_claiming_input)
{
    input_fixture fixture;
    if (!input_fixture_init(&fixture)) {
        RFB_CHECK(false);
        return;
    }

    RFB_CHECK(rdp_live_input_run(
                  NULL, &fixture.queue, &fixture.worker_stop,
                  &fixture.terminal, &fixture.ops) ==
              FARSEE_MT_TERMINAL_INTERNAL_FAILURE);
    RFB_CHECK(rdp_live_input_run(
                  &fixture.tick, &fixture.queue, &fixture.worker_stop,
                  &fixture.terminal, NULL) ==
              FARSEE_MT_TERMINAL_INTERNAL_FAILURE);

    rdp_live_input_ops incomplete = fixture.ops;
    incomplete.monotonic_ms = NULL;
    RFB_CHECK(rdp_live_input_run(
                  &fixture.tick, &fixture.queue, &fixture.worker_stop,
                  &fixture.terminal, &incomplete) ==
              FARSEE_MT_TERMINAL_INTERNAL_FAILURE);
    incomplete = fixture.ops;
    incomplete.probe_winsize = NULL;
    RFB_CHECK(rdp_live_input_run(
                  &fixture.tick, &fixture.queue, &fixture.worker_stop,
                  &fixture.terminal, &incomplete) ==
              FARSEE_MT_TERMINAL_INTERNAL_FAILURE);
    incomplete = fixture.ops;
    incomplete.refresh_layout = NULL;
    RFB_CHECK(rdp_live_input_run(
                  &fixture.tick, &fixture.queue, &fixture.worker_stop,
                  &fixture.terminal, &incomplete) ==
              FARSEE_MT_TERMINAL_INTERNAL_FAILURE);
    incomplete = fixture.ops;
    incomplete.draw_status = NULL;
    RFB_CHECK(rdp_live_input_run(
                  &fixture.tick, &fixture.queue, &fixture.worker_stop,
                  &fixture.terminal, &incomplete) ==
              FARSEE_MT_TERMINAL_INTERNAL_FAILURE);
    incomplete = fixture.ops;
    incomplete.poll_input = NULL;
    RFB_CHECK(rdp_live_input_run(
                  &fixture.tick, &fixture.queue, &fixture.worker_stop,
                  &fixture.terminal, &incomplete) ==
              FARSEE_MT_TERMINAL_INTERNAL_FAILURE);

    RFB_CHECK(fixture.tick.inj == NULL);
    RFB_CHECK_EQ_UINT(fixture.fake.poll_calls, 0u);
    input_fixture_destroy(&fixture);
}

RFB_TEST(rdp_live_input,
         repeated_sessions__resample_winsize_and_status_independently)
{
    input_fixture fixture;
    if (!input_fixture_init(&fixture)) {
        RFB_CHECK(false);
        return;
    }
    fixture.tick.shell.layout_active = true;
    fixture.fake.probe_ok = true;
    fixture.fake.cols = 120u;
    fixture.fake.rows = 40u;
    fixture.fake.pixel_width = 1200u;
    fixture.fake.pixel_height = 800u;
    fixture.fake.polls[0].request_stop = true;
    fixture.fake.polls[1].request_stop = true;
    fixture.fake.poll_count = 2u;

    RFB_CHECK(input_fixture_run(&fixture) ==
              FARSEE_MT_TERMINAL_REQUESTED_STOP);
    RFB_CHECK_EQ_UINT(fixture.fake.probe_calls, 1u);
    RFB_CHECK_EQ_UINT(fixture.fake.refresh_calls, 1u);
    RFB_CHECK_EQ_UINT(fixture.fake.draw_calls, 2u);
    RFB_CHECK_EQ_UINT(fixture.tick.shell.term_cols, 120u);
    RFB_CHECK_EQ_UINT(fixture.tick.shell.term_rows, 40u);
    RFB_CHECK_EQ_UINT(fixture.tick.shell.term_pw, 1200u);
    RFB_CHECK_EQ_UINT(fixture.tick.shell.term_ph, 800u);

    input_fixture_reset_run(&fixture);
    RFB_CHECK(input_fixture_run(&fixture) ==
              FARSEE_MT_TERMINAL_REQUESTED_STOP);
    RFB_CHECK_EQ_UINT(fixture.fake.probe_calls, 2u);
    RFB_CHECK_EQ_UINT(fixture.fake.refresh_calls, 1u);
    RFB_CHECK_EQ_UINT(fixture.fake.draw_calls, 3u);
    RFB_CHECK(fixture.tick.inj == NULL);

    input_fixture_destroy(&fixture);
}

RFB_TEST(rdp_live_input,
         geometry_sampling__each_noncolumn_change_refreshes_layout)
{
    for (unsigned changed = 0u; changed < 3u; changed++) {
        input_fixture fixture;
        if (!input_fixture_init(&fixture)) {
            RFB_FAIL("cannot initialize input fixture");
            return;
        }
        fixture.tick.shell.layout_active = true;
        farsee_live_shell_set_term_geom(
            &fixture.tick.shell, 80u, 24u, 800u, 600u);
        fixture.fake.probe_ok = true;
        fixture.fake.cols = 80u;
        fixture.fake.rows = changed == 0u ? 25u : 24u;
        fixture.fake.pixel_width = changed == 1u ? 801u : 800u;
        fixture.fake.pixel_height = changed == 2u ? 601u : 600u;
        fixture.fake.polls[0].request_stop = true;
        fixture.fake.poll_count = 1u;

        RFB_CHECK(input_fixture_run(&fixture) ==
                  FARSEE_MT_TERMINAL_REQUESTED_STOP);
        RFB_CHECK_EQ_UINT(fixture.fake.probe_calls, 1u);
        RFB_CHECK_EQ_UINT(fixture.fake.refresh_calls, 1u);
        RFB_CHECK_EQ_UINT(fixture.fake.draw_calls, 2u);
        input_fixture_destroy(&fixture);
    }
}

RFB_TEST(rdp_live_input,
         advancing_clock__resamples_geometry_and_link_status)
{
    input_fixture fixture;
    if (!input_fixture_init(&fixture)) {
        RFB_FAIL("cannot initialize input fixture");
        return;
    }
    fixture.tick.shell.layout_active = true;
    fixture.fake.monotonic_step_ms = 250u;
    fixture.fake.polls[0].result = 0;
    fixture.fake.polls[1].result = 0;
    fixture.fake.polls[2].request_stop = true;
    fixture.fake.poll_count = 3u;

    RFB_CHECK(input_fixture_run(&fixture) ==
              FARSEE_MT_TERMINAL_REQUESTED_STOP);
    RFB_CHECK_EQ_UINT(fixture.fake.probe_calls, 3u);
    RFB_CHECK_EQ_UINT(fixture.fake.draw_calls, 3u);
    RFB_CHECK_EQ_UINT(fixture.fake.poll_calls, 3u);
    input_fixture_destroy(&fixture);
}

RFB_TEST(rdp_live_input,
         unrelated_poll_event__does_not_read_or_fail_input)
{
    input_fixture fixture;
    if (!input_fixture_init(&fixture)) {
        RFB_FAIL("cannot initialize input fixture");
        return;
    }
    fixture.fake.polls[0].result = 1;
    fixture.fake.polls[0].revents = POLLOUT;
    fixture.fake.polls[1].request_stop = true;
    fixture.fake.poll_count = 2u;

    RFB_CHECK(input_fixture_run(&fixture) ==
              FARSEE_MT_TERMINAL_REQUESTED_STOP);
    RFB_CHECK_EQ_UINT(fixture.fake.poll_calls, 2u);
    RFB_CHECK_EQ_UINT(fixture.fake.read_calls, 0u);
    input_fixture_destroy(&fixture);
}

RFB_TEST(rdp_live_input,
         ready_key_then_eagain__queues_exact_press_release_and_stops)
{
    input_fixture fixture;
    if (!input_fixture_init(&fixture)) {
        RFB_CHECK(false);
        return;
    }
    rdp_live_bind_shell_ops(&fixture.tick);
    fixture.fake.polls[0].result = 1;
    fixture.fake.polls[0].revents = POLLIN;
    fixture.fake.polls[1].request_stop = true;
    fixture.fake.poll_count = 2u;
    fixture.fake.reads[0].result = 1;
    fixture.fake.reads[0].data[0] = (uint8_t)'a';
    fixture.fake.reads[1].result = -1;
    fixture.fake.reads[1].error_number = EAGAIN;
    fixture.fake.read_count = 2u;

    RFB_CHECK(input_fixture_run(&fixture) ==
              FARSEE_MT_TERMINAL_REQUESTED_STOP);
    RFB_CHECK(farsee_mt_terminal_load(&fixture.terminal) ==
              FARSEE_MT_TERMINAL_REQUESTED_STOP);
    RFB_CHECK_EQ_UINT(fixture.fake.poll_calls, 2u);
    RFB_CHECK_EQ_UINT(fixture.fake.read_calls, 2u);
    RFB_CHECK_EQ_INT(fixture.fake.last_poll_fd, 17);
    RFB_CHECK_EQ_INT(fixture.fake.last_poll_timeout_ms, 20);

    rdp_inj_cmd command;
    memset(&command, 0, sizeof command);
    RFB_CHECK(rdp_inj_queue_pop(
        &fixture.queue, &command, farsee_thread_monotonic_ms(), NULL));
    RFB_CHECK(command.kind == RDP_INJ_KEY);
    RFB_CHECK_EQ_UINT(command.keysym, (uint32_t)'a');
    RFB_CHECK_EQ_UINT(command.unicode, (uint32_t)'a');
    RFB_CHECK(command.down);
    RFB_CHECK(!command.repeat);
    memset(&command, 0, sizeof command);
    RFB_CHECK(rdp_inj_queue_pop(
        &fixture.queue, &command, farsee_thread_monotonic_ms(), NULL));
    RFB_CHECK(command.kind == RDP_INJ_KEY);
    RFB_CHECK_EQ_UINT(command.keysym, (uint32_t)'a');
    RFB_CHECK_EQ_UINT(command.unicode, (uint32_t)'a');
    RFB_CHECK(!command.down);
    RFB_CHECK(!command.repeat);
    RFB_CHECK(fixture.tick.inj == NULL);

    input_fixture_destroy(&fixture);
}

RFB_TEST(rdp_live_input,
         interrupted_poll_and_read__retry_without_input_failure)
{
    input_fixture fixture;
    if (!input_fixture_init(&fixture)) {
        RFB_CHECK(false);
        return;
    }
    fixture.fake.polls[0].result = -1;
    fixture.fake.polls[0].error_number = EINTR;
    fixture.fake.polls[1].result = 1;
    fixture.fake.polls[1].revents = POLLIN;
    fixture.fake.polls[2].request_stop = true;
    fixture.fake.poll_count = 3u;
    fixture.fake.reads[0].result = -1;
    fixture.fake.reads[0].error_number = EINTR;
    fixture.fake.reads[1].result = 0;
    fixture.fake.read_count = 2u;

    RFB_CHECK(input_fixture_run(&fixture) ==
              FARSEE_MT_TERMINAL_REQUESTED_STOP);
    RFB_CHECK(farsee_mt_terminal_load(&fixture.terminal) ==
              FARSEE_MT_TERMINAL_REQUESTED_STOP);
    RFB_CHECK_EQ_UINT(fixture.fake.poll_calls, 3u);
    RFB_CHECK_EQ_UINT(fixture.fake.read_calls, 2u);
    RFB_CHECK(fixture.tick.inj == NULL);

    input_fixture_destroy(&fixture);
}

RFB_TEST(rdp_live_input, poll_error__reports_input_failure_and_clears_queue)
{
    input_fixture fixture;
    if (!input_fixture_init(&fixture)) {
        RFB_CHECK(false);
        return;
    }
    fixture.fake.polls[0].result = -1;
    fixture.fake.polls[0].error_number = EIO;
    fixture.fake.poll_count = 1u;

    RFB_CHECK(input_fixture_run(&fixture) ==
              FARSEE_MT_TERMINAL_INPUT_FAILURE);
    RFB_CHECK(farsee_mt_terminal_load(&fixture.terminal) ==
              FARSEE_MT_TERMINAL_INPUT_FAILURE);
    RFB_CHECK_EQ_UINT(fixture.fake.poll_calls, 1u);
    RFB_CHECK_EQ_UINT(fixture.fake.read_calls, 0u);
    RFB_CHECK(fixture.tick.inj == NULL);

    input_fixture_destroy(&fixture);
}

RFB_TEST(rdp_live_input, read_error__reports_input_failure_and_clears_queue)
{
    input_fixture fixture;
    if (!input_fixture_init(&fixture)) {
        RFB_CHECK(false);
        return;
    }
    fixture.fake.polls[0].result = 1;
    fixture.fake.polls[0].revents = POLLIN;
    fixture.fake.poll_count = 1u;
    fixture.fake.reads[0].result = -1;
    fixture.fake.reads[0].error_number = EIO;
    fixture.fake.read_count = 1u;

    RFB_CHECK(input_fixture_run(&fixture) ==
              FARSEE_MT_TERMINAL_INPUT_FAILURE);
    RFB_CHECK(farsee_mt_terminal_load(&fixture.terminal) ==
              FARSEE_MT_TERMINAL_INPUT_FAILURE);
    RFB_CHECK_EQ_UINT(fixture.fake.poll_calls, 1u);
    RFB_CHECK_EQ_UINT(fixture.fake.read_calls, 1u);
    RFB_CHECK(fixture.tick.inj == NULL);

    input_fixture_destroy(&fixture);
}

RFB_TEST(rdp_live_input, no_tty__uses_bounded_idle_wait_until_stop)
{
    input_fixture fixture;
    if (!input_fixture_init(&fixture)) {
        RFB_CHECK(false);
        return;
    }
    fixture.tick.shell.tty_fd = -1;
    fixture.fake.polls[0].request_stop = true;
    fixture.fake.poll_count = 1u;

    RFB_CHECK(input_fixture_run(&fixture) ==
              FARSEE_MT_TERMINAL_REQUESTED_STOP);
    RFB_CHECK_EQ_UINT(fixture.fake.poll_calls, 1u);
    RFB_CHECK_EQ_INT(fixture.fake.last_poll_fd, -1);
    RFB_CHECK_EQ_INT(fixture.fake.last_poll_timeout_ms, 20);
    RFB_CHECK_EQ_UINT(fixture.fake.read_calls, 0u);
    RFB_CHECK(fixture.tick.inj == NULL);

    input_fixture_destroy(&fixture);
}

RFB_TEST(rdp_live_input, preexisting_process_stop__does_not_poll_or_claim_queue)
{
    input_fixture fixture;
    if (!input_fixture_init(&fixture)) {
        RFB_CHECK(false);
        return;
    }
    farsee_atomic_int_store(&fixture.process_stop, 1);

    RFB_CHECK(input_fixture_run(&fixture) ==
              FARSEE_MT_TERMINAL_REQUESTED_STOP);
    RFB_CHECK(farsee_mt_terminal_load(&fixture.terminal) ==
              FARSEE_MT_TERMINAL_REQUESTED_STOP);
    RFB_CHECK_EQ_UINT(fixture.fake.poll_calls, 0u);
    RFB_CHECK(fixture.tick.inj == NULL);

    input_fixture_destroy(&fixture);
}

RFB_TEST(rdp_live_input,
         shell_ops__guard_missing_owners_and_clamp_zoom)
{
    rdp_live_bind_shell_ops(NULL);

    rdp_live_tick tick;
    memset(&tick, 0, sizeof tick);
    farsee_live_shell_init(&tick.shell, NULL, 1u);
    farsee_modifier_synth_init(&tick.synth_mods);
    rdp_live_bind_shell_ops(&tick);
    const rfb_norm_key key = {
        .keysym = (uint32_t)'z',
        .text = (uint32_t)'z',
        .down = true,
        .source = RFB_NORM_SOURCE_LEGACY,
    };

    tick.shell.ops->inject_key(NULL, &key);
    tick.shell.ops->inject_key(tick.shell.ops_user, NULL);
    tick.shell.ops->inject_key(tick.shell.ops_user, &key);
    RFB_CHECK(!tick.shell.ops->inject_pointer(
        NULL, 1, 2, 0u, 0, 0));
    RFB_CHECK(!tick.shell.ops->inject_pointer(
        tick.shell.ops_user, 1, 2, 0u, 0, 0));
    tick.shell.ops->request_quit(NULL);
    tick.shell.ops->request_quit(tick.shell.ops_user);
    tick.shell.ops->on_layout_applied(NULL);
    tick.shell.ops->on_layout_applied(tick.shell.ops_user);
    rdp_frame_slot slot;
    if (rdp_frame_slot_init(&slot)) {
        tick.slot = &slot;
        tick.shell.ops->on_layout_applied(tick.shell.ops_user);
        tick.slot = NULL;
        rdp_frame_slot_destroy(&slot);
    } else {
        RFB_FAIL("cannot initialize frame slot");
    }

    char unchanged = 'x';
    tick.shell.ops->status_extra(NULL, &unchanged, sizeof unchanged);
    tick.shell.ops->status_extra(tick.shell.ops_user, NULL,
                                 sizeof unchanged);
    tick.shell.ops->status_extra(tick.shell.ops_user, &unchanged, 0u);
    RFB_CHECK_EQ_INT(unchanged, 'x');

    farsee_live_shell_set_view_scale(&tick.shell, 50u);
    tick.shell.ops->zoom(NULL, 10);
    RFB_CHECK_EQ_UINT(farsee_live_shell_view_scale(&tick.shell), 50u);
    tick.shell.ops->zoom(tick.shell.ops_user, 10);
    RFB_CHECK_EQ_UINT(farsee_live_shell_view_scale(&tick.shell), 60u);
    tick.shell.ops->zoom(tick.shell.ops_user, -1000);
    RFB_CHECK_EQ_UINT(farsee_live_shell_view_scale(&tick.shell),
                      FARSEE_VIEW_SCALE_MIN_PCT);
    tick.shell.ops->zoom(tick.shell.ops_user, -1);
    RFB_CHECK_EQ_UINT(farsee_live_shell_view_scale(&tick.shell),
                      FARSEE_VIEW_SCALE_MIN_PCT);
    tick.shell.ops->zoom(tick.shell.ops_user, 1000);
    RFB_CHECK_EQ_UINT(farsee_live_shell_view_scale(&tick.shell),
                      FARSEE_VIEW_SCALE_MAX_PCT);
    tick.shell.ops->zoom(tick.shell.ops_user, 1);
    RFB_CHECK_EQ_UINT(farsee_live_shell_view_scale(&tick.shell),
                      FARSEE_VIEW_SCALE_MAX_PCT);
}

RFB_TEST(rdp_live_input,
         timeout_then_verbose_poll_error__reports_failure)
{
    input_fixture fixture;
    if (!input_fixture_init(&fixture)) {
        RFB_CHECK(false);
        return;
    }
    fixture.tick.verbose = true;
    fixture.fake.probe_ok = false;
    fixture.fake.polls[0].result = 0;
    fixture.fake.polls[1].result = -1;
    fixture.fake.polls[1].error_number = EIO;
    fixture.fake.poll_count = 2u;

    RFB_CHECK(input_fixture_run(&fixture) ==
              FARSEE_MT_TERMINAL_INPUT_FAILURE);
    RFB_CHECK_EQ_UINT(fixture.fake.probe_calls, 1u);
    RFB_CHECK_EQ_UINT(fixture.fake.poll_calls, 2u);
    RFB_CHECK_EQ_UINT(fixture.fake.read_calls, 0u);
    RFB_CHECK(fixture.tick.inj == NULL);

    input_fixture_destroy(&fixture);
}

RFB_TEST(rdp_live_input,
         view_only_key_and_pointer__do_not_publish_injection_or_cursor)
{
    input_fixture fixture;
    if (!input_fixture_init(&fixture)) {
        RFB_CHECK(false);
        return;
    }
    rdp_display_sink sink;
    rdp_display_sink_init(&sink);
    fixture.tick.inj = &fixture.queue;
    fixture.tick.sink = &sink;
    fixture.tick.shell.view_only = true;
    rdp_live_bind_shell_ops(&fixture.tick);
    const rfb_norm_key key = {
        .keysym = (uint32_t)'x',
        .text = (uint32_t)'x',
        .down = true,
        .source = RFB_NORM_SOURCE_LEGACY,
    };

    fixture.tick.shell.ops->inject_key(fixture.tick.shell.ops_user, &key);
    RFB_CHECK(!fixture.tick.shell.ops->inject_pointer(
        fixture.tick.shell.ops_user, 9, 11, 1u, 0, 0));
    RFB_CHECK_EQ_INT(farsee_atomic_int_load(&sink.cursor_visible), 0);
    rdp_inj_cmd command;
    memset(&command, 0, sizeof command);
    RFB_CHECK(!rdp_inj_queue_pop(
        &fixture.queue, &command, farsee_thread_monotonic_ms(), NULL));

    fixture.tick.inj = NULL;
    input_fixture_destroy(&fixture);
}

RFB_TEST(rdp_live_input,
         status_extra__formats_link_and_verbose_owner_counters)
{
    rdp_live_tick tick;
    memset(&tick, 0, sizeof tick);
    farsee_live_shell_init(&tick.shell, NULL, 1u);
    rdp_display_sink sink;
    rdp_display_sink_init(&sink);
    tick.sink = &sink;
    tick.verbose = true;
    farsee_atomic_u64_store(&tick.link_meta,
                            farsee_link_meta_pack(27u, true, true));
    farsee_atomic_u64_store(&tick.link_rate_pub,
                            farsee_link_rate_pack(512u, true));
    farsee_atomic_u64_store(&tick.shell.input_events, 3u);
    farsee_atomic_u64_store(&sink.end_paint_count, 4u);
    farsee_atomic_u64_store(&sink.frame_count, 5u);
    rdp_live_bind_shell_ops(&tick);
    char status[256];
    memset(status, 0, sizeof status);

    tick.shell.ops->status_extra(tick.shell.ops_user, status, sizeof status);
    RFB_CHECK(strstr(status, "50%") != NULL);
    RFB_CHECK(strstr(status, "27ms") != NULL);
    RFB_CHECK(strstr(status, "512KiB/s") != NULL);
    RFB_CHECK(strstr(status, "in=3") != NULL);
    RFB_CHECK(strstr(status, "paint=4") != NULL);
    RFB_CHECK(strstr(status, "show=5") != NULL);

    tick.verbose = false;
    memset(status, 0, sizeof status);
    tick.shell.ops->status_extra(tick.shell.ops_user, status, sizeof status);
    RFB_CHECK(strstr(status, "in=") == NULL);
    RFB_CHECK(strstr(status, "50%") != NULL);
}

#endif  // FARSEE_WITH_RDP
