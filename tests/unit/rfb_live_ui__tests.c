// SPDX-License-Identifier: Apache-2.0
//
// Private RFB live UI-owner boundary tests.

#include "app/rfb_live_ui.h"
#include "tests/test_framework/rfb_test.h"

#include <stdint.h>
#include <string.h>

RFB_TEST(rfb_live_ui, pointer_accept__queues_exact_state_and_quit_stops_both)
{
    farsee_cmd_queue queue;
    if (!farsee_cmd_queue_init(&queue)) {
        RFB_CHECK(false);
        return;
    }

    rfb_live_ui ui;
    memset(&ui, 0, sizeof ui);
    farsee_atomic_int worker_stop;
    farsee_atomic_int session_stop;
    farsee_atomic_int_store(&worker_stop, 0);
    farsee_atomic_int_store(&session_stop, 0);
    ui.cmds = &queue;
    ui.stop = &worker_stop;
    ui.session_stop = &session_stop;
    ui.prev_buttons = 2u;
    rfb_live_ui_bind_shell_ops(&ui);

    RFB_CHECK(ui.shell.ops == &ui.shell_ops);
    RFB_CHECK(ui.shell.ops_user == &ui);
    RFB_CHECK(ui.shell.ops->suspend == NULL);
    RFB_CHECK(ui.shell.ops->inject_pointer(
        ui.shell.ops_user, 19, 31, 5u, -120, 120));

    farsee_cmd command;
    memset(&command, 0, sizeof command);
    RFB_CHECK(farsee_cmd_queue_pop(
        &queue, &command, farsee_thread_monotonic_ms(), NULL));
    RFB_CHECK(command.kind == FARSEE_CMD_POINTER);
    RFB_CHECK_EQ_INT(command.pe.abs_x, 19);
    RFB_CHECK_EQ_INT(command.pe.abs_y, 31);
    RFB_CHECK_EQ_INT(command.pe.wheel_v, -120);
    RFB_CHECK_EQ_INT(command.pe.wheel_h, 120);
    RFB_CHECK_EQ_UINT(command.pe.buttons, 5u);
    RFB_CHECK_EQ_UINT(command.prev_buttons, 2u);
    RFB_CHECK_EQ_UINT(ui.prev_buttons, 5u);

    ui.shell.ops->request_quit(ui.shell.ops_user);
    RFB_CHECK(farsee_atomic_int_load_nonzero(&worker_stop));
    RFB_CHECK(farsee_atomic_int_load_nonzero(&session_stop));
    farsee_cmd_queue_destroy(&queue);
}

RFB_TEST(rfb_live_ui,
         rfb_pointer_full_queue__rejects_without_advancing_state)
{
    farsee_cmd_queue queue;
    if (!farsee_cmd_queue_init(&queue)) {
        RFB_CHECK(false);
        return;
    }
    for (size_t i = 0u; i < FARSEE_CMD_QUEUE_CAP; i++) {
        farsee_cmd key;
        memset(&key, 0, sizeof key);
        key.kind = FARSEE_CMD_KEY;
        key.key.logical = (uint32_t)('a' + (i % 26u));
        key.key.action = FARSEE_KEY_PRESS;
        RFB_CHECK(farsee_cmd_queue_push(&queue, &key));
    }

    rfb_live_ui ui;
    memset(&ui, 0, sizeof ui);
    ui.cmds = &queue;
    ui.prev_buttons = 4u;
    rfb_live_ui_bind_shell_ops(&ui);

    RFB_CHECK(!ui.shell.ops->inject_pointer(
        ui.shell.ops_user, 8, 9, 1u, 0, 0));
    RFB_CHECK_EQ_UINT(ui.prev_buttons, 4u);
    farsee_cmd_queue_destroy(&queue);
}

RFB_TEST(rfb_live_ui, view_only_input__queues_nothing)
{
    farsee_cmd_queue queue;
    if (!farsee_cmd_queue_init(&queue)) {
        RFB_CHECK(false);
        return;
    }

    rfb_live_ui ui;
    memset(&ui, 0, sizeof ui);
    farsee_live_shell_init(&ui.shell, NULL, RFB_LIVE_STATUS_ROWS);
    ui.cmds = &queue;
    ui.prev_buttons = 2u;
    ui.shell.view_only = true;
    rfb_live_ui_bind_shell_ops(&ui);
    RFB_CHECK(!ui.shell.ops->inject_pointer(
        ui.shell.ops_user, 8, 9, 1u, 0, 0));
    static const uint8_t input[] = "a\033[<0;2;3M";
    rfb_live_ui_process_input(&ui, input, sizeof input - 1u);

    farsee_cmd command;
    RFB_CHECK(!farsee_cmd_queue_pop(
        &queue, &command, farsee_thread_monotonic_ms(), NULL));
    RFB_CHECK_EQ_UINT(ui.prev_buttons, 2u);
    farsee_cmd_queue_destroy(&queue);
}

RFB_TEST(rfb_live_ui, normalized_key__queues_exact_primary_edge)
{
    farsee_cmd_queue queue;
    if (!farsee_cmd_queue_init(&queue)) {
        RFB_CHECK(false);
        return;
    }

    rfb_live_ui ui;
    memset(&ui, 0, sizeof ui);
    farsee_live_shell_init(&ui.shell, NULL, RFB_LIVE_STATUS_ROWS);
    farsee_modifier_synth_init(&ui.synth_mods);
    ui.cmds = &queue;
    rfb_live_ui_bind_shell_ops(&ui);

    const rfb_norm_key key = {
        .keysym = (uint32_t)'x',
        .text = (uint32_t)'x',
        .modifiers = RFB_MOD_NONE,
        .down = true,
        .repeat = false,
        .source = RFB_NORM_SOURCE_KITTY,
    };
    ui.shell.ops->inject_key(ui.shell.ops_user, &key);

    farsee_cmd command;
    memset(&command, 0, sizeof command);
    RFB_CHECK(farsee_cmd_queue_pop(
        &queue, &command, farsee_thread_monotonic_ms(), NULL));
    RFB_CHECK_EQ_INT(command.kind, FARSEE_CMD_KEY);
    RFB_CHECK_EQ_UINT(command.key.logical, (uint32_t)'x');
    RFB_CHECK_EQ_INT(command.key.action, FARSEE_KEY_PRESS);
    RFB_CHECK(!farsee_cmd_queue_pop(
        &queue, &command, farsee_thread_monotonic_ms(), NULL));

    ui.shell.ops->inject_key(NULL, &key);
    ui.shell.ops->inject_key(ui.shell.ops_user, NULL);
    farsee_cmd_queue_destroy(&queue);
}

RFB_TEST(rfb_live_ui,
         physical_modifier_delivery_failure__stops_both_owners)
{
    farsee_cmd_queue queue;
    if (!farsee_cmd_queue_init(&queue)) {
        RFB_CHECK(false);
        return;
    }
    for (size_t i = 0u; i < FARSEE_CMD_QUEUE_CAP; i++) {
        farsee_cmd command;
        memset(&command, 0, sizeof command);
        command.kind = FARSEE_CMD_KEY;
        command.key.logical = (uint32_t)'a';
        command.key.action = FARSEE_KEY_PRESS;
        RFB_CHECK(farsee_cmd_queue_push(&queue, &command));
    }

    rfb_live_ui ui;
    memset(&ui, 0, sizeof ui);
    farsee_live_shell_init(&ui.shell, NULL, RFB_LIVE_STATUS_ROWS);
    farsee_modifier_synth_init(&ui.synth_mods);
    farsee_atomic_int worker_stop = 0;
    farsee_atomic_int session_stop = 0;
    ui.cmds = &queue;
    ui.stop = &worker_stop;
    ui.session_stop = &session_stop;
    rfb_live_ui_bind_shell_ops(&ui);

    const rfb_norm_key shift = {
        .keysym = XK_Shift_L,
        .text = 0u,
        .modifiers = RFB_MOD_NONE,
        .down = true,
        .repeat = false,
        .source = RFB_NORM_SOURCE_KITTY,
    };
    ui.shell.ops->inject_key(ui.shell.ops_user, &shift);
    RFB_CHECK(farsee_modifier_synth_requires_stop(&ui.synth_mods));
    RFB_CHECK(farsee_atomic_int_load_nonzero(&worker_stop));
    RFB_CHECK(farsee_atomic_int_load_nonzero(&session_stop));
    farsee_cmd_queue_destroy(&queue);
}

RFB_TEST(rfb_live_ui, shell_callbacks__format_status_zoom_and_tolerate_no_slot)
{
    rfb_live_ui_bind_shell_ops(NULL);
    rfb_live_ui_process_input(NULL, NULL, 0u);

    rfb_live_ui ui;
    memset(&ui, 0, sizeof ui);
    farsee_live_shell_init(&ui.shell, NULL, RFB_LIVE_STATUS_ROWS);
    farsee_live_shell_set_view_scale(&ui.shell, 50u);
    farsee_live_shell_set_term_geom(&ui.shell, 80u, 24u, 800u, 480u);
    ui.shell.desk_w = 640u;
    ui.shell.desk_h = 480u;
    rfb_live_ui_bind_shell_ops(&ui);

    char status[96];
    memset(status, 0, sizeof status);
    ui.shell.ops->status_extra(ui.shell.ops_user, status, sizeof status);
    RFB_CHECK(strstr(status, "50%") != NULL);
    ui.shell.ops->status_extra(NULL, status, sizeof status);
    ui.shell.ops->status_extra(ui.shell.ops_user, NULL, sizeof status);
    ui.shell.ops->status_extra(ui.shell.ops_user, status, 0u);

    ui.shell.ops->zoom(NULL, 10);
    ui.shell.ops->zoom(ui.shell.ops_user, 10);
    RFB_CHECK_EQ_UINT(farsee_live_shell_view_scale(&ui.shell), 60u);
    farsee_live_shell_set_view_scale(&ui.shell, FARSEE_VIEW_SCALE_MAX_PCT);
    ui.shell.ops->zoom(ui.shell.ops_user, 10);
    RFB_CHECK_EQ_UINT(farsee_live_shell_view_scale(&ui.shell),
                      FARSEE_VIEW_SCALE_MAX_PCT);
    farsee_live_shell_set_view_scale(&ui.shell, FARSEE_VIEW_SCALE_MIN_PCT);
    ui.shell.ops->zoom(ui.shell.ops_user, -10);
    RFB_CHECK_EQ_UINT(farsee_live_shell_view_scale(&ui.shell),
                      FARSEE_VIEW_SCALE_MIN_PCT);

    ui.shell.ops->on_layout_applied(NULL);
    ui.shell.ops->on_layout_applied(ui.shell.ops_user);
}
