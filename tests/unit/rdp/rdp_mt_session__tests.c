// SPDX-License-Identifier: Apache-2.0
//
// Deterministic tests for the live RDP multi-thread session owner.

#ifdef FARSEE_WITH_RDP

#include "protocol/rdp/rdp_mt_session_internal.h"
#include "farsee/socket_posix.h"
#include "tests/test_framework/rfb_test.h"

#include <freerdp/freerdp.h>
#include <freerdp/input.h>

#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

typedef enum fake_worker {
    FAKE_NONE = 0,
    FAKE_PROTOCOL,
    FAKE_PRESENT,
    FAKE_INPUT,
} fake_worker;

typedef struct fake_mt {
    fake_worker worker;
    rdp_display_sink *sink;
    bool saw_slot;
    bool mark_frame;
    farsee_error run_error;
    farsee_mt_terminal_kind run_kind;
    bool context_ready;
    unsigned shall_calls;
    unsigned disconnect_on;
    bool clean_disconnect;
    rdp_mt_pump_result pump_result;
    unsigned pump_calls;
    farsee_frame_publish_result publish_failure;
    uint64_t clock_ms;
    bool wire_stats_ok;
    uint64_t wire_in;
    unsigned wire_stats_calls;
    int wire_fd;
    uint32_t tcp_mask;
    uint32_t rtt_ms;
    unsigned tcp_calls;
    bool inject_key_ok;
    bool key_event_ok;
    farsee_physical_key key_physical;
    unsigned key_calls;
    uint32_t last_keysym;
    unsigned pointer_calls;
    bool use_pointer_reached;
    unsigned pointer_reached;
    farsee_pointer_event last_pointer;
    unsigned last_previous_buttons;
    unsigned release_calls;
    bool release_clears;
    unsigned stop_calls;
    bool present_ok;
    unsigned present_calls;
    uint32_t interval_ms;
    bool cursor_visible;
    int32_t cursor_x;
    int32_t cursor_y;
    unsigned after_calls;
    unsigned input_calls;
    farsee_mt_terminal_kind input_kind;
    rdp_mt_config *config;
    bool clear_context_before_worker;
    bool clear_input_before_worker;
    bool hide_sink_during_worker;
    bool clear_after_present_before_worker;
    bool accept_foreign_context;
    bool pass_null_frame;
} fake_mt;

typedef struct fixture {
    fake_mt fake;
    rdp_mt_session_ops ops;
    rdp_mt_config cfg;
    rdp_display_sink sink;
    rdp_frame_slot slot;
    rdp_inj_queue inj;
    farsee_key_ledger ledger;
    farsee_atomic_int stop;
    farsee_atomic_int force_repaint;
    farsee_atomic_u64 link_meta;
    farsee_atomic_u64 link_rx;
    farsee_atomic_u64 link_rate;
    unsigned wire_buttons;
} fixture;

typedef struct default_input_fixture {
    rdp_freerdp_ctx *ctx;
    rdpInput *input;
    void *saved_param1;
    pKeyboardEvent saved_keyboard;
    pMouseEvent saved_mouse;
    unsigned keyboard_calls;
    unsigned mouse_calls;
    UINT16 last_keyboard_flags;
    UINT16 last_mouse_flags;
} default_input_fixture;

static default_input_fixture *default_input_from(rdpInput *input)
{
    return input != NULL ? (default_input_fixture *)input->param1 : NULL;
}

static BOOL default_input_keyboard(rdpInput *input, UINT16 flags, UINT8 code)
{
    (void)code;
    default_input_fixture *input_fixture = default_input_from(input);
    if (input_fixture == NULL) {
        return FALSE;
    }
    input_fixture->keyboard_calls++;
    input_fixture->last_keyboard_flags = flags;
    return TRUE;
}

static BOOL default_input_mouse(rdpInput *input, UINT16 flags,
                                UINT16 x, UINT16 y)
{
    (void)x;
    (void)y;
    default_input_fixture *input_fixture = default_input_from(input);
    if (input_fixture == NULL) {
        return FALSE;
    }
    input_fixture->mouse_calls++;
    input_fixture->last_mouse_flags = flags;
    return TRUE;
}

static bool default_input_fixture_init(default_input_fixture *input_fixture)
{
    if (input_fixture == NULL) {
        return false;
    }
    memset(input_fixture, 0, sizeof *input_fixture);
    input_fixture->ctx = rdp_freerdp_create();
    if (input_fixture->ctx == NULL) {
        return false;
    }
    freerdp *instance =
        (freerdp *)rdp_freerdp_instance_opaque(input_fixture->ctx);
    if (instance == NULL || instance->context == NULL ||
        instance->context->input == NULL) {
        rdp_freerdp_destroy(&input_fixture->ctx);
        return false;
    }
    input_fixture->input = instance->context->input;
    input_fixture->saved_param1 = input_fixture->input->param1;
    input_fixture->saved_keyboard = input_fixture->input->KeyboardEvent;
    input_fixture->saved_mouse = input_fixture->input->MouseEvent;
    input_fixture->input->param1 = input_fixture;
    input_fixture->input->KeyboardEvent = default_input_keyboard;
    input_fixture->input->MouseEvent = default_input_mouse;
    return true;
}

static void default_input_fixture_destroy(default_input_fixture *input_fixture)
{
    if (input_fixture == NULL || input_fixture->ctx == NULL) {
        return;
    }
    input_fixture->input->param1 = input_fixture->saved_param1;
    input_fixture->input->KeyboardEvent = input_fixture->saved_keyboard;
    input_fixture->input->MouseEvent = input_fixture->saved_mouse;
    rdp_freerdp_destroy(&input_fixture->ctx);
}

static farsee_mt_terminal_kind fake_input(void *user, rdp_inj_queue *inj,
                                          farsee_atomic_int *stop,
                                          farsee_mt_terminal *terminal)
{
    fake_mt *fake = (fake_mt *)user;
    (void)inj;
    (void)stop;
    (void)terminal;
    fake->input_calls++;
    return fake->input_kind;
}

static farsee_error fake_run(void *user, const farsee_mt_config *cfg,
                             farsee_mt_outcome *outcome)
{
    fake_mt *fake = (fake_mt *)user;
    if (fake->clear_context_before_worker) {
        fake->config->ctx = NULL;
    }
    if (fake->clear_input_before_worker) {
        fake->config->input_fn = NULL;
    }
    rdp_display_sink *saved_sink = fake->config->sink;
    if (fake->hide_sink_during_worker) {
        fake->config->sink = NULL;
    }
    if (fake->clear_after_present_before_worker) {
        fake->config->after_present_fn = NULL;
    }
    fake->saw_slot = fake->sink->frame_slot == cfg->slot;
    if (fake->mark_frame) {
        farsee_atomic_int_store(&fake->sink->first_frame_delivered, 1);
    }
    if (fake->worker == FAKE_NONE) {
        outcome->kind = fake->run_kind;
        outcome->error = fake->run_error;
        return fake->run_error;
    }
    farsee_mt_terminal terminal;
    farsee_mt_terminal_init(&terminal);
    farsee_mt_terminal_kind kind = FARSEE_MT_TERMINAL_INTERNAL_FAILURE;
    if (fake->worker == FAKE_PROTOCOL) {
        kind = cfg->protocol_fn(cfg->protocol_user, cfg->slot, cfg->cmds,
                                cfg->stop_flag, &terminal);
    } else if (fake->worker == FAKE_PRESENT) {
        kind = cfg->present_fn(cfg->present_user, cfg->slot, cfg->stop_flag,
                               &terminal);
    } else if (fake->worker == FAKE_INPUT) {
        kind = cfg->input_fn(cfg->input_user, cfg->cmds, cfg->stop_flag,
                             &terminal);
    }
    fake->config->sink = saved_sink;
    (void)farsee_mt_terminal_report(&terminal, kind);
    outcome->kind = farsee_mt_terminal_load(&terminal);
    outcome->error = farsee_mt_terminal_error(outcome->kind);
    return outcome->error;
}

static farsee_mt_terminal_kind fake_present_loop(
    void *user, farsee_frame_slot *slot, farsee_atomic_int *stop,
    uint32_t interval_ms, farsee_mt_on_frame_fn on_frame,
    void *on_frame_user, farsee_mt_after_present_fn after_present,
    void *after_present_user, farsee_atomic_int *force_repaint,
    farsee_mt_terminal *terminal)
{
    fake_mt *fake = (fake_mt *)user;
    const uint8_t pixels[8] = { 1u, 2u, 3u, 0xffu,
                                4u, 5u, 6u, 0xffu };
    const farsee_frame_view view = {
        .pixels = pixels, .w = 2u, .h = 1u, .stride = 8u, .gen = 7u,
    };
    (void)slot;
    (void)stop;
    (void)force_repaint;
    fake->interval_ms = interval_ms;
    const bool ok = on_frame(
        on_frame_user, fake->pass_null_frame ? NULL : &view);
    if (after_present != NULL) {
        after_present(after_present_user);
    }
    if (!ok) {
        (void)farsee_mt_terminal_report(
            terminal, FARSEE_MT_TERMINAL_PRESENTER_FAILURE);
        return FARSEE_MT_TERMINAL_PRESENTER_FAILURE;
    }
    return FARSEE_MT_TERMINAL_REQUESTED_STOP;
}

static void *fake_context(void *user, rdp_freerdp_ctx *ctx)
{
    fake_mt *fake = (fake_mt *)user;
    (void)ctx;
    return fake->context_ready ? fake : NULL;
}

static bool fake_shall_disconnect(void *user, void *context)
{
    fake_mt *fake = (fake_mt *)user;
    RFB_CHECK(context == fake || fake->accept_foreign_context);
    fake->shall_calls++;
    return fake->disconnect_on != 0u &&
           fake->shall_calls >= fake->disconnect_on;
}

static rdp_mt_pump_result fake_pump(void *user, void *context)
{
    fake_mt *fake = (fake_mt *)user;
    RFB_CHECK(context == fake || fake->accept_foreign_context);
    fake->pump_calls++;
    if (fake->publish_failure != FARSEE_FRAME_PUBLISH_OK) {
        farsee_atomic_int_store(&fake->sink->frame_publish_failure,
                                (int)fake->publish_failure);
    }
    return fake->pump_result;
}

static bool fake_clean(void *user, rdp_freerdp_ctx *ctx)
{
    (void)ctx;
    return ((fake_mt *)user)->clean_disconnect;
}

static uint64_t fake_clock(void *user)
{
    fake_mt *fake = (fake_mt *)user;
    fake->clock_ms += 100u;
    return fake->clock_ms;
}

static bool fake_wire_stats(void *user, rdp_freerdp_ctx *ctx,
                            uint64_t *in_bytes, uint64_t *out_bytes)
{
    fake_mt *fake = (fake_mt *)user;
    (void)ctx;
    fake->wire_stats_calls++;
    if (!fake->wire_stats_ok) {
        return false;
    }
    *in_bytes = fake->wire_in;
    *out_bytes = 125u;
    return true;
}

static int fake_wire_fd(void *user, rdp_freerdp_ctx *ctx)
{
    (void)ctx;
    return ((fake_mt *)user)->wire_fd;
}

static uint32_t fake_tcp(void *user, int fd, uint32_t *out_rtt)
{
    fake_mt *fake = (fake_mt *)user;
    RFB_CHECK(fd == fake->wire_fd);
    fake->tcp_calls++;
    if ((fake->tcp_mask & FARSEE_TCP_STAT_RTT) != 0u) {
        *out_rtt = fake->rtt_ms;
    }
    return fake->tcp_mask;
}

static bool fake_key(void *user, rdp_freerdp_ctx *ctx, uint32_t keysym,
                     uint32_t unicode, bool down, bool repeat)
{
    fake_mt *fake = (fake_mt *)user;
    (void)ctx;
    (void)unicode;
    (void)down;
    (void)repeat;
    fake->key_calls++;
    fake->last_keysym = keysym;
    return fake->inject_key_ok;
}

static bool fake_key_event(void *user, farsee_key_event *out,
                           uint32_t keysym, uint32_t unicode,
                           bool down, bool repeat)
{
    fake_mt *fake = (fake_mt *)user;
    memset(out, 0, sizeof *out);
    out->physical = fake->key_physical;
    out->logical = keysym;
    out->unicode = unicode;
    out->action = repeat ? FARSEE_KEY_REPEAT
                         : (down ? FARSEE_KEY_PRESS : FARSEE_KEY_RELEASE);
    out->quality = FARSEE_INPUT_QUALITY_INFERRED;
    return fake->key_event_ok;
}

static bool fake_pointer(void *user, rdp_freerdp_ctx *ctx,
                         const farsee_pointer_event *event,
                         unsigned previous_buttons, unsigned *out_reached)
{
    fake_mt *fake = (fake_mt *)user;
    (void)ctx;
    fake->pointer_calls++;
    fake->last_pointer = *event;
    fake->last_previous_buttons = previous_buttons;
    *out_reached = fake->use_pointer_reached ? fake->pointer_reached
                                             : event->buttons;
    return true;
}

static void fake_release(void *user, rdp_freerdp_ctx *ctx,
                         farsee_key_ledger *ledger)
{
    fake_mt *fake = (fake_mt *)user;
    farsee_physical_key released[FARSEE_KEY_LEDGER_MAX];
    (void)ctx;
    fake->release_calls++;
    if (fake->release_clears) {
        (void)farsee_key_ledger_release_all(
            ledger, released, FARSEE_KEY_LEDGER_MAX);
    }
}

static void fake_stop(void *user, rdp_freerdp_ctx *ctx)
{
    (void)ctx;
    ((fake_mt *)user)->stop_calls++;
}

static bool fake_present(void *user, rdp_freerdp_ctx *ctx,
                         const uint8_t *pixels, uint32_t width,
                         uint32_t height, uint32_t stride,
                         bool cursor_visible, int32_t cursor_x,
                         int32_t cursor_y)
{
    fake_mt *fake = (fake_mt *)user;
    (void)ctx;
    RFB_CHECK(pixels != NULL);
    RFB_CHECK_EQ_UINT(width, 2u);
    RFB_CHECK_EQ_UINT(height, 1u);
    RFB_CHECK_EQ_UINT(stride, 8u);
    fake->present_calls++;
    fake->cursor_visible = cursor_visible;
    fake->cursor_x = cursor_x;
    fake->cursor_y = cursor_y;
    return fake->present_ok;
}

static void fake_after(void *user)
{
    ((fake_mt *)user)->after_calls++;
}

static bool fixture_init(fixture *f)
{
    memset(f, 0, sizeof *f);
    if (!rdp_frame_slot_init(&f->slot)) {
        return false;
    }
    if (!rdp_inj_queue_init(&f->inj)) {
        rdp_frame_slot_destroy(&f->slot);
        return false;
    }
    rdp_display_sink_init(&f->sink);
    farsee_key_ledger_init(&f->ledger);
    farsee_atomic_int_store(&f->stop, 0);
    f->fake.sink = &f->sink;
    f->fake.context_ready = true;
    f->fake.clean_disconnect = true;
    f->fake.pump_result = RDP_MT_PUMP_IDLE;
    f->fake.wire_fd = -1;
    f->fake.inject_key_ok = true;
    f->fake.key_event_ok = true;
    f->fake.key_physical = 4u;
    f->fake.release_clears = true;
    f->fake.present_ok = true;
    f->fake.input_kind = FARSEE_MT_TERMINAL_REQUESTED_STOP;
    f->ops = (rdp_mt_session_ops) {
        .user = &f->fake,
        .run_threads = fake_run,
        .present_loop = fake_present_loop,
        .protocol_context = fake_context,
        .shall_disconnect = fake_shall_disconnect,
        .pump_once = fake_pump,
        .clean_peer_disconnect = fake_clean,
        .monotonic_ms = fake_clock,
        .wire_stats = fake_wire_stats,
        .wire_fd = fake_wire_fd,
        .tcp_stats = fake_tcp,
        .key_event_from_keysym = fake_key_event,
        .inject_key_from_keysym = fake_key,
        .inject_pointer = fake_pointer,
        .release_all = fake_release,
        .request_stop = fake_stop,
        .present_bgra = fake_present,
    };
    f->cfg = (rdp_mt_config) {
        .ctx = (rdp_freerdp_ctx *)(void *)&f->fake,
        .sink = &f->sink,
        .slot = &f->slot,
        .inj = &f->inj,
        .ledger = &f->ledger,
        .wire_buttons = &f->wire_buttons,
        .stop_flag = &f->stop,
        .present_interval_ms = 33u,
        .input_fn = fake_input,
        .input_user = &f->fake,
        .after_present_fn = fake_after,
        .after_present_user = &f->fake,
        .force_repaint = &f->force_repaint,
    };
    f->fake.config = &f->cfg;
    return true;
}

static void fixture_destroy(fixture *f)
{
    rdp_inj_queue_destroy(&f->inj);
    rdp_frame_slot_destroy(&f->slot);
}

static bool fixture_queue_key(fixture *f, bool down)
{
    rdp_inj_cmd command;
    memset(&command, 0, sizeof command);
    command.kind = RDP_INJ_KEY;
    command.keysym = (uint32_t)'k';
    command.unicode = (uint32_t)'k';
    command.down = down;
    return rdp_inj_queue_push(&f->inj, &command);
}

static farsee_error fixture_run_protocol(fixture *f,
                                         farsee_mt_outcome *outcome)
{
    f->fake.worker = FAKE_PROTOCOL;
    f->fake.disconnect_on = 2u;
    f->fake.mark_frame = true;
    return rdp_mt_run_with_ops(&f->cfg, NULL, outcome, &f->ops);
}

RFB_TEST(rdp_mt_session, run__null_config_fails_closed)
{
    farsee_mt_outcome outcome;
    bool got_frame = true;
    const farsee_error error =
        rdp_mt_run_with_ops(NULL, &got_frame, &outcome, NULL);
    RFB_CHECK(error.code == FARSEE_ERR_STATE);
    RFB_CHECK(error.subsystem == FARSEE_SUB_RDP);
    RFB_CHECK(!got_frame);
    RFB_CHECK(outcome.kind == FARSEE_MT_TERMINAL_INTERNAL_FAILURE);
    RFB_CHECK(rdp_mt_run(NULL, NULL, NULL).code == FARSEE_ERR_STATE);
}

RFB_TEST(rdp_mt_session, run__core_error_maps_and_detaches_slot)
{
    fixture f;
    RFB_CHECK(fixture_init(&f));
    f.fake.worker = FAKE_NONE;
    f.fake.run_kind = FARSEE_MT_TERMINAL_THREAD_CREATION_FAILURE;
    f.fake.run_error = farsee_error_make(
        FARSEE_ERR_INTERNAL, FARSEE_SUB_CORE, FARSEE_PHASE_ACTIVE);
    farsee_mt_outcome outcome;
    const farsee_error error =
        rdp_mt_run_with_ops(&f.cfg, NULL, &outcome, &f.ops);
    RFB_CHECK(f.fake.saw_slot);
    RFB_CHECK(f.sink.frame_slot == NULL);
    RFB_CHECK(error.code == FARSEE_ERR_INTERNAL);
    RFB_CHECK(error.subsystem == FARSEE_SUB_RDP);
    RFB_CHECK(outcome.kind == FARSEE_MT_TERMINAL_THREAD_CREATION_FAILURE);
    RFB_CHECK(outcome.error.subsystem == FARSEE_SUB_RDP);
    fixture_destroy(&f);
}

RFB_TEST(rdp_mt_session, protocol__missing_context_is_internal_failure)
{
    fixture f;
    RFB_CHECK(fixture_init(&f));
    f.fake.worker = FAKE_PROTOCOL;
    f.fake.context_ready = false;
    farsee_mt_outcome outcome;
    const farsee_error error =
        rdp_mt_run_with_ops(&f.cfg, NULL, &outcome, &f.ops);
    RFB_CHECK(error.code == FARSEE_ERR_INTERNAL);
    RFB_CHECK(error.subsystem == FARSEE_SUB_RDP);
    RFB_CHECK(outcome.kind == FARSEE_MT_TERMINAL_INTERNAL_FAILURE);
    RFB_CHECK_EQ_UINT(f.fake.pump_calls, 0u);
    fixture_destroy(&f);
}

RFB_TEST(rdp_mt_session, protocol__peer_close_before_frame_is_connect_failure)
{
    fixture f;
    RFB_CHECK(fixture_init(&f));
    f.fake.worker = FAKE_PROTOCOL;
    f.fake.disconnect_on = 1u;
    bool got_frame = true;
    farsee_mt_outcome outcome;
    const farsee_error error =
        rdp_mt_run_with_ops(&f.cfg, &got_frame, &outcome, &f.ops);
    RFB_CHECK(error.code == FARSEE_ERR_CONNECT_FAILURE);
    RFB_CHECK(outcome.kind == FARSEE_MT_TERMINAL_PEER_CLOSED);
    RFB_CHECK(outcome.error.code == FARSEE_ERR_CONNECT_FAILURE);
    RFB_CHECK(!got_frame);
    fixture_destroy(&f);
}

RFB_TEST(rdp_mt_session, protocol__transport_failure_is_protocol_failure)
{
    fixture f;
    RFB_CHECK(fixture_init(&f));
    f.fake.worker = FAKE_PROTOCOL;
    f.fake.pump_result = RDP_MT_PUMP_TRANSPORT_FAILURE;
    farsee_mt_outcome outcome;
    const farsee_error error =
        rdp_mt_run_with_ops(&f.cfg, NULL, &outcome, &f.ops);
    RFB_CHECK(error.code == FARSEE_ERR_PROTOCOL_VIOLATION);
    RFB_CHECK(error.subsystem == FARSEE_SUB_RDP);
    RFB_CHECK(outcome.kind == FARSEE_MT_TERMINAL_PROTOCOL_FAILURE);
    RFB_CHECK_EQ_UINT(f.fake.pump_calls, 1u);
    fixture_destroy(&f);
}

RFB_TEST(rdp_mt_session, protocol__publish_oom_is_allocation_failure)
{
    fixture f;
    RFB_CHECK(fixture_init(&f));
    f.fake.worker = FAKE_PROTOCOL;
    f.fake.pump_result = RDP_MT_PUMP_DISPATCH_FAILURE;
    f.fake.publish_failure = FARSEE_FRAME_PUBLISH_OUT_OF_MEMORY;
    farsee_mt_outcome outcome;
    const farsee_error error =
        rdp_mt_run_with_ops(&f.cfg, NULL, &outcome, &f.ops);
    RFB_CHECK(error.code == FARSEE_ERR_OUT_OF_MEMORY);
    RFB_CHECK(error.subsystem == FARSEE_SUB_RDP);
    RFB_CHECK(outcome.kind == FARSEE_MT_TERMINAL_ALLOCATION_FAILURE);
    fixture_destroy(&f);
}

RFB_TEST(rdp_mt_session, protocol__invalid_publish_is_protocol_failure)
{
    fixture f;
    RFB_CHECK(fixture_init(&f));
    f.fake.worker = FAKE_PROTOCOL;
    f.fake.pump_result = RDP_MT_PUMP_DISPATCH_FAILURE;
    f.fake.publish_failure = FARSEE_FRAME_PUBLISH_INVALID;
    farsee_mt_outcome outcome;
    const farsee_error error =
        rdp_mt_run_with_ops(&f.cfg, NULL, &outcome, &f.ops);
    RFB_CHECK(error.code == FARSEE_ERR_PROTOCOL_VIOLATION);
    RFB_CHECK(error.subsystem == FARSEE_SUB_RDP);
    RFB_CHECK(outcome.kind == FARSEE_MT_TERMINAL_PROTOCOL_FAILURE);
    fixture_destroy(&f);
}

RFB_TEST(rdp_mt_session, protocol__drains_and_releases_input_state)
{
    fixture f;
    RFB_CHECK(fixture_init(&f));
    f.fake.worker = FAKE_PROTOCOL;
    f.fake.disconnect_on = 2u;
    f.fake.mark_frame = true;
    rdp_inj_cmd key;
    memset(&key, 0, sizeof key);
    key.kind = RDP_INJ_KEY;
    key.keysym = (uint32_t)'a';
    key.down = true;
    RFB_CHECK(rdp_inj_queue_push(&f.inj, &key));
    rdp_inj_cmd pointer;
    memset(&pointer, 0, sizeof pointer);
    pointer.kind = RDP_INJ_POINTER;
    pointer.pe.abs_x = 19;
    pointer.pe.abs_y = 23;
    pointer.pe.buttons = FARSEE_BUTTON_LEFT;
    RFB_CHECK(rdp_inj_queue_push(&f.inj, &pointer));
    rdp_inj_cmd release;
    memset(&release, 0, sizeof release);
    release.kind = RDP_INJ_RELEASE_ALL;
    RFB_CHECK(rdp_inj_queue_push(&f.inj, &release));
    bool got_frame = false;
    const farsee_error error =
        rdp_mt_run_with_ops(&f.cfg, &got_frame, NULL, &f.ops);
    RFB_CHECK(error.code == FARSEE_E_OK);
    RFB_CHECK(got_frame);
    RFB_CHECK_EQ_UINT(f.fake.key_calls, 1u);
    RFB_CHECK_EQ_UINT(f.fake.last_keysym, (uint32_t)'a');
    RFB_CHECK_EQ_UINT(f.fake.release_calls, 1u);
    RFB_CHECK_EQ_UINT(f.fake.pointer_calls, 2u);
    RFB_CHECK_EQ_INT(f.fake.last_pointer.abs_x, 19);
    RFB_CHECK_EQ_INT(f.fake.last_pointer.abs_y, 23);
    RFB_CHECK_EQ_UINT(f.fake.last_pointer.buttons, 0u);
    RFB_CHECK_EQ_UINT(f.fake.last_previous_buttons, FARSEE_BUTTON_LEFT);
    RFB_CHECK_EQ_UINT(f.ledger.count, 0u);
    RFB_CHECK_EQ_UINT(f.wire_buttons, 0u);
    fixture_destroy(&f);
}

RFB_TEST(rdp_mt_session, protocol__publishes_wire_and_kernel_link_metrics)
{
    fixture f;
    RFB_CHECK(fixture_init(&f));
    f.fake.worker = FAKE_PROTOCOL;
    f.fake.disconnect_on = 2u;
    f.fake.mark_frame = true;
    f.fake.wire_stats_ok = true;
    f.fake.wire_in = 900u;
    f.fake.wire_fd = 7;
    f.fake.tcp_mask = FARSEE_TCP_STAT_RTT;
    f.fake.rtt_ms = 14u;
    f.cfg.link_meta = &f.link_meta;
    f.cfg.link_rx_bytes = &f.link_rx;
    f.cfg.link_rate_pub = &f.link_rate;
    const farsee_error error =
        rdp_mt_run_with_ops(&f.cfg, NULL, NULL, &f.ops);
    uint32_t rtt = 0u;
    bool have_rtt = false;
    bool have_rx = false;
    farsee_link_meta_unpack(farsee_atomic_u64_load(&f.link_meta),
                            &rtt, &have_rtt, &have_rx);
    RFB_CHECK(error.code == FARSEE_E_OK);
    RFB_CHECK_EQ_UINT(farsee_atomic_u64_load(&f.link_rx), 900u);
    RFB_CHECK_EQ_UINT(rtt, 14u);
    RFB_CHECK(have_rtt);
    RFB_CHECK(have_rx);
    fixture_destroy(&f);
}

RFB_TEST(rdp_mt_session, present__uses_cursor_and_marks_first_frame)
{
    fixture f;
    RFB_CHECK(fixture_init(&f));
    f.fake.worker = FAKE_PRESENT;
    farsee_atomic_int_store(&f.sink.cursor_visible, 1);
    farsee_atomic_int_store(&f.sink.cursor_x, 31);
    farsee_atomic_int_store(&f.sink.cursor_y, 47);
    bool got_frame = false;
    const farsee_error error =
        rdp_mt_run_with_ops(&f.cfg, &got_frame, NULL, &f.ops);
    RFB_CHECK(error.code == FARSEE_E_OK);
    RFB_CHECK(got_frame);
    RFB_CHECK_EQ_UINT(f.fake.present_calls, 1u);
    RFB_CHECK_EQ_UINT(f.fake.interval_ms, 33u);
    RFB_CHECK(f.fake.cursor_visible);
    RFB_CHECK_EQ_INT(f.fake.cursor_x, 31);
    RFB_CHECK_EQ_INT(f.fake.cursor_y, 47);
    RFB_CHECK_EQ_UINT(f.fake.after_calls, 1u);
    fixture_destroy(&f);
}

RFB_TEST(rdp_mt_session, present__failure_remains_presenter_failure)
{
    fixture f;
    RFB_CHECK(fixture_init(&f));
    f.fake.worker = FAKE_PRESENT;
    f.fake.present_ok = false;
    bool got_frame = true;
    farsee_mt_outcome outcome;
    const farsee_error error =
        rdp_mt_run_with_ops(&f.cfg, &got_frame, &outcome, &f.ops);
    RFB_CHECK(error.code == FARSEE_ERR_PRESENTER_FAILURE);
    RFB_CHECK(outcome.kind == FARSEE_MT_TERMINAL_PRESENTER_FAILURE);
    RFB_CHECK(!got_frame);
    RFB_CHECK_EQ_UINT(f.fake.after_calls, 1u);
    fixture_destroy(&f);
}

RFB_TEST(rdp_mt_session, input__failure_requests_protocol_stop)
{
    fixture f;
    RFB_CHECK(fixture_init(&f));
    f.fake.worker = FAKE_INPUT;
    f.fake.input_kind = FARSEE_MT_TERMINAL_INPUT_FAILURE;
    farsee_mt_outcome outcome;
    const farsee_error error =
        rdp_mt_run_with_ops(&f.cfg, NULL, &outcome, &f.ops);
    RFB_CHECK(error.code == FARSEE_ERR_LOCAL_IO_FAILURE);
    RFB_CHECK(outcome.kind == FARSEE_MT_TERMINAL_INPUT_FAILURE);
    RFB_CHECK_EQ_UINT(f.fake.input_calls, 1u);
    RFB_CHECK_EQ_UINT(f.fake.stop_calls, 1u);
    RFB_CHECK(farsee_atomic_int_load_nonzero(&f.stop));
    fixture_destroy(&f);
}

RFB_TEST(rdp_mt_session, run__each_required_config_pointer_fails_closed)
{
    for (unsigned missing = 0u; missing < 6u; missing++) {
        fixture f;
        RFB_CHECK(fixture_init(&f));
        rdp_mt_config bad = f.cfg;
        switch (missing) {
        case 0u: bad.ctx = NULL; break;
        case 1u: bad.sink = NULL; break;
        case 2u: bad.slot = NULL; break;
        case 3u: bad.inj = NULL; break;
        case 4u: bad.stop_flag = NULL; break;
        case 5u: bad.input_fn = NULL; break;
        default: RFB_CHECK(false); break;
        }
        bool got_frame = true;
        farsee_mt_outcome outcome;
        memset(&outcome, 0xa5, sizeof outcome);
        const farsee_error error =
            rdp_mt_run_with_ops(&bad, &got_frame, &outcome, &f.ops);
        RFB_CHECK(error.code == FARSEE_ERR_STATE);
        RFB_CHECK(error.subsystem == FARSEE_SUB_RDP);
        RFB_CHECK(!got_frame);
        RFB_CHECK(outcome.kind == FARSEE_MT_TERMINAL_INTERNAL_FAILURE);
        RFB_CHECK(outcome.error.code == FARSEE_ERR_STATE);
        fixture_destroy(&f);
    }
}

RFB_TEST(rdp_mt_session, run__successful_core_outcome_is_copied)
{
    fixture f;
    RFB_CHECK(fixture_init(&f));
    f.fake.worker = FAKE_NONE;
    f.fake.run_kind = FARSEE_MT_TERMINAL_REQUESTED_STOP;
    f.fake.run_error = farsee_error_make(
        FARSEE_E_OK, FARSEE_SUB_NONE, FARSEE_PHASE_ACTIVE);
    farsee_mt_outcome outcome;
    memset(&outcome, 0, sizeof outcome);
    const farsee_error error =
        rdp_mt_run_with_ops(&f.cfg, NULL, &outcome, &f.ops);
    RFB_CHECK(error.code == FARSEE_E_OK);
    RFB_CHECK(outcome.kind == FARSEE_MT_TERMINAL_REQUESTED_STOP);
    RFB_CHECK(outcome.error.code == FARSEE_E_OK);
    RFB_CHECK(f.sink.frame_slot == NULL);
    fixture_destroy(&f);
}

RFB_TEST(rdp_mt_session,
         protocol_and_input__post_validation_missing_dependencies_fail_closed)
{
    fixture protocol;
    RFB_CHECK(fixture_init(&protocol));
    protocol.fake.worker = FAKE_PROTOCOL;
    protocol.fake.clear_context_before_worker = true;
    farsee_mt_outcome outcome;
    const farsee_error protocol_error =
        rdp_mt_run_with_ops(&protocol.cfg, NULL, &outcome, &protocol.ops);
    RFB_CHECK(protocol_error.code == FARSEE_ERR_INTERNAL);
    RFB_CHECK(outcome.kind == FARSEE_MT_TERMINAL_INTERNAL_FAILURE);
    RFB_CHECK_EQ_UINT(protocol.fake.pump_calls, 0u);
    fixture_destroy(&protocol);

    fixture input;
    RFB_CHECK(fixture_init(&input));
    input.fake.worker = FAKE_INPUT;
    input.fake.clear_input_before_worker = true;
    const farsee_error input_error =
        rdp_mt_run_with_ops(&input.cfg, NULL, &outcome, &input.ops);
    RFB_CHECK(input_error.code == FARSEE_ERR_INTERNAL);
    RFB_CHECK(outcome.kind == FARSEE_MT_TERMINAL_INTERNAL_FAILURE);
    RFB_CHECK_EQ_UINT(input.fake.input_calls, 0u);
    fixture_destroy(&input);
}

RFB_TEST(rdp_mt_session,
         protocol__dispatch_failure_distinguishes_clean_and_unclean_peer)
{
    for (unsigned clean = 0u; clean < 2u; clean++) {
        fixture f;
        RFB_CHECK(fixture_init(&f));
        f.fake.worker = FAKE_PROTOCOL;
        f.fake.pump_result = RDP_MT_PUMP_DISPATCH_FAILURE;
        f.fake.clean_disconnect = clean != 0u;
        farsee_mt_outcome outcome;
        const farsee_error error =
            rdp_mt_run_with_ops(&f.cfg, NULL, &outcome, &f.ops);
        if (clean != 0u) {
            RFB_CHECK(outcome.kind == FARSEE_MT_TERMINAL_PEER_CLOSED);
            RFB_CHECK(error.code == FARSEE_ERR_CONNECT_FAILURE);
        } else {
            RFB_CHECK(outcome.kind == FARSEE_MT_TERMINAL_PROTOCOL_FAILURE);
            RFB_CHECK(error.code == FARSEE_ERR_PROTOCOL_VIOLATION);
        }
        RFB_CHECK_EQ_UINT(f.fake.pump_calls, 1u);
        fixture_destroy(&f);
    }
}

RFB_TEST(rdp_mt_session,
         protocol__missing_wire_stats_and_rtt_publish_absence_flags)
{
    fixture f;
    RFB_CHECK(fixture_init(&f));
    f.fake.worker = FAKE_PROTOCOL;
    f.fake.disconnect_on = 2u;
    f.fake.mark_frame = true;
    f.fake.wire_stats_ok = false;
    f.fake.wire_fd = -1;
    f.cfg.link_meta = &f.link_meta;
    f.cfg.link_rx_bytes = &f.link_rx;
    f.cfg.link_rate_pub = NULL;
    const farsee_error error =
        rdp_mt_run_with_ops(&f.cfg, NULL, NULL, &f.ops);
    uint32_t rtt = 99u;
    bool have_rtt = true;
    bool have_rx = true;
    farsee_link_meta_unpack(farsee_atomic_u64_load(&f.link_meta),
                            &rtt, &have_rtt, &have_rx);
    RFB_CHECK(error.code == FARSEE_E_OK);
    RFB_CHECK_EQ_UINT(farsee_atomic_u64_load(&f.link_rx), 0u);
    RFB_CHECK_EQ_UINT(rtt, 0u);
    RFB_CHECK(!have_rtt);
    RFB_CHECK(!have_rx);
    fixture_destroy(&f);

    fixture no_rtt;
    RFB_CHECK(fixture_init(&no_rtt));
    no_rtt.fake.worker = FAKE_PROTOCOL;
    no_rtt.fake.disconnect_on = 2u;
    no_rtt.fake.mark_frame = true;
    no_rtt.fake.wire_stats_ok = true;
    no_rtt.fake.wire_in = 45u;
    no_rtt.fake.wire_fd = 8;
    no_rtt.fake.tcp_mask = 0u;
    no_rtt.cfg.link_meta = &no_rtt.link_meta;
    no_rtt.cfg.link_rx_bytes = &no_rtt.link_rx;
    RFB_CHECK(rdp_mt_run_with_ops(
                  &no_rtt.cfg, NULL, NULL, &no_rtt.ops).code == FARSEE_E_OK);
    farsee_link_meta_unpack(farsee_atomic_u64_load(&no_rtt.link_meta),
                            &rtt, &have_rtt, &have_rx);
    RFB_CHECK(!have_rtt);
    RFB_CHECK(have_rx);
    RFB_CHECK_EQ_UINT(farsee_atomic_u64_load(&no_rtt.link_rx), 45u);
    fixture_destroy(&no_rtt);
}

RFB_TEST(rdp_mt_session,
         protocol__key_ledger_commits_only_successful_mapped_injection)
{
    fixture success;
    RFB_CHECK(fixture_init(&success));
    success.fake.key_physical = 40u;
    RFB_CHECK(fixture_queue_key(&success, true));
    RFB_CHECK(fixture_run_protocol(&success, NULL).code == FARSEE_E_OK);
    RFB_CHECK_EQ_UINT(success.fake.key_calls, 1u);
    RFB_CHECK_EQ_UINT(success.ledger.count, 1u);
    RFB_CHECK_EQ_UINT(success.ledger.down[0], 40u);
    fixture_destroy(&success);

    fixture inject_failure;
    RFB_CHECK(fixture_init(&inject_failure));
    inject_failure.fake.key_physical = 41u;
    inject_failure.fake.inject_key_ok = false;
    RFB_CHECK(fixture_queue_key(&inject_failure, true));
    RFB_CHECK(fixture_run_protocol(&inject_failure, NULL).code == FARSEE_E_OK);
    RFB_CHECK_EQ_UINT(inject_failure.fake.key_calls, 1u);
    RFB_CHECK_EQ_UINT(inject_failure.ledger.count, 0u);
    fixture_destroy(&inject_failure);

    fixture map_failure;
    RFB_CHECK(fixture_init(&map_failure));
    map_failure.fake.key_event_ok = false;
    RFB_CHECK(fixture_queue_key(&map_failure, true));
    RFB_CHECK(fixture_run_protocol(&map_failure, NULL).code == FARSEE_E_OK);
    RFB_CHECK_EQ_UINT(map_failure.fake.key_calls, 0u);
    RFB_CHECK_EQ_UINT(map_failure.ledger.count, 0u);
    fixture_destroy(&map_failure);

    fixture no_ledger;
    RFB_CHECK(fixture_init(&no_ledger));
    no_ledger.cfg.ledger = NULL;
    RFB_CHECK(fixture_queue_key(&no_ledger, true));
    RFB_CHECK(fixture_run_protocol(&no_ledger, NULL).code == FARSEE_E_OK);
    RFB_CHECK_EQ_UINT(no_ledger.fake.key_calls, 1u);
    fixture_destroy(&no_ledger);

    fixture no_physical;
    RFB_CHECK(fixture_init(&no_physical));
    no_physical.fake.key_physical = 0u;
    RFB_CHECK(fixture_queue_key(&no_physical, true));
    RFB_CHECK(fixture_run_protocol(&no_physical, NULL).code == FARSEE_E_OK);
    RFB_CHECK_EQ_UINT(no_physical.fake.key_calls, 1u);
    RFB_CHECK_EQ_UINT(no_physical.ledger.count, 0u);
    fixture_destroy(&no_physical);
}

RFB_TEST(rdp_mt_session,
         protocol__full_ledger_releases_before_new_hold_or_refuses_it)
{
    for (unsigned release_clears = 0u; release_clears < 2u;
         release_clears++) {
        fixture f;
        RFB_CHECK(fixture_init(&f));
        for (farsee_physical_key physical = 1u;
             physical <= FARSEE_KEY_LEDGER_MAX; physical++) {
            farsee_key_event event;
            memset(&event, 0, sizeof event);
            event.physical = physical;
            event.action = FARSEE_KEY_PRESS;
            RFB_CHECK(farsee_key_ledger_apply(&f.ledger, &event));
        }
        f.fake.key_physical = 100u;
        f.fake.release_clears = release_clears != 0u;
        RFB_CHECK(fixture_queue_key(&f, true));
        RFB_CHECK(fixture_run_protocol(&f, NULL).code == FARSEE_E_OK);
        RFB_CHECK_EQ_UINT(f.fake.release_calls, 1u);
        if (release_clears != 0u) {
            RFB_CHECK_EQ_UINT(f.fake.key_calls, 1u);
            RFB_CHECK_EQ_UINT(f.ledger.count, 1u);
            RFB_CHECK_EQ_UINT(f.ledger.down[0], 100u);
        } else {
            RFB_CHECK_EQ_UINT(f.fake.key_calls, 0u);
            RFB_CHECK_EQ_UINT(f.ledger.count, FARSEE_KEY_LEDGER_MAX);
        }
        fixture_destroy(&f);
    }
}

RFB_TEST(rdp_mt_session,
         protocol__duplicate_down_then_release_preserves_exact_ledger)
{
    fixture f;
    RFB_CHECK(fixture_init(&f));
    f.fake.key_physical = 4u;
    farsee_key_event held;
    memset(&held, 0, sizeof held);
    held.physical = 4u;
    held.action = FARSEE_KEY_PRESS;
    RFB_CHECK(farsee_key_ledger_apply(&f.ledger, &held));
    RFB_CHECK(fixture_queue_key(&f, true));
    RFB_CHECK(fixture_queue_key(&f, false));
    RFB_CHECK(fixture_run_protocol(&f, NULL).code == FARSEE_E_OK);
    RFB_CHECK_EQ_UINT(f.fake.key_calls, 2u);
    RFB_CHECK_EQ_UINT(f.ledger.count, 0u);
    fixture_destroy(&f);
}

RFB_TEST(rdp_mt_session,
         protocol__partial_pointer_progress_retries_without_wire_publication)
{
    fixture f;
    RFB_CHECK(fixture_init(&f));
    f.fake.use_pointer_reached = true;
    f.fake.pointer_reached = 0u;
    f.cfg.wire_buttons = NULL;
    rdp_inj_cmd pointer;
    memset(&pointer, 0, sizeof pointer);
    pointer.kind = RDP_INJ_POINTER;
    pointer.pe.abs_x = 17;
    pointer.pe.abs_y = 19;
    pointer.pe.buttons = FARSEE_BUTTON_LEFT;
    RFB_CHECK(rdp_inj_queue_push(&f.inj, &pointer));
    RFB_CHECK(fixture_run_protocol(&f, NULL).code == FARSEE_E_OK);
    RFB_CHECK(f.fake.pointer_calls >= 3u);
    RFB_CHECK_EQ_UINT(f.fake.last_previous_buttons, 0u);
    RFB_CHECK_EQ_UINT(f.fake.last_pointer.buttons, FARSEE_BUTTON_LEFT);
    fixture_destroy(&f);
}

RFB_TEST(rdp_mt_session,
         present__mutex_optional_sink_and_after_callback_paths_are_safe)
{
    fixture locked;
    RFB_CHECK(fixture_init(&locked));
    locked.fake.worker = FAKE_PRESENT;
    locked.cfg.io_mu = farsee_mutex_create();
    RFB_CHECK(locked.cfg.io_mu != NULL);
    RFB_CHECK(rdp_mt_run_with_ops(
                  &locked.cfg, NULL, NULL, &locked.ops).code == FARSEE_E_OK);
    RFB_CHECK_EQ_UINT(locked.fake.present_calls, 1u);
    farsee_mutex_destroy(&locked.cfg.io_mu);
    fixture_destroy(&locked);

    fixture sparse;
    RFB_CHECK(fixture_init(&sparse));
    sparse.fake.worker = FAKE_PRESENT;
    sparse.fake.hide_sink_during_worker = true;
    sparse.fake.clear_after_present_before_worker = true;
    bool got_frame = true;
    RFB_CHECK(rdp_mt_run_with_ops(
                  &sparse.cfg, &got_frame, NULL, &sparse.ops).code == FARSEE_E_OK);
    RFB_CHECK(!got_frame);
    RFB_CHECK(!sparse.fake.cursor_visible);
    RFB_CHECK_EQ_INT(sparse.fake.cursor_x, 0);
    RFB_CHECK_EQ_INT(sparse.fake.cursor_y, 0);
    RFB_CHECK_EQ_UINT(sparse.fake.after_calls, 0u);
    fixture_destroy(&sparse);
}

RFB_TEST(rdp_mt_session,
         protocol__bounded_final_drain_delivers_the_sixty_fifth_key)
{
    fixture f;
    RFB_CHECK(fixture_init(&f));
    f.fake.worker = FAKE_PROTOCOL;
    f.fake.pump_result = RDP_MT_PUMP_TRANSPORT_FAILURE;
    f.fake.mark_frame = true;
    for (unsigned i = 0u; i < 65u; i++) {
        RFB_CHECK(fixture_queue_key(&f, true));
    }

    farsee_mt_outcome outcome;
    const farsee_error error =
        rdp_mt_run_with_ops(&f.cfg, NULL, &outcome, &f.ops);
    RFB_CHECK(error.code == FARSEE_ERR_PROTOCOL_VIOLATION);
    RFB_CHECK(outcome.kind == FARSEE_MT_TERMINAL_PROTOCOL_FAILURE);
    RFB_CHECK_EQ_UINT(f.fake.pump_calls, 1u);
    RFB_CHECK_EQ_UINT(f.fake.key_calls, 65u);
    RFB_CHECK_EQ_UINT(f.ledger.count, 1u);
    fixture_destroy(&f);
}

RFB_TEST(rdp_mt_session,
         protocol__default_input_ops_preserve_key_and_button_ownership)
{
    default_input_fixture input;
    if (!default_input_fixture_init(&input)) {
        RFB_FAIL("cannot initialize FreeRDP input fixture");
        return;
    }
    fixture f;
    RFB_CHECK(fixture_init(&f));
    f.cfg.ctx = input.ctx;
    f.fake.worker = FAKE_PROTOCOL;
    f.fake.disconnect_on = 2u;
    f.fake.mark_frame = true;
    f.ops.monotonic_ms = NULL;
    f.ops.key_event_from_keysym = NULL;
    f.ops.inject_key_from_keysym = NULL;
    f.ops.inject_pointer = NULL;
    f.ops.release_all = NULL;

    RFB_CHECK(fixture_queue_key(&f, true));
    rdp_inj_cmd pointer;
    memset(&pointer, 0, sizeof pointer);
    pointer.kind = RDP_INJ_POINTER;
    pointer.pe.abs_x = 17;
    pointer.pe.abs_y = 19;
    pointer.pe.buttons = FARSEE_BUTTON_LEFT;
    RFB_CHECK(rdp_inj_queue_push(&f.inj, &pointer));
    rdp_inj_cmd release;
    memset(&release, 0, sizeof release);
    release.kind = RDP_INJ_RELEASE_ALL;
    RFB_CHECK(rdp_inj_queue_push(&f.inj, &release));

    RFB_CHECK(rdp_mt_run_with_ops(
                  &f.cfg, NULL, NULL, &f.ops).code == FARSEE_E_OK);
    RFB_CHECK_EQ_UINT(input.keyboard_calls, 2u);
    RFB_CHECK((input.last_keyboard_flags & KBD_FLAGS_RELEASE) != 0u);
    RFB_CHECK_EQ_UINT(input.mouse_calls, 4u);
    RFB_CHECK((input.last_mouse_flags & PTR_FLAGS_BUTTON1) != 0u);
    RFB_CHECK((input.last_mouse_flags & PTR_FLAGS_DOWN) == 0u);
    RFB_CHECK_EQ_UINT(f.fake.key_calls, 0u);
    RFB_CHECK_EQ_UINT(f.fake.pointer_calls, 0u);
    RFB_CHECK_EQ_UINT(f.fake.release_calls, 0u);
    RFB_CHECK_EQ_UINT(f.ledger.count, 0u);
    RFB_CHECK_EQ_UINT(f.wire_buttons, 0u);
    fixture_destroy(&f);
    default_input_fixture_destroy(&input);
}

RFB_TEST(rdp_mt_session,
         protocol__default_context_disconnect_and_present_paths_fail_closed)
{
    rdp_freerdp_ctx *ctx = rdp_freerdp_create();
    if (ctx == NULL) {
        RFB_FAIL("cannot initialize FreeRDP context");
        return;
    }

    fixture transport;
    RFB_CHECK(fixture_init(&transport));
    transport.cfg.ctx = ctx;
    transport.fake.worker = FAKE_PROTOCOL;
    transport.fake.accept_foreign_context = true;
    transport.fake.pump_result = RDP_MT_PUMP_TRANSPORT_FAILURE;
    transport.ops.protocol_context = NULL;
    transport.ops.shall_disconnect = NULL;
    RFB_CHECK(rdp_mt_run_with_ops(
                  &transport.cfg, NULL, NULL,
                  &transport.ops).code == FARSEE_ERR_PROTOCOL_VIOLATION);
    RFB_CHECK_EQ_UINT(transport.fake.pump_calls, 1u);
    fixture_destroy(&transport);

    fixture clean;
    RFB_CHECK(fixture_init(&clean));
    clean.cfg.ctx = ctx;
    clean.fake.worker = FAKE_PROTOCOL;
    clean.fake.accept_foreign_context = true;
    clean.fake.pump_result = RDP_MT_PUMP_DISPATCH_FAILURE;
    clean.ops.protocol_context = NULL;
    clean.ops.shall_disconnect = NULL;
    clean.ops.clean_peer_disconnect = NULL;
    RFB_CHECK(rdp_mt_run_with_ops(
                  &clean.cfg, NULL, NULL,
                  &clean.ops).code == FARSEE_ERR_CONNECT_FAILURE);
    RFB_CHECK_EQ_UINT(clean.fake.pump_calls, 1u);
    fixture_destroy(&clean);

    fixture present;
    RFB_CHECK(fixture_init(&present));
    present.cfg.ctx = ctx;
    present.fake.worker = FAKE_PRESENT;
    present.ops.present_bgra = NULL;
    farsee_mt_outcome outcome;
    RFB_CHECK(rdp_mt_run_with_ops(
                  &present.cfg, NULL, &outcome,
                  &present.ops).code == FARSEE_ERR_PRESENTER_FAILURE);
    RFB_CHECK(outcome.kind == FARSEE_MT_TERMINAL_PRESENTER_FAILURE);
    RFB_CHECK_EQ_UINT(present.fake.present_calls, 0u);
    fixture_destroy(&present);

    rdp_freerdp_destroy(&ctx);
}

RFB_TEST(rdp_mt_session,
         protocol__link_sampling_throttles_and_default_tcp_probe_is_safe)
{
    int sockets[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) {
        RFB_FAIL("cannot initialize local socket pair");
        return;
    }
    fixture f;
    RFB_CHECK(fixture_init(&f));
    f.fake.worker = FAKE_PROTOCOL;
    f.fake.disconnect_on = 3u;
    f.fake.mark_frame = true;
    f.fake.wire_stats_ok = true;
    f.fake.wire_in = 700u;
    f.fake.wire_fd = sockets[0];
    f.cfg.link_meta = &f.link_meta;
    f.cfg.link_rx_bytes = &f.link_rx;
    f.cfg.link_rate_pub = &f.link_rate;
    f.ops.tcp_stats = NULL;

    RFB_CHECK(rdp_mt_run_with_ops(
                  &f.cfg, NULL, NULL, &f.ops).code == FARSEE_E_OK);
    uint32_t rtt = 99u;
    bool have_rtt = true;
    bool have_rx = false;
    farsee_link_meta_unpack(farsee_atomic_u64_load(&f.link_meta),
                            &rtt, &have_rtt, &have_rx);
    RFB_CHECK_EQ_UINT(f.fake.wire_stats_calls, 1u);
    RFB_CHECK_EQ_UINT(f.fake.tcp_calls, 0u);
    RFB_CHECK_EQ_UINT(farsee_atomic_u64_load(&f.link_rx), 700u);
    RFB_CHECK(!have_rtt);
    RFB_CHECK(have_rx);
    fixture_destroy(&f);
    (void)close(sockets[0]);
    (void)close(sockets[1]);

    fixture incomplete;
    RFB_CHECK(fixture_init(&incomplete));
    incomplete.fake.worker = FAKE_PROTOCOL;
    incomplete.fake.disconnect_on = 2u;
    incomplete.fake.mark_frame = true;
    incomplete.cfg.link_meta = &incomplete.link_meta;
    incomplete.cfg.link_rx_bytes = NULL;
    RFB_CHECK(rdp_mt_run_with_ops(
                  &incomplete.cfg, NULL, NULL,
                  &incomplete.ops).code == FARSEE_E_OK);
    RFB_CHECK_EQ_UINT(incomplete.fake.wire_stats_calls, 0u);
    fixture_destroy(&incomplete);
}

RFB_TEST(rdp_mt_session,
         present_and_run__null_frame_and_default_threads_are_bounded)
{
    fixture null_frame;
    RFB_CHECK(fixture_init(&null_frame));
    null_frame.fake.worker = FAKE_PRESENT;
    null_frame.fake.pass_null_frame = true;
    farsee_mt_outcome outcome;
    RFB_CHECK(rdp_mt_run_with_ops(
                  &null_frame.cfg, NULL, &outcome,
                  &null_frame.ops).code == FARSEE_ERR_PRESENTER_FAILURE);
    RFB_CHECK(outcome.kind == FARSEE_MT_TERMINAL_PRESENTER_FAILURE);
    RFB_CHECK_EQ_UINT(null_frame.fake.present_calls, 0u);
    RFB_CHECK_EQ_UINT(null_frame.fake.after_calls, 1u);
    fixture_destroy(&null_frame);

    rdp_freerdp_ctx *ctx = rdp_freerdp_create();
    if (ctx == NULL) {
        RFB_FAIL("cannot initialize FreeRDP context");
        return;
    }
    fixture threaded;
    RFB_CHECK(fixture_init(&threaded));
    threaded.cfg.ctx = ctx;
    farsee_atomic_int_store(&threaded.stop, 1);
    bool got_frame = true;
    memset(&outcome, 0, sizeof outcome);
    RFB_CHECK(rdp_mt_run_with_ops(
                  &threaded.cfg, &got_frame, &outcome,
                  NULL).code == FARSEE_E_OK);
    RFB_CHECK(outcome.kind == FARSEE_MT_TERMINAL_REQUESTED_STOP);
    RFB_CHECK(!got_frame);
    RFB_CHECK_EQ_UINT(threaded.fake.input_calls, 1u);
    fixture_destroy(&threaded);
    rdp_freerdp_destroy(&ctx);
}

RFB_TEST(rdp_mt_session,
         run__noncore_error_and_peer_close_allow_null_outcomes)
{
    fixture core_error;
    RFB_CHECK(fixture_init(&core_error));
    core_error.fake.worker = FAKE_NONE;
    core_error.fake.run_kind = FARSEE_MT_TERMINAL_INPUT_FAILURE;
    core_error.fake.run_error = farsee_error_make(
        FARSEE_ERR_LOCAL_IO_FAILURE, FARSEE_SUB_INPUT,
        FARSEE_PHASE_ACTIVE);
    const farsee_error error = rdp_mt_run_with_ops(
        &core_error.cfg, NULL, NULL, &core_error.ops);
    RFB_CHECK(error.code == FARSEE_ERR_LOCAL_IO_FAILURE);
    RFB_CHECK(error.subsystem == FARSEE_SUB_INPUT);
    fixture_destroy(&core_error);

    fixture peer;
    RFB_CHECK(fixture_init(&peer));
    peer.fake.worker = FAKE_PROTOCOL;
    peer.fake.disconnect_on = 1u;
    RFB_CHECK(rdp_mt_run_with_ops(
                  &peer.cfg, NULL, NULL,
                  &peer.ops).code == FARSEE_ERR_CONNECT_FAILURE);
    fixture_destroy(&peer);
}

RFB_TEST(rdp_mt_session,
         protocol__release_without_ledger_clears_remote_buttons)
{
    fixture f;
    RFB_CHECK(fixture_init(&f));
    f.cfg.ledger = NULL;

    rdp_inj_cmd pointer;
    memset(&pointer, 0, sizeof pointer);
    pointer.kind = RDP_INJ_POINTER;
    pointer.pe.abs_x = 23;
    pointer.pe.abs_y = 29;
    pointer.pe.buttons = FARSEE_BUTTON_LEFT;
    RFB_CHECK(rdp_inj_queue_push(&f.inj, &pointer));

    rdp_inj_cmd release;
    memset(&release, 0, sizeof release);
    release.kind = RDP_INJ_RELEASE_ALL;
    RFB_CHECK(rdp_inj_queue_push(&f.inj, &release));

    RFB_CHECK(fixture_run_protocol(&f, NULL).code == FARSEE_E_OK);
    RFB_CHECK_EQ_UINT(f.fake.release_calls, 0u);
    RFB_CHECK_EQ_UINT(f.fake.pointer_calls, 2u);
    RFB_CHECK_EQ_UINT(f.fake.last_previous_buttons, FARSEE_BUTTON_LEFT);
    RFB_CHECK_EQ_UINT(f.fake.last_pointer.buttons, 0u);
    RFB_CHECK_EQ_UINT(f.wire_buttons, 0u);
    fixture_destroy(&f);
}

RFB_TEST(rdp_mt_session,
         protocol__default_pump_on_unconnected_context_fails_closed)
{
    rdp_freerdp_ctx *ctx = rdp_freerdp_create();
    if (ctx == NULL) {
        RFB_FAIL("cannot initialize FreeRDP context");
        return;
    }
    fixture f;
    RFB_CHECK(fixture_init(&f));
    f.cfg.ctx = ctx;
    f.fake.worker = FAKE_PROTOCOL;
    f.fake.accept_foreign_context = true;
    f.fake.disconnect_on = 2u;
    f.fake.clean_disconnect = false;
    f.fake.mark_frame = true;
    f.ops.protocol_context = NULL;
    f.ops.pump_once = NULL;

    farsee_mt_outcome outcome;
    const farsee_error error =
        rdp_mt_run_with_ops(&f.cfg, NULL, &outcome, &f.ops);
    RFB_CHECK(error.code == FARSEE_ERR_PROTOCOL_VIOLATION);
    RFB_CHECK(outcome.kind == FARSEE_MT_TERMINAL_PROTOCOL_FAILURE);
    RFB_CHECK_EQ_UINT(f.fake.pump_calls, 0u);
    fixture_destroy(&f);
    rdp_freerdp_destroy(&ctx);
}

RFB_TEST(rdp_mt_session,
         protocol__default_wire_probes_publish_missing_sample)
{
    rdp_freerdp_ctx *ctx = rdp_freerdp_create();
    if (ctx == NULL) {
        RFB_FAIL("cannot initialize FreeRDP context");
        return;
    }
    fixture f;
    RFB_CHECK(fixture_init(&f));
    f.cfg.ctx = ctx;
    f.fake.worker = FAKE_PROTOCOL;
    f.fake.accept_foreign_context = true;
    f.fake.disconnect_on = 2u;
    f.fake.mark_frame = true;
    f.cfg.link_meta = &f.link_meta;
    f.cfg.link_rx_bytes = &f.link_rx;
    f.cfg.link_rate_pub = &f.link_rate;
    f.ops.protocol_context = NULL;
    f.ops.wire_stats = NULL;
    f.ops.wire_fd = NULL;

    RFB_CHECK(rdp_mt_run_with_ops(
                  &f.cfg, NULL, NULL, &f.ops).code == FARSEE_E_OK);
    uint32_t rtt = 99u;
    bool have_rtt = true;
    bool have_rx = true;
    farsee_link_meta_unpack(farsee_atomic_u64_load(&f.link_meta),
                            &rtt, &have_rtt, &have_rx);
    RFB_CHECK_EQ_UINT(f.fake.wire_stats_calls, 0u);
    RFB_CHECK_EQ_UINT(f.fake.tcp_calls, 0u);
    RFB_CHECK_EQ_UINT(farsee_atomic_u64_load(&f.link_rx), 0u);
    RFB_CHECK_EQ_UINT(farsee_atomic_u64_load(&f.link_rate), 0u);
    RFB_CHECK_EQ_UINT(rtt, 0u);
    RFB_CHECK(!have_rtt);
    RFB_CHECK(!have_rx);
    fixture_destroy(&f);
    rdp_freerdp_destroy(&ctx);
}

RFB_TEST(rdp_mt_session,
         run__partial_ops_use_default_thread_owner)
{
    fixture f;
    RFB_CHECK(fixture_init(&f));
    f.ops.run_threads = NULL;
    farsee_atomic_int_store(&f.stop, 1);

    bool got_frame = false;
    farsee_mt_outcome outcome;
    const farsee_error error =
        rdp_mt_run_with_ops(&f.cfg, &got_frame, &outcome, &f.ops);
    RFB_CHECK(error.code == FARSEE_E_OK);
    RFB_CHECK(outcome.kind == FARSEE_MT_TERMINAL_REQUESTED_STOP);
    RFB_CHECK(got_frame);
    RFB_CHECK_EQ_UINT(f.fake.present_calls, 1u);
    RFB_CHECK_EQ_UINT(f.fake.input_calls, 1u);
    fixture_destroy(&f);
}

#endif  // FARSEE_WITH_RDP
