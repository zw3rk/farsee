// SPDX-License-Identifier: Apache-2.0
//
// RFB session input-owner wire and state-admission tests.

#include "rfb_test.h"

#include "farsee/allocator.h"
#include "farsee/buffer.h"
#include "farsee/farsee_cmd_queue.h"
#include "farsee/farsee_input.h"
#include "farsee/input.h"
#include "farsee/limits.h"
#include "rfb/rfb_session_internal.h"

#include <string.h>

typedef struct input_capture {
    uint8_t bytes[1024];
    size_t length;
    size_t writes;
    size_t write_limit;
    bool reject_key_release;
} input_capture;

static rfb_io_result capture_write(void *opaque, const uint8_t *data,
                                   size_t length, size_t *written)
{
    input_capture *capture = (input_capture *)opaque;
    if (capture == NULL || data == NULL || written == NULL ||
        length > sizeof capture->bytes - capture->length) {
        return RFB_IO_ERROR;
    }
    if (capture->writes >= capture->write_limit) {
        *written = 0u;
        return RFB_IO_ERROR;
    }
    if (capture->reject_key_release && length >= 2u && data[0] == 4u &&
        data[1] == 0u) {
        *written = 0u;
        return RFB_IO_ERROR;
    }
    memcpy(capture->bytes + capture->length, data, length);
    capture->length += length;
    capture->writes++;
    *written = length;
    return RFB_IO_OK;
}

static bool input_session_init(rfb_session *session, farsee_cmd_queue *queue,
                               input_capture *capture, size_t output_limit)
{
    if (!farsee_cmd_queue_init(queue)) {
        return false;
    }
    memset(capture, 0, sizeof *capture);
    capture->write_limit = SIZE_MAX;
    rfb_session_clear(session);
    session->alloc = rfb_default_allocator();
    rfb_buffer_init(&session->in, session->alloc, RFB_LIMIT_FB_BYTES_POLICY);
    rfb_buffer_init(&session->out, session->alloc, output_limit);
    session->io.write = capture_write;
    session->io.ctx = capture;
    session->io_open = true;
    session->active = true;
    session->cfg.cmds = queue;
    farsee_key_ledger_init(&session->key_ledger);
    return true;
}

static bool ledger_contains(const farsee_key_ledger *ledger,
                            farsee_physical_key key)
{
    for (size_t i = 0u; i < ledger->count; i++) {
        if (ledger->down[i] == key) {
            return true;
        }
    }
    return false;
}

static void input_session_destroy(rfb_session *session,
                                  farsee_cmd_queue *queue)
{
    session->active = false;
    rfb_session_destroy(session);
    farsee_cmd_queue_destroy(queue);
}

RFB_TEST(rfb_session_input, cleartext_key_and_pointer__exact_wire_and_state)
{
    unsigned char storage[16384];
    RFB_CHECK(rfb_session_size() <= sizeof storage);
    rfb_session *session = (rfb_session *)(void *)storage;
    farsee_cmd_queue queue;
    input_capture capture;
    if (!input_session_init(session, &queue, &capture,
                            RFB_LIMIT_OUTBOUND_BYTES)) {
        RFB_CHECK(false);
        return;
    }

    farsee_cmd key;
    memset(&key, 0, sizeof key);
    key.kind = FARSEE_CMD_KEY;
    key.key.logical = 0x61u;
    key.key.action = FARSEE_KEY_PRESS;
    RFB_CHECK(farsee_cmd_queue_push(&queue, &key));

    farsee_cmd pointer;
    memset(&pointer, 0, sizeof pointer);
    pointer.kind = FARSEE_CMD_POINTER;
    pointer.pe.abs_x = 19;
    pointer.pe.abs_y = 31;
    pointer.pe.buttons = FARSEE_BUTTON_LEFT;
    RFB_CHECK(farsee_cmd_queue_push(&queue, &pointer));

    RFB_CHECK_EQ_INT(rfb_session_internal_drain_cmds(session), RFB_OK);
    static const uint8_t expected[] = {
        4u, 1u, 0u, 0u, 0u, 0u, 0u, 0x61u,
        5u, RFB_BUTTON_LEFT, 0u, 19u, 0u, 31u,
    };
    RFB_CHECK_EQ_UINT(capture.length, sizeof expected);
    RFB_CHECK(memcmp(capture.bytes, expected, sizeof expected) == 0);
    RFB_CHECK_EQ_UINT(session->key_ledger.count, 1u);
    RFB_CHECK_EQ_UINT(session->held_buttons, FARSEE_BUTTON_LEFT);
    RFB_CHECK_EQ_UINT(session->last_ptr_x, 19u);
    RFB_CHECK_EQ_UINT(session->last_ptr_y, 31u);

    input_session_destroy(session, &queue);
}

RFB_TEST(rfb_session_input, view_only__rejects_queued_input_without_state)
{
    unsigned char storage[16384];
    RFB_CHECK(rfb_session_size() <= sizeof storage);
    rfb_session *session = (rfb_session *)(void *)storage;
    farsee_cmd_queue queue;
    input_capture capture;
    if (!input_session_init(session, &queue, &capture,
                            RFB_LIMIT_OUTBOUND_BYTES)) {
        RFB_CHECK(false);
        return;
    }
    session->cfg.view_only = true;
    session->held_buttons = FARSEE_BUTTON_RIGHT;
    session->last_ptr_x = 7u;
    session->last_ptr_y = 8u;

    farsee_cmd key;
    memset(&key, 0, sizeof key);
    key.kind = FARSEE_CMD_KEY;
    key.key.logical = 0x61u;
    key.key.action = FARSEE_KEY_PRESS;
    RFB_CHECK(farsee_cmd_queue_push(&queue, &key));

    RFB_CHECK_EQ_INT(rfb_session_internal_drain_cmds(session), RFB_OK);
    RFB_CHECK_EQ_UINT(capture.length, 0u);
    RFB_CHECK_EQ_UINT(session->key_ledger.count, 0u);
    RFB_CHECK_EQ_UINT(session->held_buttons, FARSEE_BUTTON_RIGHT);
    RFB_CHECK_EQ_UINT(session->last_ptr_x, 7u);
    RFB_CHECK_EQ_UINT(session->last_ptr_y, 8u);

    input_session_destroy(session, &queue);
}

RFB_TEST(rfb_session_input, output_limit__preserves_pointer_state)
{
    unsigned char storage[16384];
    RFB_CHECK(rfb_session_size() <= sizeof storage);
    rfb_session *session = (rfb_session *)(void *)storage;
    farsee_cmd_queue queue;
    input_capture capture;
    if (!input_session_init(session, &queue, &capture, 5u)) {
        RFB_CHECK(false);
        return;
    }
    session->held_buttons = FARSEE_BUTTON_RIGHT;
    session->last_ptr_x = 7u;
    session->last_ptr_y = 8u;

    farsee_cmd pointer;
    memset(&pointer, 0, sizeof pointer);
    pointer.kind = FARSEE_CMD_POINTER;
    pointer.pe.abs_x = 19;
    pointer.pe.abs_y = 31;
    pointer.pe.buttons = FARSEE_BUTTON_LEFT;
    RFB_CHECK(farsee_cmd_queue_push(&queue, &pointer));

    RFB_CHECK_EQ_INT(rfb_session_internal_drain_cmds(session), RFB_ERR_LIMIT);
    RFB_CHECK_EQ_UINT(capture.length, 0u);
    RFB_CHECK_EQ_UINT(session->held_buttons, FARSEE_BUTTON_RIGHT);
    RFB_CHECK_EQ_UINT(session->last_ptr_x, 7u);
    RFB_CHECK_EQ_UINT(session->last_ptr_y, 8u);

    input_session_destroy(session, &queue);
}

RFB_TEST(rfb_session_input, output_limit__preserves_key_ledger)
{
    unsigned char storage[16384];
    RFB_CHECK(rfb_session_size() <= sizeof storage);
    rfb_session *session = (rfb_session *)(void *)storage;
    farsee_cmd_queue queue;
    input_capture capture;
    if (!input_session_init(session, &queue, &capture, 7u)) {
        RFB_CHECK(false);
        return;
    }

    farsee_cmd key;
    memset(&key, 0, sizeof key);
    key.kind = FARSEE_CMD_KEY;
    key.key.logical = 0x61u;
    key.key.action = FARSEE_KEY_PRESS;
    RFB_CHECK(farsee_cmd_queue_push(&queue, &key));

    RFB_CHECK_EQ_INT(rfb_session_internal_drain_cmds(session), RFB_ERR_LIMIT);
    RFB_CHECK_EQ_UINT(capture.length, 0u);
    RFB_CHECK_EQ_UINT(session->key_ledger.count, 0u);

    input_session_destroy(session, &queue);
}

RFB_TEST(rfb_session_input, release_all_failure__preserves_unsent_keys)
{
    unsigned char storage[16384];
    RFB_CHECK(rfb_session_size() <= sizeof storage);
    rfb_session *session = (rfb_session *)(void *)storage;
    farsee_cmd_queue queue;
    input_capture capture;
    if (!input_session_init(session, &queue, &capture, 7u)) {
        RFB_CHECK(false);
        return;
    }

    farsee_key_event down;
    memset(&down, 0, sizeof down);
    down.action = FARSEE_KEY_PRESS;
    down.physical = 0x61u;
    RFB_CHECK(farsee_key_ledger_apply(&session->key_ledger, &down));
    down.physical = 0x62u;
    RFB_CHECK(farsee_key_ledger_apply(&session->key_ledger, &down));

    farsee_cmd release;
    memset(&release, 0, sizeof release);
    release.kind = FARSEE_CMD_RELEASE_ALL;
    RFB_CHECK(farsee_cmd_queue_push(&queue, &release));

    RFB_CHECK_EQ_INT(rfb_session_internal_drain_cmds(session), RFB_ERR_LIMIT);
    RFB_CHECK_EQ_UINT(session->key_ledger.count, 2u);
    RFB_CHECK(ledger_contains(&session->key_ledger, 0x61u));
    RFB_CHECK(ledger_contains(&session->key_ledger, 0x62u));

    input_session_destroy(session, &queue);
}

RFB_TEST(rfb_session_input, release_all_partial_failure__retains_unsent_keys)
{
    unsigned char storage[16384];
    RFB_CHECK(rfb_session_size() <= sizeof storage);
    rfb_session *session = (rfb_session *)(void *)storage;
    farsee_cmd_queue queue;
    input_capture capture;
    if (!input_session_init(session, &queue, &capture,
                            RFB_LIMIT_OUTBOUND_BYTES)) {
        RFB_CHECK(false);
        return;
    }
    capture.write_limit = 1u;
    for (uint32_t key = 0x61u; key <= 0x63u; key++) {
        farsee_key_event down;
        memset(&down, 0, sizeof down);
        down.action = FARSEE_KEY_PRESS;
        down.physical = key;
        RFB_CHECK(farsee_key_ledger_apply(&session->key_ledger, &down));
    }

    farsee_cmd release;
    memset(&release, 0, sizeof release);
    release.kind = FARSEE_CMD_RELEASE_ALL;
    RFB_CHECK(farsee_cmd_queue_push(&queue, &release));

    RFB_CHECK_EQ_INT(rfb_session_internal_drain_cmds(session), RFB_ERR_IO);
    static const uint8_t first_release[] = {
        4u, 0u, 0u, 0u, 0u, 0u, 0u, 0x61u,
    };
    RFB_CHECK_EQ_UINT(capture.length, sizeof first_release);
    RFB_CHECK_MEM_EQ(capture.bytes, first_release, sizeof first_release);
    RFB_CHECK_EQ_UINT(session->key_ledger.count, 2u);
    RFB_CHECK(!ledger_contains(&session->key_ledger, 0x61u));
    RFB_CHECK(ledger_contains(&session->key_ledger, 0x62u));
    RFB_CHECK(ledger_contains(&session->key_ledger, 0x63u));

    input_session_destroy(session, &queue);
}

RFB_TEST(rfb_session_input, ledger_full_release_failure__sends_no_new_key)
{
    unsigned char storage[16384];
    RFB_CHECK(rfb_session_size() <= sizeof storage);
    rfb_session *session = (rfb_session *)(void *)storage;
    farsee_cmd_queue queue;
    input_capture capture;
    if (!input_session_init(session, &queue, &capture,
                            RFB_LIMIT_OUTBOUND_BYTES)) {
        RFB_CHECK(false);
        return;
    }
    capture.reject_key_release = true;
    for (uint32_t i = 0u; i < FARSEE_KEY_LEDGER_MAX; i++) {
        farsee_key_event down;
        memset(&down, 0, sizeof down);
        down.action = FARSEE_KEY_PRESS;
        down.physical = 0x1100u + i;
        RFB_CHECK(farsee_key_ledger_apply(&session->key_ledger, &down));
    }

    farsee_cmd key;
    memset(&key, 0, sizeof key);
    key.kind = FARSEE_CMD_KEY;
    key.key.logical = 0xff01u;
    key.key.action = FARSEE_KEY_PRESS;
    RFB_CHECK(farsee_cmd_queue_push(&queue, &key));

    RFB_CHECK_EQ_INT(rfb_session_internal_drain_cmds(session), RFB_ERR_IO);
    RFB_CHECK_EQ_UINT(capture.length, 0u);
    RFB_CHECK_EQ_UINT(session->key_ledger.count, FARSEE_KEY_LEDGER_MAX);
    RFB_CHECK(!ledger_contains(&session->key_ledger, 0xff01u));
    RFB_CHECK(ledger_contains(&session->key_ledger, 0x1100u));
    RFB_CHECK(ledger_contains(
        &session->key_ledger, 0x1100u + FARSEE_KEY_LEDGER_MAX - 1u));

    input_session_destroy(session, &queue);
}

RFB_TEST(rfb_session_input, ledger_full__releases_before_new_key_down)
{
    unsigned char storage[16384];
    RFB_CHECK(rfb_session_size() <= sizeof storage);
    rfb_session *session = (rfb_session *)(void *)storage;
    farsee_cmd_queue queue;
    input_capture capture;
    if (!input_session_init(session, &queue, &capture,
                            RFB_LIMIT_OUTBOUND_BYTES)) {
        RFB_CHECK(false);
        return;
    }
    for (uint32_t i = 0u; i < FARSEE_KEY_LEDGER_MAX; i++) {
        farsee_key_event down;
        memset(&down, 0, sizeof down);
        down.action = FARSEE_KEY_PRESS;
        down.physical = 0x1100u + i;
        RFB_CHECK(farsee_key_ledger_apply(&session->key_ledger, &down));
    }

    farsee_cmd key;
    memset(&key, 0, sizeof key);
    key.kind = FARSEE_CMD_KEY;
    key.key.logical = 0xff01u;
    key.key.action = FARSEE_KEY_PRESS;
    RFB_CHECK(farsee_cmd_queue_push(&queue, &key));

    RFB_CHECK_EQ_INT(rfb_session_internal_drain_cmds(session), RFB_OK);
    RFB_CHECK_EQ_UINT(capture.length,
                      (FARSEE_KEY_LEDGER_MAX + 1u) * 8u);
    for (uint32_t i = 0u; i < FARSEE_KEY_LEDGER_MAX; i++) {
        const uint8_t *message = capture.bytes + (size_t)i * 8u;
        RFB_CHECK_EQ_UINT(message[0], 4u);
        RFB_CHECK_EQ_UINT(message[1], 0u);
        const uint32_t keysym = ((uint32_t)message[4] << 24) |
                                ((uint32_t)message[5] << 16) |
                                ((uint32_t)message[6] << 8) |
                                (uint32_t)message[7];
        RFB_CHECK_EQ_UINT(keysym, 0x1100u + i);
    }
    const uint8_t *new_key =
        capture.bytes + (size_t)FARSEE_KEY_LEDGER_MAX * 8u;
    static const uint8_t expected_new_key[] = {
        4u, 1u, 0u, 0u, 0u, 0u, 0xffu, 0x01u,
    };
    RFB_CHECK_MEM_EQ(new_key, expected_new_key, sizeof expected_new_key);
    RFB_CHECK_EQ_UINT(session->key_ledger.count, 1u);
    RFB_CHECK(ledger_contains(&session->key_ledger, 0xff01u));

    input_session_destroy(session, &queue);
}

RFB_TEST(rfb_session_input,
         pointer_format__clamps_coordinates_buttons_and_wheel_floods)
{
    farsee_pointer_event pointer;
    memset(&pointer, 0, sizeof pointer);
    pointer.abs_x = -1;
    pointer.abs_y = 0x10000;
    pointer.buttons = FARSEE_BUTTON_MIDDLE | FARSEE_BUTTON_RIGHT;
    uint8_t output[768];

    RFB_CHECK_EQ_UINT(rfb_session_format_pointer_events(
                          &pointer, output, sizeof output), 6u);
    static const uint8_t clamped[] = {
        5u, RFB_BUTTON_MIDDLE | RFB_BUTTON_RIGHT,
        0u, 0u, 0xffu, 0xffu,
    };
    RFB_CHECK_MEM_EQ(output, clamped, sizeof clamped);

    pointer.abs_x = 7;
    pointer.abs_y = 9;
    pointer.wheel_v = 33 * 120;
    pointer.wheel_h = -33 * 120;
    RFB_CHECK_EQ_UINT(rfb_session_format_pointer_events(
                          &pointer, output, sizeof output), sizeof output);
    const uint8_t held = RFB_BUTTON_MIDDLE | RFB_BUTTON_RIGHT;
    RFB_CHECK_EQ_UINT(output[1], held | RFB_BUTTON_WHEEL_UP);
    RFB_CHECK_EQ_UINT(output[7], held);
    RFB_CHECK_EQ_UINT(output[385], held | RFB_BUTTON_WHEEL_LEFT);
    RFB_CHECK_EQ_UINT(output[763], held);

    pointer.wheel_v = -33 * 120;
    pointer.wheel_h = 33 * 120;
    RFB_CHECK_EQ_UINT(rfb_session_format_pointer_events(
                          &pointer, output, sizeof output), sizeof output);
    RFB_CHECK_EQ_UINT(output[1], held | RFB_BUTTON_WHEEL_DN);
    RFB_CHECK_EQ_UINT(output[385], held | RFB_BUTTON_WHEEL_RIGHT);
    RFB_CHECK_EQ_UINT(output[763], held);
}

RFB_TEST(rfb_session_input,
         drain__null_queue_and_tick_cap_are_bounded)
{
    RFB_CHECK_EQ_INT(rfb_session_internal_drain_cmds(NULL),
                     RFB_ERR_INTERNAL);

    unsigned char storage[16384];
    RFB_CHECK(rfb_session_size() <= sizeof storage);
    rfb_session *session = (rfb_session *)(void *)storage;
    farsee_cmd_queue queue;
    input_capture capture;
    if (!input_session_init(session, &queue, &capture,
                            RFB_LIMIT_OUTBOUND_BYTES)) {
        RFB_CHECK(false);
        return;
    }
    session->cfg.cmds = NULL;
    RFB_CHECK_EQ_INT(rfb_session_internal_drain_cmds(session), RFB_OK);
    session->cfg.cmds = &queue;

    farsee_cmd key;
    memset(&key, 0, sizeof key);
    key.kind = FARSEE_CMD_KEY;
    key.key.unicode = 0x62u;
    key.key.action = FARSEE_KEY_PRESS;
    for (unsigned i = 0u; i < 33u; i++) {
        RFB_CHECK(farsee_cmd_queue_push(&queue, &key));
    }

    RFB_CHECK_EQ_INT(rfb_session_internal_drain_cmds(session), RFB_OK);
    RFB_CHECK_EQ_UINT(capture.length, 32u * 8u);
    RFB_CHECK_EQ_UINT(session->key_ledger.count, 1u);
    RFB_CHECK(ledger_contains(&session->key_ledger, 0x62u));
    RFB_CHECK_EQ_INT(rfb_session_internal_drain_cmds(session), RFB_OK);
    RFB_CHECK_EQ_UINT(capture.length, 33u * 8u);
    RFB_CHECK_EQ_UINT(session->key_ledger.count, 1u);

    input_session_destroy(session, &queue);
}

RFB_TEST(rfb_session_input,
         drain__wheel_caps_and_invalid_coordinates_preserve_position)
{
    unsigned char storage[16384];
    RFB_CHECK(rfb_session_size() <= sizeof storage);
    rfb_session *session = (rfb_session *)(void *)storage;
    farsee_cmd_queue queue;
    input_capture capture;
    if (!input_session_init(session, &queue, &capture,
                            RFB_LIMIT_OUTBOUND_BYTES)) {
        RFB_CHECK(false);
        return;
    }
    session->last_ptr_x = 11u;
    session->last_ptr_y = 13u;

    farsee_cmd pointer;
    memset(&pointer, 0, sizeof pointer);
    pointer.kind = FARSEE_CMD_POINTER;
    pointer.pe.abs_x = -1;
    pointer.pe.abs_y = 0x10000;
    pointer.pe.wheel_v = 5 * 120;
    pointer.pe.wheel_h = -5 * 120;
    RFB_CHECK(farsee_cmd_queue_push(&queue, &pointer));

    pointer.pe.abs_x = 42;
    pointer.pe.abs_y = 43;
    pointer.pe.wheel_v = -5 * 120;
    pointer.pe.wheel_h = 5 * 120;
    RFB_CHECK(farsee_cmd_queue_push(&queue, &pointer));

    pointer.pe.wheel_v = 0;
    pointer.pe.wheel_h = 0;
    pointer.pe.abs_x = 0x10000;
    pointer.pe.abs_y = 44;
    RFB_CHECK(farsee_cmd_queue_push(&queue, &pointer));
    pointer.pe.abs_x = 45;
    pointer.pe.abs_y = -1;
    RFB_CHECK(farsee_cmd_queue_push(&queue, &pointer));
    pointer.pe.abs_x = 46;
    pointer.pe.abs_y = 0x10000;
    RFB_CHECK(farsee_cmd_queue_push(&queue, &pointer));

    RFB_CHECK_EQ_INT(rfb_session_internal_drain_cmds(session), RFB_OK);
    RFB_CHECK_EQ_UINT(capture.length, 2u * 96u + 3u * 6u);
    RFB_CHECK_EQ_UINT(capture.bytes[1], RFB_BUTTON_WHEEL_UP);
    RFB_CHECK_EQ_UINT(capture.bytes[49], RFB_BUTTON_WHEEL_LEFT);
    RFB_CHECK_EQ_UINT(capture.bytes[97], RFB_BUTTON_WHEEL_DN);
    RFB_CHECK_EQ_UINT(capture.bytes[145], RFB_BUTTON_WHEEL_RIGHT);
    RFB_CHECK_EQ_UINT(session->last_ptr_x, 42u);
    RFB_CHECK_EQ_UINT(session->last_ptr_y, 43u);
    RFB_CHECK_EQ_UINT(session->held_buttons, 0u);

    input_session_destroy(session, &queue);
}

RFB_TEST(rfb_session_input,
         drain__duplicate_full_ledger_key_does_not_release_ownership)
{
    unsigned char storage[16384];
    RFB_CHECK(rfb_session_size() <= sizeof storage);
    rfb_session *session = (rfb_session *)(void *)storage;
    farsee_cmd_queue queue;
    input_capture capture;
    if (!input_session_init(session, &queue, &capture,
                            RFB_LIMIT_OUTBOUND_BYTES)) {
        RFB_CHECK(false);
        return;
    }
    for (uint32_t i = 0u; i < FARSEE_KEY_LEDGER_MAX; i++) {
        farsee_key_event down;
        memset(&down, 0, sizeof down);
        down.action = FARSEE_KEY_PRESS;
        down.physical = 0x1200u + i;
        RFB_CHECK(farsee_key_ledger_apply(&session->key_ledger, &down));
    }

    farsee_cmd key;
    memset(&key, 0, sizeof key);
    key.kind = FARSEE_CMD_KEY;
    key.key.logical = 0x1200u;
    key.key.action = FARSEE_KEY_PRESS;
    RFB_CHECK(farsee_cmd_queue_push(&queue, &key));

    RFB_CHECK_EQ_INT(rfb_session_internal_drain_cmds(session), RFB_OK);
    static const uint8_t expected[] = {
        4u, 1u, 0u, 0u, 0u, 0u, 0x12u, 0u,
    };
    RFB_CHECK_EQ_UINT(capture.length, sizeof expected);
    RFB_CHECK_MEM_EQ(capture.bytes, expected, sizeof expected);
    RFB_CHECK_EQ_UINT(session->key_ledger.count, FARSEE_KEY_LEDGER_MAX);
    RFB_CHECK(ledger_contains(&session->key_ledger, 0x1200u));

    input_session_destroy(session, &queue);
}

RFB_TEST(rfb_session_input,
         release_held__guards_failures_and_oversize_ledger_are_bounded)
{
    rfb_session_release_held_inputs(NULL);

    unsigned char guard_storage[16384];
    RFB_CHECK(rfb_session_size() <= sizeof guard_storage);
    rfb_session *guard = (rfb_session *)(void *)guard_storage;
    farsee_cmd_queue guard_queue;
    input_capture guard_capture;
    if (!input_session_init(guard, &guard_queue, &guard_capture,
                            RFB_LIMIT_OUTBOUND_BYTES)) {
        RFB_CHECK(false);
        return;
    }
    guard->io_open = false;
    guard->held_buttons = FARSEE_BUTTON_RIGHT;
    rfb_session_release_held_inputs(guard);
    RFB_CHECK_EQ_UINT(guard_capture.length, 0u);
    RFB_CHECK_EQ_UINT(guard->held_buttons, FARSEE_BUTTON_RIGHT);
    guard->io_open = true;
    input_session_destroy(guard, &guard_queue);

    unsigned char key_storage[16384];
    rfb_session *key_failure = (rfb_session *)(void *)key_storage;
    farsee_cmd_queue key_queue;
    input_capture key_capture;
    if (!input_session_init(key_failure, &key_queue, &key_capture, 7u)) {
        RFB_CHECK(false);
        return;
    }
    farsee_key_event down;
    memset(&down, 0, sizeof down);
    down.action = FARSEE_KEY_PRESS;
    down.physical = 0x61u;
    RFB_CHECK(farsee_key_ledger_apply(&key_failure->key_ledger, &down));
    key_failure->held_buttons = FARSEE_BUTTON_LEFT;
    key_failure->last_ptr_x = 21u;
    key_failure->last_ptr_y = 34u;
    rfb_session_release_held_inputs(key_failure);
    RFB_CHECK_EQ_UINT(key_failure->key_ledger.count, 1u);
    RFB_CHECK_EQ_UINT(key_failure->held_buttons, 0u);
    static const uint8_t pointer_release[] = {
        5u, 0u, 0u, 21u, 0u, 34u,
    };
    RFB_CHECK_EQ_UINT(key_capture.length, sizeof pointer_release);
    RFB_CHECK_MEM_EQ(key_capture.bytes, pointer_release,
                     sizeof pointer_release);
    input_session_destroy(key_failure, &key_queue);

    unsigned char pointer_storage[16384];
    rfb_session *pointer_failure = (rfb_session *)(void *)pointer_storage;
    farsee_cmd_queue pointer_queue;
    input_capture pointer_capture;
    if (!input_session_init(pointer_failure, &pointer_queue,
                            &pointer_capture, 5u)) {
        RFB_CHECK(false);
        return;
    }
    pointer_failure->held_buttons = FARSEE_BUTTON_MIDDLE;
    rfb_session_release_held_inputs(pointer_failure);
    RFB_CHECK_EQ_UINT(pointer_capture.length, 0u);
    RFB_CHECK_EQ_UINT(pointer_failure->held_buttons,
                      FARSEE_BUTTON_MIDDLE);
    input_session_destroy(pointer_failure, &pointer_queue);

    unsigned char clamp_storage[16384];
    rfb_session *clamped = (rfb_session *)(void *)clamp_storage;
    farsee_cmd_queue clamp_queue;
    input_capture clamp_capture;
    if (!input_session_init(clamped, &clamp_queue, &clamp_capture,
                            RFB_LIMIT_OUTBOUND_BYTES)) {
        RFB_CHECK(false);
        return;
    }
    for (uint32_t i = 0u; i < FARSEE_KEY_LEDGER_MAX; i++) {
        clamped->key_ledger.down[i] = 0x1300u + i;
    }
    clamped->key_ledger.count = FARSEE_KEY_LEDGER_MAX + 1u;
    clamped->last_ptr_x = 55u;
    clamped->last_ptr_y = 89u;
    rfb_session_release_held_inputs(clamped);
    RFB_CHECK_EQ_UINT(clamped->key_ledger.count, 0u);
    RFB_CHECK_EQ_UINT(clamp_capture.length,
                      FARSEE_KEY_LEDGER_MAX * 8u + 6u);
    const uint8_t *last = clamp_capture.bytes + clamp_capture.length - 6u;
    static const uint8_t final_pointer[] = {
        5u, 0u, 0u, 55u, 0u, 89u,
    };
    RFB_CHECK_MEM_EQ(last, final_pointer, sizeof final_pointer);
    input_session_destroy(clamped, &clamp_queue);
}
