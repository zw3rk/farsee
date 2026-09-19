// SPDX-License-Identifier: Apache-2.0
//
// Product-path coverage for post-enable Apple CBC processing. The assertions
// use the product record layer, engine, scheduler, control drain, artifact
// writer, and outbound queue rather than a second test-only implementation.

#include "rfb_test.h"

#include "farsee/apple_mvs_bits.h"
#include "farsee/apple_record.h"
#include "farsee/apple_wire_record.h"
#include "farsee/error.h"
#include "farsee/encoding.h"
#include "farsee/farsee_atomic.h"
#include "farsee/io_adapter.h"
#include "farsee/rfb_capture_control.h"
#include "farsee/rfb_session.h"
#include "farsee/socket_posix.h"
#include "rfb/rfb_session_internal.h"
#include "rfb_session_capture_fixture.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <zlib.h>

#define APPLE_CAPTURE_TEST_IO_CAP 4096u
#define APPLE_CAPTURE_TEST_INITIAL_MAX 4u
#define APPLE_CAPTURE_TEST_RECT_CAP 5u
#define APPLE_CAPTURE_TEST_FINAL_CAP 2u
#define APPLE_CAPTURE_TEST_BASE_MS UINT64_C(1000)

static const uint8_t apple_capture_test_c2s_key[16] = {
    0x10u, 0x11u, 0x12u, 0x13u, 0x14u, 0x15u, 0x16u, 0x17u,
    0x18u, 0x19u, 0x1au, 0x1bu, 0x1cu, 0x1du, 0x1eu, 0x1fu,
};
static const uint8_t apple_capture_test_c2s_iv[16] = {
    0x20u, 0x21u, 0x22u, 0x23u, 0x24u, 0x25u, 0x26u, 0x27u,
    0x28u, 0x29u, 0x2au, 0x2bu, 0x2cu, 0x2du, 0x2eu, 0x2fu,
};
static const uint8_t apple_capture_test_s2c_key[16] = {
    0x30u, 0x31u, 0x32u, 0x33u, 0x34u, 0x35u, 0x36u, 0x37u,
    0x38u, 0x39u, 0x3au, 0x3bu, 0x3cu, 0x3du, 0x3eu, 0x3fu,
};
static const uint8_t apple_capture_test_s2c_iv[16] = {
    0x40u, 0x41u, 0x42u, 0x43u, 0x44u, 0x45u, 0x46u, 0x47u,
    0x48u, 0x49u, 0x4au, 0x4bu, 0x4cu, 0x4du, 0x4eu, 0x4fu,
};
static const uint8_t apple_capture_test_initial_fbur[10] = {
    0x03u, 0x00u, 0x00u, 0x00u, 0x00u,
    0x00u, 0x00u, 0x10u, 0x00u, 0x10u,
};
static const uint8_t apple_capture_test_target_fbur[10] = {
    0x03u, 0x01u, 0x00u, 0x00u, 0x00u,
    0x00u, 0x00u, 0x10u, 0x00u, 0x10u,
};
static const uint8_t apple_capture_test_initial_record_kat[34] = {
    0x00u, 0x20u, 0x82u, 0x6au, 0xc4u, 0x86u, 0x09u, 0x93u,
    0xe3u, 0x5cu, 0xcdu, 0xa2u, 0xfdu, 0x81u, 0xd6u, 0x46u,
    0xe4u, 0xbfu, 0x61u, 0x29u, 0x7fu, 0xfdu, 0xdeu, 0xfbu,
    0xbdu, 0x8cu, 0x69u, 0x97u, 0xa3u, 0x5bu, 0x11u, 0xc9u,
    0x78u, 0x64u,
};
static const uint8_t apple_capture_test_target_record_kat[34] = {
    0x00u, 0x20u, 0x01u, 0x96u, 0x4bu, 0x93u, 0xa5u, 0xb1u,
    0x4bu, 0x2au, 0xa4u, 0x1eu, 0xa6u, 0x07u, 0xfeu, 0x3fu,
    0x0au, 0xb5u, 0x4au, 0xedu, 0x60u, 0xbeu, 0x07u, 0xd6u,
    0xa2u, 0x5cu, 0x44u, 0x94u, 0xb7u, 0x55u, 0xc4u, 0x71u,
    0x7au, 0x86u,
};

typedef struct apple_capture_test_io {
    uint8_t inbox[APPLE_CAPTURE_TEST_IO_CAP];
    size_t inbox_len;
    uint8_t outbox[APPLE_CAPTURE_TEST_IO_CAP];
    size_t outbox_len;
    size_t write_chunk;
    size_t write_budget;
    size_t write_calls;
    size_t short_writes;
    size_t read_chunk;
    rfb_io_result empty_read_result;
    bool write_error;
    // Scripted peer that makes a response readable from inside the write
    // callback. This exercises a response that is ready before the caller
    // finishes accounting for the request bytes it just wrote, without using
    // wall-clock timing.
    uint8_t reply[APPLE_CAPTURE_TEST_IO_CAP];
    size_t reply_length;
    bool reply_armed;
    uint64_t reply_after_tx_bytes;
    size_t scripted_write_blocks;
    bool scripted_write_error_after_blocks;
    uint64_t *mutable_clock_ms;
    uint64_t read_clock_advance_ms;
    uint64_t write_clock_advance_ms;
    int wake_read_fd;
    int wake_write_fd;
    farsee_atomic_u64 tx_bytes;
} apple_capture_test_io;

typedef struct apple_capture_test_fixture {
    rfb_session *session;
    apple_capture_test_io io;
    int control[2];
    rfb_session_config config;
    rfb_capture_query query;
    rfb_capture_rect_observation_v1 rectangles[APPLE_CAPTURE_TEST_RECT_CAP];
    rfb_capture_final_observation_v1 finals[APPLE_CAPTURE_TEST_FINAL_CAP];
    uint8_t binding[RFB_CAPTURE_CONTROL_BINDING_SIZE];
    apple_record_layer server_records;
    bool server_records_initialized;
    uint64_t now_ms;
} apple_capture_test_fixture;

static bool apple_capture_test_expect_initial(
    apple_capture_test_fixture *fixture);

static bool apple_capture_test_seed_inbox(apple_capture_test_io *io,
                                          const uint8_t *data, size_t length);

static rfb_io_result apple_capture_test_io_connect(
    void *opaque, const rfb_io_candidate *candidate)
{
    (void)opaque;
    (void)candidate;
    return RFB_IO_OK;
}

static rfb_io_result apple_capture_test_io_read(
    void *opaque, uint8_t *out, size_t capacity, size_t *out_length)
{
    apple_capture_test_io *io = (apple_capture_test_io *)opaque;
    *out_length = 0u;
    if (io->inbox_len == 0u) {
        return io->empty_read_result;
    }
    if (io->mutable_clock_ms != NULL) {
        *io->mutable_clock_ms += io->read_clock_advance_ms;
    }
    const size_t count = capacity < io->inbox_len ? capacity : io->inbox_len;
    const size_t bounded_count =
        io->read_chunk != 0u && io->read_chunk < count
            ? io->read_chunk
            : count;
    memcpy(out, io->inbox, bounded_count);
    memmove(io->inbox, io->inbox + bounded_count,
            io->inbox_len - bounded_count);
    io->inbox_len -= bounded_count;
    if (io->inbox_len == 0u) {
        uint8_t wake = 0u;
        (void)recv(io->wake_read_fd, &wake, 1u, MSG_DONTWAIT);
    }
    *out_length = bounded_count;
    return RFB_IO_OK;
}

static rfb_io_result apple_capture_test_io_write(
    void *opaque, const uint8_t *data, size_t length, size_t *out_length)
{
    apple_capture_test_io *io = (apple_capture_test_io *)opaque;
    io->write_calls++;
    *out_length = 0u;
    if (io->mutable_clock_ms != NULL) {
        *io->mutable_clock_ms += io->write_clock_advance_ms;
    }
    if (io->scripted_write_blocks != 0u) {
        io->scripted_write_blocks--;
        return RFB_IO_BLOCK;
    }
    if (io->scripted_write_error_after_blocks) {
        return RFB_IO_ERROR;
    }
    if (io->write_error) {
        return RFB_IO_ERROR;
    }
    if (io->write_budget == 0u) {
        return RFB_IO_BLOCK;
    }
    size_t count = length;
    if (io->write_chunk != 0u && count > io->write_chunk) {
        count = io->write_chunk;
    }
    if (count > io->write_budget) {
        count = io->write_budget;
    }
    if (count > sizeof io->outbox - io->outbox_len) {
        return RFB_IO_ERROR;
    }
    memcpy(io->outbox + io->outbox_len, data, count);
    io->outbox_len += count;
    io->write_budget -= count;
    if (count < length) {
        io->short_writes++;
    }
    const uint64_t tx_total =
        farsee_atomic_u64_fetch_add(&io->tx_bytes, (uint64_t)count) +
        (uint64_t)count;
    if (io->reply_armed && tx_total >= io->reply_after_tx_bytes) {
        io->reply_armed = false;
        if (!apple_capture_test_seed_inbox(io, io->reply, io->reply_length)) {
            return RFB_IO_ERROR;
        }
    }
    *out_length = count;
    return RFB_IO_OK;
}

static void apple_capture_test_io_close(void *opaque)
{
    (void)opaque;
}

static rfb_io_adapter apple_capture_test_io_adapter(
    apple_capture_test_io *io)
{
    const rfb_io_adapter adapter = {
        .ctx = io,
        .connect = apple_capture_test_io_connect,
        .read = apple_capture_test_io_read,
        .write = apple_capture_test_io_write,
        .close = apple_capture_test_io_close,
    };
    return adapter;
}

static bool apple_capture_test_seed_inbox(apple_capture_test_io *io,
                                          const uint8_t *data, size_t length)
{
    if (length > sizeof io->inbox - io->inbox_len) {
        return false;
    }
    memcpy(io->inbox + io->inbox_len, data, length);
    io->inbox_len += length;
    const uint8_t wake = 1u;
    return send(io->wake_write_fd, &wake, 1u, MSG_DONTWAIT) == 1;
}

static bool apple_capture_test_wake_io(apple_capture_test_io *io)
{
    const uint8_t wake = 1u;
    return send(io->wake_write_fd, &wake, 1u, MSG_DONTWAIT) == 1;
}

static bool apple_capture_test_pop_record(
    apple_capture_test_fixture *fixture, uint8_t *plaintext,
    size_t plaintext_capacity, size_t *plaintext_length,
    size_t *wire_length)
{
    const size_t total = apple_wire_cipher_record_len(
        fixture->io.outbox, fixture->io.outbox_len, APPLE_RECORD_MAX_BODY);
    if (total == 0u || total == (size_t)-1) {
        return false;
    }
    const size_t ciphertext_length = total - 2u;
    if (apple_wire_record_open(
            &fixture->server_records, fixture->io.outbox + 2u,
            ciphertext_length, plaintext, plaintext_capacity,
            plaintext_length) != RFB_OK) {
        return false;
    }
    memmove(fixture->io.outbox, fixture->io.outbox + total,
            fixture->io.outbox_len - total);
    fixture->io.outbox_len -= total;
    *wire_length = total;
    return true;
}

static bool apple_capture_test_seal_plaintext(
    apple_capture_test_fixture *fixture, const uint8_t *message,
    size_t message_length, uint8_t *wire, size_t wire_capacity,
    size_t *wire_length)
{
    return apple_wire_record_seal(
               &fixture->server_records, message, message_length, wire,
               wire_capacity, wire_length) == RFB_OK;
}

static bool apple_capture_test_seed_plaintext(
    apple_capture_test_fixture *fixture, const uint8_t *message,
    size_t message_length)
{
    uint8_t wire[512];
    size_t wire_length = 0u;
    return apple_capture_test_seal_plaintext(
               fixture, message, message_length, wire, sizeof wire,
               &wire_length) &&
           apple_capture_test_seed_inbox(&fixture->io, wire, wire_length);
}

// Arm the scripted peer to seal `message` and make it readable as soon as the
// session's cumulative transmit count reaches `after_tx_bytes`.
static bool apple_capture_test_arm_reply(
    apple_capture_test_fixture *fixture, const uint8_t *message,
    size_t message_length, uint64_t after_tx_bytes)
{
    size_t wire_length = 0u;
    if (!apple_capture_test_seal_plaintext(
            fixture, message, message_length, fixture->io.reply,
            sizeof fixture->io.reply, &wire_length)) {
        return false;
    }
    fixture->io.reply_length = wire_length;
    fixture->io.reply_after_tx_bytes = after_tx_bytes;
    fixture->io.reply_armed = true;
    return true;
}

// Timing overrides let frequent control traffic starve the quiet window.
static uint32_t apple_capture_test_quiet_ms = 1u;
static uint32_t apple_capture_test_response_ms = 20u;

static bool apple_capture_test_fixture_init_mode(
    apple_capture_test_fixture *fixture, bool initial_only_control)
{
    memset(fixture, 0, sizeof *fixture);
    fixture->control[0] = -1;
    fixture->control[1] = -1;
    fixture->io.wake_read_fd = -1;
    fixture->io.wake_write_fd = -1;
    fixture->io.write_budget = SIZE_MAX;
    fixture->io.empty_read_result = RFB_IO_BLOCK;
    fixture->now_ms = APPLE_CAPTURE_TEST_BASE_MS;

    int wake[2] = {-1, -1};
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, wake) != 0 ||
        socketpair(AF_UNIX, SOCK_DGRAM, 0, fixture->control) != 0) {
        if (wake[0] >= 0) {
            (void)close(wake[0]);
            (void)close(wake[1]);
        }
        return false;
    }
    fixture->io.wake_read_fd = wake[0];
    fixture->io.wake_write_fd = wake[1];
    for (size_t i = 0u; i < 2u; i++) {
        const int flags = fcntl(fixture->control[i], F_GETFL, 0);
        if (flags < 0 ||
            fcntl(fixture->control[i], F_SETFL, flags | O_NONBLOCK) != 0) {
            return false;
        }
    }
    fixture->session = (rfb_session *)calloc(1u, rfb_session_size());
    if (fixture->session == NULL) {
        return false;
    }
    rfb_session_clear(fixture->session);

    fixture->query.id = 4101u;
    fixture->query.incremental = true;
    fixture->query.geometry_policy = RFB_CAPTURE_GEOMETRY_WITHIN_REQUEST;
    fixture->query.width = 16u;
    fixture->query.height = 16u;
    for (size_t i = 0u; i < sizeof fixture->binding; i++) {
        fixture->binding[i] = (uint8_t)(i + 1u);
    }
    fixture->config.view_only = true;
    fixture->config.capture_queries =
        initial_only_control ? NULL : &fixture->query;
    fixture->config.capture_query_count = initial_only_control ? 0u : 1u;
    fixture->config.capture_response_timeout_ms =
        apple_capture_test_response_ms;
    fixture->config.capture_quiet_ms = apple_capture_test_quiet_ms;
    fixture->config.capture_initial_only = initial_only_control;
    fixture->config.capture_initial_zrle_only = initial_only_control;
    fixture->config.capture_require_mutation_ack = !initial_only_control;
    fixture->config.capture_mutation_timeout_ms = 20u;
    fixture->config.capture_control_fd = fixture->control[0];
    fixture->config.capture_slot_nonce = UINT64_C(0x1020304050607080);
    fixture->config.capture_transition_id = UINT32_C(0x01020304);
    fixture->config.capture_source_b_binding = fixture->binding;
    fixture->config.capture_initial_rectangle_max =
        APPLE_CAPTURE_TEST_INITIAL_MAX;
    fixture->config.capture_rect_observations = fixture->rectangles;
    fixture->config.capture_rect_observation_capacity =
        APPLE_CAPTURE_TEST_RECT_CAP;
    fixture->config.capture_final_observations = fixture->finals;
    fixture->config.capture_final_observation_capacity =
        APPLE_CAPTURE_TEST_FINAL_CAP;

    uint8_t wrap[16];
    memset(wrap, 0xa5, sizeof wrap);
    apple_record_init(&fixture->server_records, wrap);
    fixture->server_records_initialized = true;
    if (!apple_record_set_direction(
            &fixture->server_records, APPLE_DIR_DECRYPT,
            apple_capture_test_c2s_key, apple_capture_test_c2s_iv) ||
        !apple_record_set_direction(
            &fixture->server_records, APPLE_DIR_ENCRYPT,
            apple_capture_test_s2c_key, apple_capture_test_s2c_iv)) {
        return false;
    }

    const rfb_io_adapter adapter = apple_capture_test_io_adapter(&fixture->io);
    return rfb_session_test_activate_apple_capture(
               fixture->session, &fixture->config, &adapter,
               fixture->io.wake_read_fd, &fixture->io.tx_bytes, 16u, 16u,
               apple_capture_test_c2s_key, apple_capture_test_c2s_iv,
               apple_capture_test_s2c_key, apple_capture_test_s2c_iv,
               fixture->now_ms) == RFB_OK;
}

static bool apple_capture_test_fixture_init(
    apple_capture_test_fixture *fixture)
{
    return apple_capture_test_fixture_init_mode(fixture, false);
}

static size_t apple_capture_test_zrle_fbu(uint8_t *out, size_t capacity)
{
    static const uint8_t expanded[] = {1u, 0x33u, 0x22u, 0x11u};
    uint8_t compressed[64];
    z_stream stream;
    memset(&stream, 0, sizeof stream);
    RFB_CHECK_EQ_INT(deflateInit(&stream, Z_DEFAULT_COMPRESSION), Z_OK);
    stream.next_in = (Bytef *)(uintptr_t)expanded;
    stream.avail_in = (uInt)sizeof expanded;
    stream.next_out = compressed;
    stream.avail_out = (uInt)sizeof compressed;
    RFB_CHECK_EQ_INT(deflate(&stream, Z_SYNC_FLUSH), Z_OK);
    RFB_CHECK_EQ_UINT(stream.avail_in, 0u);
    const size_t compressed_length =
        sizeof compressed - (size_t)stream.avail_out;
    const int end_result = deflateEnd(&stream);
    RFB_CHECK(end_result == Z_OK || end_result == Z_DATA_ERROR);
    const size_t total = 4u + 12u + 4u + compressed_length;
    RFB_CHECK(capacity >= total);
    memset(out, 0, total);
    out[3] = 1u;
    out[8] = 0u;
    out[9] = 16u;
    out[10] = 0u;
    out[11] = 16u;
    out[12] = 0u;
    out[13] = 0u;
    out[14] = 0u;
    out[15] = RFB_ENCODING_ZRLE;
    out[16] = (uint8_t)(compressed_length >> 24u);
    out[17] = (uint8_t)(compressed_length >> 16u);
    out[18] = (uint8_t)(compressed_length >> 8u);
    out[19] = (uint8_t)compressed_length;
    memcpy(out + 20u, compressed, compressed_length);
    return total;
}

static void apple_capture_test_fixture_destroy(
    apple_capture_test_fixture *fixture)
{
    if (fixture->session != NULL) {
        rfb_session_destroy(fixture->session);
        free(fixture->session);
    }
    if (fixture->server_records_initialized) {
        apple_record_destroy(&fixture->server_records);
    }
    if (fixture->control[0] >= 0) {
        (void)close(fixture->control[0]);
    }
    if (fixture->control[1] >= 0) {
        (void)close(fixture->control[1]);
    }
    if (fixture->io.wake_read_fd >= 0) {
        (void)close(fixture->io.wake_read_fd);
    }
    if (fixture->io.wake_write_fd >= 0) {
        (void)close(fixture->io.wake_write_fd);
    }
}

RFB_TEST(rfb_session_apple_capture,
         initial_only_zrle_produces_product_frame)
{
    apple_capture_test_fixture fixture;
    RFB_CHECK(apple_capture_test_fixture_init_mode(&fixture, true));
    RFB_CHECK(apple_capture_test_expect_initial(&fixture));
    uint8_t response[96];
    const size_t response_length = apple_capture_test_zrle_fbu(
        response, sizeof response);
    RFB_CHECK(apple_capture_test_seed_plaintext(
        &fixture, response, response_length));
    fixture.now_ms++;
    RFB_CHECK_EQ_INT(rfb_session_test_apple_capture_step(
                         fixture.session, fixture.now_ms),
                     RFB_OK);
    fixture.now_ms++;
    RFB_CHECK_EQ_INT(rfb_session_test_apple_capture_step(
                         fixture.session, fixture.now_ms),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_session_capture_state(fixture.session),
                     RFB_CAPTURE_SCHEDULER_DONE);
    const rfb_framebuffer *frame = rfb_session_framebuffer(fixture.session);
    RFB_CHECK(frame != NULL);
    RFB_CHECK_EQ_UINT(frame->width, 16u);
    RFB_CHECK_EQ_UINT(frame->height, 16u);
    static const uint8_t expected[] = {0x11u, 0x22u, 0x33u, 0xffu};
    RFB_CHECK_MEM_EQ(frame->rgba, expected, sizeof expected);
    RFB_CHECK(fixture.finals[0].terminal);
    RFB_CHECK_EQ_INT(fixture.finals[0].classification,
                     RFB_CAPTURE_FINAL_CONTROL_CLOSED);
    apple_capture_test_fixture_destroy(&fixture);
}

RFB_TEST(rfb_session_apple_capture,
         initial_only_competing_fbu_before_quiet_is_terminal)
{
    apple_capture_test_fixture fixture;
    RFB_CHECK(apple_capture_test_fixture_init_mode(&fixture, true));
    RFB_CHECK(apple_capture_test_expect_initial(&fixture));
    uint8_t one[96];
    const size_t one_length = apple_capture_test_zrle_fbu(one, sizeof one);
    uint8_t competing[192];
    RFB_CHECK(sizeof competing >= one_length * 2u);
    memcpy(competing, one, one_length);
    memcpy(competing + one_length, one, one_length);
    RFB_CHECK(apple_capture_test_seed_plaintext(
        &fixture, competing, one_length * 2u));
    fixture.now_ms++;
    RFB_CHECK_EQ_INT(rfb_session_test_apple_capture_step(
                         fixture.session, fixture.now_ms),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(rfb_session_capture_failure(fixture.session),
                     RFB_CAPTURE_FAILURE_UNSOLICITED_FBU);
    RFB_CHECK(fixture.finals[0].terminal);
    RFB_CHECK_EQ_INT(fixture.finals[0].classification,
                     RFB_CAPTURE_FINAL_REJECTED);
    apple_capture_test_fixture_destroy(&fixture);
}

static bool apple_capture_test_expect_initial(
    apple_capture_test_fixture *fixture)
{
    uint8_t plaintext[64];
    size_t plaintext_length = 0u;
    size_t wire_length = 0u;
    return apple_capture_test_pop_record(
               fixture, plaintext, sizeof plaintext, &plaintext_length,
               &wire_length) &&
           wire_length == 34u &&
           plaintext_length == sizeof apple_capture_test_initial_fbur &&
           memcmp(plaintext, apple_capture_test_initial_fbur,
                  sizeof apple_capture_test_initial_fbur) == 0;
}

static bool apple_capture_test_enter_hold(
    apple_capture_test_fixture *fixture)
{
    static const uint8_t initial_fbu[] = {0x00u, 0x00u, 0x00u, 0x00u};
    if (!apple_capture_test_seed_plaintext(
            fixture, initial_fbu, sizeof initial_fbu)) {
        return false;
    }
    for (size_t i = 0u; i < 6u; i++) {
        fixture->now_ms++;
        if (rfb_session_test_apple_capture_step(
                fixture->session, fixture->now_ms) != RFB_OK) {
            return false;
        }
        if (rfb_session_capture_state(fixture->session) ==
            RFB_CAPTURE_SCHEDULER_MUTATION_HOLD) {
            break;
        }
    }
    if (rfb_session_capture_state(fixture->session) !=
        RFB_CAPTURE_SCHEDULER_MUTATION_HOLD) {
        return false;
    }
    fixture->now_ms++;
    if (rfb_session_test_apple_capture_step(
            fixture->session, fixture->now_ms) != RFB_OK) {
        return false;
    }
    uint8_t ready_wire[RFB_CAPTURE_CONTROL_WIRE_SIZE];
    const ssize_t ready_length = recv(
        fixture->control[1], ready_wire, sizeof ready_wire, MSG_DONTWAIT);
    rfb_capture_control_message ready;
    return ready_length == (ssize_t)sizeof ready_wire &&
           rfb_capture_control_decode(ready_wire, sizeof ready_wire,
                                      &ready) == RFB_OK &&
           ready.kind == RFB_CAPTURE_CONTROL_READY_FOR_MUTATION;
}

static bool apple_capture_test_send_ack(
    apple_capture_test_fixture *fixture)
{
    rfb_capture_control_message ack;
    memset(&ack, 0, sizeof ack);
    ack.kind = RFB_CAPTURE_CONTROL_MUTATION_ACK;
    ack.slot_nonce = UINT64_C(0x1020304050607080);
    ack.transition_id = UINT32_C(0x01020304);
    memcpy(ack.source_b_binding, fixture->binding,
           sizeof ack.source_b_binding);
    uint8_t wire[RFB_CAPTURE_CONTROL_WIRE_SIZE];
    size_t wire_length = 0u;
    return rfb_capture_control_encode(
               &ack, wire, sizeof wire, &wire_length) == RFB_OK &&
           send(fixture->control[1], wire, wire_length, 0) ==
               (ssize_t)wire_length;
}

static size_t apple_capture_test_mvs_body(uint8_t *body, size_t capacity)
{
    if (capacity < 16u) {
        return 0u;
    }
    uint8_t commands[8];
    apple_mvs_bit_writer writer;
    apple_mvs_bit_writer_init(&writer, commands, sizeof commands);
    bool ok = apple_mvs_bit_writer_put(&writer, 0u, 1u);
    // This characterization fixture has two command records, each covering
    // two tiles. It makes no assertion about a one-record run-N interpretation.
    for (size_t i = 0u; ok && i < 2u; i++) {
        ok = apple_mvs_bit_writer_put(&writer, 4u, 3u) &&
             apple_mvs_bit_writer_put(&writer, 1u, 1u) &&
             apple_mvs_bit_writer_put(&writer, 0u, 4u);
    }
    ok = ok && apple_mvs_bit_writer_put(&writer, 0x6du, 8u) &&
         apple_mvs_bit_writer_finish(&writer);
    if (!ok || writer.len > capacity - 7u || writer.len > UINT32_MAX - 6u) {
        return 0u;
    }
    body[0] = 0u;
    body[1] = 3u;
    body[2] = 5u;
    const uint32_t image_offset = 6u + (uint32_t)writer.len;
    body[3] = (uint8_t)(image_offset >> 16u);
    body[4] = (uint8_t)(image_offset >> 8u);
    body[5] = (uint8_t)image_offset;
    memcpy(body + 6u, commands, writer.len);
    body[image_offset] = 0x6du;
    return (size_t)image_offset + 1u;
}

static size_t apple_capture_test_target_fbu(uint8_t *message,
                                            size_t capacity)
{
    uint8_t body[16];
    const size_t body_length = apple_capture_test_mvs_body(body, sizeof body);
    const size_t needed = 4u + 12u + 4u + body_length + 1u;
    if (body_length == 0u || capacity < needed) {
        return 0u;
    }
    static const uint8_t prefix[] = {
        0x00u, 0x00u, 0x00u, 0x01u,
        0x00u, 0x00u, 0x00u, 0x00u,
        0x00u, 0x10u, 0x00u, 0x10u,
        0x00u, 0x00u, 0x03u, 0xf3u,
    };
    memcpy(message, prefix, sizeof prefix);
    message[16] = (uint8_t)(body_length >> 24u);
    message[17] = (uint8_t)(body_length >> 16u);
    message[18] = (uint8_t)(body_length >> 8u);
    message[19] = (uint8_t)body_length;
    memcpy(message + 20u, body, body_length);
    message[20u + body_length] = 0x02u; // following Bell alignment guard
    return needed;
}

static bool apple_capture_test_finish_target(
    apple_capture_test_fixture *fixture)
{
    uint8_t response[64];
    const size_t response_length = apple_capture_test_target_fbu(
        response, sizeof response);
    if (!apple_capture_test_seed_plaintext(
            fixture, response, response_length)) {
        return false;
    }
    for (size_t i = 0u; i < 6u; i++) {
        fixture->now_ms++;
        if (rfb_session_test_apple_capture_step(
                fixture->session, fixture->now_ms) != RFB_OK) {
            return false;
        }
        if (rfb_session_capture_state(fixture->session) ==
            RFB_CAPTURE_SCHEDULER_DONE) {
            return true;
        }
    }
    return false;
}

static bool apple_capture_test_finish_loaded_target(
    apple_capture_test_fixture *fixture)
{
    for (size_t i = 0u; i < 6u; i++) {
        fixture->now_ms++;
        if (rfb_session_test_apple_capture_step(
                fixture->session, fixture->now_ms) != RFB_OK) {
            return false;
        }
        if (rfb_session_capture_state(fixture->session) ==
            RFB_CAPTURE_SCHEDULER_DONE) {
            return true;
        }
    }
    return false;
}

static bool apple_capture_test_queue_target(
    apple_capture_test_fixture *fixture)
{
    if (!apple_capture_test_send_ack(fixture)) {
        return false;
    }
    fixture->now_ms++;
    return rfb_session_test_apple_capture_step(
               fixture->session, fixture->now_ms) == RFB_OK;
}

static bool apple_capture_test_enter_outstanding(
    apple_capture_test_fixture *fixture)
{
    if (!apple_capture_test_expect_initial(fixture) ||
        !apple_capture_test_enter_hold(fixture) ||
        !apple_capture_test_queue_target(fixture)) {
        return false;
    }
    uint8_t target[64];
    size_t target_length = 0u;
    size_t target_wire_length = 0u;
    return rfb_session_capture_state(fixture->session) ==
               RFB_CAPTURE_SCHEDULER_OUTSTANDING &&
           apple_capture_test_pop_record(
               fixture, target, sizeof target, &target_length,
               &target_wire_length) &&
           target_length == sizeof apple_capture_test_target_fbur &&
           memcmp(target, apple_capture_test_target_fbur,
                  sizeof apple_capture_test_target_fbur) == 0;
}

static bool apple_capture_test_set_nonblocking(int fd)
{
    const int flags = fcntl(fd, F_GETFL, 0);
    return flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

static bool apple_capture_test_socket_send_all(
    int fd, const uint8_t *data, size_t length)
{
    size_t sent = 0u;
    for (size_t attempts = 0u; sent < length && attempts < 64u;
         attempts++) {
        const ssize_t result = send(fd, data + sent, length - sent, 0);
        if (result > 0) {
            sent += (size_t)result;
            continue;
        }
        if (result < 0 && errno != EINTR) {
            return false;
        }
    }
    return sent == length;
}

static bool apple_capture_test_socket_recv_exact(
    int fd, uint8_t *data, size_t length)
{
    size_t received = 0u;
    for (size_t attempts = 0u; received < length && attempts < 64u;
         attempts++) {
        const ssize_t result = recv(
            fd, data + received, length - received, MSG_DONTWAIT);
        if (result > 0) {
            received += (size_t)result;
            continue;
        }
        if (result < 0 && errno != EINTR && errno != EAGAIN &&
            errno != EWOULDBLOCK) {
            return false;
        }
    }
    return received == length;
}

static bool apple_capture_test_socket_fill(int fd, size_t *filled)
{
    uint8_t bytes[4096];
    memset(bytes, 0xabu, sizeof bytes);
    *filled = 0u;
    for (size_t attempts = 0u; attempts < 4096u; attempts++) {
        const ssize_t result = send(fd, bytes, sizeof bytes, 0);
        if (result > 0) {
            *filled += (size_t)result;
            continue;
        }
        if (result < 0 && errno == EINTR) {
            continue;
        }
        return result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) &&
               *filled != 0u;
    }
    return false;
}

static bool apple_capture_test_socket_enter_hold(
    apple_capture_test_fixture *fixture, int peer_fd)
{
    static const uint8_t initial_fbu[] = {0x00u, 0x00u, 0x00u, 0x00u};
    uint8_t wire[64];
    size_t wire_length = 0u;
    if (!apple_capture_test_seal_plaintext(
            fixture, initial_fbu, sizeof initial_fbu, wire, sizeof wire,
            &wire_length) ||
        !apple_capture_test_socket_send_all(peer_fd, wire, wire_length)) {
        return false;
    }
    for (size_t i = 0u; i < 6u; i++) {
        fixture->now_ms++;
        if (rfb_session_test_apple_capture_step(
                fixture->session, fixture->now_ms) != RFB_OK) {
            return false;
        }
        if (rfb_session_capture_state(fixture->session) ==
            RFB_CAPTURE_SCHEDULER_MUTATION_HOLD) {
            break;
        }
    }
    if (rfb_session_capture_state(fixture->session) !=
        RFB_CAPTURE_SCHEDULER_MUTATION_HOLD) {
        return false;
    }
    fixture->now_ms++;
    if (rfb_session_test_apple_capture_step(
            fixture->session, fixture->now_ms) != RFB_OK) {
        return false;
    }
    uint8_t ready_wire[RFB_CAPTURE_CONTROL_WIRE_SIZE];
    const ssize_t ready_length = recv(
        fixture->control[1], ready_wire, sizeof ready_wire, MSG_DONTWAIT);
    rfb_capture_control_message ready;
    return ready_length == (ssize_t)sizeof ready_wire &&
           rfb_capture_control_decode(ready_wire, sizeof ready_wire,
                                      &ready) == RFB_OK &&
           ready.kind == RFB_CAPTURE_CONTROL_READY_FOR_MUTATION;
}

typedef struct apple_capture_test_clock {
    uint64_t now_ms;
    uint64_t advance_ms;
    size_t calls;
    size_t hold_calls;
} apple_capture_test_clock;

static uint64_t apple_capture_test_clock_now_ms(void *opaque)
{
    apple_capture_test_clock *clock = (apple_capture_test_clock *)opaque;
    const uint64_t sampled_ms = clock->now_ms;
    clock->calls++;
    if (clock->hold_calls == 0u || clock->calls >= clock->hold_calls) {
        clock->now_ms += clock->advance_ms;
    }
    return sampled_ms;
}

typedef struct apple_capture_test_zero_clock {
    uint64_t now_ms;
    size_t calls;
    size_t zero_call;
} apple_capture_test_zero_clock;

static uint64_t apple_capture_test_zero_clock_now_ms(void *opaque)
{
    apple_capture_test_zero_clock *clock =
        (apple_capture_test_zero_clock *)opaque;
    clock->calls++;
    return clock->calls == clock->zero_call ? 0u : clock->now_ms;
}

RFB_TEST(rfb_session_apple_capture,
         capture_step_rejects_invalid_owner_and_clock_inputs)
{
    apple_capture_test_zero_clock clock = {
        .now_ms = APPLE_CAPTURE_TEST_BASE_MS + 1u,
        .calls = 0u,
        .zero_call = SIZE_MAX,
    };
    RFB_CHECK_EQ_INT(rfb_session_test_apple_capture_step_with_clock(
                         NULL, apple_capture_test_zero_clock_now_ms,
                         &clock, 0),
                     RFB_ERR_INTERNAL);

    apple_capture_test_fixture fixture;
    RFB_CHECK(apple_capture_test_fixture_init(&fixture));
    fixture.session->active = false;
    RFB_CHECK_EQ_INT(rfb_session_test_apple_capture_step_with_clock(
                         fixture.session,
                         apple_capture_test_zero_clock_now_ms, &clock, 0),
                     RFB_ERR_INTERNAL);
    fixture.session->active = true;
    fixture.session->capture_enabled = false;
    RFB_CHECK_EQ_INT(rfb_session_test_apple_capture_step_with_clock(
                         fixture.session,
                         apple_capture_test_zero_clock_now_ms, &clock, 0),
                     RFB_ERR_INTERNAL);
    fixture.session->capture_enabled = true;
    RFB_CHECK_EQ_INT(rfb_session_test_apple_capture_step_with_clock(
                         fixture.session, NULL, NULL, 0),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(rfb_session_test_apple_capture_step_with_clock(
                         fixture.session,
                         apple_capture_test_zero_clock_now_ms, &clock, -1),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(rfb_session_test_apple_capture_step_with_clock(
                         fixture.session,
                         apple_capture_test_zero_clock_now_ms, &clock, 0),
                     RFB_OK);
    apple_capture_test_fixture_destroy(&fixture);
}

RFB_TEST(rfb_session_apple_capture,
         zero_clock_sample_fails_each_idle_transition)
{
    for (size_t zero_call = 1u; zero_call <= 4u; zero_call++) {
        apple_capture_test_fixture fixture;
        RFB_CHECK(apple_capture_test_fixture_init(&fixture));
        apple_capture_test_zero_clock clock = {
            .now_ms = fixture.now_ms + 1u,
            .calls = 0u,
            .zero_call = zero_call,
        };
        RFB_CHECK_EQ_INT(rfb_session_test_apple_capture_step_with_clock(
                             fixture.session,
                             apple_capture_test_zero_clock_now_ms,
                             &clock, 0),
                         RFB_ERR_INTERNAL);
        RFB_CHECK_EQ_UINT(clock.calls, zero_call);
        RFB_CHECK_EQ_INT(rfb_session_last_error(fixture.session),
                         RFB_ERR_INTERNAL);
        apple_capture_test_fixture_destroy(&fixture);
    }
}

RFB_TEST(rfb_session_apple_capture,
         closed_control_owner_fails_before_ready_message)
{
    apple_capture_test_fixture fixture;
    RFB_CHECK(apple_capture_test_fixture_init(&fixture));
    RFB_CHECK(apple_capture_test_expect_initial(&fixture));
    static const uint8_t initial_fbu[] = {0x00u, 0x00u, 0x00u, 0x00u};
    RFB_CHECK(apple_capture_test_seed_plaintext(
        &fixture, initial_fbu, sizeof initial_fbu));
    for (size_t i = 0u; i < 6u &&
                        rfb_session_capture_state(fixture.session) !=
                            RFB_CAPTURE_SCHEDULER_MUTATION_HOLD;
         i++) {
        fixture.now_ms++;
        RFB_CHECK_EQ_INT(rfb_session_test_apple_capture_step(
                             fixture.session, fixture.now_ms),
                         RFB_OK);
    }
    RFB_CHECK_EQ_INT(rfb_session_capture_state(fixture.session),
                     RFB_CAPTURE_SCHEDULER_MUTATION_HOLD);
    RFB_CHECK(!fixture.session->capture_control_ready_sent);
    RFB_CHECK_EQ_INT(close(fixture.control[0]), 0);
    fixture.control[0] = -1;

    fixture.now_ms++;
    RFB_CHECK_EQ_INT(rfb_session_test_apple_capture_step(
                         fixture.session, fixture.now_ms),
                     RFB_ERR_IO);
    RFB_CHECK_EQ_INT(rfb_session_capture_failure(fixture.session),
                     RFB_CAPTURE_FAILURE_CONTROL);
    RFB_CHECK_EQ_INT(rfb_session_last_error(fixture.session), RFB_ERR_IO);
    apple_capture_test_fixture_destroy(&fixture);
}

RFB_TEST(rfb_session_apple_capture,
         missing_transport_counter_rejects_target_admission)
{
    apple_capture_test_fixture fixture;
    RFB_CHECK(apple_capture_test_fixture_init(&fixture));
    RFB_CHECK(apple_capture_test_expect_initial(&fixture));
    RFB_CHECK(apple_capture_test_enter_hold(&fixture));
    fixture.session->transport_tx_bytes = NULL;
    RFB_CHECK(apple_capture_test_send_ack(&fixture));
    fixture.now_ms++;
    RFB_CHECK_EQ_INT(rfb_session_test_apple_capture_step(
                         fixture.session, fixture.now_ms),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(rfb_session_capture_failure(fixture.session),
                     RFB_CAPTURE_FAILURE_REQUEST_DRAIN);
    RFB_CHECK_EQ_INT(rfb_session_last_error(fixture.session),
                     RFB_ERR_PROTOCOL);
    apple_capture_test_fixture_destroy(&fixture);
}

RFB_TEST(rfb_session_apple_capture,
         wrapping_transport_counter_fails_target_admission)
{
    apple_capture_test_fixture fixture;
    RFB_CHECK(apple_capture_test_fixture_init(&fixture));
    RFB_CHECK(apple_capture_test_expect_initial(&fixture));
    RFB_CHECK(apple_capture_test_enter_hold(&fixture));
    farsee_atomic_u64_store(&fixture.io.tx_bytes, UINT64_MAX - 8u);
    RFB_CHECK(apple_capture_test_send_ack(&fixture));
    fixture.now_ms++;
    RFB_CHECK_EQ_INT(rfb_session_test_apple_capture_step(
                         fixture.session, fixture.now_ms),
                     RFB_ERR_LIMIT);
    RFB_CHECK_EQ_INT(rfb_session_capture_failure(fixture.session),
                     RFB_CAPTURE_FAILURE_REQUEST_DRAIN);
    RFB_CHECK_EQ_INT(rfb_session_last_error(fixture.session), RFB_ERR_LIMIT);
    apple_capture_test_fixture_destroy(&fixture);
}

RFB_TEST(rfb_session_apple_capture,
         hard_read_error_records_peer_closure)
{
    apple_capture_test_fixture fixture;
    RFB_CHECK(apple_capture_test_fixture_init(&fixture));
    RFB_CHECK(apple_capture_test_expect_initial(&fixture));
    fixture.io.empty_read_result = RFB_IO_ERROR;
    RFB_CHECK(apple_capture_test_wake_io(&fixture.io));
    fixture.now_ms++;
    RFB_CHECK_EQ_INT(rfb_session_test_apple_capture_step(
                         fixture.session, fixture.now_ms),
                     RFB_ERR_EOF);
    RFB_CHECK_EQ_INT(rfb_session_capture_failure(fixture.session),
                     RFB_CAPTURE_FAILURE_EOF);
    RFB_CHECK_EQ_INT(rfb_session_last_error(fixture.session), RFB_ERR_EOF);
    apple_capture_test_fixture_destroy(&fixture);
}

RFB_TEST(rfb_session_apple_capture,
         exact_sealed_target_survives_forced_partial_write_and_binds_tx_bytes)
{
    apple_capture_test_fixture fixture;
    RFB_CHECK(apple_capture_test_fixture_init(&fixture));
    RFB_CHECK(rfb_session_apple_records_active(fixture.session));
    RFB_CHECK(apple_capture_test_expect_initial(&fixture));
    RFB_CHECK(apple_capture_test_enter_hold(&fixture));

    const uint64_t tx_before = farsee_atomic_u64_load(&fixture.io.tx_bytes);
    fixture.io.write_chunk = 5u;
    fixture.io.write_budget = 5u;
    RFB_CHECK(apple_capture_test_queue_target(&fixture));
    RFB_CHECK_EQ_INT(rfb_session_capture_state(fixture.session),
                     RFB_CAPTURE_SCHEDULER_REQUEST_DRAINING);
    RFB_CHECK_EQ_UINT(farsee_atomic_u64_load(&fixture.io.tx_bytes),
                      tx_before + 5u);
    RFB_CHECK(fixture.io.short_writes > 0u);

    fixture.io.write_budget = SIZE_MAX;
    fixture.now_ms++;
    RFB_CHECK_EQ_INT(rfb_session_test_apple_capture_step(
                         fixture.session, fixture.now_ms),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_session_capture_state(fixture.session),
                     RFB_CAPTURE_SCHEDULER_OUTSTANDING);
    RFB_CHECK_EQ_UINT(farsee_atomic_u64_load(&fixture.io.tx_bytes),
                      tx_before + 34u);

    uint8_t plaintext[64];
    size_t plaintext_length = 0u;
    size_t wire_length = 0u;
    RFB_CHECK(apple_capture_test_pop_record(
        &fixture, plaintext, sizeof plaintext, &plaintext_length,
        &wire_length));
    RFB_CHECK_EQ_UINT(wire_length, 34u);
    RFB_CHECK_EQ_UINT(plaintext_length,
                      sizeof apple_capture_test_target_fbur);
    RFB_CHECK(memcmp(plaintext, apple_capture_test_target_fbur,
                     sizeof apple_capture_test_target_fbur) == 0);
    apple_capture_test_fixture_destroy(&fixture);
}

RFB_TEST(rfb_session_apple_capture,
         real_socket_backpressure_binds_sealed_target_to_transport_counter)
{
    apple_capture_test_fixture fixture;
    if (!apple_capture_test_fixture_init(&fixture)) {
        RFB_FAIL("could not initialize capture fixture");
        return;
    }

    int transport[2] = {-1, -1};
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, transport) != 0 ||
        !apple_capture_test_set_nonblocking(transport[0]) ||
        !apple_capture_test_set_nonblocking(transport[1])) {
        RFB_FAIL("could not initialize nonblocking transport socketpair");
        if (transport[0] >= 0) {
            (void)close(transport[0]);
        }
        if (transport[1] >= 0) {
            (void)close(transport[1]);
        }
        apple_capture_test_fixture_destroy(&fixture);
        return;
    }

    int send_buffer = 4096;
    RFB_CHECK_EQ_INT(setsockopt(transport[0], SOL_SOCKET, SO_SNDBUF,
                               &send_buffer, sizeof send_buffer),
                     0);
    rfb_session_destroy(fixture.session);
    rfb_socket_ctx socket_ctx;
    const rfb_io_adapter adapter = rfb_socket_adapter_make(&socket_ctx);
    socket_ctx.fd = transport[0];
    socket_ctx.nonblocking = true;
    RFB_CHECK_EQ_INT(rfb_session_test_activate_apple_capture(
                         fixture.session, &fixture.config, &adapter,
                         transport[0], &socket_ctx.tx_bytes, 16u, 16u,
                         apple_capture_test_c2s_key,
                         apple_capture_test_c2s_iv,
                         apple_capture_test_s2c_key,
                         apple_capture_test_s2c_iv, fixture.now_ms),
                     RFB_OK);

    uint8_t initial_wire[sizeof apple_capture_test_initial_record_kat];
    RFB_CHECK(apple_capture_test_socket_recv_exact(
        transport[1], initial_wire, sizeof initial_wire));
    RFB_CHECK_MEM_EQ(initial_wire, apple_capture_test_initial_record_kat,
                     sizeof initial_wire);
    RFB_CHECK(apple_capture_test_socket_enter_hold(&fixture, transport[1]));

    size_t prefill_length = 0u;
    RFB_CHECK(apple_capture_test_socket_fill(transport[0], &prefill_length));
    const uint64_t tx_before =
        farsee_atomic_u64_load(&socket_ctx.tx_bytes);
    RFB_CHECK(apple_capture_test_send_ack(&fixture));
    fixture.now_ms++;
    RFB_CHECK_EQ_INT(rfb_session_test_apple_capture_step(
                         fixture.session, fixture.now_ms),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_session_capture_state(fixture.session),
                     RFB_CAPTURE_SCHEDULER_REQUEST_DRAINING);
    RFB_CHECK_EQ_UINT(farsee_atomic_u64_load(&socket_ctx.tx_bytes),
                      tx_before);

    uint8_t prefill[4096];
    size_t remaining = prefill_length;
    while (remaining != 0u) {
        const size_t chunk = remaining < sizeof prefill
                                 ? remaining
                                 : sizeof prefill;
        RFB_CHECK(apple_capture_test_socket_recv_exact(
            transport[1], prefill, chunk));
        remaining -= chunk;
    }
    RFB_CHECK_EQ_INT(rfb_session_capture_state(fixture.session),
                     RFB_CAPTURE_SCHEDULER_REQUEST_DRAINING);
    RFB_CHECK_EQ_UINT(farsee_atomic_u64_load(&socket_ctx.tx_bytes),
                      tx_before);

    RFB_CHECK_EQ_INT(rfb_session_test_apple_capture_step(
                         fixture.session, fixture.now_ms),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_session_capture_state(fixture.session),
                     RFB_CAPTURE_SCHEDULER_OUTSTANDING);
    RFB_CHECK_EQ_UINT(farsee_atomic_u64_load(&socket_ctx.tx_bytes),
                      tx_before +
                          sizeof apple_capture_test_target_record_kat);
    uint8_t target_wire[sizeof apple_capture_test_target_record_kat];
    RFB_CHECK(apple_capture_test_socket_recv_exact(
        transport[1], target_wire, sizeof target_wire));
    RFB_CHECK_MEM_EQ(target_wire, apple_capture_test_target_record_kat,
                     sizeof target_wire);

    apple_capture_test_fixture_destroy(&fixture);
    (void)close(transport[0]);
    (void)close(transport[1]);
}

RFB_TEST(rfb_session_apple_capture,
         deterministic_initial_and_target_records_match_fixed_kat)
{
    apple_capture_test_fixture fixture;
    RFB_CHECK(apple_capture_test_fixture_init(&fixture));
    RFB_CHECK_EQ_UINT(fixture.io.outbox_len,
                      sizeof apple_capture_test_initial_record_kat);
    RFB_CHECK(memcmp(fixture.io.outbox,
                     apple_capture_test_initial_record_kat,
                     sizeof apple_capture_test_initial_record_kat) == 0);
    RFB_CHECK(apple_capture_test_expect_initial(&fixture));
    RFB_CHECK(apple_capture_test_enter_hold(&fixture));
    RFB_CHECK(apple_capture_test_queue_target(&fixture));
    RFB_CHECK_EQ_UINT(fixture.io.outbox_len,
                      sizeof apple_capture_test_target_record_kat);
    RFB_CHECK(memcmp(fixture.io.outbox,
                     apple_capture_test_target_record_kat,
                     sizeof apple_capture_test_target_record_kat) == 0);
    apple_capture_test_fixture_destroy(&fixture);
}

RFB_TEST(rfb_session_apple_capture,
         eagain_boundaries_preserve_exact_sealed_target_and_drain_state)
{
    static const size_t boundaries[] = {1u, 2u, 18u, 33u};
    for (size_t i = 0u; i < sizeof boundaries / sizeof boundaries[0]; i++) {
        apple_capture_test_fixture fixture;
        RFB_CHECK(apple_capture_test_fixture_init(&fixture));
        RFB_CHECK(apple_capture_test_expect_initial(&fixture));
        RFB_CHECK(apple_capture_test_enter_hold(&fixture));
        const uint64_t tx_before =
            farsee_atomic_u64_load(&fixture.io.tx_bytes);
        fixture.io.write_chunk = boundaries[i];
        fixture.io.write_budget = boundaries[i];
        RFB_CHECK(apple_capture_test_queue_target(&fixture));
        RFB_CHECK_EQ_INT(rfb_session_capture_state(fixture.session),
                         RFB_CAPTURE_SCHEDULER_REQUEST_DRAINING);
        RFB_CHECK_EQ_UINT(farsee_atomic_u64_load(&fixture.io.tx_bytes),
                          tx_before + boundaries[i]);
        RFB_CHECK(fixture.io.short_writes > 0u);

        fixture.io.write_budget = SIZE_MAX;
        fixture.now_ms++;
        RFB_CHECK_EQ_INT(rfb_session_test_apple_capture_step(
                             fixture.session, fixture.now_ms),
                         RFB_OK);
        RFB_CHECK_EQ_INT(rfb_session_capture_state(fixture.session),
                         RFB_CAPTURE_SCHEDULER_OUTSTANDING);
        RFB_CHECK_EQ_UINT(farsee_atomic_u64_load(&fixture.io.tx_bytes),
                          tx_before +
                              sizeof apple_capture_test_target_record_kat);
        RFB_CHECK_EQ_UINT(fixture.io.outbox_len,
                          sizeof apple_capture_test_target_record_kat);
        RFB_CHECK(memcmp(fixture.io.outbox,
                         apple_capture_test_target_record_kat,
                         sizeof apple_capture_test_target_record_kat) == 0);
        apple_capture_test_fixture_destroy(&fixture);
    }
}

RFB_TEST(rfb_session_apple_capture,
         encrypted_fbu_is_predrain_terminal_at_every_outbound_boundary)
{
    static const size_t boundaries[] = {1u, 2u, 18u, 33u};
    for (size_t i = 0u; i < sizeof boundaries / sizeof boundaries[0]; i++) {
        apple_capture_test_fixture fixture;
        RFB_CHECK(apple_capture_test_fixture_init(&fixture));
        RFB_CHECK(apple_capture_test_expect_initial(&fixture));
        RFB_CHECK(apple_capture_test_enter_hold(&fixture));
        fixture.io.write_chunk = boundaries[i];
        fixture.io.write_budget = boundaries[i];
        RFB_CHECK(apple_capture_test_queue_target(&fixture));
        RFB_CHECK_EQ_INT(rfb_session_capture_state(fixture.session),
                         RFB_CAPTURE_SCHEDULER_REQUEST_DRAINING);

        uint8_t response[64];
        const size_t response_length = apple_capture_test_target_fbu(
            response, sizeof response);
        RFB_CHECK(apple_capture_test_seed_plaintext(
            &fixture, response, response_length));
        fixture.now_ms++;
        RFB_CHECK_EQ_INT(rfb_session_test_apple_capture_step(
                             fixture.session, fixture.now_ms),
                         RFB_ERR_PROTOCOL);
        RFB_CHECK_EQ_INT(rfb_session_capture_failure(fixture.session),
                         RFB_CAPTURE_FAILURE_UNSOLICITED_FBU);
        const rfb_error sticky = rfb_session_last_error(fixture.session);
        fixture.now_ms++;
        (void)rfb_session_test_apple_capture_step(
            fixture.session, fixture.now_ms);
        RFB_CHECK_EQ_INT(rfb_session_capture_failure(fixture.session),
                         RFB_CAPTURE_FAILURE_UNSOLICITED_FBU);
        RFB_CHECK_EQ_INT(rfb_session_last_error(fixture.session), sticky);
        apple_capture_test_fixture_destroy(&fixture);
    }
}

RFB_TEST(rfb_session_apple_capture,
         sealed_request_that_cannot_drain_hits_request_drain_deadline)
{
    apple_capture_test_fixture fixture;
    RFB_CHECK(apple_capture_test_fixture_init(&fixture));
    RFB_CHECK(apple_capture_test_expect_initial(&fixture));
    RFB_CHECK(apple_capture_test_enter_hold(&fixture));
    fixture.io.write_budget = 0u;
    RFB_CHECK(apple_capture_test_queue_target(&fixture));
    RFB_CHECK_EQ_INT(rfb_session_capture_state(fixture.session),
                     RFB_CAPTURE_SCHEDULER_REQUEST_DRAINING);
    fixture.now_ms += 20u;
    RFB_CHECK_EQ_INT(rfb_session_test_apple_capture_step(
                         fixture.session, fixture.now_ms),
                     RFB_ERR_TIMEOUT);
    RFB_CHECK_EQ_INT(rfb_session_capture_failure(fixture.session),
                     RFB_CAPTURE_FAILURE_REQUEST_DRAIN);
    const rfb_error sticky = rfb_session_last_error(fixture.session);
    fixture.now_ms++;
    (void)rfb_session_test_apple_capture_step(
        fixture.session, fixture.now_ms);
    RFB_CHECK_EQ_INT(rfb_session_capture_state(fixture.session),
                     RFB_CAPTURE_SCHEDULER_FAILED);
    RFB_CHECK_EQ_INT(rfb_session_capture_failure(fixture.session),
                     RFB_CAPTURE_FAILURE_REQUEST_DRAIN);
    RFB_CHECK_EQ_INT(rfb_session_last_error(fixture.session), sticky);
    apple_capture_test_fixture_destroy(&fixture);
}

RFB_TEST(rfb_session_apple_capture,
         sealed_fbu_arriving_before_target_drain_is_rejected)
{
    apple_capture_test_fixture fixture;
    RFB_CHECK(apple_capture_test_fixture_init(&fixture));
    RFB_CHECK(apple_capture_test_expect_initial(&fixture));
    RFB_CHECK(apple_capture_test_enter_hold(&fixture));
    fixture.io.write_chunk = 3u;
    fixture.io.write_budget = 3u;
    RFB_CHECK(apple_capture_test_queue_target(&fixture));
    RFB_CHECK_EQ_INT(rfb_session_capture_state(fixture.session),
                     RFB_CAPTURE_SCHEDULER_REQUEST_DRAINING);

    uint8_t response[64];
    const size_t response_length = apple_capture_test_target_fbu(
        response, sizeof response);
    RFB_CHECK(apple_capture_test_seed_plaintext(
        &fixture, response, response_length));
    fixture.now_ms++;
    RFB_CHECK_EQ_INT(rfb_session_test_apple_capture_step(
                         fixture.session, fixture.now_ms),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(rfb_session_capture_failure(fixture.session),
                     RFB_CAPTURE_FAILURE_UNSOLICITED_FBU);
    apple_capture_test_fixture_destroy(&fixture);
}

// rfb_io_queue_bytes drains each appended request. A response can therefore be
// readable before the caller finishes request accounting. Once the transport
// has admitted every request byte, the request is outstanding and that response
// is classified as its response rather than an unsolicited update.
RFB_TEST(rfb_session_apple_capture,
         target_reply_admitted_with_the_request_is_not_unsolicited)
{
    apple_capture_test_fixture fixture;
    RFB_CHECK(apple_capture_test_fixture_init(&fixture));
    RFB_CHECK(apple_capture_test_expect_initial(&fixture));
    RFB_CHECK(apple_capture_test_enter_hold(&fixture));

    uint8_t response[64];
    const size_t response_length = apple_capture_test_target_fbu(
        response, sizeof response);
    RFB_CHECK(response_length != 0u);
    const uint64_t tx_before = farsee_atomic_u64_load(&fixture.io.tx_bytes);
    RFB_CHECK(apple_capture_test_arm_reply(
        &fixture, response, response_length,
        tx_before + sizeof apple_capture_test_target_record_kat));

    RFB_CHECK(apple_capture_test_send_ack(&fixture));
    fixture.now_ms++;
    const rfb_error queued = rfb_session_test_apple_capture_step(
        fixture.session, fixture.now_ms);
    RFB_CHECK_EQ_INT(rfb_session_capture_failure(fixture.session),
                     RFB_CAPTURE_FAILURE_NONE);
    RFB_CHECK_EQ_INT(queued, RFB_OK);
    RFB_CHECK_EQ_UINT(farsee_atomic_u64_load(&fixture.io.tx_bytes),
                      tx_before + sizeof apple_capture_test_target_record_kat);
    RFB_CHECK(!fixture.io.reply_armed);

    RFB_CHECK(apple_capture_test_finish_loaded_target(&fixture));
    RFB_CHECK_EQ_INT(rfb_session_capture_state(fixture.session),
                     RFB_CAPTURE_SCHEDULER_DONE);
    RFB_CHECK_EQ_INT(rfb_session_capture_failure(fixture.session),
                     RFB_CAPTURE_FAILURE_NONE);
    RFB_CHECK(fixture.finals[1].terminal);
    RFB_CHECK_EQ_UINT(fixture.finals[1].classification,
                      RFB_CAPTURE_FINAL_ASSOCIATION_CLOSED);
    RFB_CHECK_EQ_UINT(fixture.finals[1].failure,
                      RFB_CAPTURE_FAILURE_NONE);
    apple_capture_test_fixture_destroy(&fixture);
}

// A reply admitted before the request's final byte remains unsolicited because
// the request is not yet outstanding.
RFB_TEST(rfb_session_apple_capture,
         reply_before_the_last_request_byte_stays_unsolicited)
{
    apple_capture_test_fixture fixture;
    RFB_CHECK(apple_capture_test_fixture_init(&fixture));
    RFB_CHECK(apple_capture_test_expect_initial(&fixture));
    RFB_CHECK(apple_capture_test_enter_hold(&fixture));

    uint8_t response[64];
    const size_t response_length = apple_capture_test_target_fbu(
        response, sizeof response);
    RFB_CHECK(response_length != 0u);
    const uint64_t tx_before = farsee_atomic_u64_load(&fixture.io.tx_bytes);
    RFB_CHECK(apple_capture_test_arm_reply(&fixture, response,
                                           response_length, tx_before + 1u));
    fixture.io.write_budget =
        sizeof apple_capture_test_target_record_kat - 1u;

    RFB_CHECK(apple_capture_test_send_ack(&fixture));
    fixture.now_ms++;
    RFB_CHECK_EQ_INT(rfb_session_test_apple_capture_step(
                         fixture.session, fixture.now_ms),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_UINT(
        farsee_atomic_u64_load(&fixture.io.tx_bytes),
        tx_before + sizeof apple_capture_test_target_record_kat - 1u);
    RFB_CHECK_EQ_INT(rfb_session_capture_state(fixture.session),
                     RFB_CAPTURE_SCHEDULER_FAILED);
    RFB_CHECK_EQ_INT(rfb_session_capture_failure(fixture.session),
                     RFB_CAPTURE_FAILURE_UNSOLICITED_FBU);
    apple_capture_test_fixture_destroy(&fixture);
}

RFB_TEST(rfb_session_apple_capture,
         readable_fbu_wins_simultaneous_final_target_write_boundary)
{
    apple_capture_test_fixture fixture;
    RFB_CHECK(apple_capture_test_fixture_init(&fixture));
    RFB_CHECK(apple_capture_test_expect_initial(&fixture));
    RFB_CHECK(apple_capture_test_enter_hold(&fixture));
    fixture.io.write_budget = 5u;
    RFB_CHECK(apple_capture_test_queue_target(&fixture));
    RFB_CHECK_EQ_INT(rfb_session_capture_state(fixture.session),
                     RFB_CAPTURE_SCHEDULER_REQUEST_DRAINING);

    uint8_t response[64];
    const size_t response_length = apple_capture_test_target_fbu(
        response, sizeof response);
    uint8_t response_wire[128];
    size_t response_wire_length = 0u;
    RFB_CHECK(apple_capture_test_seal_plaintext(
        &fixture, response, response_length, response_wire,
        sizeof response_wire, &response_wire_length));
    RFB_CHECK(apple_capture_test_seed_inbox(
        &fixture.io, response_wire, response_wire_length));
    fixture.io.read_chunk = 1u;
    fixture.io.write_budget = SIZE_MAX;
    fixture.now_ms++;
    const uint64_t tx_before =
        farsee_atomic_u64_load(&fixture.io.tx_bytes);
    rfb_error result = RFB_OK;
    bool classified = false;
    for (size_t i = 0u; i < response_wire_length + 2u; i++) {
        result = rfb_session_test_apple_capture_step(
            fixture.session, fixture.now_ms);
        if (fixture.io.inbox_len != 0u) {
            RFB_CHECK_EQ_INT(result, RFB_OK);
            RFB_CHECK_EQ_INT(rfb_session_capture_state(fixture.session),
                             RFB_CAPTURE_SCHEDULER_REQUEST_DRAINING);
            RFB_CHECK_EQ_UINT(
                farsee_atomic_u64_load(&fixture.io.tx_bytes), tx_before);
            RFB_CHECK(!fixture.finals[1].present);
            continue;
        }
        classified = true;
        break;
    }
    RFB_CHECK(classified);
    RFB_CHECK_EQ_INT(result, RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(rfb_session_capture_state(fixture.session),
                     RFB_CAPTURE_SCHEDULER_FAILED);
    RFB_CHECK_EQ_INT(rfb_session_capture_failure(fixture.session),
                     RFB_CAPTURE_FAILURE_UNSOLICITED_FBU);
    RFB_CHECK(fixture.finals[1].terminal);
    RFB_CHECK_EQ_UINT(fixture.finals[1].classification,
                      RFB_CAPTURE_FINAL_REJECTED);
    RFB_CHECK_EQ_UINT(fixture.finals[1].failure,
                      RFB_CAPTURE_FAILURE_UNSOLICITED_FBU);
    apple_capture_test_fixture_destroy(&fixture);
}

RFB_TEST(rfb_session_apple_capture,
         typed_record_read_boundary_keeps_following_fbu_predrain)
{
    apple_capture_test_fixture fixture;
    RFB_CHECK(apple_capture_test_fixture_init(&fixture));
    RFB_CHECK(apple_capture_test_expect_initial(&fixture));
    RFB_CHECK(apple_capture_test_enter_hold(&fixture));
    fixture.io.write_budget = 5u;
    RFB_CHECK(apple_capture_test_queue_target(&fixture));
    RFB_CHECK_EQ_INT(rfb_session_capture_state(fixture.session),
                     RFB_CAPTURE_SCHEDULER_REQUEST_DRAINING);

    static const uint8_t typed_control[16] = {
        0x00u, 0x00u, 0x00u, 0x01u,
        0x00u, 0x00u, 0x00u, 0x00u,
        0x00u, 0x00u, 0x00u, 0x00u,
        0x00u, 0x00u, 0x77u, 0x77u,
    };
    uint8_t response[64];
    const size_t response_length = apple_capture_test_target_fbu(
        response, sizeof response);
    uint8_t wire[256];
    size_t typed_wire_length = 0u;
    size_t response_wire_length = 0u;
    RFB_CHECK(apple_capture_test_seal_plaintext(
        &fixture, typed_control, sizeof typed_control, wire, sizeof wire,
        &typed_wire_length));
    RFB_CHECK(apple_capture_test_seal_plaintext(
        &fixture, response, response_length, wire + typed_wire_length,
        sizeof wire - typed_wire_length, &response_wire_length));
    RFB_CHECK(apple_capture_test_seed_inbox(
        &fixture.io, wire, typed_wire_length + response_wire_length));

    fixture.io.read_chunk = typed_wire_length;
    fixture.io.write_budget = SIZE_MAX;
    fixture.now_ms++;
    const uint64_t tx_before =
        farsee_atomic_u64_load(&fixture.io.tx_bytes);
    rfb_error result = rfb_session_test_apple_capture_step(
        fixture.session, fixture.now_ms);
    RFB_CHECK_EQ_INT(result, RFB_OK);
    RFB_CHECK_EQ_INT(rfb_session_capture_state(fixture.session),
                     RFB_CAPTURE_SCHEDULER_REQUEST_DRAINING);
    RFB_CHECK_EQ_UINT(farsee_atomic_u64_load(&fixture.io.tx_bytes),
                      tx_before);
    RFB_CHECK_EQ_UINT(fixture.io.inbox_len, response_wire_length);

    bool classified = false;
    const size_t max_steps =
        response_wire_length / typed_wire_length + 3u;
    for (size_t i = 0u; i < max_steps; i++) {
        result = rfb_session_test_apple_capture_step(
            fixture.session, fixture.now_ms);
        if (fixture.io.inbox_len != 0u) {
            RFB_CHECK_EQ_INT(result, RFB_OK);
            RFB_CHECK_EQ_INT(rfb_session_capture_state(fixture.session),
                             RFB_CAPTURE_SCHEDULER_REQUEST_DRAINING);
            RFB_CHECK_EQ_UINT(
                farsee_atomic_u64_load(&fixture.io.tx_bytes), tx_before);
            continue;
        }
        classified = true;
        break;
    }
    RFB_CHECK(classified);
    RFB_CHECK_EQ_INT(result, RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(rfb_session_capture_state(fixture.session),
                     RFB_CAPTURE_SCHEDULER_FAILED);
    RFB_CHECK_EQ_INT(rfb_session_capture_failure(fixture.session),
                     RFB_CAPTURE_FAILURE_UNSOLICITED_FBU);
    RFB_CHECK_EQ_UINT(farsee_atomic_u64_load(&fixture.io.tx_bytes),
                      tx_before);
    RFB_CHECK(fixture.finals[1].terminal);
    RFB_CHECK_EQ_INT(fixture.finals[1].classification,
                     RFB_CAPTURE_FINAL_REJECTED);
    apple_capture_test_fixture_destroy(&fixture);
}

RFB_TEST(rfb_session_apple_capture,
         eof_while_target_is_draining_is_terminal_and_sticky)
{
    apple_capture_test_fixture fixture;
    RFB_CHECK(apple_capture_test_fixture_init(&fixture));
    RFB_CHECK(apple_capture_test_expect_initial(&fixture));
    RFB_CHECK(apple_capture_test_enter_hold(&fixture));
    fixture.io.write_budget = 0u;
    RFB_CHECK(apple_capture_test_queue_target(&fixture));
    fixture.io.empty_read_result = RFB_IO_EOF;
    RFB_CHECK(apple_capture_test_wake_io(&fixture.io));
    fixture.now_ms++;
    RFB_CHECK_EQ_INT(rfb_session_test_apple_capture_step(
                         fixture.session, fixture.now_ms),
                     RFB_ERR_EOF);
    RFB_CHECK_EQ_INT(rfb_session_capture_state(fixture.session),
                     RFB_CAPTURE_SCHEDULER_FAILED);
    RFB_CHECK_EQ_INT(rfb_session_capture_failure(fixture.session),
                     RFB_CAPTURE_FAILURE_EOF);
    fixture.now_ms++;
    (void)rfb_session_test_apple_capture_step(
        fixture.session, fixture.now_ms);
    RFB_CHECK_EQ_INT(rfb_session_capture_failure(fixture.session),
                     RFB_CAPTURE_FAILURE_EOF);
    RFB_CHECK_EQ_INT(rfb_session_last_error(fixture.session), RFB_ERR_EOF);
    apple_capture_test_fixture_destroy(&fixture);
}

RFB_TEST(rfb_session_apple_capture,
         outbound_write_error_is_request_drain_terminal_and_sticky)
{
    apple_capture_test_fixture fixture;
    RFB_CHECK(apple_capture_test_fixture_init(&fixture));
    RFB_CHECK(apple_capture_test_expect_initial(&fixture));
    RFB_CHECK(apple_capture_test_enter_hold(&fixture));
    fixture.io.write_error = true;
    RFB_CHECK(apple_capture_test_send_ack(&fixture));
    fixture.now_ms++;
    RFB_CHECK_EQ_INT(rfb_session_test_apple_capture_step(
                         fixture.session, fixture.now_ms),
                     RFB_ERR_IO);
    RFB_CHECK_EQ_INT(rfb_session_capture_state(fixture.session),
                     RFB_CAPTURE_SCHEDULER_FAILED);
    RFB_CHECK_EQ_INT(rfb_session_capture_failure(fixture.session),
                     RFB_CAPTURE_FAILURE_REQUEST_DRAIN);
    fixture.now_ms++;
    (void)rfb_session_test_apple_capture_step(
        fixture.session, fixture.now_ms);
    RFB_CHECK_EQ_INT(rfb_session_capture_failure(fixture.session),
                     RFB_CAPTURE_FAILURE_REQUEST_DRAIN);
    RFB_CHECK_EQ_INT(rfb_session_last_error(fixture.session), RFB_ERR_IO);
    apple_capture_test_fixture_destroy(&fixture);
}

RFB_TEST(rfb_session_apple_capture,
         secondary_drain_error_after_block_is_sticky_request_drain)
{
    apple_capture_test_fixture fixture;
    RFB_CHECK(apple_capture_test_fixture_init(&fixture));
    RFB_CHECK(apple_capture_test_expect_initial(&fixture));
    RFB_CHECK(apple_capture_test_enter_hold(&fixture));
    fixture.io.write_budget = 1u;
    RFB_CHECK(apple_capture_test_queue_target(&fixture));
    RFB_CHECK_EQ_INT(rfb_session_capture_state(fixture.session),
                     RFB_CAPTURE_SCHEDULER_REQUEST_DRAINING);

    fixture.io.write_budget = SIZE_MAX;
    fixture.io.scripted_write_blocks = 1u;
    fixture.io.scripted_write_error_after_blocks = true;
    fixture.now_ms++;
    RFB_CHECK_EQ_INT(rfb_session_test_apple_capture_step(
                         fixture.session, fixture.now_ms),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_session_capture_state(fixture.session),
                     RFB_CAPTURE_SCHEDULER_REQUEST_DRAINING);
    fixture.now_ms++;
    RFB_CHECK_EQ_INT(rfb_session_test_apple_capture_step(
                         fixture.session, fixture.now_ms),
                     RFB_ERR_IO);
    RFB_CHECK_EQ_INT(rfb_session_capture_state(fixture.session),
                     RFB_CAPTURE_SCHEDULER_FAILED);
    RFB_CHECK_EQ_INT(rfb_session_capture_failure(fixture.session),
                     RFB_CAPTURE_FAILURE_REQUEST_DRAIN);
    RFB_CHECK_EQ_INT(rfb_session_last_error(fixture.session), RFB_ERR_IO);
    fixture.io.empty_read_result = RFB_IO_EOF;
    fixture.now_ms++;
    (void)rfb_session_test_apple_capture_step(
        fixture.session, fixture.now_ms);
    RFB_CHECK_EQ_INT(rfb_session_capture_failure(fixture.session),
                     RFB_CAPTURE_FAILURE_REQUEST_DRAIN);
    RFB_CHECK_EQ_INT(rfb_session_last_error(fixture.session), RFB_ERR_IO);
    apple_capture_test_fixture_destroy(&fixture);
}

RFB_TEST(rfb_session_apple_capture,
         transition_clock_rejects_fbu_crossing_deadline_during_decode)
{
    apple_capture_test_fixture fixture;
    RFB_CHECK(apple_capture_test_fixture_init(&fixture));
    RFB_CHECK(apple_capture_test_enter_outstanding(&fixture));
    uint8_t response[64];
    const size_t response_length = apple_capture_test_target_fbu(
        response, sizeof response);
    RFB_CHECK(apple_capture_test_seed_plaintext(
        &fixture, response, response_length));

    apple_capture_test_clock clock = {
        .now_ms = fixture.now_ms + 1u,
        .advance_ms = 20u,
        .calls = 0u,
        .hold_calls = 4u,
    };
    RFB_CHECK_EQ_INT(rfb_session_test_apple_capture_step_with_clock(
                         fixture.session, apple_capture_test_clock_now_ms,
                         &clock, 0),
                     RFB_ERR_TIMEOUT);
    RFB_CHECK(clock.calls >= 3u);
    RFB_CHECK_EQ_INT(rfb_session_capture_state(fixture.session),
                     RFB_CAPTURE_SCHEDULER_FAILED);
    RFB_CHECK_EQ_INT(rfb_session_capture_failure(fixture.session),
                     RFB_CAPTURE_FAILURE_TIMEOUT);
    RFB_CHECK(fixture.finals[1].terminal);
    RFB_CHECK(!fixture.finals[1].fbu_complete);
    RFB_CHECK_EQ_INT(fixture.finals[1].classification,
                     RFB_CAPTURE_FINAL_REJECTED);
    apple_capture_test_fixture_destroy(&fixture);
}

RFB_TEST(rfb_session_apple_capture,
         wrong_transport_delta_is_request_drain_terminal_and_sticky)
{
    apple_capture_test_fixture fixture;
    RFB_CHECK(apple_capture_test_fixture_init(&fixture));
    RFB_CHECK(apple_capture_test_expect_initial(&fixture));
    RFB_CHECK(apple_capture_test_enter_hold(&fixture));
    fixture.io.write_chunk = 2u;
    fixture.io.write_budget = 2u;
    RFB_CHECK(apple_capture_test_queue_target(&fixture));
    const uint64_t observed =
        farsee_atomic_u64_load(&fixture.io.tx_bytes);
    RFB_CHECK(observed > 0u);
    farsee_atomic_u64_store(&fixture.io.tx_bytes, observed - 1u);
    fixture.io.write_budget = SIZE_MAX;
    fixture.now_ms++;
    RFB_CHECK_EQ_INT(rfb_session_test_apple_capture_step(
                         fixture.session, fixture.now_ms),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(rfb_session_capture_state(fixture.session),
                     RFB_CAPTURE_SCHEDULER_FAILED);
    RFB_CHECK_EQ_INT(rfb_session_capture_failure(fixture.session),
                     RFB_CAPTURE_FAILURE_REQUEST_DRAIN);
    fixture.now_ms++;
    (void)rfb_session_test_apple_capture_step(
        fixture.session, fixture.now_ms);
    RFB_CHECK_EQ_INT(rfb_session_capture_failure(fixture.session),
                     RFB_CAPTURE_FAILURE_REQUEST_DRAIN);
    apple_capture_test_fixture_destroy(&fixture);
}

RFB_TEST(rfb_session_apple_capture,
         extra_transmitted_byte_is_request_drain_terminal_and_sticky)
{
    apple_capture_test_fixture fixture;
    RFB_CHECK(apple_capture_test_fixture_init(&fixture));
    RFB_CHECK(apple_capture_test_expect_initial(&fixture));
    RFB_CHECK(apple_capture_test_enter_hold(&fixture));
    fixture.io.write_chunk = 2u;
    fixture.io.write_budget = 2u;
    RFB_CHECK(apple_capture_test_queue_target(&fixture));
    RFB_CHECK(fixture.io.outbox_len < sizeof fixture.io.outbox);
    fixture.io.outbox[fixture.io.outbox_len++] = 0xeeu;
    (void)farsee_atomic_u64_fetch_add(&fixture.io.tx_bytes, 1u);
    fixture.io.write_budget = SIZE_MAX;
    fixture.now_ms++;
    RFB_CHECK_EQ_INT(rfb_session_test_apple_capture_step(
                         fixture.session, fixture.now_ms),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(rfb_session_capture_state(fixture.session),
                     RFB_CAPTURE_SCHEDULER_FAILED);
    RFB_CHECK_EQ_INT(rfb_session_capture_failure(fixture.session),
                     RFB_CAPTURE_FAILURE_REQUEST_DRAIN);
    fixture.now_ms++;
    (void)rfb_session_test_apple_capture_step(
        fixture.session, fixture.now_ms);
    RFB_CHECK_EQ_INT(rfb_session_capture_failure(fixture.session),
                     RFB_CAPTURE_FAILURE_REQUEST_DRAIN);
    apple_capture_test_fixture_destroy(&fixture);
}

RFB_TEST(rfb_session_apple_capture,
         typed_control_during_hold_preserves_multi_record_and_bell_alignment)
{
    apple_capture_test_fixture fixture;
    RFB_CHECK(apple_capture_test_fixture_init(&fixture));
    RFB_CHECK(apple_capture_test_expect_initial(&fixture));
    RFB_CHECK(apple_capture_test_enter_hold(&fixture));
    static const uint8_t typed_control[16] = {
        0x00u, 0x00u, 0x00u, 0x01u,
        0x00u, 0x00u, 0x00u, 0x00u,
        0x00u, 0x00u, 0x00u, 0x00u,
        0x00u, 0x00u, 0x77u, 0x77u,
    };
    RFB_CHECK(apple_capture_test_seed_plaintext(
        &fixture, typed_control, sizeof typed_control));
    fixture.now_ms++;
    RFB_CHECK_EQ_INT(rfb_session_test_apple_capture_step(
                         fixture.session, fixture.now_ms),
                     RFB_OK);
    fixture.now_ms++;
    RFB_CHECK_EQ_INT(rfb_session_test_apple_capture_step(
                         fixture.session, fixture.now_ms),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_session_capture_state(fixture.session),
                     RFB_CAPTURE_SCHEDULER_MUTATION_HOLD);

    RFB_CHECK(apple_capture_test_queue_target(&fixture));
    uint8_t target[64];
    size_t target_length = 0u;
    size_t target_wire_length = 0u;
    RFB_CHECK(apple_capture_test_pop_record(
        &fixture, target, sizeof target, &target_length,
        &target_wire_length));
    RFB_CHECK(memcmp(target, apple_capture_test_target_fbur,
                     sizeof apple_capture_test_target_fbur) == 0);
    RFB_CHECK(apple_capture_test_finish_target(&fixture));
    RFB_CHECK_EQ_UINT(
        fixture.rectangles[APPLE_CAPTURE_TEST_INITIAL_MAX].mvs_command_records,
        2u);
    RFB_CHECK_EQ_UINT(
        fixture.rectangles[APPLE_CAPTURE_TEST_INITIAL_MAX].mvs_first_run, 2u);
    RFB_CHECK(fixture.finals[1].terminal);
    RFB_CHECK_EQ_INT(fixture.finals[1].classification,
                     RFB_CAPTURE_FINAL_ASSOCIATION_CLOSED);
    apple_capture_test_fixture_destroy(&fixture);
}

RFB_TEST(rfb_session_apple_capture,
         sealed_multi_record_response_is_classified_by_product_capture_path)
{
    apple_capture_test_fixture fixture;
    RFB_CHECK(apple_capture_test_fixture_init(&fixture));
    RFB_CHECK(apple_capture_test_expect_initial(&fixture));
    RFB_CHECK(apple_capture_test_enter_hold(&fixture));
    RFB_CHECK(apple_capture_test_queue_target(&fixture));
    uint8_t target[64];
    size_t target_length = 0u;
    size_t target_wire_length = 0u;
    RFB_CHECK(apple_capture_test_pop_record(
        &fixture, target, sizeof target, &target_length,
        &target_wire_length));
    RFB_CHECK(apple_capture_test_finish_target(&fixture));
    RFB_CHECK_EQ_UINT(
        fixture.rectangles[APPLE_CAPTURE_TEST_INITIAL_MAX].mvs_command_records,
        2u);
    RFB_CHECK_EQ_UINT(
        fixture.rectangles[APPLE_CAPTURE_TEST_INITIAL_MAX].mvs_first_run, 2u);
    RFB_CHECK(fixture.finals[1].terminal);
    apple_capture_test_fixture_destroy(&fixture);
}

RFB_TEST(rfb_session_apple_capture,
         inbound_encrypted_record_fragments_at_prefix_ciphertext_and_final_byte)
{
    apple_capture_test_fixture fixture;
    RFB_CHECK(apple_capture_test_fixture_init(&fixture));
    RFB_CHECK(apple_capture_test_enter_outstanding(&fixture));
    uint8_t response[64];
    const size_t response_length = apple_capture_test_target_fbu(
        response, sizeof response);
    uint8_t wire[128];
    size_t wire_length = 0u;
    RFB_CHECK(apple_capture_test_seal_plaintext(
        &fixture, response, response_length, wire, sizeof wire,
        &wire_length));
    RFB_CHECK(wire_length > 19u);
    const size_t cuts[] = {1u, 2u, 18u, wire_length - 1u, wire_length};
    size_t offset = 0u;
    for (size_t i = 0u; i < sizeof cuts / sizeof cuts[0]; i++) {
        RFB_CHECK(cuts[i] > offset && cuts[i] <= wire_length);
        RFB_CHECK(apple_capture_test_seed_inbox(
            &fixture.io, wire + offset, cuts[i] - offset));
        fixture.now_ms++;
        RFB_CHECK_EQ_INT(rfb_session_test_apple_capture_step(
                             fixture.session, fixture.now_ms),
                         RFB_OK);
        if (cuts[i] < wire_length) {
            RFB_CHECK_EQ_INT(rfb_session_capture_state(fixture.session),
                             RFB_CAPTURE_SCHEDULER_OUTSTANDING);
        }
        offset = cuts[i];
    }
    RFB_CHECK(apple_capture_test_finish_loaded_target(&fixture));
    RFB_CHECK_EQ_UINT(
        fixture.rectangles[APPLE_CAPTURE_TEST_INITIAL_MAX].mvs_command_records,
        2u);
    RFB_CHECK(fixture.finals[1].terminal);
    apple_capture_test_fixture_destroy(&fixture);
}

RFB_TEST(rfb_session_apple_capture,
         coalesced_typed_and_fbu_records_preserve_record_and_bell_alignment)
{
    apple_capture_test_fixture fixture;
    RFB_CHECK(apple_capture_test_fixture_init(&fixture));
    RFB_CHECK(apple_capture_test_enter_outstanding(&fixture));
    static const uint8_t typed_control[16] = {
        0x00u, 0x00u, 0x00u, 0x01u,
        0x00u, 0x00u, 0x00u, 0x00u,
        0x00u, 0x00u, 0x00u, 0x00u,
        0x00u, 0x00u, 0x77u, 0x77u,
    };
    uint8_t response[64];
    const size_t response_length = apple_capture_test_target_fbu(
        response, sizeof response);
    uint8_t wire[256];
    size_t typed_wire_length = 0u;
    size_t response_wire_length = 0u;
    RFB_CHECK(apple_capture_test_seal_plaintext(
        &fixture, typed_control, sizeof typed_control, wire, sizeof wire,
        &typed_wire_length));
    RFB_CHECK(apple_capture_test_seal_plaintext(
        &fixture, response, response_length, wire + typed_wire_length,
        sizeof wire - typed_wire_length, &response_wire_length));
    RFB_CHECK(apple_capture_test_seed_inbox(
        &fixture.io, wire, typed_wire_length + response_wire_length));
    fixture.now_ms++;
    RFB_CHECK_EQ_INT(rfb_session_test_apple_capture_step(
                         fixture.session, fixture.now_ms),
                     RFB_OK);
    RFB_CHECK(apple_capture_test_finish_loaded_target(&fixture));
    RFB_CHECK_EQ_UINT(
        fixture.rectangles[APPLE_CAPTURE_TEST_INITIAL_MAX].mvs_command_records,
        2u);
    RFB_CHECK(fixture.finals[1].terminal);
    apple_capture_test_fixture_destroy(&fixture);
}

RFB_TEST(rfb_session_apple_capture,
         malformed_encrypted_record_fails_before_target_admission)
{
    apple_capture_test_fixture fixture;
    RFB_CHECK(apple_capture_test_fixture_init(&fixture));
    RFB_CHECK(apple_capture_test_enter_outstanding(&fixture));
    uint8_t response[64];
    const size_t response_length = apple_capture_test_target_fbu(
        response, sizeof response);
    uint8_t wire[128];
    size_t wire_length = 0u;
    RFB_CHECK(apple_capture_test_seal_plaintext(
        &fixture, response, response_length, wire, sizeof wire,
        &wire_length));
    RFB_CHECK(wire_length > 3u);
    wire[3] ^= 0x80u;
    RFB_CHECK(apple_capture_test_seed_inbox(
        &fixture.io, wire, wire_length));
    fixture.now_ms++;
    RFB_CHECK_EQ_INT(rfb_session_test_apple_capture_step(
                         fixture.session, fixture.now_ms),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(rfb_session_last_error(fixture.session),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK(!fixture.finals[1].present);
    apple_capture_test_fixture_destroy(&fixture);
}

RFB_TEST(rfb_session_apple_capture,
         truncated_encrypted_record_then_eof_is_terminal_without_admission)
{
    apple_capture_test_fixture fixture;
    RFB_CHECK(apple_capture_test_fixture_init(&fixture));
    RFB_CHECK(apple_capture_test_enter_outstanding(&fixture));
    uint8_t response[64];
    const size_t response_length = apple_capture_test_target_fbu(
        response, sizeof response);
    uint8_t wire[128];
    size_t wire_length = 0u;
    RFB_CHECK(apple_capture_test_seal_plaintext(
        &fixture, response, response_length, wire, sizeof wire,
        &wire_length));
    RFB_CHECK(wire_length > 1u);
    RFB_CHECK(apple_capture_test_seed_inbox(
        &fixture.io, wire, wire_length - 1u));
    fixture.now_ms++;
    RFB_CHECK_EQ_INT(rfb_session_test_apple_capture_step(
                         fixture.session, fixture.now_ms),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_session_capture_state(fixture.session),
                     RFB_CAPTURE_SCHEDULER_OUTSTANDING);
    fixture.io.empty_read_result = RFB_IO_EOF;
    RFB_CHECK(apple_capture_test_wake_io(&fixture.io));
    fixture.now_ms++;
    RFB_CHECK_EQ_INT(rfb_session_test_apple_capture_step(
                         fixture.session, fixture.now_ms),
                     RFB_ERR_EOF);
    RFB_CHECK_EQ_INT(rfb_session_capture_failure(fixture.session),
                     RFB_CAPTURE_FAILURE_EOF);
    RFB_CHECK(!fixture.finals[1].fbu_complete);
    apple_capture_test_fixture_destroy(&fixture);
}

RFB_TEST(rfb_session_apple_capture,
         encrypted_fbu_during_mutation_hold_is_unsolicited_terminal)
{
    apple_capture_test_fixture fixture;
    RFB_CHECK(apple_capture_test_fixture_init(&fixture));
    RFB_CHECK(apple_capture_test_expect_initial(&fixture));
    RFB_CHECK(apple_capture_test_enter_hold(&fixture));
    uint8_t response[64];
    const size_t response_length = apple_capture_test_target_fbu(
        response, sizeof response);
    RFB_CHECK(apple_capture_test_seed_plaintext(
        &fixture, response, response_length));
    fixture.now_ms++;
    RFB_CHECK_EQ_INT(rfb_session_test_apple_capture_step(
                         fixture.session, fixture.now_ms),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(rfb_session_capture_state(fixture.session),
                     RFB_CAPTURE_SCHEDULER_FAILED);
    RFB_CHECK_EQ_INT(rfb_session_capture_failure(fixture.session),
                     RFB_CAPTURE_FAILURE_UNSOLICITED_FBU);
    RFB_CHECK(fixture.finals[1].terminal);
    apple_capture_test_fixture_destroy(&fixture);
}

// Typed control messages can follow a framebuffer update. This fixture uses a
// single request, one ZRLE update, and nine consecutive 8-byte type-20
// messages. Those messages carry no damage and must not restart the quiet
// window. See lode/BLACK-FRAME-RACE.md.
RFB_TEST(rfb_session_apple_capture,
         typed_control_during_quiet_does_not_restart_the_window)
{
    apple_capture_test_fixture fixture;
    // A quiet window wider than the control cadence, inside a response
    // timeout that still bounds the run.
    apple_capture_test_quiet_ms = 40u;
    apple_capture_test_response_ms = 400u;
    RFB_CHECK(apple_capture_test_fixture_init_mode(&fixture, true));
    RFB_CHECK(apple_capture_test_expect_initial(&fixture));
    uint8_t response[96];
    const size_t response_length = apple_capture_test_zrle_fbu(
        response, sizeof response);
    RFB_CHECK(apple_capture_test_seed_plaintext(
        &fixture, response, response_length));
    fixture.now_ms++;
    RFB_CHECK_EQ_INT(rfb_session_test_apple_capture_step(
                         fixture.session, fixture.now_ms),
                     RFB_OK);

    // Repeat the same valid control message nine times.
    static const uint8_t control[] = {
        0x14u, 0x00u, 0x00u, 0x04u, 0x00u, 0x01u, 0x00u, 0x04u,
    };
    // Each message lands well inside the quiet window, so treating it as
    // activity restarts the window every time and it never closes.
    for (int i = 0; i < 9; i++) {
        RFB_CHECK(apple_capture_test_seed_plaintext(
            &fixture, control, sizeof control));
        fixture.now_ms += 10u;
        RFB_CHECK_EQ_INT(rfb_session_test_apple_capture_step(
                             fixture.session, fixture.now_ms),
                         RFB_OK);
    }

    // The quiet window must still close despite the control traffic.
    fixture.now_ms += 50u;
    RFB_CHECK_EQ_INT(rfb_session_test_apple_capture_step(
                         fixture.session, fixture.now_ms),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_session_capture_state(fixture.session),
                     RFB_CAPTURE_SCHEDULER_DONE);
    RFB_CHECK_EQ_INT(rfb_session_capture_failure(fixture.session),
                     RFB_CAPTURE_FAILURE_NONE);
    RFB_CHECK(fixture.finals[0].terminal);
    RFB_CHECK_EQ_INT(fixture.finals[0].classification,
                     RFB_CAPTURE_FINAL_CONTROL_CLOSED);
    apple_capture_test_fixture_destroy(&fixture);
    apple_capture_test_quiet_ms = 1u;
    apple_capture_test_response_ms = 20u;
}
