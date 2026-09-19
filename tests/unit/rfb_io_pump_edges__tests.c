// SPDX-License-Identifier: Apache-2.0
//
// Edge contracts for the RFB I/O pump.

#include "rfb_test.h"

#include "fake_io.h"
#include "farsee/allocator.h"
#include "farsee/buffer.h"
#include "farsee/error.h"
#include "farsee/limits.h"
#include "farsee/rfb_io_pump.h"

#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

typedef struct pump_fixture {
    fake_io wire;
    rfb_io_adapter adapter;
    rfb_buffer in;
    rfb_buffer out;
    rfb_error last_error;
    rfb_io_pump pump;
} pump_fixture;

typedef struct pump_script {
    rfb_io_result read_result;
    rfb_io_result write_result;
    size_t read_n;
    size_t write_n;
    uint8_t read_byte;
    unsigned read_calls;
    unsigned write_calls;
} pump_script;

typedef struct socket_io {
    int fd;
} socket_io;

static rfb_io_result socket_read(void *context, uint8_t *data, size_t size,
                                 size_t *out_size)
{
    socket_io *io = (socket_io *)context;
    const ssize_t got = recv(io->fd, data, size, 0);
    if (got > 0) {
        *out_size = (size_t)got;
        return RFB_IO_OK;
    }
    *out_size = 0u;
    if (got == 0) {
        return RFB_IO_EOF;
    }
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
        return RFB_IO_BLOCK;
    }
    return RFB_IO_ERROR;
}

static rfb_io_result socket_write(void *context, const uint8_t *data,
                                  size_t size, size_t *out_size)
{
    socket_io *io = (socket_io *)context;
    const ssize_t wrote = send(io->fd, data, size, 0);
    if (wrote >= 0) {
        *out_size = (size_t)wrote;
        return RFB_IO_OK;
    }
    *out_size = 0u;
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
        return RFB_IO_BLOCK;
    }
    return RFB_IO_ERROR;
}

static rfb_io_result scripted_read(void *context, uint8_t *data, size_t size,
                                   size_t *out_size)
{
    pump_script *script = (pump_script *)context;
    script->read_calls++;
    *out_size = 0u;
    if (script->read_result == RFB_IO_OK) {
        const size_t count = script->read_n < size ? script->read_n : size;
        memset(data, script->read_byte, count);
        *out_size = count;
    }
    return script->read_result;
}

static rfb_io_result scripted_write(void *context, const uint8_t *data,
                                    size_t size, size_t *out_size)
{
    pump_script *script = (pump_script *)context;
    (void)data;
    script->write_calls++;
    *out_size = 0u;
    if (script->write_result == RFB_IO_OK) {
        *out_size = script->write_n < size ? script->write_n : size;
    }
    return script->write_result;
}

static void pump_fixture_use_script(pump_fixture *fixture,
                                    pump_script *script)
{
    fixture->adapter.ctx = script;
    fixture->adapter.read = scripted_read;
    fixture->adapter.write = scripted_write;
}

static void make_server_init(uint8_t message[25], uint32_t name_length)
{
    memset(message, 0, 25u);
    message[1] = 4u;
    message[3] = 3u;
    message[4] = 32u;
    message[5] = 24u;
    message[7] = 1u;
    message[9] = 255u;
    message[11] = 255u;
    message[13] = 255u;
    message[14] = 16u;
    message[15] = 8u;
    message[20] = (uint8_t)(name_length >> 24);
    message[21] = (uint8_t)(name_length >> 16);
    message[22] = (uint8_t)(name_length >> 8);
    message[23] = (uint8_t)name_length;
    message[24] = 'x';
}

static void *always_fail_alloc(rfb_allocator *allocator, size_t size)
{
    (void)allocator;
    (void)size;
    return NULL;
}

static void always_fail_free(rfb_allocator *allocator, void *allocation)
{
    (void)allocator;
    (void)allocation;
}

static void pump_fixture_init(pump_fixture *fixture)
{
    memset(fixture, 0, sizeof *fixture);
    fake_io_init(&fixture->wire, rfb_default_allocator());
    fixture->adapter = fake_io_adapter_make(&fixture->wire);
    rfb_buffer_init(&fixture->in, rfb_default_allocator(), 4096u);
    rfb_buffer_init(&fixture->out, rfb_default_allocator(), 4096u);
    fixture->last_error = RFB_OK;
    fixture->pump.io = &fixture->adapter;
    fixture->pump.fd = -1;
    fixture->pump.in = &fixture->in;
    fixture->pump.out = &fixture->out;
    fixture->pump.last_error = &fixture->last_error;
}

static void pump_fixture_destroy(pump_fixture *fixture)
{
    rfb_buffer_destroy(&fixture->in);
    rfb_buffer_destroy(&fixture->out);
    fake_io_destroy(&fixture->wire);
}

RFB_TEST(io_pump_edges, drain__normal_write__commits_all_bytes)
{
    pump_fixture fixture;
    pump_fixture_init(&fixture);
    static const uint8_t bytes[] = { 1u, 2u, 3u, 4u };
    RFB_CHECK_EQ_INT(rfb_buffer_append(&fixture.out, bytes, sizeof bytes),
                     RFB_OK);

    RFB_CHECK_EQ_INT(rfb_io_drain_out(&fixture.pump, 0), RFB_OK);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&fixture.out), 0u);
    RFB_CHECK_EQ_UINT(fake_io_outbox_len(&fixture.wire), sizeof bytes);
    RFB_CHECK_MEM_EQ(fake_io_outbox_data(&fixture.wire), bytes, sizeof bytes);
    RFB_CHECK_EQ_INT(fixture.last_error, RFB_OK);
    pump_fixture_destroy(&fixture);
}

RFB_TEST(io_pump_edges, drain__closed_poll_descriptor__fails_io)
{
    int fds[2];
    RFB_CHECK(pipe(fds) == 0);

    pump_fixture fixture;
    pump_fixture_init(&fixture);
    fixture.wire.wmode = FAKE_W_EAGAIN;
    fixture.pump.fd = fds[0];
    static const uint8_t byte = 0x5au;
    RFB_CHECK_EQ_INT(rfb_buffer_append(&fixture.out, &byte, 1u), RFB_OK);
    RFB_CHECK(close(fds[0]) == 0);

    RFB_CHECK_EQ_INT(rfb_io_drain_out(&fixture.pump, 50), RFB_ERR_IO);
    RFB_CHECK_EQ_INT(fixture.last_error, RFB_ERR_IO);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&fixture.out), 1u);

    RFB_CHECK(close(fds[1]) == 0);
    pump_fixture_destroy(&fixture);
}

RFB_TEST(io_pump_edges, public_guards__reject_incomplete_pumps)
{
    pump_fixture fixture;
    pump_fixture_init(&fixture);
    uint8_t byte = 0u;
    rfb_server_init server_init;
    memset(&server_init, 0, sizeof server_init);

    RFB_CHECK(!rfb_io_stop_requested(NULL));
    RFB_CHECK(!rfb_io_stop_requested(&fixture.pump));
    RFB_CHECK_EQ_INT(rfb_io_drain_out(NULL, 0), RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(rfb_io_queue_bytes(NULL, &byte, 1u), RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(rfb_io_read_some(NULL, 0), RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(rfb_io_read_some_no_drain(NULL, 0), RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(rfb_io_recv_exact(NULL, &byte, 1u), RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(rfb_io_recv_exact(&fixture.pump, NULL, 0u),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(rfb_io_read_server_init(NULL, &server_init),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(rfb_io_read_server_init(&fixture.pump, NULL),
                     RFB_ERR_INTERNAL);

    fixture.pump.io = NULL;
    RFB_CHECK_EQ_INT(rfb_io_drain_out(&fixture.pump, 0), RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(rfb_io_read_some(&fixture.pump, 0), RFB_ERR_INTERNAL);
    fixture.pump.io = &fixture.adapter;
    fixture.pump.in = NULL;
    RFB_CHECK_EQ_INT(rfb_io_read_some(&fixture.pump, 0), RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(rfb_io_recv_exact(&fixture.pump, &byte, 1u),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(rfb_io_read_server_init(&fixture.pump, &server_init),
                     RFB_ERR_INTERNAL);
    fixture.pump.in = &fixture.in;
    fixture.pump.out = NULL;
    RFB_CHECK_EQ_INT(rfb_io_drain_out(&fixture.pump, 0), RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(rfb_io_queue_bytes(&fixture.pump, &byte, 1u),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(rfb_io_read_some(&fixture.pump, 0), RFB_ERR_INTERNAL);
    pump_fixture_destroy(&fixture);
}

RFB_TEST(io_pump_edges, stop_flag__reports_and_cancels_receive_operations)
{
    pump_fixture fixture;
    pump_fixture_init(&fixture);
    farsee_atomic_int stop = 0;
    fixture.pump.stop_flag = &stop;
    RFB_CHECK(!rfb_io_stop_requested(&fixture.pump));
    farsee_atomic_int_store(&stop, 1);
    RFB_CHECK(rfb_io_stop_requested(&fixture.pump));

    uint8_t byte = 0u;
    rfb_server_init server_init;
    memset(&server_init, 0, sizeof server_init);
    RFB_CHECK_EQ_INT(rfb_io_recv_exact(&fixture.pump, &byte, 1u),
                     RFB_ERR_CANCELLED);
    RFB_CHECK_EQ_INT(fixture.last_error, RFB_ERR_CANCELLED);
    fixture.last_error = RFB_OK;
    RFB_CHECK_EQ_INT(rfb_io_read_server_init(&fixture.pump, &server_init),
                     RFB_ERR_CANCELLED);
    RFB_CHECK_EQ_INT(fixture.last_error, RFB_ERR_CANCELLED);
    pump_fixture_destroy(&fixture);
}

RFB_TEST(io_pump_edges, drain__adapter_outcomes__preserve_or_consume_queue)
{
    pump_fixture fixture;
    pump_fixture_init(&fixture);
    static const uint8_t bytes[] = { 8u, 9u, 10u };
    RFB_CHECK_EQ_INT(rfb_buffer_append(&fixture.out, bytes, sizeof bytes),
                     RFB_OK);

    pump_script script;
    memset(&script, 0, sizeof script);
    pump_fixture_use_script(&fixture, &script);

    script.write_result = RFB_IO_BLOCK;
    RFB_CHECK_EQ_INT(rfb_io_drain_out(&fixture.pump, 0), RFB_OK);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&fixture.out), sizeof bytes);

    script.write_result = RFB_IO_OK;
    script.write_n = 0u;
    RFB_CHECK_EQ_INT(rfb_io_drain_out(&fixture.pump, 0), RFB_OK);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&fixture.out), sizeof bytes);

    script.write_result = RFB_IO_EOF;
    fixture.last_error = RFB_OK;
    RFB_CHECK_EQ_INT(rfb_io_drain_out(&fixture.pump, 0), RFB_ERR_IO);
    RFB_CHECK_EQ_INT(fixture.last_error, RFB_ERR_IO);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&fixture.out), sizeof bytes);

    script.write_result = RFB_IO_ERROR;
    fixture.pump.last_error = NULL;
    RFB_CHECK_EQ_INT(rfb_io_drain_out(&fixture.pump, 0), RFB_ERR_IO);

    script.write_result = RFB_IO_OK;
    script.write_n = 1u;
    RFB_CHECK_EQ_INT(rfb_io_drain_out(&fixture.pump, 0), RFB_OK);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&fixture.out), 0u);
    RFB_CHECK(script.write_calls >= 7u);
    pump_fixture_destroy(&fixture);
}

RFB_TEST(io_pump_edges, drain__ready_but_blocked__stops_after_spin_cap)
{
    int fds[2];
    RFB_CHECK(pipe(fds) == 0);
    pump_fixture fixture;
    pump_fixture_init(&fixture);
    fixture.wire.wmode = FAKE_W_EAGAIN;
    fixture.pump.fd = fds[1];
    static const uint8_t byte = 0xa5u;
    RFB_CHECK_EQ_INT(rfb_buffer_append(&fixture.out, &byte, 1u), RFB_OK);

    RFB_CHECK_EQ_INT(rfb_io_drain_out(&fixture.pump, 100), RFB_OK);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&fixture.out), 1u);
    RFB_CHECK(close(fds[0]) == 0);
    RFB_CHECK(close(fds[1]) == 0);
    pump_fixture_destroy(&fixture);
}

RFB_TEST(io_pump_edges, queue_bytes__success_and_limit_failure__set_contract)
{
    pump_fixture fixture;
    pump_fixture_init(&fixture);
    static const uint8_t bytes[] = { 1u, 3u };
    RFB_CHECK_EQ_INT(rfb_io_queue_bytes(&fixture.pump, bytes, sizeof bytes),
                     RFB_OK);
    RFB_CHECK_EQ_UINT(fake_io_outbox_len(&fixture.wire), sizeof bytes);

    rfb_buffer_destroy(&fixture.out);
    rfb_buffer_init(&fixture.out, rfb_default_allocator(), 1u);
    fixture.last_error = RFB_OK;
    RFB_CHECK_EQ_INT(rfb_io_queue_bytes(&fixture.pump, bytes, sizeof bytes),
                     RFB_ERR_LIMIT);
    RFB_CHECK_EQ_INT(fixture.last_error, RFB_ERR_LIMIT);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&fixture.out), 0u);
    pump_fixture_destroy(&fixture);
}

RFB_TEST(io_pump_edges, read_some__poll_errors_and_hangup__fail_closed)
{
    int invalid[2];
    RFB_CHECK(pipe(invalid) == 0);
    pump_fixture fixture;
    pump_fixture_init(&fixture);
    fixture.pump.fd = invalid[0];
    RFB_CHECK(close(invalid[0]) == 0);
    RFB_CHECK_EQ_INT(rfb_io_read_some(&fixture.pump, 0), RFB_ERR_IO);
    RFB_CHECK_EQ_INT(fixture.last_error, RFB_ERR_IO);
    RFB_CHECK(close(invalid[1]) == 0);

    int hung_up[2];
    RFB_CHECK(pipe(hung_up) == 0);
    fixture.pump.fd = hung_up[0];
    fixture.last_error = RFB_OK;
    RFB_CHECK(close(hung_up[1]) == 0);
    RFB_CHECK_EQ_INT(rfb_io_read_some(&fixture.pump, 0), RFB_ERR_EOF);
    RFB_CHECK_EQ_INT(fixture.last_error, RFB_ERR_EOF);
    RFB_CHECK(close(hung_up[0]) == 0);
    pump_fixture_destroy(&fixture);
}

RFB_TEST(io_pump_edges, read_some__stream_data_and_eof__are_distinct)
{
    int sockets[2];
    RFB_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);

    pump_fixture fixture;
    pump_fixture_init(&fixture);
    socket_io io = { .fd = sockets[0] };
    fixture.adapter.ctx = &io;
    fixture.adapter.read = socket_read;
    fixture.adapter.write = socket_write;
    fixture.pump.fd = sockets[0];

    const uint8_t token = 0x7bu;
    RFB_CHECK(send(sockets[1], &token, 1u, 0) == 1);
    RFB_CHECK_EQ_INT(rfb_io_read_some_no_drain(&fixture.pump, 100), RFB_OK);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&fixture.in), 1u);
    RFB_CHECK_EQ_UINT(rfb_buffer_data(&fixture.in)[0], token);
    rfb_buffer_clear(&fixture.in);

    RFB_CHECK(shutdown(sockets[1], SHUT_WR) == 0);
    fixture.last_error = RFB_OK;
    RFB_CHECK_EQ_INT(rfb_io_read_some_no_drain(&fixture.pump, 100),
                     RFB_ERR_EOF);
    RFB_CHECK_EQ_INT(fixture.last_error, RFB_ERR_EOF);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&fixture.in), 0u);

    RFB_CHECK(close(sockets[0]) == 0);
    RFB_CHECK(close(sockets[1]) == 0);
    pump_fixture_destroy(&fixture);
}

RFB_TEST(io_pump_edges, read_some__readable_adapter_outcomes__are_distinct)
{
    static const rfb_io_result outcomes[] = {
        RFB_IO_BLOCK, RFB_IO_EOF, RFB_IO_ERROR, RFB_IO_OK
    };
    static const rfb_error expected[] = {
        RFB_OK, RFB_ERR_EOF, RFB_ERR_IO, RFB_OK
    };
    for (size_t index = 0u; index < sizeof outcomes / sizeof outcomes[0];
         index++) {
        int fds[2];
        RFB_CHECK(pipe(fds) == 0);
        const uint8_t token = 1u;
        RFB_CHECK(write(fds[1], &token, 1u) == 1);

        pump_fixture fixture;
        pump_fixture_init(&fixture);
        fixture.pump.fd = fds[0];
        pump_script script;
        memset(&script, 0, sizeof script);
        script.read_result = outcomes[index];
        script.read_n = outcomes[index] == RFB_IO_OK ? 2u : 0u;
        script.read_byte = 0x6bu;
        pump_fixture_use_script(&fixture, &script);

        RFB_CHECK_EQ_INT(rfb_io_read_some(&fixture.pump, 0), expected[index]);
        RFB_CHECK_EQ_UINT(script.read_calls, 1u);
        RFB_CHECK_EQ_INT(fixture.last_error, expected[index]);
        if (outcomes[index] == RFB_IO_OK) {
            RFB_CHECK_EQ_UINT(rfb_buffer_length(&fixture.in), 2u);
            RFB_CHECK_EQ_UINT(rfb_buffer_data(&fixture.in)[0], 0x6bu);
        } else {
            RFB_CHECK_EQ_UINT(rfb_buffer_length(&fixture.in), 0u);
        }
        RFB_CHECK(close(fds[0]) == 0);
        RFB_CHECK(close(fds[1]) == 0);
        pump_fixture_destroy(&fixture);
    }
}

RFB_TEST(io_pump_edges, read_some__hangup_after_read_block__reports_eof)
{
    int fds[2];
    RFB_CHECK(pipe(fds) == 0);
    const uint8_t token = 1u;
    RFB_CHECK(write(fds[1], &token, 1u) == 1);
    RFB_CHECK(close(fds[1]) == 0);

    pump_fixture fixture;
    pump_fixture_init(&fixture);
    fixture.pump.fd = fds[0];
    pump_script script;
    memset(&script, 0, sizeof script);
    script.read_result = RFB_IO_BLOCK;
    pump_fixture_use_script(&fixture, &script);
    RFB_CHECK_EQ_INT(rfb_io_read_some_no_drain(&fixture.pump, 0), RFB_ERR_EOF);
    RFB_CHECK_EQ_INT(fixture.last_error, RFB_ERR_EOF);
    RFB_CHECK_EQ_UINT(script.read_calls, 1u);
    RFB_CHECK(close(fds[0]) == 0);
    pump_fixture_destroy(&fixture);
}

RFB_TEST(io_pump_edges, read_some_no_drain__leaves_outbound_bytes_queued)
{
    pump_fixture fixture;
    pump_fixture_init(&fixture);
    static const uint8_t byte = 4u;
    RFB_CHECK_EQ_INT(rfb_buffer_append(&fixture.out, &byte, 1u), RFB_OK);
    RFB_CHECK_EQ_INT(rfb_io_read_some_no_drain(&fixture.pump, 0), RFB_OK);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&fixture.out), 1u);
    RFB_CHECK_EQ_UINT(fake_io_outbox_len(&fixture.wire), 0u);
    pump_fixture_destroy(&fixture);
}

RFB_TEST(io_pump_edges, read_some__input_allocation_failure__is_reported)
{
    int fds[2];
    RFB_CHECK(pipe(fds) == 0);
    const uint8_t token = 1u;
    RFB_CHECK(write(fds[1], &token, 1u) == 1);

    pump_fixture fixture;
    pump_fixture_init(&fixture);
    fixture.pump.fd = fds[0];
    rfb_buffer_destroy(&fixture.in);
    rfb_allocator allocator = {
        .alloc = always_fail_alloc,
        .free = always_fail_free,
        .user = NULL,
    };
    rfb_buffer_init(&fixture.in, &allocator, 4096u);
    pump_script script;
    memset(&script, 0, sizeof script);
    script.read_result = RFB_IO_OK;
    script.read_n = 1u;
    pump_fixture_use_script(&fixture, &script);

    RFB_CHECK_EQ_INT(rfb_io_read_some(&fixture.pump, 0), RFB_ERR_NOMEM);
    RFB_CHECK_EQ_INT(fixture.last_error, RFB_ERR_NOMEM);
    RFB_CHECK(close(fds[0]) == 0);
    RFB_CHECK(close(fds[1]) == 0);
    pump_fixture_destroy(&fixture);
}

RFB_TEST(io_pump_edges, recv_exact__buffered_and_adapter_bytes__preserve_order)
{
    int fds[2];
    RFB_CHECK(pipe(fds) == 0);
    const uint8_t token = 1u;
    RFB_CHECK(write(fds[1], &token, 1u) == 1);
    pump_fixture fixture;
    pump_fixture_init(&fixture);
    fixture.pump.fd = fds[0];
    static const uint8_t prefix[] = { 1u, 2u };
    RFB_CHECK_EQ_INT(rfb_buffer_append(&fixture.in, prefix, sizeof prefix),
                     RFB_OK);
    pump_script script;
    memset(&script, 0, sizeof script);
    script.read_result = RFB_IO_OK;
    script.read_n = 2u;
    script.read_byte = 3u;
    pump_fixture_use_script(&fixture, &script);

    uint8_t output[4] = { 0u };
    RFB_CHECK_EQ_INT(rfb_io_recv_exact(&fixture.pump, output, sizeof output),
                     RFB_OK);
    static const uint8_t expected[] = { 1u, 2u, 3u, 3u };
    RFB_CHECK_MEM_EQ(output, expected, sizeof expected);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&fixture.in), 0u);
    RFB_CHECK_EQ_INT(rfb_io_recv_exact(&fixture.pump, output, 0u), RFB_OK);
    RFB_CHECK(close(fds[0]) == 0);
    RFB_CHECK(close(fds[1]) == 0);
    pump_fixture_destroy(&fixture);
}

RFB_TEST(io_pump_edges, recv_exact__adapter_error__propagates)
{
    int fds[2];
    RFB_CHECK(pipe(fds) == 0);
    const uint8_t token = 1u;
    RFB_CHECK(write(fds[1], &token, 1u) == 1);
    pump_fixture fixture;
    pump_fixture_init(&fixture);
    fixture.pump.fd = fds[0];
    pump_script script;
    memset(&script, 0, sizeof script);
    script.read_result = RFB_IO_ERROR;
    pump_fixture_use_script(&fixture, &script);
    uint8_t output = 0u;
    RFB_CHECK_EQ_INT(rfb_io_recv_exact(&fixture.pump, &output, 1u),
                     RFB_ERR_IO);
    RFB_CHECK_EQ_INT(fixture.last_error, RFB_ERR_IO);
    RFB_CHECK(close(fds[0]) == 0);
    RFB_CHECK(close(fds[1]) == 0);
    pump_fixture_destroy(&fixture);
}

RFB_TEST(io_pump_edges, server_init__limit_parse_and_allocator_failures_preserve_input)
{
    pump_fixture fixture;
    pump_fixture_init(&fixture);
    uint8_t message[25];
    make_server_init(message, (uint32_t)RFB_LIMIT_DESKTOP_NAME_BYTES + 1u);
    RFB_CHECK_EQ_INT(rfb_buffer_append(&fixture.in, message, 24u), RFB_OK);
    rfb_server_init server_init;
    memset(&server_init, 0, sizeof server_init);
    RFB_CHECK_EQ_INT(rfb_io_read_server_init(&fixture.pump, &server_init),
                     RFB_ERR_LIMIT);
    RFB_CHECK_EQ_INT(fixture.last_error, RFB_ERR_LIMIT);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&fixture.in), 24u);

    rfb_buffer_clear(&fixture.in);
    make_server_init(message, 0u);
    message[4] = 0u;
    RFB_CHECK_EQ_INT(rfb_buffer_append(&fixture.in, message, 24u), RFB_OK);
    fixture.last_error = RFB_OK;
    RFB_CHECK_EQ_INT(rfb_io_read_server_init(&fixture.pump, &server_init),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(fixture.last_error, RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&fixture.in), 24u);

    rfb_buffer_clear(&fixture.in);
    make_server_init(message, 1u);
    RFB_CHECK_EQ_INT(rfb_buffer_append(&fixture.in, message, sizeof message),
                     RFB_OK);
    rfb_allocator allocator = {
        .alloc = always_fail_alloc,
        .free = always_fail_free,
        .user = NULL,
    };
    fixture.pump.alloc = &allocator;
    fixture.last_error = RFB_OK;
    RFB_CHECK_EQ_INT(rfb_io_read_server_init(&fixture.pump, &server_init),
                     RFB_ERR_NOMEM);
    RFB_CHECK_EQ_INT(fixture.last_error, RFB_ERR_NOMEM);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&fixture.in), sizeof message);
    pump_fixture_destroy(&fixture);
}

RFB_TEST(io_pump_edges, server_init__partial_message__reads_and_consumes_exactly)
{
    int fds[2];
    RFB_CHECK(pipe(fds) == 0);
    const uint8_t token = 1u;
    RFB_CHECK(write(fds[1], &token, 1u) == 1);
    pump_fixture fixture;
    pump_fixture_init(&fixture);
    fixture.pump.fd = fds[0];
    uint8_t message[25];
    make_server_init(message, 1u);
    RFB_CHECK_EQ_INT(rfb_buffer_append(&fixture.in, message, 12u), RFB_OK);
    fake_io_seed_inbox(&fixture.wire, message + 12u, sizeof message - 12u);

    rfb_server_init server_init;
    memset(&server_init, 0, sizeof server_init);
    RFB_CHECK_EQ_INT(rfb_io_read_server_init(&fixture.pump, &server_init),
                     RFB_OK);
    RFB_CHECK_EQ_UINT(server_init.width, 4u);
    RFB_CHECK_EQ_UINT(server_init.height, 3u);
    RFB_CHECK_EQ_UINT(server_init.name_length, 1u);
    RFB_CHECK_MEM_EQ(server_init.name, "x", 2u);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&fixture.in), 0u);
    rfb_server_init_destroy(&server_init);
    RFB_CHECK(close(fds[0]) == 0);
    RFB_CHECK(close(fds[1]) == 0);
    pump_fixture_destroy(&fixture);
}

RFB_TEST(io_pump_edges,
         read_some__outbound_drain_failure__returns_before_poll)
{
    pump_fixture fixture;
    pump_fixture_init(&fixture);
    static const uint8_t byte = 0x91u;
    RFB_CHECK_EQ_INT(rfb_buffer_append(&fixture.out, &byte, 1u), RFB_OK);

    pump_script script;
    memset(&script, 0, sizeof script);
    script.write_result = RFB_IO_ERROR;
    script.read_result = RFB_IO_OK;
    script.read_n = 1u;
    pump_fixture_use_script(&fixture, &script);

    RFB_CHECK_EQ_INT(rfb_io_read_some(&fixture.pump, 0), RFB_ERR_IO);
    RFB_CHECK_EQ_INT(fixture.last_error, RFB_ERR_IO);
    RFB_CHECK_EQ_UINT(script.write_calls, 1u);
    RFB_CHECK_EQ_UINT(script.read_calls, 0u);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&fixture.out), 1u);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&fixture.in), 0u);
    pump_fixture_destroy(&fixture);
}

RFB_TEST(io_pump_edges, read_some__hung_up_zero_read__reports_eof)
{
    int hung_up[2];
    RFB_CHECK(pipe(hung_up) == 0);
    static const uint8_t token = 1u;
    RFB_CHECK(write(hung_up[1], &token, 1u) == 1);
    RFB_CHECK(close(hung_up[1]) == 0);
    pump_fixture fixture;
    pump_fixture_init(&fixture);
    fixture.pump.fd = hung_up[0];
    pump_script script;
    memset(&script, 0, sizeof script);
    script.read_result = RFB_IO_OK;
    script.read_n = 0u;
    pump_fixture_use_script(&fixture, &script);

    RFB_CHECK_EQ_INT(rfb_io_read_some_no_drain(&fixture.pump, 0), RFB_ERR_EOF);
    RFB_CHECK_EQ_INT(fixture.last_error, RFB_ERR_EOF);
    RFB_CHECK_EQ_UINT(script.read_calls, 1u);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&fixture.in), 0u);
    RFB_CHECK(close(hung_up[0]) == 0);
    pump_fixture_destroy(&fixture);
}

RFB_TEST(io_pump_edges,
         server_init__drain_and_partial_read_errors__preserve_buffers)
{
    pump_fixture fixture;
    pump_fixture_init(&fixture);
    pump_script script;
    memset(&script, 0, sizeof script);
    script.write_result = RFB_IO_ERROR;
    script.read_result = RFB_IO_OK;
    pump_fixture_use_script(&fixture, &script);
    static const uint8_t outbound = 0x73u;
    RFB_CHECK_EQ_INT(rfb_buffer_append(&fixture.out, &outbound, 1u), RFB_OK);
    rfb_server_init server_init;
    memset(&server_init, 0, sizeof server_init);

    RFB_CHECK_EQ_INT(rfb_io_read_server_init(&fixture.pump, &server_init),
                     RFB_ERR_IO);
    RFB_CHECK_EQ_INT(fixture.last_error, RFB_ERR_IO);
    RFB_CHECK_EQ_UINT(script.write_calls, 1u);
    RFB_CHECK_EQ_UINT(script.read_calls, 0u);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&fixture.out), 1u);
    pump_fixture_destroy(&fixture);

    int readable[2];
    RFB_CHECK(pipe(readable) == 0);
    static const uint8_t token = 1u;
    RFB_CHECK(write(readable[1], &token, 1u) == 1);
    pump_fixture_init(&fixture);
    fixture.pump.fd = readable[0];
    uint8_t message[25];
    make_server_init(message, 1u);
    RFB_CHECK_EQ_INT(rfb_buffer_append(&fixture.in, message, 24u), RFB_OK);
    memset(&script, 0, sizeof script);
    script.read_result = RFB_IO_ERROR;
    script.write_result = RFB_IO_OK;
    pump_fixture_use_script(&fixture, &script);

    RFB_CHECK_EQ_INT(rfb_io_read_server_init(&fixture.pump, &server_init),
                     RFB_ERR_IO);
    RFB_CHECK_EQ_INT(fixture.last_error, RFB_ERR_IO);
    RFB_CHECK_EQ_UINT(script.write_calls, 0u);
    RFB_CHECK_EQ_UINT(script.read_calls, 1u);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&fixture.in), 24u);
    RFB_CHECK(close(readable[0]) == 0);
    RFB_CHECK(close(readable[1]) == 0);
    pump_fixture_destroy(&fixture);
}
