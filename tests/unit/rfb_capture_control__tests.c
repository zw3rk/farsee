// SPDX-License-Identifier: Apache-2.0

#include "rfb_test.h"

#include "farsee/rfb_capture_control.h"

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <stdint.h>
#include <string.h>

RFB_TEST(rfb_capture_control, ready_exact_wire_and_roundtrip)
{
    rfb_capture_control_message message;
    memset(&message, 0, sizeof message);
    message.kind = RFB_CAPTURE_CONTROL_READY_FOR_MUTATION;
    message.slot_nonce = UINT64_C(0x0102030405060708);
    message.transition_id = UINT32_C(0x11223344);
    uint8_t wire[RFB_CAPTURE_CONTROL_WIRE_SIZE];
    size_t wire_len = 0u;
    RFB_CHECK_EQ_INT(rfb_capture_control_encode(
                         &message, wire, sizeof wire, &wire_len),
                     RFB_OK);
    RFB_CHECK_EQ_UINT(wire_len, sizeof wire);
    static const uint8_t prefix[] = {
        'M', 'V', 'S', 'C', 0x00u, 0x01u, 0x00u, 0x01u,
        0x01u, 0x02u, 0x03u, 0x04u, 0x05u, 0x06u, 0x07u, 0x08u,
        0x11u, 0x22u, 0x33u, 0x44u,
    };
    RFB_CHECK(memcmp(wire, prefix, sizeof prefix) == 0);
    for (size_t i = sizeof prefix; i < sizeof wire; i++) {
        RFB_CHECK_EQ_UINT(wire[i], 0u);
    }
    rfb_capture_control_message decoded;
    memset(&decoded, 0xa5, sizeof decoded);
    RFB_CHECK_EQ_INT(rfb_capture_control_decode(wire, wire_len, &decoded),
                     RFB_OK);
    RFB_CHECK_EQ_INT(decoded.kind,
                     RFB_CAPTURE_CONTROL_READY_FOR_MUTATION);
    RFB_CHECK_EQ_UINT(decoded.slot_nonce, message.slot_nonce);
    RFB_CHECK_EQ_UINT(decoded.transition_id, message.transition_id);
}

RFB_TEST(rfb_capture_control, ack_binding_roundtrip)
{
    rfb_capture_control_message message;
    memset(&message, 0, sizeof message);
    message.kind = RFB_CAPTURE_CONTROL_MUTATION_ACK;
    message.slot_nonce = UINT64_C(0xfedcba9876543210);
    message.transition_id = 4101u;
    for (size_t i = 0u; i < sizeof message.source_b_binding; i++) {
        message.source_b_binding[i] = (uint8_t)(i + 1u);
    }
    uint8_t wire[RFB_CAPTURE_CONTROL_WIRE_SIZE];
    size_t wire_len = 0u;
    RFB_CHECK_EQ_INT(rfb_capture_control_encode(
                         &message, wire, sizeof wire, &wire_len),
                     RFB_OK);
    rfb_capture_control_message decoded;
    RFB_CHECK_EQ_INT(rfb_capture_control_decode(wire, wire_len, &decoded),
                     RFB_OK);
    RFB_CHECK_EQ_INT(decoded.kind, RFB_CAPTURE_CONTROL_MUTATION_ACK);
    RFB_CHECK(memcmp(decoded.source_b_binding, message.source_b_binding,
                     sizeof decoded.source_b_binding) == 0);
}

RFB_TEST(rfb_capture_control, rejects_invalid_fields_and_framing)
{
    rfb_capture_control_message message;
    memset(&message, 0, sizeof message);
    message.kind = RFB_CAPTURE_CONTROL_MUTATION_ACK;
    message.slot_nonce = 9u;
    message.transition_id = 10u;
    message.source_b_binding[0] = 1u;
    uint8_t wire[RFB_CAPTURE_CONTROL_WIRE_SIZE];
    size_t wire_len = 0u;
    RFB_CHECK_EQ_INT(rfb_capture_control_encode(
                         &message, wire, sizeof wire, &wire_len),
                     RFB_OK);

    rfb_capture_control_message out;
    RFB_CHECK_EQ_INT(rfb_capture_control_decode(wire, wire_len - 1u, &out),
                     RFB_ERR_PROTOCOL);
    uint8_t bad[RFB_CAPTURE_CONTROL_WIRE_SIZE];
    memcpy(bad, wire, sizeof bad);
    bad[0] ^= 1u;
    RFB_CHECK_EQ_INT(rfb_capture_control_decode(bad, sizeof bad, &out),
                     RFB_ERR_PROTOCOL);
    memcpy(bad, wire, sizeof bad);
    bad[5] = 2u;
    RFB_CHECK_EQ_INT(rfb_capture_control_decode(bad, sizeof bad, &out),
                     RFB_ERR_PROTOCOL);
    memcpy(bad, wire, sizeof bad);
    bad[7] = 3u;
    RFB_CHECK_EQ_INT(rfb_capture_control_decode(bad, sizeof bad, &out),
                     RFB_ERR_PROTOCOL);

    message.slot_nonce = 0u;
    RFB_CHECK_EQ_INT(rfb_capture_control_encode(
                         &message, wire, sizeof wire, &wire_len),
                     RFB_ERR_PROTOCOL);
    message.slot_nonce = 9u;
    message.transition_id = 0u;
    RFB_CHECK_EQ_INT(rfb_capture_control_encode(
                         &message, wire, sizeof wire, &wire_len),
                     RFB_ERR_PROTOCOL);
    message.transition_id = 10u;
    memset(message.source_b_binding, 0, sizeof message.source_b_binding);
    RFB_CHECK_EQ_INT(rfb_capture_control_encode(
                         &message, wire, sizeof wire, &wire_len),
                     RFB_ERR_PROTOCOL);
    message.kind = RFB_CAPTURE_CONTROL_READY_FOR_MUTATION;
    message.source_b_binding[0] = 1u;
    RFB_CHECK_EQ_INT(rfb_capture_control_encode(
                         &message, wire, sizeof wire, &wire_len),
                     RFB_ERR_PROTOCOL);

    wire_len = 99u;
    RFB_CHECK_EQ_INT(rfb_capture_control_encode(
                         NULL, wire, sizeof wire, &wire_len),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_UINT(wire_len, 0u);
    message.kind = (rfb_capture_control_kind)99;
    RFB_CHECK_EQ_INT(rfb_capture_control_encode(
                         &message, wire, sizeof wire, &wire_len),
                     RFB_ERR_PROTOCOL);
    memset(&message, 0, sizeof message);
    message.kind = RFB_CAPTURE_CONTROL_READY_FOR_MUTATION;
    message.slot_nonce = 9u;
    message.transition_id = 10u;
    RFB_CHECK_EQ_INT(rfb_capture_control_encode(
                         &message, NULL, sizeof wire, &wire_len),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(rfb_capture_control_encode(
                         &message, wire, sizeof wire, NULL),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(rfb_capture_control_encode(
                         &message, wire, sizeof wire - 1u, &wire_len),
                     RFB_ERR_LIMIT);

    RFB_CHECK_EQ_INT(rfb_capture_control_encode(
                         &message, wire, sizeof wire, &wire_len),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_capture_control_decode(NULL, wire_len, &out),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(rfb_capture_control_decode(wire, wire_len, NULL),
                     RFB_ERR_PROTOCOL);
    memcpy(bad, wire, sizeof bad);
    bad[4] = 1u;
    RFB_CHECK_EQ_INT(rfb_capture_control_decode(bad, sizeof bad, &out),
                     RFB_ERR_PROTOCOL);
    memcpy(bad, wire, sizeof bad);
    bad[6] = 1u;
    RFB_CHECK_EQ_INT(rfb_capture_control_decode(bad, sizeof bad, &out),
                     RFB_ERR_PROTOCOL);
    memcpy(bad, wire, sizeof bad);
    bad[8] = 0u;
    memset(bad + 8u, 0, 8u);
    RFB_CHECK_EQ_INT(rfb_capture_control_decode(bad, sizeof bad, &out),
                     RFB_ERR_PROTOCOL);
    memcpy(bad, wire, sizeof bad);
    memset(bad + 16u, 0, 4u);
    RFB_CHECK_EQ_INT(rfb_capture_control_decode(bad, sizeof bad, &out),
                     RFB_ERR_PROTOCOL);
    memcpy(bad, wire, sizeof bad);
    bad[20] = 1u;
    RFB_CHECK_EQ_INT(rfb_capture_control_decode(bad, sizeof bad, &out),
                     RFB_ERR_PROTOCOL);

    memset(&message, 0, sizeof message);
    message.kind = RFB_CAPTURE_CONTROL_MUTATION_ACK;
    message.slot_nonce = 9u;
    message.transition_id = 10u;
    message.source_b_binding[0] = 1u;
    RFB_CHECK_EQ_INT(rfb_capture_control_encode(
                         &message, wire, sizeof wire, &wire_len),
                     RFB_OK);
    memset(wire + 20u, 0, RFB_CAPTURE_CONTROL_BINDING_SIZE);
    RFB_CHECK_EQ_INT(rfb_capture_control_decode(wire, sizeof wire, &out),
                     RFB_ERR_PROTOCOL);
}

RFB_TEST(rfb_capture_control, endpoint_requires_connected_pathless_socketpair)
{
    RFB_CHECK(!rfb_capture_control_endpoint_valid(-1));
    int pair[2] = {-1, -1};
    RFB_CHECK_EQ_INT(socketpair(AF_UNIX, SOCK_DGRAM, 0, pair), 0);
    RFB_CHECK(!rfb_capture_control_endpoint_valid(pair[0]));
    RFB_CHECK(fcntl(pair[0], F_SETFL,
                    fcntl(pair[0], F_GETFL, 0) | O_NONBLOCK) == 0);
    RFB_CHECK(rfb_capture_control_endpoint_valid(pair[0]));

    int stream_pair[2] = {-1, -1};
    RFB_CHECK_EQ_INT(socketpair(AF_UNIX, SOCK_STREAM, 0, stream_pair), 0);
    RFB_CHECK(fcntl(stream_pair[0], F_SETFL,
                    fcntl(stream_pair[0], F_GETFL, 0) | O_NONBLOCK) == 0);
    RFB_CHECK(!rfb_capture_control_endpoint_valid(stream_pair[0]));

    char regular_path[] = "/tmp/farsee-control-file-XXXXXX";
    const int regular = mkstemp(regular_path);
    RFB_CHECK(regular >= 0);
    RFB_CHECK(fcntl(regular, F_SETFL,
                    fcntl(regular, F_GETFL, 0) | O_NONBLOCK) == 0);
    RFB_CHECK(!rfb_capture_control_endpoint_valid(regular));

    int unconnected = socket(AF_UNIX, SOCK_DGRAM, 0);
    RFB_CHECK(unconnected >= 0);
    RFB_CHECK(fcntl(unconnected, F_SETFL,
                    fcntl(unconnected, F_GETFL, 0) | O_NONBLOCK) == 0);
    RFB_CHECK(!rfb_capture_control_endpoint_valid(unconnected));

    char path[sizeof(((struct sockaddr_un *)0)->sun_path)];
    const int path_n = snprintf(path, sizeof path, "/tmp/farsee-control-%ld",
                                (long)getpid());
    RFB_CHECK(path_n > 0 && (size_t)path_n < sizeof path);
    (void)unlink(path);
    int bound = socket(AF_UNIX, SOCK_DGRAM, 0);
    RFB_CHECK(bound >= 0);
    struct sockaddr_un address;
    memset(&address, 0, sizeof address);
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, path, (size_t)path_n + 1u);
    RFB_CHECK_EQ_INT(bind(bound, (struct sockaddr *)&address,
                          (socklen_t)(offsetof(struct sockaddr_un, sun_path) +
                                      (size_t)path_n + 1u)),
                     0);
    RFB_CHECK(!rfb_capture_control_endpoint_valid(bound));

    (void)close(bound);
    (void)unlink(path);
    (void)close(regular);
    (void)unlink(regular_path);
    (void)close(stream_pair[0]);
    (void)close(stream_pair[1]);
    (void)close(unconnected);
    (void)close(pair[0]);
    (void)close(pair[1]);
}

static rfb_error drain_one_datagram(
    const uint8_t *wire, size_t wire_length, bool allow_ack,
    uint64_t slot_nonce, uint32_t transition_id,
    const uint8_t binding[RFB_CAPTURE_CONTROL_BINDING_SIZE], bool *accepted)
{
    int pair[2] = {-1, -1};
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, pair) != 0) {
        return RFB_ERR_INTERNAL;
    }
    const int flags = fcntl(pair[0], F_GETFL, 0);
    if (flags < 0 || fcntl(pair[0], F_SETFL, flags | O_NONBLOCK) != 0 ||
        send(pair[1], wire, wire_length, 0) != (ssize_t)wire_length) {
        (void)close(pair[0]);
        (void)close(pair[1]);
        return RFB_ERR_INTERNAL;
    }
    const rfb_error result = rfb_capture_control_drain_ack(
        pair[0], allow_ack, slot_nonce, transition_id, binding, accepted);
    (void)close(pair[0]);
    (void)close(pair[1]);
    return result;
}

RFB_TEST(rfb_capture_control, drain_ack_validates_every_datagram_field)
{
    uint8_t binding[RFB_CAPTURE_CONTROL_BINDING_SIZE];
    memset(binding, 0xa5, sizeof binding);
    rfb_capture_control_message message;
    memset(&message, 0, sizeof message);
    message.kind = RFB_CAPTURE_CONTROL_MUTATION_ACK;
    message.slot_nonce = UINT64_C(0x1122334455667788);
    message.transition_id = UINT32_C(0x12345678);
    memcpy(message.source_b_binding, binding, sizeof binding);
    uint8_t wire[RFB_CAPTURE_CONTROL_WIRE_SIZE];
    size_t wire_length = 0u;
    RFB_CHECK_EQ_INT(rfb_capture_control_encode(
                         &message, wire, sizeof wire, &wire_length),
                     RFB_OK);

    bool accepted = false;
    RFB_CHECK_EQ_INT(drain_one_datagram(
                         wire, wire_length, true, message.slot_nonce,
                         message.transition_id, binding, &accepted),
                     RFB_OK);
    RFB_CHECK(accepted);
    accepted = true;
    RFB_CHECK_EQ_INT(drain_one_datagram(
                         wire, wire_length, false, message.slot_nonce,
                         message.transition_id, binding, &accepted),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK(!accepted);
    RFB_CHECK_EQ_INT(drain_one_datagram(
                         wire, wire_length - 1u, true, message.slot_nonce,
                         message.transition_id, binding, &accepted),
                     RFB_ERR_PROTOCOL);
    uint8_t bad[RFB_CAPTURE_CONTROL_WIRE_SIZE];
    memcpy(bad, wire, sizeof bad);
    bad[0] ^= 1u;
    RFB_CHECK_EQ_INT(drain_one_datagram(
                         bad, sizeof bad, true, message.slot_nonce,
                         message.transition_id, binding, &accepted),
                     RFB_ERR_PROTOCOL);

    rfb_capture_control_message ready;
    memset(&ready, 0, sizeof ready);
    ready.kind = RFB_CAPTURE_CONTROL_READY_FOR_MUTATION;
    ready.slot_nonce = message.slot_nonce;
    ready.transition_id = message.transition_id;
    RFB_CHECK_EQ_INT(rfb_capture_control_encode(
                         &ready, bad, sizeof bad, &wire_length),
                     RFB_OK);
    RFB_CHECK_EQ_INT(drain_one_datagram(
                         bad, wire_length, true, message.slot_nonce,
                         message.transition_id, binding, &accepted),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(drain_one_datagram(
                         wire, sizeof wire, true, message.slot_nonce + 1u,
                         message.transition_id, binding, &accepted),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK_EQ_INT(drain_one_datagram(
                         wire, sizeof wire, true, message.slot_nonce,
                         message.transition_id + 1u, binding, &accepted),
                     RFB_ERR_PROTOCOL);
    uint8_t other_binding[RFB_CAPTURE_CONTROL_BINDING_SIZE];
    memcpy(other_binding, binding, sizeof other_binding);
    other_binding[0] ^= 1u;
    RFB_CHECK_EQ_INT(drain_one_datagram(
                         wire, sizeof wire, true, message.slot_nonce,
                         message.transition_id, other_binding, &accepted),
                     RFB_ERR_PROTOCOL);
}

RFB_TEST(rfb_capture_control, drain_ack_rejects_arguments_and_read_failures)
{
    uint8_t binding[RFB_CAPTURE_CONTROL_BINDING_SIZE];
    memset(binding, 1, sizeof binding);
    bool accepted = true;
    RFB_CHECK_EQ_INT(rfb_capture_control_drain_ack(
                         -1, true, 1u, 1u, binding, &accepted),
                     RFB_ERR_INTERNAL);

    int pair[2] = {-1, -1};
    RFB_CHECK_EQ_INT(socketpair(AF_UNIX, SOCK_DGRAM, 0, pair), 0);
    RFB_CHECK(fcntl(pair[0], F_SETFL,
                    fcntl(pair[0], F_GETFL, 0) | O_NONBLOCK) == 0);
    RFB_CHECK_EQ_INT(rfb_capture_control_drain_ack(
                         pair[0], true, 0u, 1u, binding, &accepted),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(rfb_capture_control_drain_ack(
                         pair[0], true, 1u, 0u, binding, &accepted),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(rfb_capture_control_drain_ack(
                         pair[0], true, 1u, 1u, NULL, &accepted),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(rfb_capture_control_drain_ack(
                         pair[0], true, 1u, 1u, binding, NULL),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(rfb_capture_control_drain_ack(
                         pair[0], true, 1u, 1u, binding, &accepted),
                     RFB_OK);
    RFB_CHECK(!accepted);
    RFB_CHECK_EQ_INT(send(pair[1], "", 0u, 0), 0);
    RFB_CHECK_EQ_INT(rfb_capture_control_drain_ack(
                         pair[0], true, 1u, 1u, binding, &accepted),
                     RFB_ERR_IO);
    const int closed = pair[0];
    RFB_CHECK_EQ_INT(close(pair[0]), 0);
    pair[0] = -1;
    RFB_CHECK_EQ_INT(rfb_capture_control_drain_ack(
                         closed, true, 1u, 1u, binding, &accepted),
                     RFB_ERR_IO);
    (void)close(pair[1]);
}

RFB_TEST(rfb_capture_control, queued_duplicate_is_rejected_atomically)
{
    int pair[2] = {-1, -1};
    RFB_CHECK_EQ_INT(socketpair(AF_UNIX, SOCK_DGRAM, 0, pair), 0);
    for (size_t i = 0u; i < 2u; i++) {
        RFB_CHECK(fcntl(pair[i], F_SETFL,
                        fcntl(pair[i], F_GETFL, 0) | O_NONBLOCK) == 0);
    }
    uint8_t binding[RFB_CAPTURE_CONTROL_BINDING_SIZE];
    memset(binding, 0xa5, sizeof binding);
    rfb_capture_control_message message;
    memset(&message, 0, sizeof message);
    message.kind = RFB_CAPTURE_CONTROL_MUTATION_ACK;
    message.slot_nonce = UINT64_C(0x1122334455667788);
    message.transition_id = UINT32_C(0x12345678);
    memcpy(message.source_b_binding, binding, sizeof binding);
    uint8_t wire[RFB_CAPTURE_CONTROL_WIRE_SIZE];
    size_t wire_length = 0u;
    RFB_CHECK_EQ_INT(rfb_capture_control_encode(
                         &message, wire, sizeof wire, &wire_length),
                     RFB_OK);
    RFB_CHECK_EQ_INT(send(pair[1], wire, wire_length, 0),
                     (ssize_t)wire_length);
    RFB_CHECK_EQ_INT(send(pair[1], wire, wire_length, 0),
                     (ssize_t)wire_length);
    bool accepted = true;
    RFB_CHECK_EQ_INT(rfb_capture_control_drain_ack(
                         pair[0], true, message.slot_nonce,
                         message.transition_id, binding, &accepted),
                     RFB_ERR_PROTOCOL);
    RFB_CHECK(!accepted);
    uint8_t extra = 0u;
    RFB_CHECK(recv(pair[0], &extra, 1u, MSG_DONTWAIT) < 0 &&
              (errno == EAGAIN || errno == EWOULDBLOCK));
    (void)close(pair[0]);
    (void)close(pair[1]);
}
