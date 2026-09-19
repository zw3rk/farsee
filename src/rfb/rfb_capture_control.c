// SPDX-License-Identifier: Apache-2.0
//
// Versioned pathless control datagrams for capture-only scene mutation.

#include "farsee/rfb_capture_control.h"

#include <errno.h>
#include <stdbool.h>
#include <fcntl.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static const uint8_t k_magic[4] = {'M', 'V', 'S', 'C'};

static bool binding_zero(const uint8_t binding[RFB_CAPTURE_CONTROL_BINDING_SIZE])
{
    uint8_t any = 0u;
    for (size_t i = 0u; i < RFB_CAPTURE_CONTROL_BINDING_SIZE; i++) {
        any |= binding[i];
    }
    return any == 0u;
}

static bool message_valid(const rfb_capture_control_message *message)
{
    if (message == NULL || message->slot_nonce == 0u ||
        message->transition_id == 0u) {
        return false;
    }
    if (message->kind == RFB_CAPTURE_CONTROL_READY_FOR_MUTATION) {
        return binding_zero(message->source_b_binding);
    }
    if (message->kind == RFB_CAPTURE_CONTROL_MUTATION_ACK) {
        return !binding_zero(message->source_b_binding);
    }
    return false;
}

rfb_error rfb_capture_control_encode(
    const rfb_capture_control_message *message, uint8_t *out,
    size_t out_capacity, size_t *out_length)
{
    if (out_length != NULL) {
        *out_length = 0u;
    }
    if (!message_valid(message) || out == NULL || out_length == NULL) {
        return RFB_ERR_PROTOCOL;
    }
    if (out_capacity < RFB_CAPTURE_CONTROL_WIRE_SIZE) {
        return RFB_ERR_LIMIT;
    }
    memcpy(out, k_magic, sizeof k_magic);
    out[4] = 0u;
    out[5] = 1u;
    out[6] = 0u;
    out[7] = (uint8_t)message->kind;
    for (size_t i = 0u; i < 8u; i++) {
        out[8u + i] =
            (uint8_t)(message->slot_nonce >> (56u - (unsigned)i * 8u));
    }
    out[16] = (uint8_t)(message->transition_id >> 24u);
    out[17] = (uint8_t)(message->transition_id >> 16u);
    out[18] = (uint8_t)(message->transition_id >> 8u);
    out[19] = (uint8_t)message->transition_id;
    memcpy(out + 20u, message->source_b_binding,
           RFB_CAPTURE_CONTROL_BINDING_SIZE);
    *out_length = RFB_CAPTURE_CONTROL_WIRE_SIZE;
    return RFB_OK;
}

rfb_error rfb_capture_control_decode(
    const uint8_t *wire, size_t wire_length,
    rfb_capture_control_message *out)
{
    if (wire == NULL || out == NULL ||
        wire_length != RFB_CAPTURE_CONTROL_WIRE_SIZE ||
        memcmp(wire, k_magic, sizeof k_magic) != 0 || wire[4] != 0u ||
        wire[5] != 1u || wire[6] != 0u ||
        (wire[7] != (uint8_t)RFB_CAPTURE_CONTROL_READY_FOR_MUTATION &&
         wire[7] != (uint8_t)RFB_CAPTURE_CONTROL_MUTATION_ACK)) {
        return RFB_ERR_PROTOCOL;
    }
    rfb_capture_control_message decoded;
    memset(&decoded, 0, sizeof decoded);
    decoded.kind = (rfb_capture_control_kind)wire[7];
    for (size_t i = 0u; i < 8u; i++) {
        decoded.slot_nonce = (decoded.slot_nonce << 8u) | wire[8u + i];
    }
    decoded.transition_id = ((uint32_t)wire[16] << 24u) |
                            ((uint32_t)wire[17] << 16u) |
                            ((uint32_t)wire[18] << 8u) |
                            (uint32_t)wire[19];
    memcpy(decoded.source_b_binding, wire + 20u,
           RFB_CAPTURE_CONTROL_BINDING_SIZE);
    if (!message_valid(&decoded)) {
        return RFB_ERR_PROTOCOL;
    }
    *out = decoded;
    return RFB_OK;
}

static bool pathless_unix_address(int fd, bool peer)
{
    struct sockaddr_un address;
    socklen_t length = (socklen_t)sizeof address;
    memset(&address, 0, sizeof address);
    const int result = peer
                           ? getpeername(fd, (struct sockaddr *)&address,
                                         &length)
                           : getsockname(fd, (struct sockaddr *)&address,
                                         &length);
    const socklen_t path_offset =
        (socklen_t)offsetof(struct sockaddr_un, sun_path);
    if (result != 0 || address.sun_family != AF_UNIX ||
        length > (socklen_t)sizeof address) {
        return false;
    }
    const size_t path_length =
        length > path_offset ? (size_t)(length - path_offset) : 0u;
    for (size_t i = 0u; i < path_length; i++) {
        if (address.sun_path[i] != '\0') {
            return false;
        }
    }
    return true;
}

bool rfb_capture_control_endpoint_valid(int fd)
{
    if (fd < 0) {
        return false;
    }
    const int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || (flags & O_NONBLOCK) == 0) {
        return false;
    }
    int type = 0;
    socklen_t type_length = (socklen_t)sizeof type;
    return getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &type_length) == 0 &&
           type_length == (socklen_t)sizeof type && type == SOCK_DGRAM &&
           pathless_unix_address(fd, false) &&
           pathless_unix_address(fd, true);
}

rfb_error rfb_capture_control_drain_ack(
    int fd, bool allow_ack, uint64_t slot_nonce, uint32_t transition_id,
    const uint8_t source_b_binding[RFB_CAPTURE_CONTROL_BINDING_SIZE],
    bool *accepted)
{
    if (fd < 0 || slot_nonce == 0u || transition_id == 0u ||
        source_b_binding == NULL || accepted == NULL) {
        return RFB_ERR_INTERNAL;
    }
    *accepted = false;
    size_t valid_count = 0u;
    rfb_error result = RFB_OK;
    for (;;) {
        uint8_t wire[RFB_CAPTURE_CONTROL_WIRE_SIZE + 1u];
        const ssize_t length = recv(fd, wire, sizeof wire, MSG_DONTWAIT);
        if (length < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            }
            return RFB_ERR_IO;
        }
        if (length == 0) {
            return RFB_ERR_IO;
        }
        rfb_capture_control_message message;
        if (!allow_ack ||
            length != (ssize_t)RFB_CAPTURE_CONTROL_WIRE_SIZE ||
            rfb_capture_control_decode(wire, (size_t)length, &message) !=
                RFB_OK ||
            message.kind != RFB_CAPTURE_CONTROL_MUTATION_ACK ||
            message.slot_nonce != slot_nonce ||
            message.transition_id != transition_id ||
            memcmp(message.source_b_binding, source_b_binding,
                   RFB_CAPTURE_CONTROL_BINDING_SIZE) != 0) {
            result = RFB_ERR_PROTOCOL;
            continue;
        }
        valid_count++;
        if (valid_count > 1u) {
            result = RFB_ERR_PROTOCOL;
        }
    }
    if (result == RFB_OK && valid_count == 1u) {
        *accepted = true;
    }
    return result;
}
