// SPDX-License-Identifier: Apache-2.0
//
// Pure decoders for private damage-campaign schedule and metadata artifacts.

#include "farsee/rfb_capture_artifact.h"

#include <stdbool.h>
#include <string.h>

static bool decimal_u32(const char *row, size_t length, size_t *offset,
                        uint32_t *out)
{
    if (*offset >= length || row[*offset] < '0' || row[*offset] > '9') {
        return false;
    }
    if (row[*offset] == '0') {
        (*offset)++;
        *out = 0u;
        return true;
    }
    uint32_t value = 0u;
    do {
        const uint32_t digit = (uint32_t)(row[*offset] - '0');
        if (value > (UINT32_MAX - digit) / 10u) {
            return false;
        }
        value = value * 10u + digit;
        (*offset)++;
    } while (*offset < length && row[*offset] >= '0' &&
             row[*offset] <= '9');
    *out = value;
    return true;
}

rfb_error rfb_capture_schedule_v2_parse(
    const char *row, size_t row_length, rfb_capture_schedule_v2 *out)
{
    if (row == NULL || out == NULL || row_length == 0u ||
        row[row_length - 1u] != '\n') {
        return RFB_ERR_PROTOCOL;
    }
    uint32_t fields[8];
    size_t offset = 0u;
    for (size_t i = 0u; i < 8u; i++) {
        if (!decimal_u32(row, row_length, &offset, &fields[i])) {
            return RFB_ERR_PROTOCOL;
        }
        const char separator = i + 1u == 8u ? '\n' : '\t';
        if (offset >= row_length || row[offset] != separator) {
            return RFB_ERR_PROTOCOL;
        }
        offset++;
    }
    if (offset != row_length || fields[0] != 2u || fields[1] == 0u ||
        fields[2] != 1u || fields[3] > UINT16_MAX ||
        fields[4] > UINT16_MAX || fields[5] == 0u ||
        fields[5] > UINT16_MAX || fields[6] == 0u ||
        fields[6] > UINT16_MAX || fields[7] == 0u) {
        return RFB_ERR_PROTOCOL;
    }
    rfb_capture_schedule_v2 parsed;
    memset(&parsed, 0, sizeof parsed);
    parsed.query.id = fields[1];
    parsed.query.incremental = true;
    parsed.query.geometry_policy = RFB_CAPTURE_GEOMETRY_WITHIN_REQUEST;
    parsed.query.x = (uint16_t)fields[3];
    parsed.query.y = (uint16_t)fields[4];
    parsed.query.width = (uint16_t)fields[5];
    parsed.query.height = (uint16_t)fields[6];
    parsed.transition_id = fields[7];
    *out = parsed;
    return RFB_OK;
}

rfb_error rfb_capture_metadata_v1_decode(
    const uint8_t *wire, size_t wire_length, rfb_capture_metadata_v1 *out)
{
    if (wire == NULL || out == NULL ||
        wire_length != RFB_CAPTURE_METADATA_V1_WIRE_SIZE) {
        return RFB_ERR_PROTOCOL;
    }
    rfb_capture_metadata_v1 decoded;
    memset(&decoded, 0, sizeof decoded);
    for (size_t i = 0u; i < 8u; i++) {
        decoded.slot_nonce = (decoded.slot_nonce << 8u) | wire[i];
    }
    memcpy(decoded.source_b_binding, wire + 8u,
           RFB_CAPTURE_CONTROL_BINDING_SIZE);
    uint8_t binding_any = 0u;
    for (size_t i = 0u; i < RFB_CAPTURE_CONTROL_BINDING_SIZE; i++) {
        binding_any |= decoded.source_b_binding[i];
    }
    if (decoded.slot_nonce == 0u || binding_any == 0u) {
        return RFB_ERR_PROTOCOL;
    }
    *out = decoded;
    return RFB_OK;
}
