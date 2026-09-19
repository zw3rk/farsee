// SPDX-License-Identifier: Apache-2.0
//
// Pure decoders for private damage-campaign schedule and metadata artifacts.

#ifndef FARSEE_INCLUDE_FARSEE_RFB_CAPTURE_ARTIFACT_H
#define FARSEE_INCLUDE_FARSEE_RFB_CAPTURE_ARTIFACT_H

#include "farsee/error.h"
#include "farsee/rfb_capture_control.h"
#include "farsee/rfb_capture_scheduler.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RFB_CAPTURE_METADATA_V1_WIRE_SIZE ((size_t)40u)

typedef struct rfb_capture_schedule_v2 {
    rfb_capture_query query;
    uint32_t transition_id;
} rfb_capture_schedule_v2;

typedef struct rfb_capture_metadata_v1 {
    uint64_t slot_nonce;
    uint8_t source_b_binding[RFB_CAPTURE_CONTROL_BINDING_SIZE];
} rfb_capture_metadata_v1;

rfb_error rfb_capture_schedule_v2_parse(
    const char *row, size_t row_length, rfb_capture_schedule_v2 *out);
rfb_error rfb_capture_metadata_v1_decode(
    const uint8_t *wire, size_t wire_length, rfb_capture_metadata_v1 *out);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_RFB_CAPTURE_ARTIFACT_H
