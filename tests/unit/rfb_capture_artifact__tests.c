// SPDX-License-Identifier: Apache-2.0

#include "rfb_test.h"

#include "farsee/rfb_capture_artifact.h"

#include <stdint.h>
#include <string.h>

RFB_TEST(rfb_capture_artifact, schedule_v2_accepts_exact_frozen_row)
{
    const char row[] = "2\t310001\t1\t0\t0\t1024\t768\t4101\n";
    rfb_capture_schedule_v2 parsed;
    memset(&parsed, 0, sizeof parsed);
    RFB_CHECK_EQ_INT(rfb_capture_schedule_v2_parse(row, strlen(row), &parsed),
                     RFB_OK);
    RFB_CHECK_EQ_UINT(parsed.query.id, 310001u);
    RFB_CHECK(parsed.query.incremental);
    RFB_CHECK_EQ_INT(parsed.query.geometry_policy,
                     RFB_CAPTURE_GEOMETRY_WITHIN_REQUEST);
    RFB_CHECK_EQ_UINT(parsed.query.x, 0u);
    RFB_CHECK_EQ_UINT(parsed.query.y, 0u);
    RFB_CHECK_EQ_UINT(parsed.query.width, 1024u);
    RFB_CHECK_EQ_UINT(parsed.query.height, 768u);
    RFB_CHECK_EQ_UINT(parsed.transition_id, 4101u);
}

RFB_TEST(rfb_capture_artifact, schedule_v2_rejects_nonexact_rows)
{
    static const char *const rejected[] = {
        "",
        "2 310001 1 0 0 1024 768 4101\n",
        "2\t310001 1\t0\t0\t1024\t768\t4101\n",
        "1\t310001\t1\t0\t0\t1024\t768\t4101\n",
        "2\t310001\t0\t0\t0\t1024\t768\t4101\n",
        "2\t310001\t1\t0\t0\t1024\t768\n",
        "2\t310001\t1\t0\t0\t1024\t768\t4101\textra\n",
        "2\t0\t1\t0\t0\t1024\t768\t4101\n",
        "2\t310001\t1\t0\t0\t1024\t768\t0\n",
        "2\t+310001\t1\t0\t0\t1024\t768\t4101\n",
        "02\t310001\t1\t0\t0\t1024\t768\t4101\n",
        "2\t0310001\t1\t0\t0\t1024\t768\t4101\n",
        "2\t310001\t01\t0\t0\t1024\t768\t4101\n",
        "2\t310001\t1\t00\t0\t1024\t768\t4101\n",
        "2\t310001\t1\t0\t00\t1024\t768\t4101\n",
        "2\t310001\t1\t0\t0\t01024\t768\t4101\n",
        "2\t310001\t1\t0\t0\t1024\t0768\t4101\n",
        "2\t310001\t1\t0\t0\t1024\t768\t04101\n",
        "2\t4294967296\t1\t0\t0\t1024\t768\t4101\n",
        "2\t310001\t1\t0\t0\t1024\t768\t4101\r\n",
        "2\t310001\t1\t0\t0\t1024\t768\t4101\nmore",
        "2\t310001\t1\t0\t0\t1024\t768\t4101\ntrailing\n",
    };
    for (size_t i = 0u; i < sizeof rejected / sizeof rejected[0]; i++) {
        rfb_capture_schedule_v2 parsed;
        unsigned char unchanged[sizeof parsed];
        memset(&parsed, 0xa5, sizeof parsed);
        memcpy(unchanged, &parsed, sizeof unchanged);
        RFB_CHECK_EQ_INT(rfb_capture_schedule_v2_parse(
                             rejected[i], strlen(rejected[i]), &parsed),
                         RFB_ERR_PROTOCOL);
        RFB_CHECK(memcmp(&parsed, unchanged, sizeof parsed) == 0);
    }

    const char exact[] = "2\t310001\t1\t0\t0\t1024\t768\t4101\n";
    for (size_t separator = 0u; separator < 7u; separator++) {
        char mixed[sizeof exact];
        rfb_capture_schedule_v2 parsed;
        unsigned char unchanged[sizeof parsed];
        memcpy(mixed, exact, sizeof mixed);
        size_t seen = 0u;
        for (size_t i = 0u; i < sizeof mixed; i++) {
            if (mixed[i] == '\t' && seen++ == separator) {
                mixed[i] = ' ';
                break;
            }
        }
        memset(&parsed, 0xa5, sizeof parsed);
        memcpy(unchanged, &parsed, sizeof unchanged);
        RFB_CHECK_EQ_INT(rfb_capture_schedule_v2_parse(
                             mixed, strlen(mixed), &parsed),
                         RFB_ERR_PROTOCOL);
        RFB_CHECK(memcmp(&parsed, unchanged, sizeof parsed) == 0);
    }
}

RFB_TEST(rfb_capture_artifact, metadata_v1_decodes_exact_nonce_and_binding)
{
    uint8_t wire[RFB_CAPTURE_METADATA_V1_WIRE_SIZE];
    memset(wire, 0, sizeof wire);
    const uint64_t nonce = UINT64_C(0x0102030405060708);
    for (size_t i = 0u; i < 8u; i++) {
        wire[i] = (uint8_t)(nonce >> (56u - (unsigned)i * 8u));
    }
    for (size_t i = 0u; i < RFB_CAPTURE_CONTROL_BINDING_SIZE; i++) {
        wire[8u + i] = (uint8_t)(i + 1u);
    }
    rfb_capture_metadata_v1 metadata;
    memset(&metadata, 0, sizeof metadata);
    RFB_CHECK_EQ_INT(rfb_capture_metadata_v1_decode(wire, sizeof wire,
                                                    &metadata),
                     RFB_OK);
    RFB_CHECK_EQ_UINT(metadata.slot_nonce, nonce);
    RFB_CHECK(memcmp(metadata.source_b_binding, wire + 8u,
                     RFB_CAPTURE_CONTROL_BINDING_SIZE) == 0);
}

RFB_TEST(rfb_capture_artifact, metadata_v1_rejects_size_zero_and_zero_binding)
{
    uint8_t wire[RFB_CAPTURE_METADATA_V1_WIRE_SIZE];
    memset(wire, 0x5a, sizeof wire);
    rfb_capture_metadata_v1 metadata;
    RFB_CHECK_EQ_INT(rfb_capture_metadata_v1_decode(
                         wire, sizeof wire - 1u, &metadata),
                     RFB_ERR_PROTOCOL);
    memset(wire, 0, sizeof wire);
    wire[7] = 1u;
    RFB_CHECK_EQ_INT(rfb_capture_metadata_v1_decode(wire, sizeof wire,
                                                   &metadata),
                     RFB_ERR_PROTOCOL);
    memset(wire, 0x5a, sizeof wire);
    memset(wire, 0, 8u);
    RFB_CHECK_EQ_INT(rfb_capture_metadata_v1_decode(wire, sizeof wire,
                                                   &metadata),
                     RFB_ERR_PROTOCOL);
}
