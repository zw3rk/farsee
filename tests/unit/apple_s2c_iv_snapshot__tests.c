// SPDX-License-Identifier: Apache-2.0
//
// apple_last_s2c_ct snapshot must capture record
// N's last ciphertext block BEFORE rfb_buffer_consume memmoves the next
// pipelined record over that position. With two records in one read, the
// post-consume copy reads a mix of the next record's bytes.

#include "rfb_test.h"
#include "farsee/rfb_session.h"
#include "farsee/apple_record.h"
#include "farsee/apple_wire_record.h"
#include "farsee/buffer.h"
#include "farsee/error.h"
#include "farsee/limits.h"
#include "rfb/rfb_session_internal.h"
#include "tests/fakes/rfb_session_test_adapter.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

static const uint8_t s2c_snapshot_wrap[16] = {
    0x9Au, 0x8Bu, 0x7Cu, 0x6Du, 0x5Eu, 0x4Fu, 0x30u, 0x21u,
    0x12u, 0x03u, 0xF4u, 0xE5u, 0xD6u, 0xC7u, 0xB8u, 0xA9u
};
static const uint8_t s2c_snapshot_key[16] = {
    0x10u, 0x21u, 0x32u, 0x43u, 0x54u, 0x65u, 0x76u, 0x87u,
    0x98u, 0xA9u, 0xBAu, 0xCBu, 0xDCu, 0xEDu, 0xFEu, 0x0Fu
};
static const uint8_t s2c_snapshot_iv[16] = {
    0x0Fu, 0x1Eu, 0x2Du, 0x3Cu, 0x4Bu, 0x5Au, 0x69u, 0x78u,
    0x87u, 0x96u, 0xA5u, 0xB4u, 0xC3u, 0xD2u, 0xE1u, 0xF0u
};

typedef struct s2c_snapshot_cap {
    uint8_t buf[1024];
    size_t len;
} s2c_snapshot_cap;

static rfb_io_result s2c_snapshot_cap_write(void *ctx, const uint8_t *data, size_t n,
                                    size_t *written)
{
    s2c_snapshot_cap *cap = (s2c_snapshot_cap *)ctx;
    if (cap == NULL || data == NULL || written == NULL) {
        return RFB_IO_ERROR;
    }
    if (n > sizeof cap->buf - cap->len) {
        *written = 0;
        return RFB_IO_ERROR;
    }
    memcpy(cap->buf + cap->len, data, n);
    cap->len += n;
    *written = n;
    return RFB_IO_OK;
}

// Two pipelined records in ONE read: record 1 (a msg14 tick, consumed and
// dropped) followed by a PARTIAL record 2 header+body. The demux stops on
// the incomplete record, so the final apple_last_s2c_ct snapshot must be
// record 1's tail. Post-consume copying instead reads bytes the memmove
// shifted in from record 2.
RFB_TEST(apple_s2c_iv_snapshot, pipelined_records__iv_snapshot__matches_first_tail)
{
    unsigned char storage[16384];
    RFB_CHECK(rfb_session_size() <= sizeof storage);
    rfb_session *s = (rfb_session *)(void *)storage;

    s2c_snapshot_cap cap;
    memset(&cap, 0, sizeof cap);
    rfb_session_clear(s);
    s->alloc = rfb_default_allocator();
    s->io.write = s2c_snapshot_cap_write;
    s->io.ctx = &cap;
    s->io_open = true;
    s->active = true;
    rfb_buffer_init(&s->in, s->alloc, RFB_LIMIT_FB_BYTES_POLICY);
    rfb_buffer_init(&s->out, s->alloc, RFB_LIMIT_OUTBOUND_BYTES);
    rfb_buffer_init(&s->apple_plain, s->alloc, RFB_LIMIT_FB_BYTES_POLICY);
    rfb_buffer_init(&s->apple_stage, s->alloc, RFB_LIMIT_FB_BYTES_POLICY);
    farsee_key_ledger_init(&s->key_ledger);

    // S2C record layer on the session; mirror encryptor seals like a peer.
    apple_record_init(&s->apple_rl, s2c_snapshot_wrap);
    RFB_CHECK(apple_record_set_direction(&s->apple_rl, APPLE_DIR_DECRYPT,
                                         s2c_snapshot_key, s2c_snapshot_iv));
    s->apple_rl_inited = true;
    s->apple_records_active = true;

    apple_record_layer peer;
    apple_record_init(&peer, s2c_snapshot_wrap);
    RFB_CHECK(apple_record_set_direction(&peer, APPLE_DIR_ENCRYPT,
                                         s2c_snapshot_key, s2c_snapshot_iv));

    uint8_t rec1[64];
    size_t rec1_len = 0u;
    RFB_CHECK_EQ_INT(
        apple_wire_record_seal(&peer, apple_wire_msg14,
                               APPLE_WIRE_MSG14_LEN, rec1, sizeof rec1,
                               &rec1_len),
        RFB_OK);
    RFB_CHECK_EQ_UINT(rec1_len, 2u + APPLE_WIRE_RECORD_MIN_BODY);

    // Record 2: different plaintext (KeyEvent) so its ciphertext differs
    // from record 1 everywhere; only a 24-byte prefix arrives in this read.
    static const uint8_t key_msg[8] = {
        0x04u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x61u
    };
    uint8_t rec2[64];
    size_t rec2_len = 0u;
    RFB_CHECK_EQ_INT(apple_wire_record_seal(&peer, key_msg, sizeof key_msg,
                                            rec2, sizeof rec2, &rec2_len),
                     RFB_OK);
    RFB_CHECK_EQ_UINT(rec2_len, rec1_len);
    RFB_CHECK(memcmp(rec1, rec2, rec1_len) != 0);

    RFB_CHECK_EQ_INT(rfb_buffer_append(&s->in, rec1, rec1_len), RFB_OK);
    RFB_CHECK_EQ_INT(rfb_buffer_append(&s->in, rec2, 24u), RFB_OK);

    bool progress = false;
    RFB_CHECK_EQ_INT(rfb_session_test_process_in(s, &progress), RFB_OK);
    RFB_CHECK(progress);
    RFB_CHECK_EQ_UINT(s->apple_s2c_opened, 1u);
    RFB_CHECK(s->apple_have_last_s2c_ct);
    // The snapshot is record 1's last ciphertext block — captured before
    // the consume memmove, not after it.
    RFB_CHECK_MEM_EQ(s->apple_last_s2c_ct,
                     rec1 + rec1_len - 16u, 16u);

    rfb_session_destroy(s);
    apple_record_destroy(&peer);
}
