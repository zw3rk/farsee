// SPDX-License-Identifier: Apache-2.0
//
// Key and pointer release bytes must not bypass the
// AES-CBC record seal. Four sites appended raw KeyEvent/PointerEvent bytes
// to s->out while apple_records_active: RELEASE_ALL key-ups, the
// ledger-full fallback, and rfb_session_release_held_inputs. On the modern
// Apple path that desyncs the peer (cleartext inside a record stream) and
// discloses held keysyms.
//
// Fixture: a session whose io adapter captures every outbound byte, with
// the record layer active under known keys and a mirror decrypt layer, so
// each test can assert the WHOLE wire parses as u16be-framed records and
// the expected key-ups/mask-0 live inside decrypted plaintext.

#include "rfb_test.h"
#include "farsee/rfb_session.h"
#include "farsee/apple_record.h"
#include "farsee/apple_wire_record.h"
#include "farsee/buffer.h"
#include "farsee/error.h"
#include "farsee/farsee_cmd_queue.h"
#include "farsee/limits.h"
#include "rfb/rfb_session_internal.h"
#include "tests/fakes/rfb_session_test_adapter.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const uint8_t sealed_input_wrap[16] = {
    0xA9u, 0xB8u, 0xC7u, 0xD6u, 0xE5u, 0xF4u, 0x03u, 0x12u,
    0x21u, 0x30u, 0x4Fu, 0x5Eu, 0x6Du, 0x7Cu, 0x8Bu, 0x9Au
};
static const uint8_t sealed_input_key[16] = {
    0x00u, 0x11u, 0x22u, 0x33u, 0x44u, 0x55u, 0x66u, 0x77u,
    0x88u, 0x99u, 0xAAu, 0xBBu, 0xCCu, 0xDDu, 0xEEu, 0xFFu
};
static const uint8_t sealed_input_iv[16] = {
    0xF0u, 0xE1u, 0xD2u, 0xC3u, 0xB4u, 0xA5u, 0x96u, 0x87u,
    0x78u, 0x69u, 0x5Au, 0x4Bu, 0x3Cu, 0x2Du, 0x1Eu, 0x0Fu
};

typedef struct sealed_input_cap {
    uint8_t buf[8192];
    size_t len;
    bool overflow;
} sealed_input_cap;

static rfb_io_result sealed_input_cap_write(void *ctx, const uint8_t *data, size_t n,
                                   size_t *written)
{
    sealed_input_cap *cap = (sealed_input_cap *)ctx;
    if (cap == NULL || data == NULL || written == NULL) {
        return RFB_IO_ERROR;
    }
    if (n > sizeof cap->buf - cap->len) {
        cap->overflow = true;
        *written = 0;
        return RFB_IO_ERROR;
    }
    memcpy(cap->buf + cap->len, data, n);
    cap->len += n;
    *written = n;
    return RFB_IO_OK;
}

// Minimal active session with a capturing write adapter (fixture-style:
// no socket, deterministic, no timing).
static void sealed_input_session_init(rfb_session *s, sealed_input_cap *cap)
{
    memset(cap, 0, sizeof *cap);
    rfb_session_clear(s);
    s->alloc = rfb_default_allocator();
    s->io.write = sealed_input_cap_write;
    s->io.ctx = cap;
    s->io_open = true;
    s->active = true;
    rfb_buffer_init(&s->in, s->alloc, RFB_LIMIT_FB_BYTES_POLICY);
    rfb_buffer_init(&s->out, s->alloc, RFB_LIMIT_OUTBOUND_BYTES);
    farsee_key_ledger_init(&s->key_ledger);
}

// Enable the C2S record seal with known keys on the session, and arm a
// mirror decrypt layer so the test can open what the session sealed.
static void sealed_input_records_enable(rfb_session *s, apple_record_layer *mirror)
{
    apple_record_init(&s->apple_rl, sealed_input_wrap);
    RFB_CHECK(apple_record_set_direction(&s->apple_rl, APPLE_DIR_ENCRYPT,
                                         sealed_input_key, sealed_input_iv));
    s->apple_rl_inited = true;
    s->apple_records_active = true;

    apple_record_init(mirror, sealed_input_wrap);
    RFB_CHECK(apple_record_set_direction(mirror, APPLE_DIR_DECRYPT,
                                         sealed_input_key, sealed_input_iv));
}

// Structural seal assertion: EVERY outbound byte must parse as
// u16be(ct_len) || ct with ct a well-formed record that opens under the
// mirror layer. Any raw KeyEvent/PointerEvent byte on the wire breaks the
// framing (first raw byte 0x04/0x05 becomes a bogus ct_len prefix) and
// fails here. Returns the concatenated decrypted plaintext.
static void sealed_input_assert_all_sealed(const sealed_input_cap *cap, apple_record_layer *dec,
                                  uint8_t *plain, size_t plain_cap,
                                  size_t *plain_len)
{
    RFB_CHECK(cap->len > 0u);
    RFB_CHECK(!cap->overflow);
    size_t off = 0u;
    *plain_len = 0u;
    while (off < cap->len) {
        RFB_CHECK(off + 2u <= cap->len);
        const uint16_t ct_len =
            (uint16_t)(((uint16_t)cap->buf[off] << 8) | cap->buf[off + 1u]);
        RFB_CHECK(ct_len >= APPLE_WIRE_RECORD_MIN_BODY);
        RFB_CHECK((ct_len % 16u) == 0u);
        RFB_CHECK(off + 2u + (size_t)ct_len <= cap->len);
        uint8_t msg[512];
        size_t msg_len = 0u;
        RFB_CHECK_EQ_INT(apple_wire_record_open(dec, cap->buf + off + 2u,
                                                ct_len, msg, sizeof msg,
                                                &msg_len),
                         RFB_OK);
        RFB_CHECK(msg_len <= sizeof msg);
        RFB_CHECK(msg_len + *plain_len <= plain_cap);
        memcpy(plain + *plain_len, msg, msg_len);
        *plain_len += msg_len;
        off += 2u + (size_t)ct_len;
    }
    RFB_CHECK_EQ_UINT(off, cap->len);  // no stray cleartext anywhere
}

// Raw cleartext KeyEvent scan: [4][down][pad2][keysym u32be]. This is the
// Held keysyms must never appear unsealed.
static bool sealed_input_wire_has_raw_key_event(const uint8_t *wire, size_t len,
                                       bool down, uint32_t keysym)
{
    if (len < 8u) {
        return false;
    }
    for (size_t i = 0u; i + 8u <= len; i++) {
        if (wire[i] == 4u && wire[i + 1u] == (down ? 1u : 0u) &&
            wire[i + 2u] == 0u && wire[i + 3u] == 0u &&
            wire[i + 4u] == (uint8_t)(keysym >> 24) &&
            wire[i + 5u] == (uint8_t)(keysym >> 16) &&
            wire[i + 6u] == (uint8_t)(keysym >> 8) &&
            wire[i + 7u] == (uint8_t)keysym) {
            return true;
        }
    }
    return false;
}

static bool sealed_input_plain_has_key_event(const uint8_t *plain, size_t len,
                                    bool down, uint32_t keysym)
{
    return sealed_input_wire_has_raw_key_event(plain, len, down, keysym);
}

static bool sealed_input_plain_has_mask0_pointer(const uint8_t *plain, size_t len)
{
    if (len < 6u) {
        return false;
    }
    for (size_t i = 0u; i + 6u <= len; i++) {
        if (plain[i] == 5u && plain[i + 1u] == 0u) {
            return true;
        }
    }
    return false;
}

// rfb_session_release_held_inputs on the destroy path: key-ups
// and the mask-0 pointer event must be sealed.
RFB_TEST(apple_sealed_input_release, release_held_inputs__records_active__wire_all_sealed)
{
    unsigned char storage[16384];
    RFB_CHECK(rfb_session_size() <= sizeof storage);
    rfb_session *s = (rfb_session *)(void *)storage;
    sealed_input_cap cap;
    sealed_input_session_init(s, &cap);

    apple_record_layer mirror;
    sealed_input_records_enable(s, &mirror);

    rfb_session_test_seed_held_key(s, 0x61u);
    rfb_session_test_seed_held_buttons(s, 1u);

    rfb_session_release_held_inputs(s);

    uint8_t plain[1024];
    size_t plain_len = 0u;
    sealed_input_assert_all_sealed(&cap, &mirror, plain, sizeof plain, &plain_len);

    // − no cleartext KeyEvent for the held keysym on the wire
    RFB_CHECK(!sealed_input_wire_has_raw_key_event(cap.buf, cap.len, false, 0x61u));
    // + the release still happened — inside the sealed records
    RFB_CHECK(sealed_input_plain_has_key_event(plain, plain_len, false, 0x61u));
    RFB_CHECK(sealed_input_plain_has_mask0_pointer(plain, plain_len));
    RFB_CHECK_EQ_UINT(s->key_ledger.count, 0u);

    apple_record_destroy(&mirror);
    rfb_session_destroy(s);
}

// RELEASE_ALL key-ups inside session_drain_cmds (the mask-0
// pointer in the same command was already sealed; the key-ups must be too).
RFB_TEST(apple_sealed_input_release, release_all_cmd__records_active__wire_all_sealed)
{
    farsee_cmd_queue q;
    RFB_CHECK(farsee_cmd_queue_init(&q));

    unsigned char storage[16384];
    RFB_CHECK(rfb_session_size() <= sizeof storage);
    rfb_session *s = (rfb_session *)(void *)storage;
    sealed_input_cap cap;
    sealed_input_session_init(s, &cap);
    s->cfg.cmds = &q;

    apple_record_layer mirror;
    sealed_input_records_enable(s, &mirror);

    rfb_session_test_seed_held_key(s, 0x61u);
    rfb_session_test_seed_held_buttons(s, 1u);

    farsee_cmd cmd;
    memset(&cmd, 0, sizeof cmd);
    cmd.kind = FARSEE_CMD_RELEASE_ALL;
    RFB_CHECK(farsee_cmd_queue_push(&q, &cmd));

    RFB_CHECK_EQ_INT(rfb_session_test_drain_cmds(s), RFB_OK);

    uint8_t plain[1024];
    size_t plain_len = 0u;
    sealed_input_assert_all_sealed(&cap, &mirror, plain, sizeof plain, &plain_len);

    RFB_CHECK(!sealed_input_wire_has_raw_key_event(cap.buf, cap.len, false, 0x61u));
    RFB_CHECK(sealed_input_plain_has_key_event(plain, plain_len, false, 0x61u));
    RFB_CHECK(sealed_input_plain_has_mask0_pointer(plain, plain_len));
    RFB_CHECK_EQ_UINT(s->key_ledger.count, 0u);

    apple_record_destroy(&mirror);
    rfb_session_destroy(s);
    farsee_cmd_queue_destroy(&q);
}

// Ledger-full fallback: when a new key-down overflows the
// ledger, the drop-loop key-ups for the previously held set must be sealed.
RFB_TEST(apple_sealed_input_release, ledger_full_keydown__records_active__wire_all_sealed)
{
    farsee_cmd_queue q;
    RFB_CHECK(farsee_cmd_queue_init(&q));

    unsigned char storage[16384];
    RFB_CHECK(rfb_session_size() <= sizeof storage);
    rfb_session *s = (rfb_session *)(void *)storage;
    sealed_input_cap cap;
    sealed_input_session_init(s, &cap);
    s->cfg.cmds = &q;

    apple_record_layer mirror;
    sealed_input_records_enable(s, &mirror);

    for (uint32_t k = 0u; k < FARSEE_KEY_LEDGER_MAX; k++) {
        rfb_session_test_seed_held_key(s, 0x1100u + k);
    }
    RFB_CHECK_EQ_UINT(s->key_ledger.count, (size_t)FARSEE_KEY_LEDGER_MAX);

    farsee_cmd cmd;
    memset(&cmd, 0, sizeof cmd);
    cmd.kind = FARSEE_CMD_KEY;
    cmd.key.action = FARSEE_KEY_PRESS;
    cmd.key.logical = 0xff01u;
    RFB_CHECK(farsee_cmd_queue_push(&q, &cmd));

    RFB_CHECK_EQ_INT(rfb_session_test_drain_cmds(s), RFB_OK);

    uint8_t plain[4096];
    size_t plain_len = 0u;
    sealed_input_assert_all_sealed(&cap, &mirror, plain, sizeof plain, &plain_len);

    // − none of the released keysyms in cleartext
    RFB_CHECK(!sealed_input_wire_has_raw_key_event(cap.buf, cap.len, false, 0x1100u));
    RFB_CHECK(!sealed_input_wire_has_raw_key_event(cap.buf, cap.len, false,
                                          0x1100u + FARSEE_KEY_LEDGER_MAX -
                                              1u));
    // + the new down and the drop-loop key-ups are sealed payloads
    RFB_CHECK(sealed_input_plain_has_key_event(plain, plain_len, true, 0xff01u));
    RFB_CHECK(sealed_input_plain_has_key_event(plain, plain_len, false, 0x1100u));
    // Ledger ends holding exactly the new key.
    RFB_CHECK_EQ_UINT(s->key_ledger.count, 1u);

    apple_record_destroy(&mirror);
    rfb_session_destroy(s);
    farsee_cmd_queue_destroy(&q);
}

RFB_TEST(apple_sealed_input_release,
         full_outbound__drain_failure_does_not_advance_record_state)
{
    farsee_cmd_queue q;
    RFB_CHECK(farsee_cmd_queue_init(&q));

    unsigned char storage[16384];
    RFB_CHECK(rfb_session_size() <= sizeof storage);
    rfb_session *s = (rfb_session *)(void *)storage;
    sealed_input_cap cap;
    sealed_input_session_init(s, &cap);
    s->cfg.cmds = &q;

    apple_record_layer mirror;
    sealed_input_records_enable(s, &mirror);

    // A sealed key event needs more than one byte. Force admission failure
    // before the record layer is allowed to mutate its CBC/sequence state.
    rfb_buffer_destroy(&s->out);
    rfb_buffer_init(&s->out, s->alloc, 1u);

    farsee_cmd cmd;
    memset(&cmd, 0, sizeof cmd);
    cmd.kind = FARSEE_CMD_KEY;
    cmd.key.action = FARSEE_KEY_RELEASE;
    cmd.key.logical = 0x61u;
    RFB_CHECK(farsee_cmd_queue_push(&q, &cmd));

    const uint64_t sequence_before = s->apple_rl.encrypt.sequence;
    RFB_CHECK_EQ_INT(rfb_session_test_drain_cmds(s), RFB_ERR_LIMIT);

    RFB_CHECK_EQ_INT(rfb_session_last_error(s), RFB_ERR_LIMIT);
    RFB_CHECK_EQ_UINT(s->apple_rl.encrypt.sequence, sequence_before);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&s->out), 0u);

    apple_record_destroy(&mirror);
    rfb_session_destroy(s);
    farsee_cmd_queue_destroy(&q);
}

RFB_TEST(apple_sealed_input_release, inherited_cleartext_override__is_ignored)
{
    unsigned char storage[16384];
    RFB_CHECK(rfb_session_size() <= sizeof storage);
    rfb_session *s = (rfb_session *)(void *)storage;
    sealed_input_cap cap;
    sealed_input_session_init(s, &cap);

    apple_record_layer mirror;
    sealed_input_records_enable(s, &mirror);
    RFB_CHECK_EQ_INT(setenv("FARSEE_APPLE_EXPERIMENT", "1", 1), 0);
    RFB_CHECK_EQ_INT(setenv("FARSEE_APPLE_FORCE_CLEARTEXT_OUT", "1", 1), 0);

    const uint8_t key_up[8] = { 4u, 0u, 0u, 0u, 0u, 0u, 0u, 0x61u };
    RFB_CHECK_EQ_INT(session_queue_bytes(s, key_up, sizeof key_up), RFB_OK);

    RFB_CHECK_EQ_INT(unsetenv("FARSEE_APPLE_FORCE_CLEARTEXT_OUT"), 0);
    RFB_CHECK_EQ_INT(unsetenv("FARSEE_APPLE_EXPERIMENT"), 0);
    uint8_t plain[64];
    size_t plain_len = 0u;
    sealed_input_assert_all_sealed(&cap, &mirror, plain, sizeof plain, &plain_len);
    RFB_CHECK_MEM_EQ(plain, key_up, sizeof key_up);

    apple_record_destroy(&mirror);
    rfb_session_destroy(s);
}

RFB_TEST(apple_sealed_input_release, inherited_plaintext_dump_override__creates_no_file)
{
    char directory[] = "/tmp/farsee-no-plain-dump-XXXXXX";
    RFB_CHECK(mkdtemp(directory) != NULL);
    char path[128];
    RFB_CHECK(snprintf(path, sizeof path, "%s/plain.ndjson", directory) > 0);

    unsigned char storage[16384];
    RFB_CHECK(rfb_session_size() <= sizeof storage);
    rfb_session *s = (rfb_session *)(void *)storage;
    sealed_input_cap cap;
    sealed_input_session_init(s, &cap);
    apple_record_layer mirror;
    sealed_input_records_enable(s, &mirror);

    RFB_CHECK_EQ_INT(setenv("FARSEE_APPLE_DUMP_PLAIN", "1", 1), 0);
    RFB_CHECK_EQ_INT(setenv("FARSEE_APPLE_DUMP_KEYS", "1", 1), 0);
    RFB_CHECK_EQ_INT(setenv("FARSEE_APPLE_DUMP_DIR", directory, 1), 0);
    RFB_CHECK_EQ_INT(setenv("FARSEE_DUMP_FRAME", path, 1), 0);
    const uint8_t key_up[8] = { 4u, 0u, 0u, 0u, 0u, 0u, 0u, 0x61u };
    RFB_CHECK_EQ_INT(session_queue_bytes(s, key_up, sizeof key_up), RFB_OK);
    RFB_CHECK_EQ_INT(unsetenv("FARSEE_DUMP_FRAME"), 0);
    RFB_CHECK_EQ_INT(unsetenv("FARSEE_APPLE_DUMP_DIR"), 0);
    RFB_CHECK_EQ_INT(unsetenv("FARSEE_APPLE_DUMP_KEYS"), 0);
    RFB_CHECK_EQ_INT(unsetenv("FARSEE_APPLE_DUMP_PLAIN"), 0);

    RFB_CHECK(access(path, F_OK) != 0);
    apple_record_destroy(&mirror);
    rfb_session_destroy(s);
    RFB_CHECK_EQ_INT(rmdir(directory), 0);
}
