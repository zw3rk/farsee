// SPDX-License-Identifier: Apache-2.0
//
// Live RFB clipboard bridge tests: host UTF-8, RFC Latin-1, sanitization,
// direction policy, polling de-duplication, and ClientCutText wire bytes.

#include "rfb_test.h"

#include "farsee/allocator.h"
#include "farsee/apple_record.h"
#include "farsee/apple_wire_record.h"
#include "farsee/buffer.h"
#include "farsee/limits.h"
#include "farsee/pixel_format.h"
#include "rfb/rfb_session_internal.h"
#include "tests/fakes/rfb_session_test_adapter.h"
#include "tests/test_framework/fake_io.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef struct clipboard_fake {
    fake_io io;
    const char *read_text;
    size_t read_len;
    bool override_read_result;
    long read_result;
    bool reject_write;
    unsigned reads;
    char written[128];
    size_t written_len;
    unsigned writes;
} clipboard_fake;

static const uint8_t clipboard_record_wrap[16] = {
    0xa9u, 0xb8u, 0xc7u, 0xd6u, 0xe5u, 0xf4u, 0x03u, 0x12u,
    0x21u, 0x30u, 0x4fu, 0x5eu, 0x6du, 0x7cu, 0x8bu, 0x9au
};
static const uint8_t clipboard_record_key[16] = {
    0x00u, 0x11u, 0x22u, 0x33u, 0x44u, 0x55u, 0x66u, 0x77u,
    0x88u, 0x99u, 0xaau, 0xbbu, 0xccu, 0xddu, 0xeeu, 0xffu
};
static const uint8_t clipboard_record_iv[16] = {
    0xf0u, 0xe1u, 0xd2u, 0xc3u, 0xb4u, 0xa5u, 0x96u, 0x87u,
    0x78u, 0x69u, 0x5au, 0x4bu, 0x3cu, 0x2du, 0x1eu, 0x0fu
};

static long clipboard_fake_read(void *ctx, char *out, size_t cap)
{
    clipboard_fake *fake = (clipboard_fake *)ctx;
    fake->reads++;
    if (fake->override_read_result) {
        return fake->read_result;
    }
    if (fake->read_text == NULL || fake->read_len + 1u > cap) {
        return -1;
    }
    memcpy(out, fake->read_text, fake->read_len);
    out[fake->read_len] = '\0';
    return (long)fake->read_len;
}

static bool clipboard_fake_write(void *ctx, const char *text, size_t length)
{
    clipboard_fake *fake = (clipboard_fake *)ctx;
    fake->writes++;
    if (fake->reject_write || text == NULL ||
        length >= sizeof fake->written) {
        return false;
    }
    memcpy(fake->written, text, length);
    fake->written[length] = '\0';
    fake->written_len = length;
    return true;
}

static void clipboard_session_init(rfb_session *session,
                                   clipboard_fake *fake,
                                   rfb_session_dialect dialect)
{
    rfb_session_clear(session);
    session->alloc = rfb_default_allocator();
    fake_io_init(&fake->io, session->alloc);
    session->io = fake_io_adapter_make(&fake->io);
    session->io_open = true;
    rfb_buffer_init(&session->in, session->alloc,
                    RFB_LIMIT_FB_BYTES_POLICY);
    rfb_buffer_init(&session->out, session->alloc,
                    RFB_LIMIT_OUTBOUND_BYTES);
    rfb_framebuffer_init(&session->fb, session->alloc);
    session->pf = rfb_pixel_format_canonical_request();
    rfb_server_engine_init(&session->eng);
    rfb_pacing_init(&session->pacing, 0u);
    session->dialect = dialect;
    session->cfg.clipboard_enabled = true;
    session->cfg.clipboard_read_utf8 = clipboard_fake_read;
    session->cfg.clipboard_write_utf8 = clipboard_fake_write;
    session->cfg.clipboard_ctx = fake;
    rfb_clip_loop_init(&session->clipboard_loop);
}

static void clipboard_session_destroy(rfb_session *session,
                                      clipboard_fake *fake)
{
    rfb_session_destroy(session);
    fake_io_destroy(&fake->io);
}

static void clipboard_records_enable(rfb_session *session,
                                     apple_record_layer *mirror)
{
    apple_record_init(&session->apple_rl, clipboard_record_wrap);
    RFB_CHECK(apple_record_set_direction(
        &session->apple_rl, APPLE_DIR_ENCRYPT, clipboard_record_key,
        clipboard_record_iv));
    session->apple_rl_inited = true;
    session->apple_records_active = true;

    apple_record_init(mirror, clipboard_record_wrap);
    RFB_CHECK(apple_record_set_direction(
        mirror, APPLE_DIR_DECRYPT, clipboard_record_key,
        clipboard_record_iv));
}

RFB_TEST(rfb_session_clipboard,
         receive__classic_latin1_becomes_sanitized_host_utf8)
{
    rfb_session session;
    clipboard_fake fake;
    memset(&fake, 0, sizeof fake);
    clipboard_session_init(&session, &fake, RFB_SESSION_DIALECT_CLASSIC);

    static const uint8_t server_cut_text[] = {
        0x03u, 0x00u, 0x00u, 0x00u,
        0x00u, 0x00u, 0x00u, 0x09u,
        'c', 'a', 'f', 0xe9u, 0x1bu, '[', '3', '1', 'm'
    };
    RFB_CHECK_EQ_INT(rfb_buffer_append(&session.in, server_cut_text,
                                       sizeof server_cut_text),
                     RFB_OK);
    bool progress = false;
    RFB_CHECK_EQ_INT(rfb_session_test_process_in(&session, &progress),
                     RFB_OK);
    RFB_CHECK(progress);

    static const uint8_t expected[] = {
        'c', 'a', 'f', 0xc3u, 0xa9u, '[', '3', '1', 'm'
    };
    RFB_CHECK_EQ_UINT(fake.writes, 1u);
    RFB_CHECK_EQ_UINT(fake.written_len, sizeof expected);
    RFB_CHECK_MEM_EQ(fake.written, expected, sizeof expected);

    clipboard_session_destroy(&session, &fake);
}

RFB_TEST(rfb_session_clipboard,
         receive__disabled_or_view_only_never_writes_host)
{
    rfb_session session;
    clipboard_fake fake;
    memset(&fake, 0, sizeof fake);
    clipboard_session_init(&session, &fake,
                           RFB_SESSION_DIALECT_APPLE_CLEARTEXT_MVP);
    static const uint8_t remote[] = "remote";

    session.cfg.clipboard_enabled = false;
    rfb_session_internal_receive_clipboard(
        &session, remote, sizeof remote - 1u);
    session.cfg.clipboard_enabled = true;
    session.cfg.view_only = true;
    rfb_session_internal_receive_clipboard(
        &session, remote, sizeof remote - 1u);
    RFB_CHECK_EQ_UINT(fake.writes, 0u);

    clipboard_session_destroy(&session, &fake);
}

RFB_TEST(rfb_session_clipboard,
         receive__invalid_input_allocation_and_host_failures_are_bounded)
{
    static const uint8_t remote[] = "remote";
    rfb_session_internal_receive_clipboard(NULL, remote,
                                           sizeof remote - 1u);

    rfb_session session;
    clipboard_fake fake;
    memset(&fake, 0, sizeof fake);
    clipboard_session_init(&session, &fake,
                           RFB_SESSION_DIALECT_APPLE_CLEARTEXT_MVP);

    rfb_session_internal_receive_clipboard(&session, NULL, 1u);
    rfb_session_internal_receive_clipboard(&session, NULL, 0u);
    RFB_CHECK_EQ_UINT(fake.writes, 0u);

    session.alloc = NULL;
    rfb_session_internal_receive_clipboard(
        &session, remote, sizeof remote - 1u);
    session.dialect = RFB_SESSION_DIALECT_CLASSIC;
    rfb_session_internal_receive_clipboard(
        &session, remote, sizeof remote - 1u);
    RFB_CHECK_EQ_UINT(fake.writes, 0u);

    session.alloc = rfb_default_allocator();
    session.dialect = RFB_SESSION_DIALECT_APPLE_CLEARTEXT_MVP;
    fake.reject_write = true;
    rfb_session_internal_receive_clipboard(
        &session, remote, sizeof remote - 1u);
    RFB_CHECK_EQ_UINT(fake.writes, 1u);
    RFB_CHECK(!session.clipboard_loop.has_last);

    clipboard_session_destroy(&session, &fake);
}

RFB_TEST(rfb_session_clipboard,
         poll__apple_utf8_emits_sanitized_client_cut_text_once)
{
    rfb_session session;
    clipboard_fake fake;
    memset(&fake, 0, sizeof fake);
    static const char local[] = "local\033[31m";
    fake.read_text = local;
    fake.read_len = sizeof local - 1u;
    clipboard_session_init(&session, &fake,
                           RFB_SESSION_DIALECT_APPLE_CLEARTEXT_MVP);

    RFB_CHECK_EQ_INT(rfb_session_internal_poll_clipboard(&session, 1000u),
                     RFB_OK);
    static const uint8_t expected[] = {
        0x06u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x09u,
        'l', 'o', 'c', 'a', 'l', '[', '3', '1', 'm'
    };
    RFB_CHECK_EQ_UINT(fake_io_outbox_len(&fake.io), sizeof expected);
    RFB_CHECK_MEM_EQ(fake_io_outbox_data(&fake.io), expected,
                     sizeof expected);

    RFB_CHECK_EQ_INT(rfb_session_internal_poll_clipboard(&session, 1250u),
                     RFB_OK);
    RFB_CHECK_EQ_UINT(fake.reads, 2u);
    RFB_CHECK_EQ_UINT(fake_io_outbox_len(&fake.io), sizeof expected);

    clipboard_session_destroy(&session, &fake);
}

RFB_TEST(rfb_session_clipboard,
         poll__inbound_echo_and_invalid_utf8_are_not_sent)
{
    rfb_session session;
    clipboard_fake fake;
    memset(&fake, 0, sizeof fake);
    static const char echo[] = "same";
    fake.read_text = echo;
    fake.read_len = sizeof echo - 1u;
    clipboard_session_init(&session, &fake,
                           RFB_SESSION_DIALECT_APPLE_CLEARTEXT_MVP);

    rfb_session_internal_receive_clipboard(
        &session, (const uint8_t *)echo, sizeof echo - 1u);
    RFB_CHECK_EQ_INT(rfb_session_internal_poll_clipboard(&session, 1000u),
                     RFB_OK);
    RFB_CHECK_EQ_UINT(fake_io_outbox_len(&fake.io), 0u);

    static const char invalid[] = { (char)0xc0, (char)0xafu };
    fake.read_text = invalid;
    fake.read_len = sizeof invalid;
    RFB_CHECK_EQ_INT(rfb_session_internal_poll_clipboard(&session, 1250u),
                     RFB_OK);
    RFB_CHECK_EQ_UINT(fake_io_outbox_len(&fake.io), 0u);

    clipboard_session_destroy(&session, &fake);
}

RFB_TEST(rfb_session_clipboard,
         poll__deadline_empty_oversize_and_sanitized_empty_are_noops)
{
    rfb_session session;
    clipboard_fake fake;
    memset(&fake, 0, sizeof fake);
    clipboard_session_init(&session, &fake,
                           RFB_SESSION_DIALECT_APPLE_CLEARTEXT_MVP);
    session.cfg.clipboard_max_bytes = 3u;
    session.clipboard_next_poll_ms = 1000u;

    RFB_CHECK_EQ_INT(rfb_session_internal_poll_clipboard(&session, 999u),
                     RFB_OK);
    RFB_CHECK_EQ_UINT(fake.reads, 0u);

    fake.override_read_result = true;
    fake.read_result = 0;
    RFB_CHECK_EQ_INT(rfb_session_internal_poll_clipboard(&session, 1000u),
                     RFB_OK);
    fake.read_result = 4;
    RFB_CHECK_EQ_INT(rfb_session_internal_poll_clipboard(&session, 1250u),
                     RFB_OK);

    static const char dropped[] = { '\x01', '\x1b', '\x7f' };
    fake.override_read_result = false;
    fake.read_text = dropped;
    fake.read_len = sizeof dropped;
    RFB_CHECK_EQ_INT(rfb_session_internal_poll_clipboard(&session, 1500u),
                     RFB_OK);
    RFB_CHECK_EQ_UINT(fake.reads, 3u);
    RFB_CHECK_EQ_UINT(fake_io_outbox_len(&fake.io), 0u);

    clipboard_session_destroy(&session, &fake);
}

RFB_TEST(rfb_session_clipboard,
         poll__host_and_message_allocation_failures_are_reported)
{
    static const char first[] = "one";
    static const char second[] = "two";
    rfb_session session;
    clipboard_fake fake;
    memset(&fake, 0, sizeof fake);
    fake.read_text = first;
    fake.read_len = sizeof first - 1u;
    clipboard_session_init(&session, &fake,
                           RFB_SESSION_DIALECT_APPLE_CLEARTEXT_MVP);

    session.alloc = NULL;
    RFB_CHECK_EQ_INT(rfb_session_internal_poll_clipboard(&session, 1000u),
                     RFB_ERR_NOMEM);
    RFB_CHECK_EQ_UINT(fake.reads, 0u);

    session.alloc = rfb_default_allocator();
    RFB_CHECK_EQ_INT(rfb_session_internal_poll_clipboard(&session, 1250u),
                     RFB_OK);
    const size_t first_wire_length = fake_io_outbox_len(&fake.io);
    RFB_CHECK(first_wire_length > 0u);

    fake.read_text = second;
    fake.read_len = sizeof second - 1u;
    session.alloc = NULL;
    RFB_CHECK_EQ_INT(rfb_session_internal_poll_clipboard(&session, 1500u),
                     RFB_ERR_NOMEM);
    RFB_CHECK_EQ_UINT(fake_io_outbox_len(&fake.io), first_wire_length);

    session.alloc = rfb_default_allocator();
    clipboard_session_destroy(&session, &fake);
}

RFB_TEST(rfb_session_clipboard,
         poll__limit_allocator_and_latin1_edges_are_bounded)
{
    static const uint8_t remote[] = "x";
    rfb_session session;
    clipboard_fake fake;
    memset(&fake, 0, sizeof fake);
    clipboard_session_init(&session, &fake, RFB_SESSION_DIALECT_CLASSIC);

    // Exercise the configured-limit clamp without allocating the maximum
    // host buffer.
    session.cfg.clipboard_max_bytes = RFB_LIMIT_CLIPBOARD_BYTES + 1u;
    rfb_session_internal_receive_clipboard(&session, NULL, 0u);
    RFB_CHECK_EQ_UINT(fake.writes, 1u);

    rfb_allocator invalid = *rfb_default_allocator();
    invalid.alloc = NULL;
    invalid.free = NULL;
    session.alloc = &invalid;
    rfb_session_internal_receive_clipboard(
        &session, remote, sizeof remote - 1u);
    RFB_CHECK_EQ_UINT(fake.writes, 1u);
    session.alloc = rfb_default_allocator();

    session.cfg.clipboard_max_bytes = 4u;
    static const char truncated[] = { (char)0xc2u };
    fake.read_text = truncated;
    fake.read_len = sizeof truncated;
    RFB_CHECK_EQ_INT(rfb_session_internal_poll_clipboard(&session, 1000u),
                     RFB_OK);

    static const char low_continuation[] = { (char)0xc2u, 'A' };
    fake.read_text = low_continuation;
    fake.read_len = sizeof low_continuation;
    RFB_CHECK_EQ_INT(rfb_session_internal_poll_clipboard(&session, 1250u),
                     RFB_OK);

    static const char high_continuation[] = {
        (char)0xc2u, (char)0xc0u
    };
    fake.read_text = high_continuation;
    fake.read_len = sizeof high_continuation;
    RFB_CHECK_EQ_INT(rfb_session_internal_poll_clipboard(&session, 1500u),
                     RFB_OK);
    RFB_CHECK_EQ_UINT(fake_io_outbox_len(&fake.io), 0u);

    // Reuse the host buffer, then fail the classic conversion allocation.
    static const char valid[] = "ok";
    fake.read_text = valid;
    fake.read_len = sizeof valid - 1u;
    invalid = *rfb_default_allocator();
    invalid.alloc = NULL;
    session.alloc = &invalid;
    RFB_CHECK_EQ_INT(rfb_session_internal_poll_clipboard(&session, 1750u),
                     RFB_OK);
    RFB_CHECK_EQ_UINT(fake_io_outbox_len(&fake.io), 0u);
    session.alloc = rfb_default_allocator();

    // Grow an existing host buffer so both sides of the reuse check execute.
    session.cfg.clipboard_max_bytes = 8u;
    fake.override_read_result = true;
    fake.read_result = 0;
    RFB_CHECK_EQ_INT(rfb_session_internal_poll_clipboard(&session, 2000u),
                     RFB_OK);
    RFB_CHECK(session.clipboard_host_cap >= 9u);

    // Cover the protected-session limit comparison when no clamp is needed.
    session.apple_records_active = true;
    session.cfg.clipboard_max_bytes = 1u;
    rfb_session_internal_receive_clipboard(&session, NULL, 0u);
    RFB_CHECK_EQ_UINT(fake.writes, 2u);

    fake.override_read_result = true;
    fake.read_result = 0;
    session.clipboard_next_poll_ms = UINT64_MAX;
    RFB_CHECK_EQ_INT(
        rfb_session_internal_poll_clipboard(&session, UINT64_MAX), RFB_OK);
    RFB_CHECK_EQ_UINT(session.clipboard_next_poll_ms, UINT64_MAX);

    // These scalar boundaries cover validator and repair lead-byte paths that
    // the bridge normally accepts before conversion.
    static const uint8_t plane_one[] = {
        0xf1u, 0x80u, 0x80u, 0x80u
    };
    static const uint8_t invalid_lead[] = { 0xf5u };
    uint8_t repaired[sizeof plane_one] = { 0u };
    size_t repaired_length = 0u;
    RFB_CHECK(rfb_clip_utf8_valid(plane_one, sizeof plane_one));
    RFB_CHECK(!rfb_clip_utf8_valid(invalid_lead, sizeof invalid_lead));
    RFB_CHECK(rfb_clip_utf8_repair(
        plane_one, sizeof plane_one, repaired, sizeof repaired,
        &repaired_length));
    RFB_CHECK_EQ_UINT(repaired_length, sizeof plane_one);
    RFB_CHECK_MEM_EQ(repaired, plane_one, sizeof plane_one);

    clipboard_session_destroy(&session, &fake);
}

RFB_TEST(rfb_session_clipboard,
         poll__classic_rejects_unicode_outside_latin1)
{
    rfb_session session;
    clipboard_fake fake;
    memset(&fake, 0, sizeof fake);
    static const char emoji[] = "\xf0\x9f\x98\x80";
    fake.read_text = emoji;
    fake.read_len = sizeof emoji - 1u;
    clipboard_session_init(&session, &fake, RFB_SESSION_DIALECT_CLASSIC);

    RFB_CHECK_EQ_INT(rfb_session_internal_poll_clipboard(&session, 1000u),
                     RFB_OK);
    RFB_CHECK_EQ_UINT(fake_io_outbox_len(&fake.io), 0u);

    clipboard_session_destroy(&session, &fake);
}

RFB_TEST(rfb_session_clipboard,
         poll__classic_converts_host_utf8_to_latin1_wire)
{
    rfb_session session;
    clipboard_fake fake;
    memset(&fake, 0, sizeof fake);
    static const char cafe[] = "caf\xc3\xa9";
    fake.read_text = cafe;
    fake.read_len = sizeof cafe - 1u;
    clipboard_session_init(&session, &fake, RFB_SESSION_DIALECT_CLASSIC);

    RFB_CHECK_EQ_INT(rfb_session_internal_poll_clipboard(&session, 1000u),
                     RFB_OK);
    static const uint8_t expected[] = {
        0x06u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x04u,
        'c', 'a', 'f', 0xe9u
    };
    RFB_CHECK_EQ_UINT(fake_io_outbox_len(&fake.io), sizeof expected);
    RFB_CHECK_MEM_EQ(fake_io_outbox_data(&fake.io), expected,
                     sizeof expected);

    clipboard_session_destroy(&session, &fake);
}

RFB_TEST(rfb_session_clipboard,
         transfer__configured_size_cap_blocks_both_directions)
{
    rfb_session session;
    clipboard_fake fake;
    memset(&fake, 0, sizeof fake);
    static const char text[] = "four";
    fake.read_text = text;
    fake.read_len = sizeof text - 1u;
    clipboard_session_init(&session, &fake,
                           RFB_SESSION_DIALECT_APPLE_CLEARTEXT_MVP);
    session.cfg.clipboard_max_bytes = 3u;

    rfb_session_internal_receive_clipboard(
        &session, (const uint8_t *)text, sizeof text - 1u);
    RFB_CHECK_EQ_UINT(fake.writes, 0u);
    RFB_CHECK_EQ_INT(rfb_session_internal_poll_clipboard(&session, 1000u),
                     RFB_OK);
    RFB_CHECK_EQ_UINT(fake_io_outbox_len(&fake.io), 0u);

    clipboard_session_destroy(&session, &fake);
}

RFB_TEST(rfb_session_clipboard,
         transfer__missing_callback_disables_entire_bridge)
{
    rfb_session session;
    clipboard_fake fake;
    memset(&fake, 0, sizeof fake);
    static const char text[] = "text";
    fake.read_text = text;
    fake.read_len = sizeof text - 1u;
    clipboard_session_init(&session, &fake,
                           RFB_SESSION_DIALECT_APPLE_CLEARTEXT_MVP);

    session.cfg.clipboard_write_utf8 = NULL;
    RFB_CHECK_EQ_INT(rfb_session_internal_poll_clipboard(&session, 1000u),
                     RFB_OK);
    RFB_CHECK_EQ_UINT(fake.reads, 0u);
    session.cfg.clipboard_write_utf8 = clipboard_fake_write;
    session.cfg.clipboard_read_utf8 = NULL;
    rfb_session_internal_receive_clipboard(
        &session, (const uint8_t *)text, sizeof text - 1u);
    RFB_CHECK_EQ_UINT(fake.writes, 0u);

    clipboard_session_destroy(&session, &fake);
}

RFB_TEST(rfb_session_clipboard,
         poll__protected_record_boundary_is_sealed_and_larger_is_blocked)
{
    static char boundary[RFB_SESSION_APPLE_CLIPBOARD_MAX_BYTES];
    memset(boundary, 'x', sizeof boundary);

    rfb_session session;
    clipboard_fake fake;
    memset(&fake, 0, sizeof fake);
    fake.read_text = boundary;
    fake.read_len = sizeof boundary;
    clipboard_session_init(&session, &fake,
                           RFB_SESSION_DIALECT_APPLE_CLEARTEXT_MVP);
    apple_record_layer mirror;
    clipboard_records_enable(&session, &mirror);

    RFB_CHECK_EQ_INT(rfb_session_internal_poll_clipboard(&session, 1000u),
                     RFB_OK);
    const uint8_t *wire = fake_io_outbox_data(&fake.io);
    const size_t wire_length = fake_io_outbox_len(&fake.io);
    RFB_CHECK(wire != NULL);
    RFB_CHECK_EQ_UINT(wire_length, 4082u);
    const uint16_t ciphertext_length =
        (uint16_t)(((uint16_t)wire[0] << 8u) | (uint16_t)wire[1]);
    RFB_CHECK_EQ_UINT(ciphertext_length, 4080u);
    // The record opener stages the complete padded plaintext in this buffer
    // before it returns only the embedded RFB message length.
    uint8_t plain[4096u];
    size_t plain_length = 0u;
    RFB_CHECK_EQ_INT(apple_wire_record_open(
                         &mirror, wire + 2u, ciphertext_length, plain,
                         sizeof plain, &plain_length),
                     RFB_OK);
    RFB_CHECK_EQ_UINT(
        plain_length, RFB_SESSION_APPLE_CLIPBOARD_MAX_BYTES + 8u);
    RFB_CHECK_EQ_UINT(plain[0], 0x06u);
    RFB_CHECK_EQ_UINT(plain[6], 0x0fu);
    RFB_CHECK_EQ_UINT(plain[7], 0xd2u);
    RFB_CHECK_MEM_EQ(plain + 8u, boundary, sizeof boundary);

    apple_record_destroy(&mirror);
    clipboard_session_destroy(&session, &fake);

    static char oversized[RFB_SESSION_APPLE_CLIPBOARD_MAX_BYTES + 1u];
    memset(oversized, 'y', sizeof oversized);
    memset(&fake, 0, sizeof fake);
    fake.read_text = oversized;
    fake.read_len = sizeof oversized;
    clipboard_session_init(&session, &fake,
                           RFB_SESSION_DIALECT_APPLE_CLEARTEXT_MVP);
    clipboard_records_enable(&session, &mirror);
    RFB_CHECK_EQ_INT(rfb_session_internal_poll_clipboard(&session, 1000u),
                     RFB_OK);
    RFB_CHECK_EQ_UINT(fake_io_outbox_len(&fake.io), 0u);

    apple_record_destroy(&mirror);
    clipboard_session_destroy(&session, &fake);
}
