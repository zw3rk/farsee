// SPDX-License-Identifier: Apache-2.0
//
// Behavioral tests for the Apple type-33 connect state machine.

#include "rfb_test.h"
#include "fake_io.h"

#include "farsee/apple_postauth.h"
#include "farsee/buffer.h"
#include "farsee/limits.h"
#include "farsee/pixel_format.h"
#include "rfb/apple_type33_connect_internal.h"

#include <stdio.h>
#include <string.h>

typedef struct connect_fixture {
    fake_io wire;
    rfb_io_adapter backing_adapter;
    rfb_io_adapter adapter;
    rfb_buffer in;
    rfb_buffer out;
    rfb_error last_error;
    rfb_io_pump pump;
    rfb_session_config cfg;
    apple_type33_connect_hooks hooks;
    apple_type33_connect_ops ops;
    rfb_error auth_result;
    rfb_error setup_result;
    bool random_result;
    uint8_t chooser_result;
    size_t auth_calls;
    uint8_t auth_selected_type;
    size_t random_calls;
    size_t setup_calls;
    size_t chooser_calls;
    size_t write_calls;
    size_t fail_write_call;
    size_t zero_write_call;
    bool chooser_accept;
    char setup_name[16];
    char chooser_name[16];
    char chooser_user[16];
} connect_fixture;

static rfb_io_result fixture_io_connect(void *ctx,
                                        const rfb_io_candidate *candidate)
{
    connect_fixture *f = (connect_fixture *)ctx;
    return f->backing_adapter.connect(f->backing_adapter.ctx, candidate);
}

static rfb_io_result fixture_io_read(void *ctx, uint8_t *data, size_t len,
                                     size_t *out_len)
{
    connect_fixture *f = (connect_fixture *)ctx;
    return f->backing_adapter.read(f->backing_adapter.ctx, data, len, out_len);
}

static rfb_io_result fixture_io_write(void *ctx, const uint8_t *data,
                                      size_t len, size_t *out_len)
{
    connect_fixture *f = (connect_fixture *)ctx;
    f->write_calls++;
    if (f->write_calls == f->fail_write_call) {
        *out_len = 0u;
        return RFB_IO_ERROR;
    }
    if (f->write_calls == f->zero_write_call) {
        *out_len = 0u;
        return RFB_IO_OK;
    }
    return f->backing_adapter.write(f->backing_adapter.ctx, data, len,
                                    out_len);
}

static void fixture_io_close(void *ctx)
{
    connect_fixture *f = (connect_fixture *)ctx;
    f->backing_adapter.close(f->backing_adapter.ctx);
}

static rfb_error fixture_authenticate(
    void *ctx, uint8_t selected_type, const apple_type33_io *io,
    const uint8_t *username, size_t username_len,
    const uint8_t *password, size_t password_len,
    uint8_t wrap_key_out[16], apple_type33_kdf_material *kdf_out,
    const char *host, uint16_t port, const char *known_hosts_path,
    bool accept_new_host, rfb_allocator *allocator)
{
    connect_fixture *f = (connect_fixture *)ctx;
    (void)io;
    (void)host;
    (void)port;
    (void)known_hosts_path;
    (void)accept_new_host;
    (void)allocator;
    f->auth_calls++;
    f->auth_selected_type = selected_type;
    RFB_CHECK_EQ_UINT(username_len, f->cfg.username_len);
    RFB_CHECK_MEM_EQ(username, f->cfg.username, username_len);
    RFB_CHECK_EQ_UINT(password_len, f->cfg.password_len);
    RFB_CHECK_MEM_EQ(password, f->cfg.password, password_len);
    if (f->auth_result != RFB_OK) {
        return f->auth_result;
    }
    for (size_t i = 0; i < 16u; i++) {
        wrap_key_out[i] = (uint8_t)(0x10u + i);
    }
    for (size_t i = 0; i < 32u; i++) {
        kdf_out->session_key_32[i] = (uint8_t)(0x80u + i);
    }
    return RFB_OK;
}

static bool fixture_random(void *ctx, uint8_t *out, size_t len)
{
    connect_fixture *f = (connect_fixture *)ctx;
    f->random_calls++;
    if (!f->random_result) {
        return false;
    }
    memset(out, 0xcc, len);
    return true;
}

static rfb_error fixture_setup(void *ctx, const rfb_server_init *si)
{
    connect_fixture *f = (connect_fixture *)ctx;
    f->setup_calls++;
    if (si->name != NULL) {
        (void)snprintf(f->setup_name, sizeof f->setup_name, "%s", si->name);
    }
    return f->setup_result;
}

static bool fixture_choose(void *ctx, const char *desktop_name,
                           const char *username, uint8_t *out_attach)
{
    connect_fixture *f = (connect_fixture *)ctx;
    f->chooser_calls++;
    (void)snprintf(f->chooser_name, sizeof f->chooser_name, "%s",
                   desktop_name != NULL ? desktop_name : "");
    (void)snprintf(f->chooser_user, sizeof f->chooser_user, "%s",
                   username != NULL ? username : "");
    *out_attach = f->chooser_result;
    return f->chooser_accept;
}

static void fixture_seed_server_init(connect_fixture *f, const uint8_t *tail,
                                     size_t tail_len)
{
    static const char name[] = "desk";
    uint8_t si[24];
    const rfb_pixel_format pf = rfb_pixel_format_canonical_request();
    memset(si, 0, sizeof si);
    si[1] = 4u;
    si[3] = 3u;
    si[4] = pf.bits_per_pixel;
    si[5] = pf.depth;
    si[6] = pf.big_endian;
    si[7] = pf.true_color;
    si[8] = (uint8_t)(pf.red_max >> 8);
    si[9] = (uint8_t)pf.red_max;
    si[10] = (uint8_t)(pf.green_max >> 8);
    si[11] = (uint8_t)pf.green_max;
    si[12] = (uint8_t)(pf.blue_max >> 8);
    si[13] = (uint8_t)pf.blue_max;
    si[14] = pf.red_shift;
    si[15] = pf.green_shift;
    si[16] = pf.blue_shift;
    si[23] = (uint8_t)(sizeof name - 1u);
    RFB_CHECK_EQ_INT(rfb_buffer_append(&f->in, si, sizeof si), RFB_OK);
    RFB_CHECK_EQ_INT(rfb_buffer_append(&f->in, name, sizeof name - 1u),
                     RFB_OK);
    RFB_CHECK_EQ_INT(rfb_buffer_append(&f->in, tail, tail_len), RFB_OK);
}

static void fixture_seed_server(connect_fixture *f, const uint8_t *tail,
                                size_t tail_len)
{
    static const uint8_t security[] = {1u, 33u};
    RFB_CHECK_EQ_INT(rfb_buffer_append(&f->in, security, sizeof security),
                     RFB_OK);
    fixture_seed_server_init(f, tail, tail_len);
}

static void fixture_init(connect_fixture *f)
{
    static const uint8_t user[] = "admin";
    static const uint8_t pass[] = "secret";
    memset(f, 0, sizeof *f);
    fake_io_init(&f->wire, rfb_default_allocator());
    f->backing_adapter = fake_io_adapter_make(&f->wire);
    f->adapter.ctx = f;
    f->adapter.connect = fixture_io_connect;
    f->adapter.read = fixture_io_read;
    f->adapter.write = fixture_io_write;
    f->adapter.close = fixture_io_close;
    rfb_buffer_init(&f->in, rfb_default_allocator(),
                    RFB_LIMIT_PRESENTATION_BYTES);
    rfb_buffer_init(&f->out, rfb_default_allocator(),
                    RFB_LIMIT_PRESENTATION_BYTES);
    f->last_error = RFB_OK;
    f->pump.io = &f->adapter;
    f->pump.fd = -1;
    f->pump.in = &f->in;
    f->pump.out = &f->out;
    f->pump.last_error = &f->last_error;
    f->cfg.auth_mode = FARSEE_AUTH_MODE_APPLE;
    f->cfg.username = user;
    f->cfg.username_len = sizeof user - 1u;
    f->cfg.password = pass;
    f->cfg.password_len = sizeof pass - 1u;
    f->cfg.shared = true;
    f->cfg.apple_attach = APPLE_ATTACH_LOGIN;
    f->hooks.ctx = f;
    f->hooks.setup_after_server_init = fixture_setup;
    f->ops.ctx = f;
    f->ops.authenticate = fixture_authenticate;
    f->ops.random_bytes = fixture_random;
    f->auth_result = RFB_OK;
    f->setup_result = RFB_OK;
    f->random_result = true;
    f->chooser_result = APPLE_ATTACH_SHARE;
    f->chooser_accept = true;
}

static void fixture_destroy(connect_fixture *f)
{
    rfb_buffer_destroy(&f->in);
    rfb_buffer_destroy(&f->out);
    fake_io_destroy(&f->wire);
}

static rfb_error fixture_connect(connect_fixture *f, uint8_t wrap[16],
                                 bool *has_wrap,
                                 rfb_session_dialect *dialect,
                                 uint8_t sk32[32])
{
    return apple_type33_connect_with_ops(&f->pump, &f->cfg, &f->hooks,
                                         wrap, has_wrap, dialect, sk32,
                                         &f->ops);
}

static void check_failure_outputs(const uint8_t wrap[16], bool has_wrap,
                                  rfb_session_dialect dialect,
                                  const uint8_t sk32[32])
{
    static const uint8_t zero16[16] = {0};
    static const uint8_t zero32[32] = {0};
    RFB_CHECK_MEM_EQ(wrap, zero16, sizeof zero16);
    RFB_CHECK(!has_wrap);
    RFB_CHECK_EQ_INT(dialect, RFB_SESSION_DIALECT_CLASSIC);
    RFB_CHECK_MEM_EQ(sk32, zero32, sizeof zero32);
}

static void fixture_expect_failure(connect_fixture *f, rfb_error expected)
{
    uint8_t wrap[16];
    uint8_t sk32[32];
    memset(wrap, 0xa5, sizeof wrap);
    memset(sk32, 0xa5, sizeof sk32);
    bool has_wrap = true;
    rfb_session_dialect dialect = RFB_SESSION_DIALECT_APPLE_CLEARTEXT_MVP;
    RFB_CHECK_EQ_INT(fixture_connect(f, wrap, &has_wrap, &dialect, sk32),
                     expected);
    check_failure_outputs(wrap, has_wrap, dialect, sk32);
}

RFB_TEST(apple_type33_connect,
         shared_login_viewer_info_ack__publishes_keys_after_setup)
{
    connect_fixture f;
    fixture_init(&f);
    static const uint8_t ack[] = {0u, 3u, 0xaau, 0xbbu, 0xccu};
    fixture_seed_server(&f, ack, sizeof ack);
    f.cfg.apple_send_viewer_info = true;
    uint8_t wrap[16] = {0};
    uint8_t sk32[32] = {0};
    bool has_wrap = false;
    rfb_session_dialect dialect = RFB_SESSION_DIALECT_CLASSIC;
    RFB_CHECK_EQ_INT(fixture_connect(&f, wrap, &has_wrap, &dialect, sk32),
                     RFB_OK);
    RFB_CHECK(has_wrap);
    RFB_CHECK_EQ_INT(dialect, RFB_SESSION_DIALECT_APPLE_CLEARTEXT_MVP);
    for (size_t i = 0; i < sizeof wrap; i++) {
        RFB_CHECK_EQ_UINT(wrap[i], 0x10u + i);
    }
    for (size_t i = 0; i < sizeof sk32; i++) {
        RFB_CHECK_EQ_UINT(sk32[i], 0x80u + i);
    }
    RFB_CHECK_EQ_UINT(f.auth_calls, 1u);
    RFB_CHECK_EQ_UINT(f.random_calls, 1u);
    RFB_CHECK_EQ_UINT(f.setup_calls, 1u);
    RFB_CHECK(strcmp(f.setup_name, "desk") == 0);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&f.in), 0u);
    const uint8_t *sent = fake_io_outbox_data(&f.wire);
    RFB_CHECK_EQ_UINT(fake_io_outbox_len(&f.wire),
                      13u + APPLE_VIEWER_INFO_LIVE_LOGIN_LEN);
    RFB_CHECK_EQ_UINT(sent[12], APPLE_POSTAUTH_CLIENT_INIT_LIVE_SHARED);
    apple_viewer_info vi;
    uint8_t attach = 0u;
    RFB_CHECK_EQ_INT(apple_postauth_parse_viewer_info_live_attach(
                         sent + 13u, APPLE_VIEWER_INFO_LIVE_LOGIN_LEN,
                         &vi, &attach),
                     RFB_OK);
    RFB_CHECK_EQ_UINT(attach, APPLE_ATTACH_LOGIN);
    RFB_CHECK_MEM_EQ(vi.device_name, "farsee", 6u);
    for (size_t i = 13u + 74u; i < fake_io_outbox_len(&f.wire); i++) {
        RFB_CHECK_EQ_UINT(sent[i], 0xccu);
    }
    fixture_destroy(&f);
}

RFB_TEST(apple_type33_connect,
         exclusive_ask_share__uses_classic_init_and_chooser)
{
    connect_fixture f;
    fixture_init(&f);
    static const uint8_t fbu_prefix[] = {0u, 0u};
    fixture_seed_server(&f, fbu_prefix, sizeof fbu_prefix);
    f.cfg.shared = false;
    f.cfg.apple_attach = APPLE_ATTACH_ASK;
    f.cfg.apple_attach_choose = fixture_choose;
    f.cfg.apple_attach_choose_ctx = &f;
    f.cfg.apple_send_viewer_info = true;
    uint8_t wrap[16] = {0};
    uint8_t sk32[32] = {0};
    bool has_wrap = false;
    rfb_session_dialect dialect = RFB_SESSION_DIALECT_CLASSIC;
    RFB_CHECK_EQ_INT(fixture_connect(&f, wrap, &has_wrap, &dialect, sk32),
                     RFB_OK);
    RFB_CHECK(has_wrap);
    RFB_CHECK_EQ_UINT(f.chooser_calls, 1u);
    RFB_CHECK(strcmp(f.chooser_name, "desk") == 0);
    RFB_CHECK(strcmp(f.chooser_user, "admin") == 0);
    RFB_CHECK_EQ_UINT(f.cfg.apple_attach, APPLE_ATTACH_SHARE);
    RFB_CHECK_EQ_UINT(f.random_calls, 0u);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&f.in), sizeof fbu_prefix);
    const uint8_t *sent = fake_io_outbox_data(&f.wire);
    RFB_CHECK_EQ_UINT(fake_io_outbox_len(&f.wire),
                      13u + APPLE_VIEWER_INFO_LIVE_LEN);
    RFB_CHECK_EQ_UINT(sent[12], 0u);
    fixture_destroy(&f);
}

RFB_TEST(apple_type33_connect,
         setup_failure__keeps_session_keys_unpublished)
{
    connect_fixture f;
    fixture_init(&f);
    fixture_seed_server(&f, NULL, 0u);
    f.setup_result = RFB_ERR_IO;
    uint8_t wrap[16];
    uint8_t sk32[32];
    memset(wrap, 0xa5, sizeof wrap);
    memset(sk32, 0xa5, sizeof sk32);
    bool has_wrap = true;
    rfb_session_dialect dialect = RFB_SESSION_DIALECT_APPLE_CLEARTEXT_MVP;
    RFB_CHECK_EQ_INT(fixture_connect(&f, wrap, &has_wrap, &dialect, sk32),
                     RFB_ERR_IO);
    check_failure_outputs(wrap, has_wrap, dialect, sk32);
    RFB_CHECK_EQ_UINT(f.setup_calls, 1u);
    fixture_destroy(&f);
}

RFB_TEST(apple_type33_connect,
         login_random_failure__keeps_session_keys_unpublished)
{
    connect_fixture f;
    fixture_init(&f);
    fixture_seed_server(&f, NULL, 0u);
    f.cfg.apple_send_viewer_info = true;
    f.random_result = false;
    uint8_t wrap[16];
    uint8_t sk32[32];
    memset(wrap, 0xa5, sizeof wrap);
    memset(sk32, 0xa5, sizeof sk32);
    bool has_wrap = true;
    rfb_session_dialect dialect = RFB_SESSION_DIALECT_APPLE_CLEARTEXT_MVP;
    RFB_CHECK_EQ_INT(fixture_connect(&f, wrap, &has_wrap, &dialect, sk32),
                     RFB_ERR_INTERNAL);
    check_failure_outputs(wrap, has_wrap, dialect, sk32);
    RFB_CHECK_EQ_UINT(f.random_calls, 1u);
    RFB_CHECK_EQ_UINT(f.setup_calls, 0u);
    fixture_destroy(&f);
}

RFB_TEST(apple_type33_connect, pure_helpers_cover_bounds_and_policy)
{
    static const uint8_t short_ack[] = {0u};
    static const uint8_t fbu[] = {0u, 0u};
    static const uint8_t oversize[] = {
        0u, (uint8_t)(APPLE_VIEWER_INFO_LIVE_ACK_BODY_MAX + 1u),
    };
    static const uint8_t incomplete[] = {0u, 3u, 0xaau};
    static const uint8_t complete[] = {0u, 2u, 0xaau, 0xbbu};
    RFB_CHECK_EQ_UINT(apple_viewer_info_live_ack_consume_len(NULL, 2u), 0u);
    RFB_CHECK_EQ_UINT(apple_viewer_info_live_ack_consume_len(
                          short_ack, sizeof short_ack),
                      0u);
    RFB_CHECK_EQ_UINT(apple_viewer_info_live_ack_consume_len(fbu, sizeof fbu),
                      0u);
    RFB_CHECK_EQ_UINT(apple_viewer_info_live_ack_consume_len(
                          oversize, sizeof oversize),
                      0u);
    RFB_CHECK_EQ_UINT(apple_viewer_info_live_ack_consume_len(
                          incomplete, sizeof incomplete),
                      0u);
    RFB_CHECK_EQ_UINT(apple_viewer_info_live_ack_consume_len(
                          complete, sizeof complete),
                      sizeof complete);

    farsee_rfb_security_policy policy = apple_connect_security_policy(NULL);
    RFB_CHECK_EQ_INT(policy.auth_mode, FARSEE_AUTH_MODE_AUTO);
    RFB_CHECK(!policy.allow_none);
    RFB_CHECK(policy.allow_vnc);
    RFB_CHECK(policy.allow_type_33);
    RFB_CHECK(!policy.allow_type_36);

    rfb_session_config cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.auth_mode = FARSEE_AUTH_MODE_VNC;
    cfg.allow_none_auth = true;
    cfg.apple_prefer_type_36 = true;
    policy = apple_connect_security_policy(&cfg);
    RFB_CHECK_EQ_INT(policy.auth_mode, FARSEE_AUTH_MODE_VNC);
    RFB_CHECK(policy.allow_none);
    RFB_CHECK(policy.allow_vnc);
    RFB_CHECK(!policy.allow_type_33);
    RFB_CHECK(policy.allow_type_36);
    cfg.auth_mode = FARSEE_AUTH_MODE_APPLE;
    cfg.apple_prefer_type_36 = false;
    policy = apple_connect_security_policy(&cfg);
    RFB_CHECK(!policy.allow_vnc);
    RFB_CHECK(policy.allow_type_33);

    static const char expected[] = "/tmp/.farsee/vnc_known_hosts";
    char path[sizeof expected];
    RFB_CHECK(!apple_type33_known_hosts_path(NULL, sizeof path, "/tmp"));
    RFB_CHECK(!apple_type33_known_hosts_path(path, 0u, "/tmp"));
    RFB_CHECK(!apple_type33_known_hosts_path(path, sizeof path, NULL));
    RFB_CHECK_EQ_UINT(path[0], '\0');
    RFB_CHECK(!apple_type33_known_hosts_path(path, sizeof path, ""));
    RFB_CHECK(!apple_type33_known_hosts_path(path, sizeof path - 1u, "/tmp"));
    RFB_CHECK_EQ_UINT(path[0], '\0');
    RFB_CHECK(apple_type33_known_hosts_path(path, sizeof path, "/tmp"));
    RFB_CHECK(strcmp(path, expected) == 0);
}

RFB_TEST(apple_type33_connect, invalid_arguments_fail_before_io)
{
    connect_fixture f;
    fixture_init(&f);
    uint8_t wrap[16] = {0};
    uint8_t sk32[32] = {0};
    bool has_wrap = false;
    rfb_session_dialect dialect = RFB_SESSION_DIALECT_CLASSIC;

    RFB_CHECK_EQ_INT(apple_type33_connect_with_ops(
                         NULL, &f.cfg, &f.hooks, wrap, &has_wrap, &dialect,
                         sk32, &f.ops),
                     RFB_ERR_INTERNAL);
    rfb_io_pump pump = f.pump;
    pump.in = NULL;
    RFB_CHECK_EQ_INT(apple_type33_connect_with_ops(
                         &pump, &f.cfg, &f.hooks, wrap, &has_wrap, &dialect,
                         sk32, &f.ops),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(apple_type33_connect_with_ops(
                         &f.pump, NULL, &f.hooks, wrap, &has_wrap, &dialect,
                         sk32, &f.ops),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(apple_type33_connect_with_ops(
                         &f.pump, &f.cfg, NULL, wrap, &has_wrap, &dialect,
                         sk32, &f.ops),
                     RFB_ERR_INTERNAL);
    apple_type33_connect_hooks hooks = f.hooks;
    hooks.setup_after_server_init = NULL;
    RFB_CHECK_EQ_INT(apple_type33_connect_with_ops(
                         &f.pump, &f.cfg, &hooks, wrap, &has_wrap, &dialect,
                         sk32, &f.ops),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(apple_type33_connect_with_ops(
                         &f.pump, &f.cfg, &f.hooks, NULL, &has_wrap, &dialect,
                         sk32, &f.ops),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(apple_type33_connect_with_ops(
                         &f.pump, &f.cfg, &f.hooks, wrap, NULL, &dialect,
                         sk32, &f.ops),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(apple_type33_connect_with_ops(
                         &f.pump, &f.cfg, &f.hooks, wrap, &has_wrap, NULL,
                         sk32, &f.ops),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(apple_type33_connect_with_ops(
                         &f.pump, &f.cfg, &f.hooks, wrap, &has_wrap, &dialect,
                         sk32, NULL),
                     RFB_ERR_INTERNAL);
    apple_type33_connect_ops ops = f.ops;
    ops.authenticate = NULL;
    RFB_CHECK_EQ_INT(apple_type33_connect_with_ops(
                         &f.pump, &f.cfg, &f.hooks, wrap, &has_wrap, &dialect,
                         sk32, &ops),
                     RFB_ERR_INTERNAL);
    ops = f.ops;
    ops.random_bytes = NULL;
    RFB_CHECK_EQ_INT(apple_type33_connect_with_ops(
                         &f.pump, &f.cfg, &f.hooks, wrap, &has_wrap, &dialect,
                         sk32, &ops),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(apple_type33_connect(NULL, &f.cfg, &f.hooks, wrap,
                                         &has_wrap, &dialect, sk32),
                     RFB_ERR_INTERNAL);
    fixture_destroy(&f);
}

RFB_TEST(apple_type33_connect, security_and_credentials_fail_closed)
{
    {
        connect_fixture f;
        fixture_init(&f);
        static const uint8_t failed[] = {0u};
        RFB_CHECK_EQ_INT(rfb_buffer_append(&f.in, failed, sizeof failed),
                         RFB_OK);
        fixture_expect_failure(&f, RFB_ERR_AUTH);
        RFB_CHECK_EQ_INT(f.last_error, RFB_ERR_AUTH);
        fixture_destroy(&f);
    }
    {
        connect_fixture f;
        fixture_init(&f);
        static const uint8_t too_many[] = {65u};
        RFB_CHECK_EQ_INT(rfb_buffer_append(&f.in, too_many, sizeof too_many),
                         RFB_OK);
        fixture_expect_failure(&f, RFB_ERR_PROTOCOL);
        RFB_CHECK_EQ_INT(f.last_error, RFB_ERR_PROTOCOL);
        fixture_destroy(&f);
    }
    {
        connect_fixture f;
        fixture_init(&f);
        static const uint8_t unsupported[] = {1u, 2u};
        RFB_CHECK_EQ_INT(rfb_buffer_append(&f.in, unsupported,
                                           sizeof unsupported),
                         RFB_OK);
        fixture_expect_failure(&f, RFB_ERR_UNSUPPORTED);
        RFB_CHECK_EQ_INT(f.last_error, RFB_ERR_UNSUPPORTED);
        fixture_destroy(&f);
    }
    {
        connect_fixture f;
        fixture_init(&f);
        fixture_seed_server(&f, NULL, 0u);
        f.cfg.username = NULL;
        fixture_expect_failure(&f, RFB_ERR_AUTH);
        fixture_destroy(&f);
    }
    {
        connect_fixture f;
        fixture_init(&f);
        fixture_seed_server(&f, NULL, 0u);
        f.cfg.username_len = 0u;
        fixture_expect_failure(&f, RFB_ERR_AUTH);
        fixture_destroy(&f);
    }
    {
        connect_fixture f;
        fixture_init(&f);
        fixture_seed_server(&f, NULL, 0u);
        f.cfg.password = NULL;
        fixture_expect_failure(&f, RFB_ERR_AUTH);
        fixture_destroy(&f);
    }
    {
        connect_fixture f;
        fixture_init(&f);
        fixture_seed_server(&f, NULL, 0u);
        f.cfg.password_len = 0u;
        fixture_expect_failure(&f, RFB_ERR_AUTH);
        fixture_destroy(&f);
    }
    {
        connect_fixture f;
        fixture_init(&f);
        fixture_seed_server(&f, NULL, 0u);
        f.auth_result = RFB_ERR_AUTH;
        f.pump.last_error = NULL;
        fixture_expect_failure(&f, RFB_ERR_AUTH);
        RFB_CHECK_EQ_UINT(f.auth_calls, 1u);
        fixture_destroy(&f);
    }
}

RFB_TEST(apple_type33_connect, transport_failures_keep_keys_unpublished)
{
    {
        connect_fixture f;
        fixture_init(&f);
        f.fail_write_call = 1u;
        fixture_expect_failure(&f, RFB_ERR_IO);
        RFB_CHECK_EQ_UINT(f.auth_calls, 0u);
        fixture_destroy(&f);
    }
    {
        connect_fixture f;
        fixture_init(&f);
        f.pump.deadline_mono_ms = 1u;
        fixture_expect_failure(&f, RFB_ERR_TIMEOUT);
        RFB_CHECK_EQ_UINT(f.auth_calls, 0u);
        fixture_destroy(&f);
    }
    {
        connect_fixture f;
        fixture_init(&f);
        static const uint8_t partial_security[] = {2u, 33u};
        RFB_CHECK_EQ_INT(rfb_buffer_append(&f.in, partial_security,
                                           sizeof partial_security),
                         RFB_OK);
        f.pump.deadline_mono_ms = 1u;
        fixture_expect_failure(&f, RFB_ERR_TIMEOUT);
        fixture_destroy(&f);
    }
    {
        connect_fixture f;
        fixture_init(&f);
        fixture_seed_server(&f, NULL, 0u);
        f.fail_write_call = 2u;
        fixture_expect_failure(&f, RFB_ERR_IO);
        RFB_CHECK_EQ_UINT(f.auth_calls, 1u);
        RFB_CHECK_EQ_UINT(f.setup_calls, 0u);
        fixture_destroy(&f);
    }
    {
        connect_fixture f;
        fixture_init(&f);
        static const uint8_t security[] = {1u, 33u};
        RFB_CHECK_EQ_INT(rfb_buffer_append(&f.in, security, sizeof security),
                         RFB_OK);
        f.pump.deadline_mono_ms = 1u;
        fixture_expect_failure(&f, RFB_ERR_TIMEOUT);
        RFB_CHECK_EQ_UINT(f.auth_calls, 0u);
        fixture_destroy(&f);
    }
    {
        connect_fixture f;
        fixture_init(&f);
        fixture_seed_server(&f, NULL, 0u);
        f.cfg.apple_send_viewer_info = true;
        f.fail_write_call = 3u;
        fixture_expect_failure(&f, RFB_ERR_IO);
        RFB_CHECK_EQ_UINT(f.random_calls, 1u);
        RFB_CHECK_EQ_UINT(f.setup_calls, 0u);
        fixture_destroy(&f);
    }
    {
        connect_fixture f;
        fixture_init(&f);
        fixture_seed_server(&f, NULL, 0u);
        f.cfg.apple_send_viewer_info = true;
        f.zero_write_call = 3u;
        f.fail_write_call = 4u;
        fixture_expect_failure(&f, RFB_ERR_IO);
        RFB_CHECK_EQ_UINT(f.random_calls, 1u);
        RFB_CHECK_EQ_UINT(f.setup_calls, 0u);
        fixture_destroy(&f);
    }
}

RFB_TEST(apple_type33_connect, type36_selection_dispatches_authentication)
{
    connect_fixture f;
    fixture_init(&f);
    static const uint8_t security[] = {1u, 36u};
    RFB_CHECK_EQ_INT(rfb_buffer_append(&f.in, security, sizeof security),
                     RFB_OK);
    fixture_seed_server_init(&f, NULL, 0u);
    f.cfg.apple_prefer_type_36 = true;
    RFB_CHECK_EQ_INT(fixture_connect(&f, (uint8_t[16]){0}, &(bool){false},
                                     &(rfb_session_dialect){0},
                                     (uint8_t[32]){0}),
                     RFB_OK);
    RFB_CHECK_EQ_UINT(f.auth_calls, 1u);
    RFB_CHECK_EQ_UINT(f.auth_selected_type, 36u);
    RFB_CHECK_EQ_UINT(f.random_calls, 0u);
    RFB_CHECK_EQ_UINT(f.setup_calls, 1u);
    fixture_destroy(&f);
}

RFB_TEST(apple_type33_connect, chooser_fallbacks_are_deterministic)
{
    {
        connect_fixture f;
        fixture_init(&f);
        fixture_seed_server(&f, NULL, 0u);
        f.cfg.apple_attach = 0xffu;
        RFB_CHECK_EQ_INT(fixture_connect(&f, (uint8_t[16]){0},
                                         &(bool){false},
                                         &(rfb_session_dialect){0},
                                         (uint8_t[32]){0}),
                         RFB_OK);
        RFB_CHECK_EQ_UINT(f.cfg.apple_attach, APPLE_ATTACH_LOGIN);
        RFB_CHECK_EQ_UINT(f.chooser_calls, 0u);
        fixture_destroy(&f);
    }
    {
        connect_fixture f;
        fixture_init(&f);
        fixture_seed_server(&f, NULL, 0u);
        f.cfg.apple_attach = APPLE_ATTACH_ASK;
        f.cfg.apple_attach_choose = fixture_choose;
        f.cfg.apple_attach_choose_ctx = &f;
        f.chooser_accept = false;
        RFB_CHECK_EQ_INT(fixture_connect(&f, (uint8_t[16]){0},
                                         &(bool){false},
                                         &(rfb_session_dialect){0},
                                         (uint8_t[32]){0}),
                         RFB_OK);
        RFB_CHECK_EQ_UINT(f.cfg.apple_attach, APPLE_ATTACH_LOGIN);
        RFB_CHECK_EQ_UINT(f.chooser_calls, 1u);
        fixture_destroy(&f);
    }
    {
        connect_fixture f;
        fixture_init(&f);
        fixture_seed_server(&f, NULL, 0u);
        f.cfg.apple_attach = APPLE_ATTACH_ASK;
        f.cfg.apple_attach_choose = fixture_choose;
        f.cfg.apple_attach_choose_ctx = &f;
        f.chooser_result = 0xffu;
        RFB_CHECK_EQ_INT(fixture_connect(&f, (uint8_t[16]){0},
                                         &(bool){false},
                                         &(rfb_session_dialect){0},
                                         (uint8_t[32]){0}),
                         RFB_OK);
        RFB_CHECK_EQ_UINT(f.cfg.apple_attach, APPLE_ATTACH_LOGIN);
        fixture_destroy(&f);
    }
    {
        connect_fixture f;
        fixture_init(&f);
        fixture_seed_server(&f, NULL, 0u);
        uint8_t long_user[129];
        memset(long_user, 'u', sizeof long_user - 1u);
        long_user[sizeof long_user - 1u] = '\0';
        f.cfg.username = long_user;
        f.cfg.username_len = sizeof long_user - 1u;
        f.cfg.apple_attach = APPLE_ATTACH_ASK;
        f.cfg.apple_attach_choose = fixture_choose;
        f.cfg.apple_attach_choose_ctx = &f;
        f.chooser_result = APPLE_ATTACH_SHARE;
        RFB_CHECK_EQ_INT(fixture_connect(&f, (uint8_t[16]){0},
                                         &(bool){false},
                                         &(rfb_session_dialect){0},
                                         (uint8_t[32]){0}),
                         RFB_OK);
        RFB_CHECK_EQ_UINT(f.cfg.apple_attach, APPLE_ATTACH_SHARE);
        RFB_CHECK_EQ_UINT(strlen(f.chooser_user), sizeof f.chooser_user - 1u);
        fixture_destroy(&f);
    }
}

RFB_TEST(apple_type33_connect, oversize_ack_prefix_is_preserved_for_demux)
{
    connect_fixture f;
    fixture_init(&f);
    static const uint8_t prefix[] = {
        0u, (uint8_t)(APPLE_VIEWER_INFO_LIVE_ACK_BODY_MAX + 1u),
    };
    fixture_seed_server(&f, prefix, sizeof prefix);
    f.cfg.apple_send_viewer_info = true;
    RFB_CHECK_EQ_INT(fixture_connect(&f, (uint8_t[16]){0}, &(bool){false},
                                     &(rfb_session_dialect){0},
                                     (uint8_t[32]){0}),
                     RFB_OK);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&f.in), sizeof prefix);
    RFB_CHECK_MEM_EQ(rfb_buffer_data(&f.in), prefix, sizeof prefix);
    fixture_destroy(&f);
}
