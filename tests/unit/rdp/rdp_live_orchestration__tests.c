// SPDX-License-Identifier: Apache-2.0
//
// Deterministic coverage for the RDP CLI owner. The real null presenter and
// credential path run around a fake FreeRDP facade, so no endpoint is needed.

#ifdef FARSEE_WITH_RDP

#include "app/rdp_live_internal.h"
#include "app/rdp_live_input.h"
#include "farsee/farsee_error.h"
#include "tests/test_framework/rfb_test.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct fake_rdp_live_state {
    bool log_ok;
    bool create_ok;
    bool apply_ok;
    bool connect_ok;
    bool got_frame;
    bool clean_peer;
    bool stop_during_connect;
    bool signal_during_destroy;
    bool use_real_context;
    uint64_t frame_count;
    uint32_t frame_width;
    uint32_t frame_height;
    farsee_error run_error;
    const char *last_error_name;

    unsigned create_calls;
    unsigned log_calls;
    unsigned destroy_calls;
    unsigned set_presenter_calls;
    unsigned apply_calls;
    unsigned connect_calls;
    unsigned clear_credentials_calls;
    unsigned run_calls;
    unsigned request_stop_calls;
    unsigned disconnect_calls;
    unsigned last_error_calls;

    farsee_rdp_settings settings;
    farsee_security_policy policy;
    farsee_trust_decision trust;
    size_t password_length;
    bool known_hosts_set;
    bool presenter_had_frame_slot;
    rdp_run_budget budget;
    rdp_display_sink *sink;
    rdp_freerdp_ctx *active_context;
} fake_rdp_live_state;

static fake_rdp_live_state fake;
static max_align_t fake_context_storage;
static volatile sig_atomic_t prior_sigterm_seen;

static void prior_sigterm_handler(int signal_number)
{
    prior_sigterm_seen = signal_number;
}

static bool fake_set_log_level(rdp_liblog_level level)
{
    (void)level;
    fake.log_calls++;
    return fake.log_ok;
}

static rdp_freerdp_ctx *fake_create(void)
{
    fake.create_calls++;
    if (!fake.create_ok) {
        return NULL;
    }
    fake.active_context = fake.use_real_context
                              ? rdp_freerdp_create()
                              : (rdp_freerdp_ctx *)&fake_context_storage;
    return fake.active_context;
}

static void fake_destroy(rdp_freerdp_ctx **ctx)
{
    fake.destroy_calls++;
    RFB_CHECK(ctx != NULL);
    if (ctx == NULL) {
        return;
    }
    RFB_CHECK(*ctx == fake.active_context);
    if (fake.use_real_context) {
        rdp_freerdp_destroy(ctx);
    } else {
        *ctx = NULL;
    }
    fake.active_context = NULL;
    if (fake.signal_during_destroy) {
        (void)raise(SIGTERM);
    }
}

static void fake_set_presenter(rdp_freerdp_ctx *ctx,
                               farsee_presenter *presenter,
                               rdp_display_sink *sink)
{
    RFB_CHECK(ctx == fake.active_context);
    RFB_CHECK(presenter != NULL);
    fake.set_presenter_calls++;
    fake.presenter_had_frame_slot =
        sink != NULL && sink->frame_slot != NULL;
    fake.sink = sink;
}

static bool fake_apply(rdp_freerdp_ctx *ctx,
                       const farsee_rdp_settings *settings,
                       const farsee_security_policy *policy,
                       const farsee_credential_response *credentials,
                       farsee_trust_decision trust,
                       const char *known_hosts_path,
                       farsee_memory_budget *memory_budget)
{
    RFB_CHECK(ctx == fake.active_context);
    RFB_CHECK(settings != NULL);
    RFB_CHECK(policy != NULL);
    RFB_CHECK(credentials != NULL);
    RFB_CHECK(memory_budget != NULL);
    fake.apply_calls++;
    fake.settings = *settings;
    fake.policy = *policy;
    fake.trust = trust;
    fake.password_length = credentials->password.len;
    fake.known_hosts_set = known_hosts_path != NULL;
    return fake.apply_ok;
}

static bool fake_connect(rdp_freerdp_ctx *ctx, farsee_atomic_int *stop)
{
    RFB_CHECK(ctx == fake.active_context);
    RFB_CHECK(stop != NULL);
    fake.connect_calls++;
    if (fake.stop_during_connect) {
        farsee_atomic_int_store(stop, 1);
    }
    return fake.connect_ok;
}

static void fake_clear_credentials(rdp_freerdp_ctx *ctx)
{
    RFB_CHECK(ctx == fake.active_context);
    fake.clear_credentials_calls++;
}

static farsee_error fake_run_until(rdp_freerdp_ctx *ctx,
                                   const rdp_run_budget *budget,
                                   bool *out_first_frame)
{
    RFB_CHECK(ctx == fake.active_context);
    RFB_CHECK(budget != NULL);
    RFB_CHECK(out_first_frame != NULL);
    RFB_CHECK_EQ_UINT(fake.clear_credentials_calls, 1u);
    fake.run_calls++;
    fake.budget = *budget;
    *out_first_frame = fake.got_frame;
    if (fake.sink != NULL) {
        farsee_atomic_u64_store(&fake.sink->frame_count, fake.frame_count);
        farsee_atomic_u64_store(
            &fake.sink->last_desk_size,
            rdp_desk_size_pack(fake.frame_width, fake.frame_height));
    }
    return fake.run_error;
}

static void fake_request_stop(rdp_freerdp_ctx *ctx)
{
    RFB_CHECK(ctx == fake.active_context);
    fake.request_stop_calls++;
}

static void fake_disconnect(rdp_freerdp_ctx *ctx)
{
    RFB_CHECK(ctx == fake.active_context);
    fake.disconnect_calls++;
}

static const char *fake_last_error_name(const rdp_freerdp_ctx *ctx)
{
    RFB_CHECK(ctx == fake.active_context);
    fake.last_error_calls++;
    return fake.last_error_name;
}

static bool fake_is_clean_peer_disconnect(const rdp_freerdp_ctx *ctx)
{
    RFB_CHECK(ctx == fake.active_context);
    return fake.clean_peer;
}

static const rdp_live_facade_ops fake_ops = {
    .set_library_log_level = fake_set_log_level,
    .create = fake_create,
    .destroy = fake_destroy,
    .set_presenter = fake_set_presenter,
    .apply_settings_with_memory_budget = fake_apply,
    .connect_with_stop = fake_connect,
    .clear_credentials = fake_clear_credentials,
    .run_until = fake_run_until,
    .request_stop = fake_request_stop,
    .disconnect = fake_disconnect,
    .last_error_name = fake_last_error_name,
    .is_clean_peer_disconnect = fake_is_clean_peer_disconnect,
};

static void fake_reset(void)
{
    memset(&fake, 0, sizeof fake);
    fake.log_ok = true;
    fake.create_ok = true;
    fake.apply_ok = true;
    fake.connect_ok = true;
    fake.run_error = farsee_error_make(
        FARSEE_E_OK, FARSEE_SUB_NONE, FARSEE_PHASE_CLOSED);
    fake.last_error_name = "ERRINFO_NONE";
}

static int password_pipe(void)
{
    int descriptors[2] = {-1, -1};
    if (pipe(descriptors) != 0) {
        return -1;
    }
    static const char password[] = "secret\n";
    if (write(descriptors[1], password, sizeof password - 1u) !=
            (ssize_t)(sizeof password - 1u) ||
        close(descriptors[1]) != 0) {
        (void)close(descriptors[0]);
        (void)close(descriptors[1]);
        return -1;
    }
    return descriptors[0];
}

static int empty_pipe(void)
{
    int descriptors[2] = {-1, -1};
    if (pipe(descriptors) != 0) {
        return -1;
    }
    if (close(descriptors[1]) != 0) {
        (void)close(descriptors[0]);
        return -1;
    }
    return descriptors[0];
}

typedef struct stderr_capture {
    int saved_fd;
    int read_fd;
} stderr_capture;

static bool stderr_capture_begin(stderr_capture *capture)
{
    int descriptors[2] = {-1, -1};
    if (capture == NULL) {
        return false;
    }
    capture->saved_fd = -1;
    capture->read_fd = -1;
    if (pipe(descriptors) != 0) {
        return false;
    }
    (void)fflush(stderr);
    capture->saved_fd = dup(STDERR_FILENO);
    capture->read_fd = descriptors[0];
    if (capture->saved_fd < 0 ||
        dup2(descriptors[1], STDERR_FILENO) < 0) {
        if (capture->saved_fd >= 0) {
            (void)close(capture->saved_fd);
        }
        (void)close(descriptors[0]);
        (void)close(descriptors[1]);
        return false;
    }
    (void)close(descriptors[1]);
    return true;
}

static bool stderr_capture_end(stderr_capture *capture,
                               char *output, size_t output_capacity)
{
    if (capture == NULL || output == NULL || output_capacity == 0u) {
        return false;
    }
    (void)fflush(stderr);
    const bool restored =
        dup2(capture->saved_fd, STDERR_FILENO) >= 0;
    (void)close(capture->saved_fd);
    size_t used = 0u;
    while (used + 1u < output_capacity) {
        const ssize_t got = read(capture->read_fd, output + used,
                                 output_capacity - used - 1u);
        if (got > 0) {
            used += (size_t)got;
            continue;
        }
        if (got < 0 && errno == EINTR) {
            continue;
        }
        break;
    }
    (void)close(capture->read_fd);
    output[used] = '\0';
    return restored;
}

static int run_null(const char *cert_policy, int password_fd,
                    uint16_t port, uint32_t width, uint32_t height,
                    uint64_t timeout, bool view_only, bool clipboard_on)
{
    return farsee_run_rdp_with_facade_ops(
        "rdp.example", port, "operator", "domain", cert_policy,
        password_fd, width, height, "null", timeout, view_only,
        clipboard_on, RDP_LIBLOG_OFF, NULL, &fake_ops);
}

typedef struct stdout_sink {
    int saved_fd;
} stdout_sink;

static bool stdout_sink_begin(stdout_sink *sink)
{
    if (sink == NULL) {
        return false;
    }
    sink->saved_fd = -1;
    if (fflush(stdout) != 0) {
        return false;
    }
    const int null_fd = open("/dev/null", O_WRONLY);
    if (null_fd < 0) {
        return false;
    }
    sink->saved_fd = dup(STDOUT_FILENO);
    if (sink->saved_fd < 0 || dup2(null_fd, STDOUT_FILENO) < 0) {
        if (sink->saved_fd >= 0) {
            (void)close(sink->saved_fd);
            sink->saved_fd = -1;
        }
        (void)close(null_fd);
        return false;
    }
    (void)close(null_fd);
    return true;
}

static bool stdout_sink_end(stdout_sink *sink)
{
    if (sink == NULL || sink->saved_fd < 0) {
        return false;
    }
    const bool flushed = fflush(stdout) == 0;
    const bool restored = dup2(sink->saved_fd, STDOUT_FILENO) >= 0;
    (void)close(sink->saved_fd);
    sink->saved_fd = -1;
    return flushed && restored;
}

static int run_kitty(const char *cert_policy, int password_fd)
{
    return farsee_run_rdp_with_facade_ops(
        "rdp.example", 3389u, "operator", "domain", cert_policy,
        password_fd, 800u, 600u, "kitty-direct", 100u, true, false,
        RDP_LIBLOG_OFF, NULL, &fake_ops);
}

static int run_kitty_with_stdout_sink(const char *cert_policy,
                                      int password_fd)
{
    stdout_sink sink;
    if (!stdout_sink_begin(&sink)) {
        (void)close(password_fd);
        RFB_FAIL("cannot redirect stdout");
        return INT_MIN;
    }
    const int result = run_kitty(cert_policy, password_fd);
    RFB_CHECK(stdout_sink_end(&sink));
    return result;
}

static void check_password_fd_closed(int fd)
{
    errno = 0;
    RFB_CHECK_EQ_INT(fcntl(fd, F_GETFD), -1);
    RFB_CHECK_EQ_INT(errno, EBADF);
}

static void check_full_teardown(void)
{
    RFB_CHECK_EQ_UINT(fake.clear_credentials_calls, 1u);
    RFB_CHECK_EQ_UINT(fake.run_calls, 1u);
    RFB_CHECK_EQ_UINT(fake.request_stop_calls, 1u);
    RFB_CHECK_EQ_UINT(fake.disconnect_calls, 1u);
    RFB_CHECK_EQ_UINT(fake.destroy_calls, 1u);
}

static void check_incomplete_facade(const rdp_live_facade_ops *ops)
{
    fake_reset();
    const int fd = password_pipe();
    RFB_CHECK(fd >= 0);
    RFB_CHECK_EQ_INT(farsee_run_rdp_with_facade_ops(
                         "rdp.example", 3389u, "operator", NULL, NULL, fd,
                         800u, 600u, "null", 100u, true, false,
                         RDP_LIBLOG_OFF, NULL, ops), 2);
    check_password_fd_closed(fd);
    RFB_CHECK_EQ_UINT(fake.log_calls, 0u);
    RFB_CHECK_EQ_UINT(fake.create_calls, 0u);
}

RFB_TEST(rdp_live_orchestration,
         null_frame__normalizes_configuration_and_tears_down)
{
    fake_reset();
    fake.got_frame = true;
    fake.frame_count = 1u;
    fake.frame_width = 1280u;
    fake.frame_height = 800u;
    const int fd = password_pipe();
    RFB_CHECK(fd >= 0);

    RFB_CHECK_EQ_INT(run_null("ignore", fd, 0u, 0u, 0u, UINT64_MAX,
                              true, true), 0);
    check_password_fd_closed(fd);
    RFB_CHECK_EQ_UINT(fake.create_calls, 1u);
    RFB_CHECK_EQ_UINT(fake.set_presenter_calls, 1u);
    RFB_CHECK_EQ_UINT(fake.apply_calls, 1u);
    RFB_CHECK_EQ_UINT(fake.connect_calls, 1u);
    RFB_CHECK_EQ_UINT(fake.settings.port, 3389u);
    RFB_CHECK_EQ_UINT(fake.settings.desktop_width, 1280u);
    RFB_CHECK_EQ_UINT(fake.settings.desktop_height, 800u);
    RFB_CHECK_EQ_UINT(fake.settings.connect_timeout_ms, UINT32_MAX);
    RFB_CHECK(!fake.settings.channels.clipboard_text);
    RFB_CHECK(fake.policy.allow_insecure_cert);
    RFB_CHECK(!fake.policy.tofu_pin_store);
    RFB_CHECK_EQ_INT(fake.trust, FARSEE_TRUST_DECISION_APPROVE_ONCE);
    RFB_CHECK_EQ_UINT(fake.password_length, 6u);
    RFB_CHECK(fake.budget.stop_on_first_frame);
    RFB_CHECK_EQ_UINT(fake.budget.settle_ms_after_first, 4000u);
    RFB_CHECK_EQ_UINT(fake.budget.deadline_monotonic_ms, UINT64_MAX);
    RFB_CHECK(fake.budget.stop_flag != NULL);
    check_full_teardown();
}

RFB_TEST(rdp_live_orchestration,
         settings_failure__destroys_context_without_connecting)
{
    fake_reset();
    fake.apply_ok = false;
    const int fd = password_pipe();
    RFB_CHECK(fd >= 0);

    RFB_CHECK_EQ_INT(run_null("pin", fd, 3390u, 640u, 480u, 25u,
                              false, true), 3);
    check_password_fd_closed(fd);
    RFB_CHECK_EQ_UINT(fake.settings.port, 3390u);
    RFB_CHECK_EQ_UINT(fake.settings.desktop_width, 640u);
    RFB_CHECK_EQ_UINT(fake.settings.desktop_height, 480u);
    RFB_CHECK_EQ_UINT(fake.settings.connect_timeout_ms, 25u);
    RFB_CHECK(fake.settings.channels.clipboard_text);
    RFB_CHECK(!fake.policy.allow_insecure_cert);
    RFB_CHECK(fake.policy.tofu_pin_store);
    RFB_CHECK_EQ_INT(fake.trust, FARSEE_TRUST_DECISION_REJECT);
    RFB_CHECK_EQ_UINT(fake.connect_calls, 0u);
    RFB_CHECK_EQ_UINT(fake.clear_credentials_calls, 0u);
    RFB_CHECK_EQ_UINT(fake.run_calls, 0u);
    RFB_CHECK_EQ_UINT(fake.destroy_calls, 1u);
}

RFB_TEST(rdp_live_orchestration,
         connect_failure__destroys_context_without_running)
{
    fake_reset();
    fake.connect_ok = false;
    fake.last_error_name = "ERRCONNECT_CONNECT_FAILED";
    const int fd = password_pipe();
    RFB_CHECK(fd >= 0);

    RFB_CHECK_EQ_INT(run_null(NULL, fd, 3389u, 800u, 600u, 100u,
                              true, false), 4);
    check_password_fd_closed(fd);
    RFB_CHECK_EQ_UINT(fake.apply_calls, 1u);
    RFB_CHECK_EQ_UINT(fake.connect_calls, 1u);
    RFB_CHECK_EQ_UINT(fake.clear_credentials_calls, 0u);
    RFB_CHECK_EQ_UINT(fake.run_calls, 0u);
    RFB_CHECK_EQ_UINT(fake.last_error_calls, 1u);
    RFB_CHECK_EQ_UINT(fake.destroy_calls, 1u);
}

static void check_signal_scope_covers_destroy(bool connect_ok)
{
    struct sigaction prior;
    struct sigaction previous;
    memset(&prior, 0, sizeof prior);
    memset(&previous, 0, sizeof previous);
    prior.sa_handler = prior_sigterm_handler;
    sigemptyset(&prior.sa_mask);
    RFB_CHECK(sigaction(SIGTERM, &prior, &previous) == 0);

    fake_reset();
    fake.connect_ok = connect_ok;
    fake.signal_during_destroy = true;
    fake.got_frame = connect_ok;
    fake.frame_count = connect_ok ? 1u : 0u;
    prior_sigterm_seen = 0;
    const int fd = password_pipe();
    RFB_CHECK(fd >= 0);
    if (fd >= 0) {
        const int result = run_null(
            NULL, fd, 3389u, 800u, 600u, 100u, true, false);
        RFB_CHECK_EQ_INT(result, connect_ok ? 0 : 4);
        check_password_fd_closed(fd);
    }

    // The live scope must still own SIGTERM while the facade is destroyed.
    RFB_CHECK_EQ_INT(prior_sigterm_seen, 0);
    RFB_CHECK_EQ_UINT(fake.destroy_calls, 1u);

    // The caller's disposition must be back in force after teardown returns.
    RFB_CHECK(raise(SIGTERM) == 0);
    RFB_CHECK_EQ_INT(prior_sigterm_seen, SIGTERM);
    RFB_CHECK(sigaction(SIGTERM, &previous, NULL) == 0);
}

RFB_TEST(rdp_live_orchestration,
         successful_session__signal_scope_covers_context_destroy)
{
    check_signal_scope_covers_destroy(true);
}

RFB_TEST(rdp_live_orchestration,
         connect_failure__signal_scope_covers_context_destroy)
{
    check_signal_scope_covers_destroy(false);
}

RFB_TEST(rdp_live_orchestration,
         cancelled_connect__is_a_clean_requested_stop)
{
    fake_reset();
    fake.stop_during_connect = true;
    fake.connect_ok = false;
    const int fd = password_pipe();
    RFB_CHECK(fd >= 0);

    RFB_CHECK_EQ_INT(run_null(NULL, fd, 3389u, 800u, 600u, 100u,
                              true, false), 0);
    check_password_fd_closed(fd);
    RFB_CHECK_EQ_UINT(fake.connect_calls, 1u);
    RFB_CHECK_EQ_UINT(fake.clear_credentials_calls, 0u);
    RFB_CHECK_EQ_UINT(fake.run_calls, 0u);
    RFB_CHECK_EQ_UINT(fake.last_error_calls, 0u);
    RFB_CHECK_EQ_UINT(fake.destroy_calls, 1u);
}

RFB_TEST(rdp_live_orchestration,
         create_failure__closes_presenter_and_password)
{
    fake_reset();
    fake.create_ok = false;
    const int fd = password_pipe();
    RFB_CHECK(fd >= 0);

    RFB_CHECK_EQ_INT(run_null(NULL, fd, 3389u, 800u, 600u, 100u,
                              true, false), 3);
    check_password_fd_closed(fd);
    RFB_CHECK_EQ_UINT(fake.create_calls, 1u);
    RFB_CHECK_EQ_UINT(fake.set_presenter_calls, 0u);
    RFB_CHECK_EQ_UINT(fake.apply_calls, 0u);
    RFB_CHECK_EQ_UINT(fake.destroy_calls, 0u);
}

RFB_TEST(rdp_live_orchestration,
         live_create_failure__disposes_kitty_before_mt_state_exists)
{
    fake_reset();
    fake.create_ok = false;
    const int fd = password_pipe();
    RFB_CHECK(fd >= 0);
    if (fd < 0) {
        return;
    }

    const int result = run_kitty_with_stdout_sink(NULL, fd);
    RFB_CHECK_EQ_INT(result, 3);
    check_password_fd_closed(fd);
    RFB_CHECK_EQ_UINT(fake.create_calls, 1u);
    RFB_CHECK_EQ_UINT(fake.set_presenter_calls, 0u);
    RFB_CHECK_EQ_UINT(fake.destroy_calls, 0u);
}

RFB_TEST(rdp_live_orchestration,
         live_settings_failure__releases_mt_owners_before_context)
{
    fake_reset();
    fake.apply_ok = false;
    const int fd = password_pipe();
    RFB_CHECK(fd >= 0);
    if (fd < 0) {
        return;
    }

    const int result = run_kitty_with_stdout_sink("pin", fd);
    RFB_CHECK_EQ_INT(result, 3);
    check_password_fd_closed(fd);
    RFB_CHECK_EQ_UINT(fake.set_presenter_calls, 1u);
    RFB_CHECK(fake.presenter_had_frame_slot);
    RFB_CHECK_EQ_UINT(fake.apply_calls, 1u);
    RFB_CHECK_EQ_UINT(fake.connect_calls, 0u);
    RFB_CHECK_EQ_UINT(fake.destroy_calls, 1u);
}

RFB_TEST(rdp_live_orchestration,
         live_connect_failure__releases_mt_owners_and_context)
{
    fake_reset();
    fake.connect_ok = false;
    fake.last_error_name = "ERRCONNECT_CONNECT_FAILED";
    const int fd = password_pipe();
    RFB_CHECK(fd >= 0);
    if (fd < 0) {
        return;
    }

    const int result = run_kitty_with_stdout_sink(NULL, fd);
    RFB_CHECK_EQ_INT(result, 4);
    check_password_fd_closed(fd);
    RFB_CHECK(fake.presenter_had_frame_slot);
    RFB_CHECK_EQ_UINT(fake.apply_calls, 1u);
    RFB_CHECK_EQ_UINT(fake.connect_calls, 1u);
    RFB_CHECK_EQ_UINT(fake.clear_credentials_calls, 0u);
    RFB_CHECK_EQ_UINT(fake.run_calls, 0u);
    RFB_CHECK_EQ_UINT(fake.last_error_calls, 1u);
    RFB_CHECK_EQ_UINT(fake.destroy_calls, 1u);
}

RFB_TEST(rdp_live_orchestration,
         timeout_without_frame__returns_session_failure)
{
    fake_reset();
    fake.run_error = farsee_error_make(
        FARSEE_ERR_TIMEOUT, FARSEE_SUB_RDP, FARSEE_PHASE_ACTIVE);
    const int fd = password_pipe();
    RFB_CHECK(fd >= 0);

    RFB_CHECK_EQ_INT(run_null(NULL, fd, 3389u, 800u, 600u, 100u,
                              true, false), 5);
    check_password_fd_closed(fd);
    check_full_teardown();
}

RFB_TEST(rdp_live_orchestration,
         backend_failure_without_frame__uses_backend_diagnostic)
{
    fake_reset();
    fake.run_error = farsee_error_make(
        FARSEE_ERR_CONNECT_FAILURE, FARSEE_SUB_RDP, FARSEE_PHASE_ACTIVE);
    fake.last_error_name = "ERRCONNECT_TRANSPORT_FAILED";
    const int fd = password_pipe();
    RFB_CHECK(fd >= 0);
    stderr_capture capture;
    if (!stderr_capture_begin(&capture)) {
        (void)close(fd);
        RFB_FAIL("cannot capture stderr");
        return;
    }

    RFB_CHECK_EQ_INT(run_null(NULL, fd, 3389u, 800u, 600u, 100u,
                              true, false), 5);
    char output[512];
    RFB_CHECK(stderr_capture_end(&capture, output, sizeof output));
    RFB_CHECK(strstr(output, "ERRCONNECT_TRANSPORT_FAILED") != NULL);
    check_password_fd_closed(fd);
    RFB_CHECK_EQ_UINT(fake.last_error_calls, 1u);
    check_full_teardown();
}

RFB_TEST(rdp_live_orchestration,
         cooperative_stop__ends_bounded_null_session_cleanly)
{
    fake_reset();
    fake.stop_during_connect = true;
    const int fd = password_pipe();
    RFB_CHECK(fd >= 0);

    RFB_CHECK_EQ_INT(run_null(NULL, fd, 3389u, 800u, 600u, 100u,
                              true, false), 0);
    check_password_fd_closed(fd);
    check_full_teardown();
}

RFB_TEST(rdp_live_orchestration,
         empty_password__fails_before_allocating_session_state)
{
    fake_reset();
    const int fd = empty_pipe();
    RFB_CHECK(fd >= 0);

    RFB_CHECK_EQ_INT(run_null(NULL, fd, 3389u, 800u, 600u, 100u,
                              true, false), 2);
    check_password_fd_closed(fd);
    RFB_CHECK_EQ_UINT(fake.create_calls, 0u);
    RFB_CHECK_EQ_UINT(fake.apply_calls, 0u);
}

RFB_TEST(rdp_live_orchestration,
         unavailable_and_invalid_log_levels__close_password_before_read)
{
    fake_reset();
    fake.log_ok = false;
    int fd = password_pipe();
    RFB_CHECK(fd >= 0);
    RFB_CHECK_EQ_INT(farsee_run_rdp_with_facade_ops(
                         "rdp.example", 3389u, "operator", NULL, NULL, fd,
                         800u, 600u, "null", 100u, true, false,
                         RDP_LIBLOG_INFO, NULL, &fake_ops), 2);
    check_password_fd_closed(fd);

    fd = password_pipe();
    RFB_CHECK(fd >= 0);
    RFB_CHECK_EQ_INT(farsee_run_rdp_with_facade_ops(
                         "rdp.example", 3389u, "operator", NULL, NULL, fd,
                         800u, 600u, "null", 100u, true, false,
                         (rdp_liblog_level)999, NULL, &fake_ops), 2);
    check_password_fd_closed(fd);
    RFB_CHECK_EQ_UINT(fake.create_calls, 0u);
}

RFB_TEST(rdp_live_orchestration,
         partial_facade__fails_closed_before_first_callback)
{
    fake_reset();
    fake.log_ok = false;
    rdp_live_facade_ops incomplete;
    memset(&incomplete, 0, sizeof incomplete);
    incomplete.set_library_log_level = fake_set_log_level;
    const int fd = password_pipe();
    RFB_CHECK(fd >= 0);

    RFB_CHECK_EQ_INT(farsee_run_rdp_with_facade_ops(
                         "rdp.example", 3389u, "operator", NULL, NULL, fd,
                         800u, 600u, "null", 100u, true, false,
                         RDP_LIBLOG_OFF, NULL, &incomplete), 2);
    check_password_fd_closed(fd);
    RFB_CHECK_EQ_UINT(fake.log_calls, 0u);
    RFB_CHECK_EQ_UINT(fake.create_calls, 0u);
}

RFB_TEST(rdp_live_orchestration,
         each_missing_facade_operation__fails_before_first_callback)
{
    rdp_live_facade_ops ops = fake_ops;
    ops.set_library_log_level = NULL;
    check_incomplete_facade(&ops);
    ops = fake_ops;
    ops.create = NULL;
    check_incomplete_facade(&ops);
    ops = fake_ops;
    ops.destroy = NULL;
    check_incomplete_facade(&ops);
    ops = fake_ops;
    ops.set_presenter = NULL;
    check_incomplete_facade(&ops);
    ops = fake_ops;
    ops.apply_settings_with_memory_budget = NULL;
    check_incomplete_facade(&ops);
    ops = fake_ops;
    ops.connect_with_stop = NULL;
    check_incomplete_facade(&ops);
    ops = fake_ops;
    ops.clear_credentials = NULL;
    check_incomplete_facade(&ops);
    ops = fake_ops;
    ops.run_until = NULL;
    check_incomplete_facade(&ops);
    ops = fake_ops;
    ops.request_stop = NULL;
    check_incomplete_facade(&ops);
    ops = fake_ops;
    ops.disconnect = NULL;
    check_incomplete_facade(&ops);
    ops = fake_ops;
    ops.last_error_name = NULL;
    check_incomplete_facade(&ops);
    ops = fake_ops;
    ops.is_clean_peer_disconnect = NULL;
    check_incomplete_facade(&ops);
}

RFB_TEST(rdp_live_orchestration,
         invalid_endpoint_and_password_fd__fail_before_session_allocation)
{
    fake_reset();
    int fd = password_pipe();
    RFB_CHECK(fd >= 0);
    RFB_CHECK_EQ_INT(farsee_run_rdp_with_facade_ops(
                         "rdp.example", 3389u, NULL, NULL, NULL, fd,
                         800u, 600u, "null", 100u, true, false,
                         RDP_LIBLOG_OFF, NULL, &fake_ops), 2);
    check_password_fd_closed(fd);
    RFB_CHECK_EQ_UINT(fake.create_calls, 0u);

    fake_reset();
    fd = password_pipe();
    RFB_CHECK(fd >= 0);
    RFB_CHECK_EQ_INT(farsee_run_rdp_with_facade_ops(
                         NULL, 3389u, "operator", NULL, NULL, fd,
                         800u, 600u, "null", 100u, true, false,
                         RDP_LIBLOG_OFF, NULL, &fake_ops), 2);
    check_password_fd_closed(fd);
    RFB_CHECK_EQ_UINT(fake.create_calls, 0u);

    fake_reset();
    int descriptors[2] = {-1, -1};
    RFB_CHECK(pipe(descriptors) == 0);
    if (descriptors[0] >= 0) {
        fd = descriptors[0];
        (void)close(descriptors[0]);
        (void)close(descriptors[1]);
        RFB_CHECK_EQ_INT(farsee_run_rdp_with_facade_ops(
                             "rdp.example", 3389u, "operator", NULL, NULL,
                             fd, 800u, 600u, "null", 100u, true, false,
                             RDP_LIBLOG_OFF, NULL, &fake_ops), 2);
        check_password_fd_closed(fd);
        RFB_CHECK_EQ_UINT(fake.create_calls, 0u);
    }
}

RFB_TEST(rdp_live_orchestration,
         default_timeout_and_info_log__complete_null_session)
{
    fake_reset();
    fake.got_frame = true;
    fake.frame_count = 1u;
    fake.frame_width = 800u;
    fake.frame_height = 600u;
    const int fd = password_pipe();
    RFB_CHECK(fd >= 0);
    RFB_CHECK_EQ_INT(farsee_run_rdp_with_facade_ops(
                         "rdp.example", 3389u, "operator", NULL, NULL, fd,
                         800u, 600u, "null", 0u, true, false,
                         RDP_LIBLOG_INFO, NULL, &fake_ops), 0);
    check_password_fd_closed(fd);
    RFB_CHECK_EQ_UINT(fake.settings.connect_timeout_ms, 30000u);
    check_full_teardown();
}

RFB_TEST(rdp_live_orchestration,
         non_view_only_null_session__releases_local_input_state)
{
    fake_reset();
    fake.use_real_context = true;
    fake.got_frame = true;
    fake.frame_count = 1u;
    fake.frame_width = 800u;
    fake.frame_height = 600u;
    const int fd = password_pipe();
    RFB_CHECK(fd >= 0);

    RFB_CHECK_EQ_INT(run_null(NULL, fd, 3389u, 800u, 600u, 100u,
                              false, true), 0);
    check_password_fd_closed(fd);
    RFB_CHECK(fake.settings.channels.clipboard_text);
    RFB_CHECK(fake.active_context == NULL);
    check_full_teardown();
}

RFB_TEST(rdp_live_orchestration,
         oversized_home__omits_truncated_pin_path_and_keeps_strict_policy)
{
    const char *old_home = getenv("HOME");
    const bool had_home = old_home != NULL;
    char *saved_home = NULL;
    if (had_home) {
        const size_t saved_length = strlen(old_home) + 1u;
        saved_home = malloc(saved_length);
        if (saved_home == NULL) {
            RFB_FAIL("cannot save HOME");
            return;
        }
        memcpy(saved_home, old_home, saved_length);
    }
    char oversized_home[600];
    memset(oversized_home, 'h', sizeof oversized_home);
    oversized_home[sizeof oversized_home - 1u] = '\0';
    if (setenv("HOME", oversized_home, 1) != 0) {
        free(saved_home);
        RFB_FAIL("cannot set oversized HOME");
        return;
    }

    fake_reset();
    fake.got_frame = true;
    const int fd = password_pipe();
    int result = 2;
    if (fd >= 0) {
        result = run_null("strict", fd, 3389u, 800u, 600u, 100u,
                          true, false);
    }

    const int restore_result = had_home ? setenv("HOME", saved_home, 1)
                                        : unsetenv("HOME");
    free(saved_home);
    RFB_CHECK_EQ_INT(restore_result, 0);
    RFB_CHECK(fd >= 0);
    if (fd < 0) {
        return;
    }
    RFB_CHECK_EQ_INT(result, 0);
    check_password_fd_closed(fd);
    RFB_CHECK(!fake.known_hosts_set);
    RFB_CHECK(!fake.policy.allow_insecure_cert);
    RFB_CHECK(!fake.policy.tofu_pin_store);
    RFB_CHECK_EQ_INT(fake.trust, FARSEE_TRUST_DECISION_REJECT);
    check_full_teardown();
}

RFB_TEST(rdp_live_orchestration,
         absent_and_empty_home__omit_known_hosts_path)
{
    const char *old_home = getenv("HOME");
    const bool had_home = old_home != NULL;
    char *saved_home = NULL;
    if (had_home) {
        const size_t saved_length = strlen(old_home) + 1u;
        saved_home = malloc(saved_length);
        if (saved_home == NULL) {
            RFB_FAIL("cannot save HOME");
            return;
        }
        memcpy(saved_home, old_home, saved_length);
    }
    if (unsetenv("HOME") != 0) {
        free(saved_home);
        RFB_FAIL("cannot unset HOME");
        return;
    }

    fake_reset();
    fake.got_frame = true;
    int fd = password_pipe();
    int absent_result = 2;
    if (fd >= 0) {
        absent_result = run_null("pin", fd, 3389u, 800u, 600u, 100u,
                                 true, false);
    }
    RFB_CHECK(fd >= 0);
    if (fd >= 0) {
        RFB_CHECK_EQ_INT(absent_result, 0);
        check_password_fd_closed(fd);
        RFB_CHECK(!fake.known_hosts_set);
        check_full_teardown();
    }

    const int empty_set_result = setenv("HOME", "", 1);
    fake_reset();
    fake.got_frame = true;
    fd = empty_set_result == 0 ? password_pipe() : -1;
    int empty_result = 2;
    if (fd >= 0) {
        empty_result = run_null("pin", fd, 3389u, 800u, 600u, 100u,
                                true, false);
    }

    const int restore_result = had_home ? setenv("HOME", saved_home, 1)
                                        : unsetenv("HOME");
    free(saved_home);
    RFB_CHECK_EQ_INT(empty_set_result, 0);
    RFB_CHECK(fd >= 0);
    if (fd >= 0) {
        RFB_CHECK_EQ_INT(empty_result, 0);
        check_password_fd_closed(fd);
        RFB_CHECK(!fake.known_hosts_set);
        check_full_teardown();
    }
    RFB_CHECK_EQ_INT(restore_result, 0);
}

RFB_TEST(rdp_live_orchestration,
         default_facade__rejects_missing_user_before_endpoint_work)
{
    fake_reset();
    const int fd = password_pipe();
    RFB_CHECK(fd >= 0);
    RFB_CHECK_EQ_INT(farsee_run_rdp_with_facade_ops(
                         "rdp.example", 3389u, NULL, NULL, NULL, fd,
                         800u, 600u, "null", 100u, true, false,
                         RDP_LIBLOG_OFF, NULL, NULL), 2);
    check_password_fd_closed(fd);
    RFB_CHECK_EQ_UINT(fake.create_calls, 0u);
}

RFB_TEST(rdp_live_orchestration,
         deadline_after__normal_and_both_overflows_saturate)
{
    RFB_CHECK_EQ_UINT(rdp_live_deadline_after(100u, 20u, 5u), 125u);
    RFB_CHECK_EQ_UINT(rdp_live_deadline_after(UINT64_MAX - 5u, 10u, 0u),
                      UINT64_MAX);
    RFB_CHECK_EQ_UINT(rdp_live_deadline_after(
                          10u, UINT64_MAX - 15u, 10u), UINT64_MAX);
}

RFB_TEST(rdp_live_orchestration,
         log__oversized_message_is_bounded_and_null_terminated)
{
    char input[700];
    memset(input, 'x', sizeof input);
    input[sizeof input - 1u] = '\0';
    stderr_capture capture;
    RFB_CHECK(stderr_capture_begin(&capture));
    if (capture.saved_fd < 0) {
        return;
    }
    rdp_live_log(NULL, "%s", input);
    char output[700];
    RFB_CHECK(stderr_capture_end(&capture, output, sizeof output));
    RFB_CHECK_EQ_UINT(strlen(output), 511u);
    for (size_t i = 0u; i < strlen(output); i++) {
        RFB_CHECK(output[i] == 'x');
    }
}

static void check_clean_peer_message(const char *error_name,
                                     const char *expected_message)
{
    fake_reset();
    fake.clean_peer = true;
    fake.frame_count = 2u;
    fake.frame_width = 1024u;
    fake.frame_height = 768u;
    fake.last_error_name = error_name;
    const int fd = password_pipe();
    RFB_CHECK(fd >= 0);
    stderr_capture capture;
    if (!stderr_capture_begin(&capture)) {
        (void)close(fd);
        RFB_FAIL("cannot capture stderr");
        return;
    }
    RFB_CHECK_EQ_INT(run_null(NULL, fd, 3389u, 1024u, 768u, 100u,
                              true, false), 0);
    char output[2048];
    RFB_CHECK(stderr_capture_end(&capture, output, sizeof output));
    RFB_CHECK(strstr(output, expected_message) != NULL);
    check_password_fd_closed(fd);
    RFB_CHECK_EQ_UINT(fake.last_error_calls, 1u);
    check_full_teardown();
}

RFB_TEST(rdp_live_orchestration,
         clean_peer_disconnects__classify_common_server_reasons)
{
    check_clean_peer_message("ERRINFO_LOGOFF_BY_USER",
                             "Windows signed this session out");
    check_clean_peer_message("ERRINFO_DISCONNECTED_BY_OTHERCONNECTION",
                             "another connection took over");
    check_clean_peer_message("ERRINFO_IDLE_TIMEOUT", "server idle-timeout");
    check_clean_peer_message("ERRINFO_UNKNOWN_SERVER_END",
                             "peer disconnect");
}

RFB_TEST(rdp_live_orchestration,
         clean_peer_disconnect__accepts_first_frame_without_counter)
{
    fake_reset();
    fake.clean_peer = true;
    fake.got_frame = true;
    fake.frame_count = 0u;
    fake.frame_width = 640u;
    fake.frame_height = 480u;
    fake.last_error_name = "ERRINFO_UNKNOWN_SERVER_END";
    const int fd = password_pipe();
    RFB_CHECK(fd >= 0);

    RFB_CHECK_EQ_INT(run_null(NULL, fd, 3389u, 640u, 480u, 100u,
                              true, false), 0);
    check_password_fd_closed(fd);
    RFB_CHECK_EQ_UINT(fake.last_error_calls, 1u);
    check_full_teardown();
}

RFB_TEST(rdp_live_orchestration,
         clean_peer_disconnect__without_any_frame_is_a_failure)
{
    fake_reset();
    fake.clean_peer = true;
    fake.last_error_name = "ERRINFO_SERVER_END_WITHOUT_FRAME";
    const int fd = password_pipe();
    RFB_CHECK(fd >= 0);

    RFB_CHECK_EQ_INT(run_null(NULL, fd, 3389u, 640u, 480u, 100u,
                              true, false), 5);
    check_password_fd_closed(fd);
    RFB_CHECK_EQ_UINT(fake.last_error_calls, 1u);
    check_full_teardown();
}

#endif  // FARSEE_WITH_RDP
