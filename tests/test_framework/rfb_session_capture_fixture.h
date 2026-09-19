// SPDX-License-Identifier: Apache-2.0

#ifndef FARSEE_TEST_RFB_SESSION_CAPTURE_FIXTURE_H
#define FARSEE_TEST_RFB_SESSION_CAPTURE_FIXTURE_H

#include "farsee/error.h"
#include "farsee/farsee_atomic.h"
#include "farsee/io_adapter.h"
#include "farsee/rfb_session.h"
#include "farsee/server_init.h"

#include <stddef.h>
#include <stdint.h>

typedef uint64_t (*rfb_session_test_clock_now_ms_fn)(void *opaque);

rfb_error rfb_session_test_activate_apple_capture(
    rfb_session *session, const rfb_session_config *config,
    const rfb_io_adapter *adapter, int poll_fd,
    farsee_atomic_u64 *transport_tx_bytes, uint16_t framebuffer_width,
    uint16_t framebuffer_height, const uint8_t c2s_key[16],
    const uint8_t c2s_iv[16], const uint8_t s2c_key[16],
    const uint8_t s2c_iv[16], uint64_t now_ms);

rfb_error rfb_session_test_apple_capture_step(rfb_session *session,
                                              uint64_t now_ms);

// Each protocol transition samples this clock independently when it records
// or validates time.
rfb_error rfb_session_test_apple_capture_step_with_clock(
    rfb_session *session, rfb_session_test_clock_now_ms_fn now_ms,
    void *clock_opaque, int poll_ms);

typedef enum rfb_session_test_modern_setup_mode {
    RFB_SESSION_TEST_MODERN_SETUP_CONTROL = 0,
    RFB_SESSION_TEST_MODERN_SETUP_PRIVATE_ENCODINGS = 1,
    RFB_SESSION_TEST_MODERN_SETUP_DEFAULT = 2
} rfb_session_test_modern_setup_mode;

// Capture the cleartext bytes delivered by the production modern
// post-ServerInit setup builder before protected records become active.
rfb_error rfb_session_test_capture_modern_setup(
    rfb_session *session, const rfb_session_config *config,
    rfb_session_test_modern_setup_mode mode, uint8_t *transport_bytes,
    size_t transport_capacity, size_t *transport_length);

#endif  // FARSEE_TEST_RFB_SESSION_CAPTURE_FIXTURE_H
