// SPDX-License-Identifier: Apache-2.0
//
// Test-only access to one-step RFB session operations.

#ifndef FARSEE_TESTS_FAKES_RFB_SESSION_TEST_ADAPTER_H
#define FARSEE_TESTS_FAKES_RFB_SESSION_TEST_ADAPTER_H

#include "farsee/error.h"
#include "farsee/rfb_session.h"

#include <stdbool.h>
#include <stdint.h>

bool rfb_session_test_attach_connected_fd(rfb_session *session, int fd);
void rfb_session_test_seed_held_key(rfb_session *session, uint32_t keysym);
void rfb_session_test_seed_held_buttons(rfb_session *session,
                                        unsigned buttons);
rfb_error rfb_session_test_drain_cmds(rfb_session *session);
rfb_error rfb_session_test_process_in(rfb_session *session, bool *progress);
rfb_error rfb_session_test_publish_frame(rfb_session *session);

#endif  // FARSEE_TESTS_FAKES_RFB_SESSION_TEST_ADAPTER_H
