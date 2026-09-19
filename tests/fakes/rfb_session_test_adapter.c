// SPDX-License-Identifier: Apache-2.0

#include "tests/fakes/rfb_session_test_adapter.h"

#include "farsee/allocator.h"
#include "farsee/buffer.h"
#include "farsee/farsee_input.h"
#include "farsee/limits.h"
#include "farsee/socket_posix.h"
#include "rfb/rfb_session_internal.h"

#include <string.h>

bool rfb_session_test_attach_connected_fd(rfb_session *session, int fd)
{
    if (session == NULL || fd < 0) {
        return false;
    }
    if (session->io_open && session->sock.fd >= 0 &&
        session->sock.fd != fd) {
        if (session->io.close != NULL) {
            session->io.close(session->io.ctx);
        }
        session->io_open = false;
    }
    if (session->alloc == NULL) {
        session->alloc = rfb_default_allocator();
    }
    if (session->in.data == NULL) {
        rfb_buffer_init(&session->in, session->alloc,
                        RFB_LIMIT_FB_BYTES_POLICY);
    }
    if (session->out.data == NULL) {
        rfb_buffer_init(&session->out, session->alloc,
                        RFB_LIMIT_OUTBOUND_BYTES);
    }
    session->io = rfb_socket_adapter_make(&session->sock);
    session->sock.fd = fd;
    session->sock.nonblocking = true;
    session->io_open = true;
    session->active = true;
    farsee_key_ledger_init(&session->key_ledger);
    session->held_buttons = 0u;
    return true;
}

void rfb_session_test_seed_held_key(rfb_session *session, uint32_t keysym)
{
    if (session == NULL || keysym == 0u) {
        return;
    }
    farsee_key_event event;
    memset(&event, 0, sizeof event);
    event.physical = keysym;
    event.logical = keysym;
    event.action = FARSEE_KEY_PRESS;
    (void)farsee_key_ledger_apply(&session->key_ledger, &event);
}

void rfb_session_test_seed_held_buttons(rfb_session *session,
                                        unsigned buttons)
{
    if (session != NULL) {
        session->held_buttons = buttons;
    }
}

rfb_error rfb_session_test_drain_cmds(rfb_session *session)
{
    if (session == NULL) {
        return RFB_ERR_INTERNAL;
    }
    return rfb_session_internal_drain_cmds(session);
}

rfb_error rfb_session_test_process_in(rfb_session *session, bool *progress)
{
    if (session == NULL) {
        return RFB_ERR_INTERNAL;
    }
    return rfb_session_internal_process_in(session, progress);
}

rfb_error rfb_session_test_publish_frame(rfb_session *session)
{
    if (session == NULL) {
        return RFB_ERR_INTERNAL;
    }
    return rfb_session_internal_publish_frame(session);
}
