// SPDX-License-Identifier: Apache-2.0
//
// Poller HUP/ERR mapping contracts. Dead peers report RFB_POLL_HUP and
// POLLNVAL reports RFB_POLL_ERR rather than a timeout.

#include "farsee/poller.h"
#include "tests/test_framework/rfb_test.h"

#include <unistd.h>

RFB_TEST(poller_error_events, poller__closed_peer_pipe__surfaces_hup_bit)
{
    int p[2];
    RFB_CHECK(pipe(p) == 0);
    RFB_CHECK(close(p[1]) == 0);  // peer gone; read end must HUP

    rfb_poll_fd f;
    f.fd = p[0];
    f.events = RFB_POLL_READ;
    f.revents = RFB_POLL_NONE;
    int ready = rfb_poll_wait(&f, 1, 200);
    RFB_CHECK_EQ_INT(ready, 1);
    RFB_CHECK_MSG(f.revents & RFB_POLL_HUP,
                  "closed peer did not report RFB_POLL_HUP");
    (void)close(p[0]);
}

RFB_TEST(poller_error_events, poller__closed_peer_with_pending_data__read_and_hup)
{
    int p[2];
    RFB_CHECK(pipe(p) == 0);
    char b = 'x';
    RFB_CHECK(write(p[1], &b, 1) == 1);
    RFB_CHECK(close(p[1]) == 0);

    rfb_poll_fd f;
    f.fd = p[0];
    f.events = RFB_POLL_READ;
    f.revents = RFB_POLL_NONE;
    int ready = rfb_poll_wait(&f, 1, 200);
    RFB_CHECK_EQ_INT(ready, 1);
    RFB_CHECK_MSG(f.revents & RFB_POLL_READ,
                  "pending bytes before HUP must still report READ");
    RFB_CHECK_MSG(f.revents & RFB_POLL_HUP,
                  "closed peer did not report RFB_POLL_HUP");
    (void)close(p[0]);
}

RFB_TEST(poller_error_events, poller__invalid_fd__surfaces_error_bit)
{
    // A closed (but positive) fd number: poll reports POLLNVAL. Some
    // platforms (Darwin) ignore negative fds instead of flagging them,
    // so use a real closed descriptor.
    int p[2];
    RFB_CHECK(pipe(p) == 0);
    int dead = p[0];
    RFB_CHECK(close(p[0]) == 0);
    RFB_CHECK(close(p[1]) == 0);

    rfb_poll_fd f;
    f.fd = dead;
    f.events = RFB_POLL_READ;
    f.revents = RFB_POLL_NONE;
    int ready = rfb_poll_wait(&f, 1, 200);
    RFB_CHECK_EQ_INT(ready, 1);
    RFB_CHECK_MSG(f.revents & RFB_POLL_ERR,
                  "POLLNVAL did not surface as RFB_POLL_ERR");
}

RFB_TEST(poller_error_events, poller__read_ready__still_counts_ready)
{
    int p[2];
    RFB_CHECK(pipe(p) == 0);
    char b = 'x';
    RFB_CHECK(write(p[1], &b, 1) == 1);

    rfb_poll_fd f;
    f.fd = p[0];
    f.events = RFB_POLL_READ;
    f.revents = RFB_POLL_NONE;
    int ready = rfb_poll_wait(&f, 1, 200);
    RFB_CHECK_EQ_INT(ready, 1);
    RFB_CHECK(f.revents & RFB_POLL_READ);
    RFB_CHECK((f.revents & RFB_POLL_HUP) == 0);
    (void)close(p[0]);
    (void)close(p[1]);
}
