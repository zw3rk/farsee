// SPDX-License-Identifier: Apache-2.0
//
// Tests for the POSIX terminal raw-mode lifecycle (plan.md §G7, §G10).

#include "rfb_test.h"
#include "farsee/tty_posix.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>

#if defined(__APPLE__)
#  include <util.h>
#elif defined(__linux__)
#  include <pty.h>
#endif

// Verify that enter_raw_mode actually changes terminal attributes.
RFB_TEST(tty, tty__enter_raw_mode__disables_echo_and_canonical) {
    int master, slave;
    if (openpty(&master, &slave, NULL, NULL, NULL) != 0) {
        RFB_CHECK(false);
        return;
    }
    rfb_tty t;
    rfb_tty_init(&t, slave);
    RFB_CHECK(rfb_tty_enter_raw_mode(&t));

    struct termios check;
    tcgetattr(slave, &check);
    RFB_CHECK(!(check.c_lflag & ECHO));
    RFB_CHECK(!(check.c_lflag & ICANON));
    RFB_CHECK(!(check.c_lflag & ISIG));

    rfb_tty_restore(&t);
    // After restore, echo should be back (default ON for a fresh PTY).
    tcgetattr(slave, &check);
    RFB_CHECK(check.c_lflag & ECHO);
    rfb_tty_destroy(&t);
    close(master);
    close(slave);
}

// Verify restore is idempotent.
RFB_TEST(tty, tty__restore_idempotent) {
    int master, slave;
    if (openpty(&master, &slave, NULL, NULL, NULL) != 0) {
        RFB_CHECK(false);
        return;
    }
    rfb_tty t;
    rfb_tty_init(&t, slave);
    rfb_tty_enter_raw_mode(&t);
    rfb_tty_restore(&t);
    rfb_tty_restore(&t);  // must not crash
    rfb_tty_destroy(&t);
    close(master);
    close(slave);
    RFB_CHECK(true);
}

// Verify NULL safety.
RFB_TEST(tty, tty__null_safety) {
    rfb_tty_init(NULL, -1);
    rfb_tty_restore(NULL);
    rfb_tty_destroy(NULL);
    RFB_CHECK(!rfb_tty_enter_raw_mode(NULL));
    RFB_CHECK(!rfb_tty_install_signal_handlers(NULL));
    RFB_CHECK(true);
}

// Verify enter on bad fd fails.
RFB_TEST(tty, tty__bad_fd__fails) {
    rfb_tty t;
    rfb_tty_init(&t, -1);
    RFB_CHECK(!rfb_tty_enter_raw_mode(&t));
    rfb_tty_destroy(&t);
}

// farsee_tty_open_input: null args fail closed (no crash).
RFB_TEST(tty, open_input__null_args__fail_closed) {
    int fd = 99;
    bool owned = true;
    RFB_CHECK(!farsee_tty_open_input(NULL, &owned));
    RFB_CHECK(!farsee_tty_open_input(&fd, NULL));
    RFB_CHECK(!farsee_tty_open_input(NULL, NULL));
    // Untouched on failure path for non-null outs is not required; only
    // that NULL is rejected without writing through a null pointer.
}

// Labels are stable for owned vs stdin-style fds (no open required).
RFB_TEST(tty, input_label__owned_and_stdin) {
    RFB_CHECK(strcmp(farsee_tty_input_label(STDIN_FILENO, false), "stdin") ==
              0);
    RFB_CHECK(strcmp(farsee_tty_input_label(-1, false), "fd") == 0);
    // Owned with bad fd falls back to "/dev/tty" literal.
    RFB_CHECK(strcmp(farsee_tty_input_label(-1, true), "/dev/tty") == 0);
    farsee_tty_close_input(-1, false); // no-op
    farsee_tty_close_input(-1, true);  // no-op (owned but invalid)
}

// Verify signal handler installation.
RFB_TEST(tty, tty__install_signal_handlers__succeeds) {
    rfb_tty t;
    rfb_tty_init(&t, STDIN_FILENO);
    RFB_CHECK(rfb_tty_install_signal_handlers(&t));
    rfb_tty_destroy(&t);
}
