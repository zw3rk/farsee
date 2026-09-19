// SPDX-License-Identifier: Apache-2.0
//
// Process-wide terminal and fatal-signal restoration for live sessions.

#ifndef FARSEE_SRC_APP_LIVE_SHELL_TTY_GUARD_H
#define FARSEE_SRC_APP_LIVE_SHELL_TTY_GUARD_H

#include <stdbool.h>
#include <stddef.h>
#include <termios.h>

#ifdef __cplusplus
extern "C" {
#endif

void farsee_live_shell_tty_guard_arm(int tty_fd, bool attrs_saved,
                                     const struct termios *saved,
                                     bool mouse_on, bool kitty_kb_on);
void farsee_live_shell_tty_guard_restore(void);

// Keep saved-attribute ownership in sync with cooperative restore/re-entry.
// NULL clears ownership. A foreign descriptor cannot change the guard.
void farsee_live_shell_tty_guard_update_attrs_for_fd(
    int tty_fd, const struct termios *saved);

// Save original flags once and set O_NONBLOCK on shared standard streams.
// Dedicated descriptors are made nonblocking without process-wide restore.
void farsee_live_shell_stdio_nonblock_arm(int fd);

// Open and close the one live input descriptor. Shared stdin flag ownership
// is delegated to the process guard; dedicated descriptors belong to caller.
bool farsee_live_shell_tty_open_input(int *out_fd, bool *out_owned);
void farsee_live_shell_tty_close_input(int fd, bool owned);
const char *farsee_live_shell_tty_input_label(int fd, bool owned);

// Write up to n bytes with bounded POLLOUT retries. Returns bytes written.
size_t farsee_live_shell_write_all(int fd, const char *s, size_t n);

// Write a terminal control sequence to each terminal owned by the guard.
void farsee_live_shell_tty_guard_write_seq(const char *sequence);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_SRC_APP_LIVE_SHELL_TTY_GUARD_H
