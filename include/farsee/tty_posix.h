// SPDX-License-Identifier: Apache-2.0
//
// farsee — POSIX terminal raw-mode lifecycle (plan.md §G7, §G10).
//
// Manages entry into and restoration from terminal raw mode. The Kitty
// presenter needs raw mode (no echo, no line buffering, no signal
// generation from control characters) to pass escape sequences and receive
// SGR mouse input. Restoration must be signal-safe so the terminal is
// restored even if the process is killed (plan.md §6.3).

#ifndef FARSEE_INCLUDE_FARSEE_TTY_POSIX_H
#define FARSEE_INCLUDE_FARSEE_TTY_POSIX_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rfb_tty {
    int fd;           // the tty file descriptor (-1 if not open)
    bool in_raw_mode; // true after enter_raw_mode, false after restore
    // Saved terminal attributes for restoration.
    // (struct termios is stored via a pointer to avoid pulling termios.h
    // into this header; the implementation manages the storage.)
    void *saved_attrs;  // opaque pointer to a struct termios
} rfb_tty;

// Initialize a tty context for the given file descriptor (typically
// STDIN_FILENO or a PTY slave). Does not enter raw mode yet.
void rfb_tty_init(rfb_tty *t, int fd);

// Enter raw mode: disable echo, canonical mode, signal generation, and
// output processing. Saves the original attributes for restoration.
// Returns true on success, false on failure.
bool rfb_tty_enter_raw_mode(rfb_tty *t);

// Restore the terminal to its original attributes. Safe to call multiple
// times; idempotent.
void rfb_tty_restore(rfb_tty *t);

// Signal-safe restoration: call this from a signal handler to restore
// the terminal without heap allocation or non-async-signal-safe calls.
// Uses a global saved-state pointer set by enter_raw_mode (plan.md §6.3).
void rfb_tty_signal_restore(int sig);

// Install signal handlers for SIGINT, SIGTERM, SIGHUP that call
// rfb_tty_signal_restore before the default disposition. Returns true
// on success.
bool rfb_tty_install_signal_handlers(rfb_tty *t);

// Release resources (frees the saved-attributes storage). Does NOT close
// the fd (the caller owns it).
void rfb_tty_destroy(rfb_tty *t);

// --- Live keyboard / mouse input fd (shared by RFB + RDP live) -------------
//
// Policy (live Kitty):
//   1) open(ttyname(STDOUT)) O_RDWR|O_NONBLOCK — same device as graphics,
//      dedicated fd (flags independent of stdout O_NONBLOCK for drains).
//   2) else isatty(STDIN) — reuse stdin (nonblocking).
//   3) else open("/dev/tty").
//
// On success *out_fd >= 0 and O_NONBLOCK is set. *out_owned is true only
// when this helper opened a new fd (caller must close); false when reusing
// STDIN_FILENO. Does not enter raw mode — callers use quiet/raw helpers.
bool farsee_tty_open_input(int *out_fd, bool *out_owned);

// Close only if owned (never closes stdin).
void farsee_tty_close_input(int fd, bool owned);

// Human-readable label for logs: "stdin", "/dev/tty", or "fd".
const char *farsee_tty_input_label(int fd, bool owned);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_TTY_POSIX_H
