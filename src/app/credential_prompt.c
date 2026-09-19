// SPDX-License-Identifier: Apache-2.0

#include "app/credential_prompt_internal.h"

#include "farsee/secret.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

static volatile sig_atomic_t prompt_signalled = 0;
static volatile sig_atomic_t prompt_signal = 0;

static void prompt_on_signal(int sig)
{
    prompt_signalled = 1;
    prompt_signal = sig;
}

int farsee_prompt_take_terminal_signal(void)
{
    const int sig = (int)prompt_signal;
    prompt_signal = 0;
    prompt_signalled = 0;
    return sig;
}

static bool install_prompt_handler(
    int signal_number, const struct sigaction *window_action,
    struct sigaction *old_action,
    farsee_prompt_signal_arm_check_fn arm_check, void *arm_check_context)
{
    if (arm_check != NULL &&
        !arm_check(arm_check_context, signal_number)) {
        return false;
    }
    return sigaction(signal_number, window_action, old_action) == 0;
}

farsee_credential_prompt_status farsee_prompt_password_tty_with_arm_check(
    char **out_buf, size_t *out_len,
    farsee_prompt_signal_arm_check_fn arm_check, void *arm_check_context)
{
    if (out_buf == NULL || out_len == NULL) {
        return FARSEE_CREDENTIAL_PROMPT_INPUT_FAILED;
    }
    *out_buf = NULL;
    *out_len = 0u;

    int tty = open("/dev/tty", O_RDWR | O_NOCTTY);
    if (tty < 0) {
        return FARSEE_CREDENTIAL_PROMPT_INPUT_FAILED;
    }

    prompt_signalled = 0;
    prompt_signal = 0;

    struct sigaction window_action;
    memset(&window_action, 0, sizeof window_action);
    window_action.sa_handler = prompt_on_signal;
    sigemptyset(&window_action.sa_mask);
    window_action.sa_flags = 0;

    struct sigaction old_int;
    struct sigaction old_term;
    struct sigaction old_hup;
    const bool armed_int = install_prompt_handler(
        SIGINT, &window_action, &old_int, arm_check, arm_check_context);
    if (!armed_int) {
        (void)close(tty);
        return FARSEE_CREDENTIAL_PROMPT_INPUT_FAILED;
    }
    const bool armed_term = install_prompt_handler(
        SIGTERM, &window_action, &old_term, arm_check, arm_check_context);
    if (!armed_term) {
        (void)sigaction(SIGINT, &old_int, NULL);
        (void)close(tty);
        return FARSEE_CREDENTIAL_PROMPT_INPUT_FAILED;
    }
    const bool armed_hup = install_prompt_handler(
        SIGHUP, &window_action, &old_hup, arm_check, arm_check_context);
    if (!armed_hup) {
        (void)sigaction(SIGTERM, &old_term, NULL);
        (void)sigaction(SIGINT, &old_int, NULL);
        (void)close(tty);
        return FARSEE_CREDENTIAL_PROMPT_INPUT_FAILED;
    }

    struct termios old_termios;
    struct termios prompt_termios;
    const bool have_termios = tcgetattr(tty, &old_termios) == 0;
    bool prompt_ready = have_termios;
    if (have_termios) {
        prompt_termios = old_termios;
        prompt_termios.c_lflag &= (tcflag_t)~(ECHO | ECHONL | ICANON);
        prompt_termios.c_cc[VMIN] = 1;
        prompt_termios.c_cc[VTIME] = 0;
        prompt_ready = tcsetattr(tty, TCSAFLUSH, &prompt_termios) == 0;
    }

    static const char prompt[] = "Password: ";
    if (prompt_ready) {
        ssize_t written;
        do {
            written = write(tty, prompt, sizeof prompt - 1u);
        } while (written < 0 && errno == EINTR && !prompt_signalled);
        prompt_ready = written == (ssize_t)(sizeof prompt - 1u);
    }

    char line[FARSEE_CREDENTIAL_PROMPT_PASSWORD_MAX + 1u];
    size_t length = 0u;
    bool completed = false;
    bool overflowed = false;
    while (prompt_ready) {
        char ch = 0;
        const ssize_t count = read(tty, &ch, 1u);
        if (count < 0) {
            if (errno == EINTR && !prompt_signalled) {
                continue;
            }
            break;
        }
        if (count == 0 || ch == '\x04') {
            break;
        }
        if (ch == '\n' || ch == '\r') {
            completed = true;
            break;
        }
        if ((ch == '\x7f' || ch == '\x08') && length > 0u) {
            length--;
            continue;
        }
        if ((unsigned char)ch < 0x20u) {
            continue;
        }
        if (length + 1u < sizeof line) {
            line[length++] = ch;
        } else {
            overflowed = true;
        }
    }

    if (!prompt_signalled) {
        const ssize_t newline_written = write(tty, "\n", 1u);
        (void)newline_written;
    }
    const bool restored =
        !have_termios || tcsetattr(tty, TCSAFLUSH, &old_termios) == 0;
    (void)close(tty);

    (void)sigaction(SIGHUP, &old_hup, NULL);
    (void)sigaction(SIGTERM, &old_term, NULL);
    (void)sigaction(SIGINT, &old_int, NULL);

    if (prompt_signalled) {
        rfb_secret_zero(line, sizeof line);
        return FARSEE_CREDENTIAL_PROMPT_TERMINAL_SIGNAL;
    }
    if (overflowed) {
        rfb_secret_zero(line, sizeof line);
        return FARSEE_CREDENTIAL_PROMPT_TOO_LONG;
    }
    if (!completed || !restored) {
        rfb_secret_zero(line, sizeof line);
        return FARSEE_CREDENTIAL_PROMPT_INPUT_FAILED;
    }

    char *buffer = (char *)malloc(length + 1u);
    if (buffer == NULL) {
        rfb_secret_zero(line, sizeof line);
        return FARSEE_CREDENTIAL_PROMPT_INPUT_FAILED;
    }
    if (length > 0u) {
        memcpy(buffer, line, length);
    }
    buffer[length] = '\0';
    rfb_secret_zero(line, sizeof line);
    *out_buf = buffer;
    *out_len = length;
    return FARSEE_CREDENTIAL_PROMPT_OK;
}

farsee_credential_prompt_status farsee_prompt_password_tty(
    char **out_buf, size_t *out_len)
{
    return farsee_prompt_password_tty_with_arm_check(
        out_buf, out_len, NULL, NULL);
}
