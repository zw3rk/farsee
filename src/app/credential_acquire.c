// SPDX-License-Identifier: Apache-2.0
//
// Shared live-client password acquisition and terminal-signal handoff.

#include "farsee/credential_acquire.h"

#include "farsee/credential_prompt.h"
#include "farsee/secret_fd.h"

#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static bool inline_password_length(const char *password, size_t *length)
{
    if (password == NULL || length == NULL) {
        return false;
    }
    for (size_t i = 0u; i <= FARSEE_CREDENTIAL_PASSWORD_MAX; i++) {
        if (password[i] == '\0') {
            *length = i;
            return true;
        }
    }
    return false;
}

static farsee_credential_acquire_status acquire_from_fd(
    int fd, farsee_secret *password)
{
    char *buffer = NULL;
    const size_t capacity = FARSEE_CREDENTIAL_PASSWORD_MAX + 1u;
    const long length = farsee_read_fd_secret(fd, &buffer, capacity);
    const bool closed = farsee_credential_close_password_fd(fd);
    if (length < 0 || !closed) {
        farsee_secret partial = {
            .data = (uint8_t *)buffer,
            .len = length > 0 ? (size_t)length : 0u,
            .cap = buffer != NULL ? capacity : 0u,
        };
        farsee_secret_destroy(&partial);
        return FARSEE_CREDENTIAL_ACQUIRE_INPUT_FAILED;
    }
    password->data = (uint8_t *)buffer;
    password->len = (size_t)length;
    password->cap = capacity;
    return FARSEE_CREDENTIAL_ACQUIRE_OK;
}

static farsee_credential_acquire_status acquire_from_inline(
    const char *inline_password, farsee_secret *password)
{
    size_t length = 0u;
    if (!inline_password_length(inline_password, &length)) {
        return FARSEE_CREDENTIAL_ACQUIRE_TOO_LONG;
    }
    uint8_t *buffer = (uint8_t *)malloc(length + 1u);
    if (buffer == NULL) {
        return FARSEE_CREDENTIAL_ACQUIRE_NO_MEMORY;
    }
    memcpy(buffer, inline_password, length + 1u);
    password->data = buffer;
    password->len = length;
    password->cap = length + 1u;
    return FARSEE_CREDENTIAL_ACQUIRE_OK;
}

static farsee_credential_acquire_status acquire_from_prompt(
    farsee_secret *password, int *terminal_signal)
{
    char *buffer = NULL;
    size_t length = 0u;
    const farsee_credential_prompt_status prompt_status =
        farsee_prompt_password_tty(&buffer, &length);
    if (prompt_status == FARSEE_CREDENTIAL_PROMPT_TERMINAL_SIGNAL) {
        const int signal_number = farsee_prompt_take_terminal_signal();
        if (signal_number == 0) {
            return FARSEE_CREDENTIAL_ACQUIRE_INPUT_FAILED;
        }
        *terminal_signal = signal_number;
        return FARSEE_CREDENTIAL_ACQUIRE_TERMINAL_SIGNAL;
    }
    if (prompt_status == FARSEE_CREDENTIAL_PROMPT_TOO_LONG) {
        return FARSEE_CREDENTIAL_ACQUIRE_TOO_LONG;
    }
    if (prompt_status != FARSEE_CREDENTIAL_PROMPT_OK) {
        return FARSEE_CREDENTIAL_ACQUIRE_INPUT_FAILED;
    }
    if (length > FARSEE_CREDENTIAL_PASSWORD_MAX) {
        farsee_secret oversized = {
            .data = (uint8_t *)buffer,
            .len = length,
            .cap = length + 1u,
        };
        farsee_secret_destroy(&oversized);
        return FARSEE_CREDENTIAL_ACQUIRE_TOO_LONG;
    }
    password->data = (uint8_t *)buffer;
    password->len = length;
    password->cap = length + 1u;
    return FARSEE_CREDENTIAL_ACQUIRE_OK;
}

farsee_credential_acquire_status farsee_credential_acquire_password(
    const farsee_credential_acquire_config *config,
    farsee_secret *out_password, int *out_terminal_signal)
{
    if (out_terminal_signal != NULL) {
        *out_terminal_signal = 0;
    }
    if (config == NULL || out_password == NULL ||
        out_terminal_signal == NULL || out_password->data != NULL ||
        out_password->len != 0u || out_password->cap != 0u) {
        if (config != NULL && config->password_fd >= 0) {
            (void)farsee_credential_close_password_fd(config->password_fd);
        }
        return FARSEE_CREDENTIAL_ACQUIRE_INVALID;
    }

    farsee_secret acquired = {0};
    farsee_credential_acquire_status status = FARSEE_CREDENTIAL_ACQUIRE_OK;
    if (config->password_fd >= 0) {
        status = acquire_from_fd(config->password_fd, &acquired);
    } else if (config->password_inline != NULL) {
        status = acquire_from_inline(config->password_inline, &acquired);
    } else if (config->required) {
        status = acquire_from_prompt(&acquired, out_terminal_signal);
    }

    if (status != FARSEE_CREDENTIAL_ACQUIRE_OK) {
        farsee_secret_destroy(&acquired);
        return status;
    }
    if (config->required && acquired.len == 0u) {
        farsee_secret_destroy(&acquired);
        return FARSEE_CREDENTIAL_ACQUIRE_EMPTY;
    }
    *out_password = acquired;
    return FARSEE_CREDENTIAL_ACQUIRE_OK;
}

bool farsee_credential_close_password_fd(int password_fd)
{
    return password_fd < 0 || close(password_fd) == 0;
}

void farsee_credential_reraise_terminal_signal(int signal_number)
{
    if (signal_number == 0) {
        return;
    }
    (void)signal(signal_number, SIG_DFL);
    (void)raise(signal_number);
    _exit(1);
}
