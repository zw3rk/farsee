// SPDX-License-Identifier: Apache-2.0
//
// Shared controlling-terminal credential prompt.

#ifndef FARSEE_INCLUDE_FARSEE_CREDENTIAL_PROMPT_H
#define FARSEE_INCLUDE_FARSEE_CREDENTIAL_PROMPT_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// The controlling-terminal prompt accepts at most 255 password bytes.
#define FARSEE_CREDENTIAL_PROMPT_PASSWORD_MAX ((size_t)255u)

typedef enum farsee_credential_prompt_status {
    FARSEE_CREDENTIAL_PROMPT_OK = 0,
    FARSEE_CREDENTIAL_PROMPT_INPUT_FAILED,
    FARSEE_CREDENTIAL_PROMPT_TOO_LONG,
    FARSEE_CREDENTIAL_PROMPT_TERMINAL_SIGNAL,
} farsee_credential_prompt_status;

// Read one password from /dev/tty with echo disabled. On OK, *out_buf owns a
// malloc'd NUL-terminated buffer and *out_len is its logical length. Input
// beyond FARSEE_CREDENTIAL_PROMPT_PASSWORD_MAX returns TOO_LONG. Ctrl-D,
// terminal EOF, and I/O failure fail closed with a typed status.
// The function restores termios and the caller's signal dispositions before
// it returns. After a signal failure, take_terminal_signal returns and clears
// the recorded signal so the caller can re-raise it.
farsee_credential_prompt_status farsee_prompt_password_tty(
    char **out_buf, size_t *out_len);
int farsee_prompt_take_terminal_signal(void);

#ifdef __cplusplus
}
#endif

#endif /* FARSEE_INCLUDE_FARSEE_CREDENTIAL_PROMPT_H */
