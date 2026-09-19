// SPDX-License-Identifier: Apache-2.0
//
// Private deterministic fault seam for the controlling-terminal prompt.

#ifndef FARSEE_SRC_APP_CREDENTIAL_PROMPT_INTERNAL_H
#define FARSEE_SRC_APP_CREDENTIAL_PROMPT_INTERNAL_H

#include "farsee/credential_prompt.h"

#include <stdbool.h>
#include <stddef.h>

typedef bool (*farsee_prompt_signal_arm_check_fn)(void *context,
                                                   int signal_number);

// The production wrapper passes no arm check. Tests can reject one signal
// installation deterministically and verify that earlier installations roll
// back before terminal attributes change.
farsee_credential_prompt_status farsee_prompt_password_tty_with_arm_check(
    char **out_buf, size_t *out_len,
    farsee_prompt_signal_arm_check_fn arm_check, void *arm_check_context);

#endif /* FARSEE_SRC_APP_CREDENTIAL_PROMPT_INTERNAL_H */
