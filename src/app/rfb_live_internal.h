// SPDX-License-Identifier: Apache-2.0
//
// Internal classic RFB live orchestration seams.

#ifndef FARSEE_SRC_APP_RFB_LIVE_INTERNAL_H
#define FARSEE_SRC_APP_RFB_LIVE_INTERNAL_H

#include "farsee/error.h"
#include "farsee/farsee_error.h"
#include "farsee/farsee_mt_session.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

// Report the terminal state of the live worker group and return the CLI exit
// code. `diagnostic` is the caller-owned output stream; NULL uses stderr.
int farsee_rfb_live_report_outcome(
    farsee_mt_terminal_kind terminal_kind, farsee_error mt_error,
    rfb_error protocol_error, uint8_t unexpected_type, bool stop_requested,
    uint64_t present_count, FILE *diagnostic);

#ifdef __cplusplus
}
#endif

#endif // FARSEE_SRC_APP_RFB_LIVE_INTERNAL_H
