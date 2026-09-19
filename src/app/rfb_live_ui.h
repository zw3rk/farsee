// SPDX-License-Identifier: Apache-2.0
//
// Private RFB live UI and shared-shell operations owner.

#ifndef FARSEE_SRC_APP_RFB_LIVE_UI_H
#define FARSEE_SRC_APP_RFB_LIVE_UI_H

#include "app/live_shell.h"
#include "farsee/buffer.h"
#include "farsee/farsee_atomic.h"
#include "farsee/farsee_cmd_queue.h"
#include "farsee/farsee_frame_slot.h"
#include "farsee/modifier_synth.h"
#include "farsee/rfb_session.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RFB_LIVE_STATUS_ROWS 2u

// The coordinator owns this state through the joined MT session. stop and
// session_stop are required before input runs; both remain borrowed and live
// until every worker returns.
typedef struct rfb_live_ui {
    farsee_live_shell shell;
    farsee_live_shell_ops shell_ops;
    rfb_buffer *kitty_out;
    farsee_cmd_queue *cmds;
    farsee_modifier_synth synth_mods;
    unsigned prev_buttons;
    farsee_frame_slot *slot;
    farsee_atomic_int *stop;
    farsee_atomic_int *session_stop;
    rfb_session *sess;
} rfb_live_ui;

void rfb_live_ui_bind_shell_ops(rfb_live_ui *ui);
void rfb_live_ui_process_input(rfb_live_ui *ui,
                               const uint8_t *data, size_t size);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_SRC_APP_RFB_LIVE_UI_H
