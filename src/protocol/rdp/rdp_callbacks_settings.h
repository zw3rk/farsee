// SPDX-License-Identifier: Apache-2.0
//
// Private FreeRDP instance-settings boundary for callback wiring.

#ifndef FARSEE_SRC_PROTOCOL_RDP_RDP_CALLBACKS_SETTINGS_H
#define FARSEE_SRC_PROTOCOL_RDP_RDP_CALLBACKS_SETTINGS_H

#include "rdp_callbacks.h"

#include <stdbool.h>

// Apply the callback context settings to an opaque freerdp instance.
// The caller retains ownership of both arguments.
bool rdp_callbacks_apply_instance_settings(
    void *freerdp_instance, const rdp_callback_context *cbctx);

#endif  // FARSEE_SRC_PROTOCOL_RDP_RDP_CALLBACKS_SETTINGS_H
