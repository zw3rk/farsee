// SPDX-License-Identifier: Apache-2.0
//
// Farsee RFB engine-adapter implementation.
//
// Maps the existing RFB handshake state machine onto the common
// farsee_engine_ops. The rfb_* types stay confined to this file (and the
// adapter header, which is a documented bridge, not a common contract).

#include "farsee/rfb_engine_adapter.h"

#include "farsee/farsee_capability.h"

#include <stddef.h>

static farsee_error_code rfb_start(farsee_engine *engine)
{
    rfb_engine_adapter *a = (rfb_engine_adapter *)(void *)engine;
    if (a->started) {
        return FARSEE_ERR_STATE;  // repeated start rejected
    }
    // Legal lifecycle transition (NEW/CONFIGURED -> CONNECTING).
    if (!farsee_lifecycle_can_transition(a->lifecycle,
                                         FARSEE_LIFECYCLE_CONNECTING)) {
        return FARSEE_ERR_STATE;
    }
    a->lifecycle = FARSEE_LIFECYCLE_CONNECTING;
    a->started = true;
    // The caller drives the handshake state machine and reactor. start()
    // changes the lifecycle to CONNECTING without completing the handshake.
    return FARSEE_E_OK;
}

static farsee_error_code rfb_request_stop(farsee_engine *engine)
{
    rfb_engine_adapter *a = (rfb_engine_adapter *)(void *)engine;
    // Repeated stop requests succeed.
    a->cancelled = true;
    if (!farsee_lifecycle_is_terminal(a->lifecycle)) {
        a->lifecycle = FARSEE_LIFECYCLE_DRAINING;
    }
    return FARSEE_E_OK;
}

static farsee_error_code rfb_query_capabilities(const farsee_engine *engine,
                                                farsee_capability_set *out_caps)
{
    (void)engine;
    farsee_capability_set_init(out_caps);
    // Advertise only the RFB capability bits set below.
    farsee_capability_set_set(out_caps, FARSEE_CAP_ABSOLUTE_POINTER, true);
    farsee_capability_set_set(out_caps, FARSEE_CAP_REMOTE_RESIZE, true);
    farsee_capability_set_set(out_caps, FARSEE_CAP_CLIPBOARD_TEXT, true);
    farsee_capability_set_set(out_caps, FARSEE_CAP_UNICODE_INPUT, true);
    return FARSEE_E_OK;
}

static void rfb_destroy(farsee_engine **engine_ptr)
{
    if (engine_ptr == NULL || *engine_ptr == NULL) {
        return;
    }
    rfb_engine_adapter *a = (rfb_engine_adapter *)(void *)*engine_ptr;
    // Destroy handshake scratch storage and clear its internal password buffer.
    rfb_handshake_destroy(&a->handshake);
    a->lifecycle = FARSEE_LIFECYCLE_CLOSED;
    // The adapter does not own its own allocation (it's embedded); the
    // caller frees the enclosing storage. Set the handle to NULL per the
    // engine contract.
    *engine_ptr = NULL;
}

static const farsee_engine_ops RFB_ADAPTER_OPS = {
    .start = rfb_start,
    .request_stop = rfb_request_stop,
    .query_capabilities = rfb_query_capabilities,
    .destroy = rfb_destroy,
};

const farsee_engine_ops *rfb_engine_adapter_ops(void)
{
    return &RFB_ADAPTER_OPS;
}

void rfb_engine_adapter_init(rfb_engine_adapter *a,
                             const rfb_handshake_policy *policy,
                             rfb_allocator *alloc)
{
    if (a == NULL) {
        return;
    }
    a->ops = &RFB_ADAPTER_OPS;
    // Initialization sets CONFIGURED; start() advances to CONNECTING.
    a->lifecycle = FARSEE_LIFECYCLE_CONFIGURED;
    a->started = false;
    a->cancelled = false;
    rfb_handshake_init(&a->handshake,
                       (policy != NULL) ? policy : NULL,
                       alloc);
}

farsee_lifecycle_state rfb_engine_adapter_lifecycle(const rfb_engine_adapter *a)
{
    return (a != NULL) ? a->lifecycle : FARSEE_LIFECYCLE_FAILED;
}
