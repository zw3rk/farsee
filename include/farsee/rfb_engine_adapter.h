// SPDX-License-Identifier: Apache-2.0
//
// Farsee RFB engine adapter.
// (FARSEE_ARCHITECTURE_IMPROVEMENT_PLAN.md §14, §22/F8.)
//
// Wraps the existing clean-room RFB session (rfb_handshake + the rfb_*
// protocol-internal engine) behind the common farsee_engine interface. This
// makes RFB a first-class Farsee engine without rewriting it (§14.1:
// preserve the existing engine; §5.2: rfb_* internals stay).
//
// This is a BRIDGE, not a common contract: it deliberately uses rfb_* types
// internally, so it is named rfb_engine_adapter.h (NOT farsee_*.h) and is
// exempt from the common-header boundary scan, exactly like the presenter
// v1 adapter. The common interface (farsee_engine.h) contains no RFB types.

#ifndef FARSEE_INCLUDE_FARSEE_RFB_ENGINE_ADAPTER_H
#define FARSEE_INCLUDE_FARSEE_RFB_ENGINE_ADAPTER_H

#include "farsee/farsee_engine.h"
#include "farsee/farsee_lifecycle.h"
#include "farsee/handshake.h"          // rfb_handshake (RFB-private, by design here)

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// The RFB engine adapter. Implements farsee_engine_ops. Holds the RFB
// handshake state machine and tracks the common lifecycle.
typedef struct rfb_engine_adapter {
    const farsee_engine_ops *ops;      // == rfb_engine_adapter_ops()
    farsee_lifecycle_state lifecycle;
    rfb_handshake handshake;            // the existing RFB session SM
    bool started;
    bool cancelled;
} rfb_engine_adapter;

// The common engine ops implemented by this adapter.
const farsee_engine_ops *rfb_engine_adapter_ops(void);

// Initialize an adapter around an RFB handshake. The caller owns the
// handshake's allocator/policy and must keep them valid for the adapter's
// lifetime. Does not start I/O.
void rfb_engine_adapter_init(rfb_engine_adapter *a,
                             const rfb_handshake_policy *policy,
                             rfb_allocator *alloc);

// Current common lifecycle state.
farsee_lifecycle_state rfb_engine_adapter_lifecycle(const rfb_engine_adapter *a);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_RFB_ENGINE_ADAPTER_H
