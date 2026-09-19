// SPDX-License-Identifier: Apache-2.0
//
// Farsee presenter v1 compatibility adapter.
//
// Maps a common display-scene frame commit into the existing v1 presenter
// contract (rfb_presenter_ops: open/resize/present/close operating on an
// rfb_framebuffer + rfb_damage_batch). This lets the existing null/
// kitty presenters receive common-scene frames WITHOUT being rewritten,
// preserving RFB output byte-for-byte (§11.8).
//
// The adapter owns a scratch rfb_framebuffer sized to the surface; on each
// present it copies the surface view's pixels into the scratch framebuffer
// (converting to canonical RGBA8 if the surface is BGRA/RGB) and forwards
// the damage as an rfb_damage_batch.

#ifndef FARSEE_INCLUDE_FARSEE_PRESENTER_V1_ADAPTER_H
#define FARSEE_INCLUDE_FARSEE_PRESENTER_V1_ADAPTER_H

#include "farsee/framebuffer.h"
#include "farsee/presenter.h"
#include "farsee/farsee_presenter_v2.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Adapter state. Embeds the v2 presenter handle (its first member is the
// v2 ops pointer, set to farsee_presenter_v1_adapter_ops()).
typedef struct farsee_presenter_v1_adapter {
    const farsee_presenter_ops_v2 *v2_ops;   // == farsee_presenter_v1_adapter_ops()
    rfb_presenter v1;                         // the wrapped existing presenter
    rfb_framebuffer scratch;                  // scratch RGBA8 buffer
    uint32_t byte_limit;                      // scratch allocation cap
    bool opened;
} farsee_presenter_v1_adapter;

// The v2 ops table implemented by the adapter.
const farsee_presenter_ops_v2 *farsee_presenter_v1_adapter_ops(void);

// Initialize an adapter wrapping `v1` (an existing rfb_presenter). The
// adapter does NOT take ownership of the v1 presenter's lifetime; the
// caller must keep it valid until after the adapter is closed.
// `byte_limit` caps the scratch framebuffer allocation.
void farsee_presenter_v1_adapter_init(farsee_presenter_v1_adapter *a,
                                      rfb_presenter v1, uint32_t byte_limit);

// Allocator-aware form for session-scoped scratch accounting. The allocator
// is borrowed and must outlive the adapter.
void farsee_presenter_v1_adapter_init_with_allocator(
    farsee_presenter_v1_adapter *a, rfb_presenter v1, uint32_t byte_limit,
    rfb_allocator *allocator);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_PRESENTER_V1_ADAPTER_H
