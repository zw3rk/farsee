// SPDX-License-Identifier: Apache-2.0
//
// Farsee presenter v2.
// (FARSEE_ARCHITECTURE_IMPROVEMENT_PLAN.md §11.7 — F4 gate.)
//
// A versioned presenter capability object + semantic interface that
// operates on the display scene's frame commits. This is the common
// presenter contract future engines publish to. The existing v1 presenters
// (rfb_presenter_ops: null/dump/kitty) are preserved behind a compatibility
// adapter (farsee_presenter_v1_adapter) so RFB output is unchanged (§11.8).
//
// Opaque: no Kitty command structures, no framebuffer types, no protocol
// types appear here (§4.2).

#ifndef FARSEE_INCLUDE_FARSEE_FARSEE_PRESENTER_V2_H
#define FARSEE_INCLUDE_FARSEE_FARSEE_PRESENTER_V2_H

#include "farsee/farsee_display.h"
#include "farsee/farsee_error.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct farsee_presenter farsee_presenter;

// Presenter capabilities (§11.7), queried at open time.
typedef struct farsee_presenter_caps {
    // Accepted decoded pixel formats (bit set if accepted).
    bool accepts_rgba8888;
    bool accepts_bgra8888;
    bool accepts_rgbx8888;
    bool accepts_bgrx8888;
    bool accepts_rgb888;
    bool supports_partial_update;     // damage rects honored
    bool supports_separate_cursor;    // cursor plane
    bool supports_shared_memory;      // SHM import
    uint32_t max_dimension;
    uint32_t max_in_flight_frames;
    uint32_t preferred_frame_rate;
} farsee_presenter_caps;

// The v-table every presenter v2 publishes. present() either completes
// synchronously or retains via an explicit release callback; buffer
// lifetime is never implicit (§11.7).
typedef struct farsee_presenter_ops_v2 {
    farsee_error_code (*open)(farsee_presenter *p,
                              farsee_presenter_caps *out_caps);
    farsee_error_code (*present)(farsee_presenter *p,
                                 const farsee_frame_commit *frame);
    farsee_error_code (*flush)(farsee_presenter *p);
    void (*close)(farsee_presenter **p);
} farsee_presenter_ops_v2;

// The presenter handle. Concrete presenters begin with a const ops pointer.
struct farsee_presenter {
    const farsee_presenter_ops_v2 *ops;
};

// --- Public accessors (dispatch through ops) -------------------------------

farsee_error farsee_presenter_open(farsee_presenter *p,
                                   farsee_presenter_caps *out_caps);
farsee_error farsee_presenter_present(farsee_presenter *p,
                                      const farsee_frame_commit *frame);
farsee_error farsee_presenter_flush(farsee_presenter *p);
void farsee_presenter_close(farsee_presenter **p);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_INCLUDE_FARSEE_FARSEE_PRESENTER_V2_H
