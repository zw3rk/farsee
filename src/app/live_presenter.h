// SPDX-License-Identifier: Apache-2.0
//
// Private live-application owner for the null and Kitty presenters.

#ifndef FARSEE_SRC_APP_LIVE_PRESENTER_H
#define FARSEE_SRC_APP_LIVE_PRESENTER_H

#include "farsee/allocator.h"
#include "farsee/buffer.h"
#include "farsee/farsee_presenter_v2.h"
#include "farsee/kitty_tile.h"
#include "farsee/presenter.h"
#include "farsee/presenter_v1_adapter.h"

#include <stdbool.h>
#include <stdint.h>

typedef enum farsee_live_presenter_protocol {
    FARSEE_LIVE_PRESENTER_RFB = 0,
    FARSEE_LIVE_PRESENTER_RDP,
} farsee_live_presenter_protocol;

typedef enum farsee_live_presenter_kind {
    FARSEE_LIVE_PRESENTER_NULL = 0,
    FARSEE_LIVE_PRESENTER_KITTY_DIRECT,
    FARSEE_LIVE_PRESENTER_KITTY_SHM,
} farsee_live_presenter_kind;

typedef enum farsee_live_presenter_init_result {
    FARSEE_LIVE_PRESENTER_INIT_OK = 0,
    FARSEE_LIVE_PRESENTER_INIT_INVALID,
    FARSEE_LIVE_PRESENTER_INIT_OPEN_FAILED,
    FARSEE_LIVE_PRESENTER_INIT_CAPABILITY_FAILED,
} farsee_live_presenter_init_result;

typedef struct farsee_live_presenter {
    farsee_live_presenter_protocol protocol;
    farsee_live_presenter_kind kind;
    rfb_presenter_null null_presenter;
    rfb_kitty_tile kitty;
    rfb_buffer kitty_out;
    rfb_presenter v1;
    farsee_presenter_v1_adapter adapter;
    farsee_presenter *v2;
    bool ready;
    bool kitty_out_live;
    bool v1_opened;
    bool v2_opened;
} farsee_live_presenter;

// Preserve each CLI's established name-resolution policy. The TTY state is
// passed in so selection stays pure and testable.
farsee_live_presenter_kind farsee_live_presenter_select(
    farsee_live_presenter_protocol protocol, const char *name,
    bool stdout_is_tty);

// Initialize a zeroed or fully destroyed owner. RFB keeps v1 closed until its
// first frame. RDP opens the existing v1-through-v2 adapter eagerly at 1x1.
farsee_live_presenter_init_result farsee_live_presenter_init(
    farsee_live_presenter *owner, farsee_live_presenter_protocol protocol,
    const char *name, bool stdout_is_tty, uint32_t initial_width,
    uint32_t initial_height, rfb_allocator *allocator);

bool farsee_live_presenter_is_kitty(const farsee_live_presenter *owner);
rfb_buffer *farsee_live_presenter_kitty_out(farsee_live_presenter *owner);
rfb_kitty_tile *farsee_live_presenter_kitty(farsee_live_presenter *owner);
farsee_presenter *farsee_live_presenter_v2(farsee_live_presenter *owner);

// RFB v1 lifecycle. These wrappers let the owner close exactly once.
int farsee_live_presenter_rfb_open(farsee_live_presenter *owner,
                                   const rfb_framebuffer *framebuffer);
int farsee_live_presenter_rfb_resize(farsee_live_presenter *owner,
                                     const rfb_framebuffer *framebuffer);
int farsee_live_presenter_rfb_present(farsee_live_presenter *owner,
                                      const rfb_framebuffer *framebuffer,
                                      const rfb_damage_batch *damage);

// Close emits presenter teardown bytes but keeps the Kitty buffer available
// for the caller's final locked drain. Destroy is idempotent and frees it.
void farsee_live_presenter_close(farsee_live_presenter *owner);
void farsee_live_presenter_destroy(farsee_live_presenter *owner);

#endif // FARSEE_SRC_APP_LIVE_PRESENTER_H
