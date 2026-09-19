// SPDX-License-Identifier: Apache-2.0
//
// Shared private owner for the live RFB and RDP presenter stacks.

#include "app/live_presenter.h"

#include <stddef.h>
#include <string.h>

#define LIVE_KITTY_OUTPUT_LIMIT ((size_t)64u * 1024u * 1024u)
#define LIVE_RDP_ADAPTER_LIMIT ((uint32_t)256u * 1024u * 1024u)
#define LIVE_RFB_TILE_EDGE 8192u
#define LIVE_RDP_MIN_TILE_EDGE 64u

farsee_live_presenter_kind farsee_live_presenter_select(
    farsee_live_presenter_protocol protocol, const char *name,
    bool stdout_is_tty)
{
    const bool automatic = name == NULL || strcmp(name, "auto") == 0;
    if (automatic) {
        return stdout_is_tty ? FARSEE_LIVE_PRESENTER_KITTY_SHM
                             : FARSEE_LIVE_PRESENTER_NULL;
    }
    if (strcmp(name, "null") == 0) {
        return FARSEE_LIVE_PRESENTER_NULL;
    }
    if (protocol == FARSEE_LIVE_PRESENTER_RFB) {
        if (strcmp(name, "kitty") == 0 ||
            strcmp(name, "kitty-direct") == 0) {
            return FARSEE_LIVE_PRESENTER_KITTY_DIRECT;
        }
        if (strcmp(name, "kitty-shm") == 0) {
            return FARSEE_LIVE_PRESENTER_KITTY_SHM;
        }
        return stdout_is_tty ? FARSEE_LIVE_PRESENTER_KITTY_SHM
                             : FARSEE_LIVE_PRESENTER_NULL;
    }
    if (protocol == FARSEE_LIVE_PRESENTER_RDP) {
        if (strcmp(name, "kitty") == 0 || strcmp(name, "kitty-shm") == 0) {
            return FARSEE_LIVE_PRESENTER_KITTY_SHM;
        }
        if (strcmp(name, "kitty-direct") == 0) {
            return FARSEE_LIVE_PRESENTER_KITTY_DIRECT;
        }
    }
    return FARSEE_LIVE_PRESENTER_NULL;
}

bool farsee_live_presenter_is_kitty(const farsee_live_presenter *owner)
{
    return owner != NULL && owner->kitty_out_live &&
           (owner->kind == FARSEE_LIVE_PRESENTER_KITTY_DIRECT ||
            owner->kind == FARSEE_LIVE_PRESENTER_KITTY_SHM);
}

rfb_buffer *farsee_live_presenter_kitty_out(farsee_live_presenter *owner)
{
    return farsee_live_presenter_is_kitty(owner) && owner->kitty_out_live
               ? &owner->kitty_out
               : NULL;
}

rfb_kitty_tile *farsee_live_presenter_kitty(farsee_live_presenter *owner)
{
    return farsee_live_presenter_is_kitty(owner) ? &owner->kitty : NULL;
}

farsee_presenter *farsee_live_presenter_v2(farsee_live_presenter *owner)
{
    if (owner == NULL || !owner->ready ||
        owner->protocol != FARSEE_LIVE_PRESENTER_RDP || !owner->v2_opened) {
        return NULL;
    }
    return owner->v2;
}

void farsee_live_presenter_close(farsee_live_presenter *owner)
{
    if (owner == NULL) {
        return;
    }
    if (owner->protocol == FARSEE_LIVE_PRESENTER_RDP && owner->v2 != NULL) {
        // The adapter close also closes v1 when open and always releases its
        // scratch framebuffer. This is required after a partial open failure.
        farsee_presenter_close(&owner->v2);
        owner->v2_opened = false;
        owner->v1_opened = false;
    } else if (owner->v1_opened) {
        rfb_presenter_close(&owner->v1);
        owner->v1_opened = false;
    }
    owner->ready = false;
}

void farsee_live_presenter_destroy(farsee_live_presenter *owner)
{
    if (owner == NULL) {
        return;
    }
    farsee_live_presenter_close(owner);
    if (owner->kitty_out_live) {
        rfb_buffer_destroy(&owner->kitty_out);
    }
    memset(owner, 0, sizeof *owner);
}

farsee_live_presenter_init_result farsee_live_presenter_init(
    farsee_live_presenter *owner, farsee_live_presenter_protocol protocol,
    const char *name, bool stdout_is_tty, uint32_t initial_width,
    uint32_t initial_height, rfb_allocator *allocator)
{
    if (owner == NULL || allocator == NULL || allocator->alloc == NULL ||
        allocator->free == NULL ||
        (protocol != FARSEE_LIVE_PRESENTER_RFB &&
         protocol != FARSEE_LIVE_PRESENTER_RDP)) {
        return FARSEE_LIVE_PRESENTER_INIT_INVALID;
    }

    memset(owner, 0, sizeof *owner);
    owner->protocol = protocol;
    owner->kind =
        farsee_live_presenter_select(protocol, name, stdout_is_tty);

    if (owner->kind == FARSEE_LIVE_PRESENTER_NULL) {
        rfb_presenter_null_init(&owner->null_presenter);
        owner->v1 = (rfb_presenter){
            .ops = &rfb_presenter_null_ops,
            .ctx = &owner->null_presenter,
        };
    } else {
        rfb_buffer_init(&owner->kitty_out, allocator,
                        LIVE_KITTY_OUTPUT_LIMIT);
        owner->kitty_out_live = true;
        uint32_t tile_edge = LIVE_RFB_TILE_EDGE;
        if (protocol == FARSEE_LIVE_PRESENTER_RDP) {
            tile_edge = initial_width > initial_height ? initial_width
                                                       : initial_height;
            if (tile_edge < LIVE_RDP_MIN_TILE_EDGE) {
                tile_edge = LIVE_RDP_MIN_TILE_EDGE;
            }
        }
        rfb_kitty_tile_init(
            &owner->kitty, allocator, &owner->kitty_out, tile_edge,
            owner->kind == FARSEE_LIVE_PRESENTER_KITTY_SHM,
            /*request_ack=*/false);
        owner->v1 = (rfb_presenter){
            .ops = &rfb_kitty_tile_ops,
            .ctx = &owner->kitty,
        };
    }

    owner->ready = true;
    if (protocol == FARSEE_LIVE_PRESENTER_RFB) {
        return FARSEE_LIVE_PRESENTER_INIT_OK;
    }

    farsee_presenter_v1_adapter_init_with_allocator(
        &owner->adapter, owner->v1, LIVE_RDP_ADAPTER_LIMIT, allocator);
    owner->v2 = (farsee_presenter *)&owner->adapter;
    owner->v2->ops = farsee_presenter_v1_adapter_ops();
    farsee_presenter_caps caps;
    const farsee_error open_error = farsee_presenter_open(owner->v2, &caps);
    if (open_error.code != FARSEE_E_OK) {
        farsee_live_presenter_destroy(owner);
        return FARSEE_LIVE_PRESENTER_INIT_OPEN_FAILED;
    }
    owner->v2_opened = true;
    owner->v1_opened = true;
    if (!caps.accepts_bgra8888) {
        farsee_live_presenter_destroy(owner);
        return FARSEE_LIVE_PRESENTER_INIT_CAPABILITY_FAILED;
    }
    return FARSEE_LIVE_PRESENTER_INIT_OK;
}

int farsee_live_presenter_rfb_open(farsee_live_presenter *owner,
                                   const rfb_framebuffer *framebuffer)
{
    if (owner == NULL || !owner->ready ||
        owner->protocol != FARSEE_LIVE_PRESENTER_RFB || framebuffer == NULL ||
        owner->v1_opened) {
        return -1;
    }
    if (rfb_presenter_open(&owner->v1, framebuffer) != 0) {
        return -1;
    }
    owner->v1_opened = true;
    return 0;
}

int farsee_live_presenter_rfb_resize(farsee_live_presenter *owner,
                                     const rfb_framebuffer *framebuffer)
{
    if (owner == NULL || !owner->ready || !owner->v1_opened ||
        owner->protocol != FARSEE_LIVE_PRESENTER_RFB || framebuffer == NULL) {
        return -1;
    }
    return rfb_presenter_resize(&owner->v1, framebuffer);
}

int farsee_live_presenter_rfb_present(farsee_live_presenter *owner,
                                      const rfb_framebuffer *framebuffer,
                                      const rfb_damage_batch *damage)
{
    if (owner == NULL || !owner->ready || !owner->v1_opened ||
        owner->protocol != FARSEE_LIVE_PRESENTER_RFB || framebuffer == NULL) {
        return -1;
    }
    return rfb_presenter_present(&owner->v1, framebuffer, damage);
}
