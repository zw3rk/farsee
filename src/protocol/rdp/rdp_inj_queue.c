// SPDX-License-Identifier: Apache-2.0
//
// RDP inject queue wrappers over farsee_cmd_queue.

#include "rdp_inj_queue.h"

#include <string.h>

bool rdp_inj_queue_init(rdp_inj_queue *q)
{
    return farsee_cmd_queue_init(q);
}

void rdp_inj_queue_destroy(rdp_inj_queue *q)
{
    farsee_cmd_queue_destroy(q);
}

void rdp_inj_queue_kick(rdp_inj_queue *q)
{
    farsee_cmd_queue_kick(q);
}

static void rdp_to_farsee_cmd(const rdp_inj_cmd *in, farsee_cmd *out)
{
    memset(out, 0, sizeof(*out));
    if (in == NULL) {
        return;
    }
    switch (in->kind) {
    case RDP_INJ_KEY:
        out->kind = FARSEE_CMD_KEY;
        out->key.logical = in->keysym;
        out->key.unicode = in->unicode;
        if (in->repeat) {
            out->key.action = FARSEE_KEY_REPEAT;
        } else if (in->down) {
            out->key.action = FARSEE_KEY_PRESS;
        } else {
            out->key.action = FARSEE_KEY_RELEASE;
        }
        break;
    case RDP_INJ_POINTER:
        out->kind = FARSEE_CMD_POINTER;
        out->pe = in->pe;
        out->prev_buttons = in->prev_buttons;
        break;
    case RDP_INJ_RELEASE_ALL:
        out->kind = FARSEE_CMD_RELEASE_ALL;
        break;
    default:
        // Fail closed: never privilege-promote garbage kinds (T11).
        out->kind = (farsee_cmd_kind)0;
        break;
    }
}

static void farsee_to_rdp_cmd(const farsee_cmd *in, rdp_inj_cmd *out)
{
    memset(out, 0, sizeof(*out));
    if (in == NULL) {
        return;
    }
    switch (in->kind) {
    case FARSEE_CMD_KEY:
        out->kind = RDP_INJ_KEY;
        out->keysym = in->key.logical;
        out->unicode = in->key.unicode;
        out->down = (in->key.action != FARSEE_KEY_RELEASE);
        out->repeat = (in->key.action == FARSEE_KEY_REPEAT);
        break;
    case FARSEE_CMD_POINTER:
        out->kind = RDP_INJ_POINTER;
        out->pe = in->pe;
        out->prev_buttons = in->prev_buttons;
        break;
    case FARSEE_CMD_RELEASE_ALL:
        out->kind = RDP_INJ_RELEASE_ALL;
        break;
    default:
        out->kind = (rdp_inj_kind)0;
        break;
    }
}

bool rdp_inj_queue_push(rdp_inj_queue *q, const rdp_inj_cmd *cmd)
{
    if (q == NULL || cmd == NULL) {
        return false;
    }
    // Refuse unknown kinds (post-t11 T7) — never enqueue kind 0 slots.
    if (cmd->kind != RDP_INJ_KEY && cmd->kind != RDP_INJ_POINTER &&
        cmd->kind != RDP_INJ_RELEASE_ALL) {
        return false;
    }
    farsee_cmd fc;
    rdp_to_farsee_cmd(cmd, &fc);
    if (fc.kind == 0) {
        return false;
    }
    return farsee_cmd_queue_push(q, &fc);
}

bool rdp_inj_queue_pop(rdp_inj_queue *q, rdp_inj_cmd *out,
                       uint64_t deadline_monotonic_ms,
                       farsee_atomic_int *stop)
{
    if (q == NULL || out == NULL) {
        return false;
    }
    farsee_cmd fc;
    if (!farsee_cmd_queue_pop(q, &fc, deadline_monotonic_ms, stop)) {
        return false;
    }
    farsee_to_rdp_cmd(&fc, out);
    return true;
}
