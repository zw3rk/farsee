// SPDX-License-Identifier: Apache-2.0

#include "farsee/modifier_synth.h"

#include "farsee/farsee_cmd_queue.h"

#include <stddef.h>
#include <string.h>

typedef struct modifier_descriptor {
    uint16_t modifier;
    uint32_t keysym;
} modifier_descriptor;

static const modifier_descriptor k_modifiers[] = {
    {RFB_MOD_SHIFT, XK_Shift_L},
    {RFB_MOD_CONTROL, XK_Control_L},
    {RFB_MOD_ALT, XK_Alt_L},
    {RFB_MOD_META, XK_Super_L},
};

static size_t modifier_count(void)
{
    return sizeof k_modifiers / sizeof k_modifiers[0];
}

static uint16_t synthesizable_modifiers(void)
{
    return (uint16_t)(RFB_MOD_SHIFT | RFB_MOD_CONTROL | RFB_MOD_ALT |
                      RFB_MOD_META);
}

static uint16_t normalized_modifiers(void)
{
    return (uint16_t)(synthesizable_modifiers() | RFB_MOD_CAPSLOCK);
}

void farsee_modifier_synth_init(farsee_modifier_synth *state)
{
    if (state != NULL) {
        state->held = RFB_MOD_NONE;
        state->reconcile = RFB_MOD_NONE;
        memset(&state->pending_primary, 0, sizeof state->pending_primary);
        state->pending_primary_valid = false;
        state->stop_required = false;
    }
}

static farsee_modifier_synth_action modifier_action(
    const modifier_descriptor *descriptor, bool down)
{
    const farsee_modifier_synth_action action = {
        .kind = FARSEE_MODIFIER_SYNTH_ACTION_MODIFIER,
        .keysym = descriptor->keysym,
        .text = 0u,
        .modifier = descriptor->modifier,
        .down = down,
        .repeat = false,
    };
    return action;
}

static farsee_modifier_synth_action primary_action(const rfb_norm_key *key,
                                                    bool down, bool repeat)
{
    const farsee_modifier_synth_action action = {
        .kind = FARSEE_MODIFIER_SYNTH_ACTION_PRIMARY,
        .keysym = key->keysym,
        .text = key->text,
        .modifier = RFB_MOD_NONE,
        .down = down,
        .repeat = repeat,
    };
    return action;
}

static bool release_selected(farsee_modifier_synth *state, uint16_t selected,
                             farsee_modifier_synth_send_fn send, void *user)
{
    bool all_delivered = true;
    for (size_t i = modifier_count(); i > 0u; i--) {
        const modifier_descriptor *descriptor = &k_modifiers[i - 1u];
        if ((selected & descriptor->modifier) == 0u) {
            continue;
        }
        if ((state->held & descriptor->modifier) == 0u) {
            state->reconcile =
                (uint16_t)(state->reconcile &
                           (uint16_t)~descriptor->modifier);
            continue;
        }
        const farsee_modifier_synth_action action =
            modifier_action(descriptor, false);
        if (!send(user, &action)) {
            state->reconcile =
                (uint16_t)(state->reconcile | descriptor->modifier);
            all_delivered = false;
            continue;
        }
        state->held =
            (uint16_t)(state->held & (uint16_t)~descriptor->modifier);
        state->reconcile =
            (uint16_t)(state->reconcile &
                       (uint16_t)~descriptor->modifier);
    }
    return all_delivered;
}

static bool reconcile_pending(farsee_modifier_synth *state,
                              farsee_modifier_synth_send_fn send, void *user)
{
    if (state->reconcile == RFB_MOD_NONE) {
        return true;
    }
    return release_selected(state, state->reconcile, send, user);
}

static bool press_missing(farsee_modifier_synth *state, uint16_t needed,
                          farsee_modifier_synth_send_fn send, void *user,
                          uint16_t *pressed)
{
    *pressed = RFB_MOD_NONE;
    for (size_t i = 0u; i < modifier_count(); i++) {
        const modifier_descriptor *descriptor = &k_modifiers[i];
        if ((needed & descriptor->modifier) == 0u ||
            (state->held & descriptor->modifier) != 0u) {
            continue;
        }
        const farsee_modifier_synth_action action =
            modifier_action(descriptor, true);
        if (!send(user, &action)) {
            return false;
        }
        state->held = (uint16_t)(state->held | descriptor->modifier);
        *pressed = (uint16_t)(*pressed | descriptor->modifier);
    }
    return true;
}

static bool send_primary(const rfb_norm_key *key, bool down, bool repeat,
                         farsee_modifier_synth_send_fn send, void *user)
{
    const farsee_modifier_synth_action action =
        primary_action(key, down, repeat);
    return send(user, &action);
}

static void retain_primary_release(farsee_modifier_synth *state,
                                   const rfb_norm_key *key)
{
    state->pending_primary = primary_action(key, false, false);
    state->pending_primary_valid = true;
}

static bool reconcile_primary_release(farsee_modifier_synth *state,
                                      farsee_modifier_synth_send_fn send,
                                      void *user)
{
    if (!state->pending_primary_valid) {
        return true;
    }
    if (!send(user, &state->pending_primary)) {
        return false;
    }
    memset(&state->pending_primary, 0, sizeof state->pending_primary);
    state->pending_primary_valid = false;
    return true;
}

static farsee_cmd key_command(const farsee_modifier_synth_action *action,
                              bool preserve_rdp_fields)
{
    farsee_cmd command;
    memset(&command, 0, sizeof command);
    command.kind = FARSEE_CMD_KEY;
    command.key.logical = action->keysym;
    command.key.quality = FARSEE_INPUT_QUALITY_INFERRED;
    if (preserve_rdp_fields) {
        command.key.unicode = action->text;
        command.key.action = action->repeat
                                 ? FARSEE_KEY_REPEAT
                                 : (action->down ? FARSEE_KEY_PRESS
                                                 : FARSEE_KEY_RELEASE);
    } else {
        command.key.action =
            action->down ? FARSEE_KEY_PRESS : FARSEE_KEY_RELEASE;
    }
    return command;
}

bool farsee_modifier_synth_rfb_queue_send(
    void *user, const farsee_modifier_synth_action *action)
{
    if (user == NULL || action == NULL) {
        return false;
    }
    farsee_cmd command = key_command(action, false);
    return farsee_cmd_queue_push((farsee_cmd_queue *)user, &command);
}

bool farsee_modifier_synth_rdp_queue_send(
    void *user, const farsee_modifier_synth_action *action)
{
    if (user == NULL || action == NULL) {
        return false;
    }
    farsee_cmd command = key_command(action, true);
    return farsee_cmd_queue_push((farsee_cmd_queue *)user, &command);
}

bool farsee_modifier_synth_rdp_direct_send(
    void *user, const farsee_modifier_synth_action *action)
{
    farsee_modifier_synth_rdp_direct_adapter *adapter =
        (farsee_modifier_synth_rdp_direct_adapter *)user;
    if (adapter == NULL || action == NULL || adapter->deliver == NULL) {
        return false;
    }
    if (!adapter->deliver(adapter->user, action)) {
        return false;
    }
    if (adapter->ledger != NULL) {
        adapter->ledger(adapter->user, action);
    }
    return true;
}

bool farsee_modifier_synth_inject(farsee_modifier_synth *state,
                                  const rfb_norm_key *key,
                                  uint16_t physical_modifiers,
                                  farsee_modifier_synth_send_fn send,
                                  void *user)
{
    if (state == NULL || key == NULL) {
        return false;
    }
    const bool physical_action =
        rfb_norm_modkey_from_sym(key->keysym) != RFB_MODKEY_NONE;
    if (send == NULL) {
        if (physical_action) {
            state->stop_required = true;
        }
        return false;
    }
    if (state->stop_required) {
        return false;
    }
    if ((key->modifiers & (uint16_t)~normalized_modifiers()) != 0u) {
        if (physical_action) {
            state->stop_required = true;
        }
        return false;
    }
    if (!reconcile_primary_release(state, send, user)) {
        if (physical_action) {
            state->stop_required = true;
        }
        return false;
    }
    if (!reconcile_pending(state, send, user)) {
        if (physical_action) {
            state->stop_required = true;
        }
        return false;
    }

    // Physical modifier events are primary edges. They do not synthesize or
    // release normalized chord state.
    if (physical_action) {
        if (!send_primary(key, key->down, key->repeat, send, user)) {
            state->stop_required = true;
            return false;
        }
        return true;
    }

    if (!key->down) {
        const bool primary_delivered =
            send_primary(key, false, false, send, user);
        if (!primary_delivered) {
            retain_primary_release(state, key);
        }
        const bool releases_delivered =
            release_selected(state, state->held, send, user);
        return primary_delivered && releases_delivered;
    }

    const uint16_t held =
        (uint16_t)(physical_modifiers | state->held);
    const uint16_t needed = rfb_norm_mods_need_synth(key->modifiers, held);
    uint16_t pressed = RFB_MOD_NONE;
    if (!press_missing(state, needed, send, user, &pressed)) {
        (void)release_selected(state, pressed, send, user);
        return false;
    }
    if (!send_primary(key, true, key->repeat, send, user)) {
        (void)release_selected(state, pressed, send, user);
        return false;
    }

    if (key->repeat || key->source == RFB_NORM_SOURCE_KITTY) {
        return true;
    }

    const bool primary_released = send_primary(key, false, false, send, user);
    if (!primary_released) {
        retain_primary_release(state, key);
    }
    const bool modifiers_released =
        release_selected(state, state->held, send, user);
    return primary_released && modifiers_released;
}

uint16_t farsee_modifier_synth_held(const farsee_modifier_synth *state)
{
    return state != NULL ? state->held : RFB_MOD_NONE;
}

bool farsee_modifier_synth_needs_reconciliation(
    const farsee_modifier_synth *state)
{
    return state != NULL &&
           (state->reconcile != RFB_MOD_NONE ||
            state->pending_primary_valid);
}

bool farsee_modifier_synth_requires_stop(const farsee_modifier_synth *state)
{
    return state != NULL && state->stop_required;
}
