// SPDX-License-Identifier: Apache-2.0

#include "rfb_test.h"

#include "farsee/farsee_cmd_queue.h"
#include "farsee/modifier_synth.h"
#include "farsee/normalized_input.h"

#include <stdint.h>

#define SYNTH_TRACE_CAPACITY 32u

typedef struct synth_protocol_fake {
    farsee_modifier_synth_action trace[SYNTH_TRACE_CAPACITY];
    bool fail_call[SYNTH_TRACE_CAPACITY];
    size_t trace_count;
    size_t ledger_count;
} synth_protocol_fake;

typedef struct synth_rdp_adapter_fake {
    farsee_modifier_synth_action trace[SYNTH_TRACE_CAPACITY];
    bool fail_call[SYNTH_TRACE_CAPACITY];
    size_t trace_count;
    size_t ledger_count;
} synth_rdp_adapter_fake;

static bool synth_fake_rfb_send(
    void *user, const farsee_modifier_synth_action *action)
{
    synth_protocol_fake *fake = (synth_protocol_fake *)user;
    RFB_CHECK(fake != NULL);
    RFB_CHECK(action != NULL);
    RFB_CHECK(fake->trace_count < SYNTH_TRACE_CAPACITY);
    if (fake == NULL || action == NULL ||
        fake->trace_count >= SYNTH_TRACE_CAPACITY) {
        return false;
    }
    const size_t call = fake->trace_count;
    fake->trace[call] = *action;
    fake->trace_count++;
    return !fake->fail_call[call];
}

static bool synth_fake_rdp_send(
    void *user, const farsee_modifier_synth_action *action)
{
    synth_protocol_fake *fake = (synth_protocol_fake *)user;
    RFB_CHECK(fake != NULL);
    RFB_CHECK(action != NULL);
    RFB_CHECK(fake->trace_count < SYNTH_TRACE_CAPACITY);
    if (fake == NULL || action == NULL ||
        fake->trace_count >= SYNTH_TRACE_CAPACITY) {
        return false;
    }
    const size_t call = fake->trace_count;
    fake->trace[call] = *action;
    fake->trace_count++;
    if (fake->fail_call[call]) {
        return false;
    }
    // Mirrors rdp_live: protocol delivery succeeds before ledger update.
    fake->ledger_count++;
    return true;
}

static bool synth_rdp_adapter_deliver(
    void *user, const farsee_modifier_synth_action *action)
{
    synth_rdp_adapter_fake *fake = (synth_rdp_adapter_fake *)user;
    if (fake == NULL || action == NULL ||
        fake->trace_count >= SYNTH_TRACE_CAPACITY) {
        return false;
    }
    const size_t call = fake->trace_count;
    fake->trace[call] = *action;
    fake->trace_count++;
    return !fake->fail_call[call];
}

static void synth_rdp_adapter_ledger(
    void *user, const farsee_modifier_synth_action *action)
{
    synth_rdp_adapter_fake *fake = (synth_rdp_adapter_fake *)user;
    RFB_CHECK(fake != NULL);
    RFB_CHECK(action != NULL);
    if (fake != NULL && action != NULL) {
        fake->ledger_count++;
    }
}

static rfb_norm_key synth_key(uint32_t keysym, uint32_t text,
                              uint16_t modifiers, bool down, bool repeat,
                              rfb_norm_source source)
{
    const rfb_norm_key key = {
        .keysym = keysym,
        .text = text,
        .modifiers = modifiers,
        .down = down,
        .repeat = repeat,
        .source = source,
    };
    return key;
}

static void check_action(const farsee_modifier_synth_action *action,
                         farsee_modifier_synth_action_kind kind,
                         uint32_t keysym, uint32_t text, uint16_t modifier,
                         bool down, bool repeat)
{
    RFB_CHECK(action != NULL);
    RFB_CHECK_EQ_INT(action->kind, kind);
    RFB_CHECK_EQ_UINT(action->keysym, keysym);
    RFB_CHECK_EQ_UINT(action->text, text);
    RFB_CHECK_EQ_UINT(action->modifier, modifier);
    RFB_CHECK_EQ_INT(action->down, down);
    RFB_CHECK_EQ_INT(action->repeat, repeat);
}

static void check_protocol_parity(const farsee_modifier_synth *rfb_state,
                                  const farsee_modifier_synth *rdp_state,
                                  const synth_protocol_fake *rfb,
                                  const synth_protocol_fake *rdp)
{
    RFB_CHECK_EQ_UINT(farsee_modifier_synth_held(rfb_state),
                      farsee_modifier_synth_held(rdp_state));
    RFB_CHECK_EQ_INT(farsee_modifier_synth_needs_reconciliation(rfb_state),
                     farsee_modifier_synth_needs_reconciliation(rdp_state));
    RFB_CHECK_EQ_UINT(rfb->trace_count, rdp->trace_count);
    for (size_t i = 0u; i < rfb->trace_count; i++) {
        check_action(&rfb->trace[i], rdp->trace[i].kind,
                     rdp->trace[i].keysym, rdp->trace[i].text,
                     rdp->trace[i].modifier, rdp->trace[i].down,
                     rdp->trace[i].repeat);
    }
}

RFB_TEST(modifier_synth,
         inject__successful_kitty_cycle__has_rfb_rdp_trace_parity)
{
    farsee_modifier_synth rfb_state;
    farsee_modifier_synth rdp_state;
    farsee_modifier_synth_init(&rfb_state);
    farsee_modifier_synth_init(&rdp_state);
    synth_protocol_fake rfb = {0};
    synth_protocol_fake rdp = {0};
    rfb_norm_key key = synth_key(
        (uint32_t)'a', (uint32_t)'a',
        (uint16_t)(RFB_MOD_CONTROL | RFB_MOD_ALT), true, false,
        RFB_NORM_SOURCE_KITTY);

    RFB_CHECK(farsee_modifier_synth_inject(
        &rfb_state, &key, RFB_MOD_NONE, synth_fake_rfb_send, &rfb));
    RFB_CHECK(farsee_modifier_synth_inject(
        &rdp_state, &key, RFB_MOD_NONE, synth_fake_rdp_send, &rdp));
    key.down = false;
    RFB_CHECK(farsee_modifier_synth_inject(
        &rfb_state, &key, RFB_MOD_NONE, synth_fake_rfb_send, &rfb));
    RFB_CHECK(farsee_modifier_synth_inject(
        &rdp_state, &key, RFB_MOD_NONE, synth_fake_rdp_send, &rdp));

    check_protocol_parity(&rfb_state, &rdp_state, &rfb, &rdp);
    RFB_CHECK_EQ_UINT(rfb.trace_count, 6u);
    RFB_CHECK_EQ_UINT(rdp.ledger_count, 6u);
    check_action(&rfb.trace[0], FARSEE_MODIFIER_SYNTH_ACTION_MODIFIER,
                 XK_Control_L, 0u, RFB_MOD_CONTROL, true, false);
    check_action(&rfb.trace[1], FARSEE_MODIFIER_SYNTH_ACTION_MODIFIER,
                 XK_Alt_L, 0u, RFB_MOD_ALT, true, false);
    check_action(&rfb.trace[2], FARSEE_MODIFIER_SYNTH_ACTION_PRIMARY,
                 (uint32_t)'a', (uint32_t)'a', RFB_MOD_NONE, true, false);
    check_action(&rfb.trace[3], FARSEE_MODIFIER_SYNTH_ACTION_PRIMARY,
                 (uint32_t)'a', (uint32_t)'a', RFB_MOD_NONE, false, false);
    check_action(&rfb.trace[4], FARSEE_MODIFIER_SYNTH_ACTION_MODIFIER,
                 XK_Alt_L, 0u, RFB_MOD_ALT, false, false);
    check_action(&rfb.trace[5], FARSEE_MODIFIER_SYNTH_ACTION_MODIFIER,
                 XK_Control_L, 0u, RFB_MOD_CONTROL, false, false);
    RFB_CHECK_EQ_UINT(farsee_modifier_synth_held(&rfb_state), RFB_MOD_NONE);
}

RFB_TEST(modifier_synth,
         inject__legacy_press__sends_auto_up_and_releases_modifier)
{
    farsee_modifier_synth state;
    farsee_modifier_synth_init(&state);
    synth_protocol_fake fake = {0};
    const rfb_norm_key key = synth_key(
        (uint32_t)'x', (uint32_t)'x', RFB_MOD_CONTROL, true, false,
        RFB_NORM_SOURCE_LEGACY);

    RFB_CHECK(farsee_modifier_synth_inject(
        &state, &key, RFB_MOD_NONE, synth_fake_rfb_send, &fake));
    RFB_CHECK_EQ_UINT(fake.trace_count, 4u);
    check_action(&fake.trace[0], FARSEE_MODIFIER_SYNTH_ACTION_MODIFIER,
                 XK_Control_L, 0u, RFB_MOD_CONTROL, true, false);
    check_action(&fake.trace[1], FARSEE_MODIFIER_SYNTH_ACTION_PRIMARY,
                 (uint32_t)'x', (uint32_t)'x', RFB_MOD_NONE, true, false);
    check_action(&fake.trace[2], FARSEE_MODIFIER_SYNTH_ACTION_PRIMARY,
                 (uint32_t)'x', (uint32_t)'x', RFB_MOD_NONE, false, false);
    check_action(&fake.trace[3], FARSEE_MODIFIER_SYNTH_ACTION_MODIFIER,
                 XK_Control_L, 0u, RFB_MOD_CONTROL, false, false);
    RFB_CHECK_EQ_UINT(farsee_modifier_synth_held(&state), RFB_MOD_NONE);
}

RFB_TEST(modifier_synth,
         inject__modifier_press_fails__sends_no_primary_and_cleans_up)
{
    farsee_modifier_synth rfb_state;
    farsee_modifier_synth rdp_state;
    farsee_modifier_synth_init(&rfb_state);
    farsee_modifier_synth_init(&rdp_state);
    synth_protocol_fake rfb = {.fail_call = {[1] = true}};
    synth_protocol_fake rdp = {.fail_call = {[1] = true}};
    const rfb_norm_key key = synth_key(
        (uint32_t)'a', (uint32_t)'a',
        (uint16_t)(RFB_MOD_SHIFT | RFB_MOD_CONTROL), true, false,
        RFB_NORM_SOURCE_KITTY);

    RFB_CHECK(!farsee_modifier_synth_inject(
        &rfb_state, &key, RFB_MOD_NONE, synth_fake_rfb_send, &rfb));
    RFB_CHECK(!farsee_modifier_synth_inject(
        &rdp_state, &key, RFB_MOD_NONE, synth_fake_rdp_send, &rdp));

    check_protocol_parity(&rfb_state, &rdp_state, &rfb, &rdp);
    RFB_CHECK_EQ_UINT(rfb.trace_count, 3u);
    RFB_CHECK_EQ_UINT(rdp.ledger_count, 2u);
    check_action(&rfb.trace[2], FARSEE_MODIFIER_SYNTH_ACTION_MODIFIER,
                 XK_Shift_L, 0u, RFB_MOD_SHIFT, false, false);
    RFB_CHECK_EQ_UINT(farsee_modifier_synth_held(&rfb_state), RFB_MOD_NONE);
    RFB_CHECK(!farsee_modifier_synth_needs_reconciliation(&rfb_state));
}

RFB_TEST(modifier_synth,
         inject__cleanup_fails__reconciles_before_next_primary)
{
    farsee_modifier_synth rfb_state;
    farsee_modifier_synth rdp_state;
    farsee_modifier_synth_init(&rfb_state);
    farsee_modifier_synth_init(&rdp_state);
    synth_protocol_fake rfb = {
        .fail_call = {[1] = true, [2] = true},
    };
    synth_protocol_fake rdp = {
        .fail_call = {[1] = true, [2] = true},
    };
    const rfb_norm_key failed = synth_key(
        (uint32_t)'a', (uint32_t)'a',
        (uint16_t)(RFB_MOD_SHIFT | RFB_MOD_CONTROL), true, false,
        RFB_NORM_SOURCE_KITTY);
    const rfb_norm_key next = synth_key(
        (uint32_t)'b', (uint32_t)'b', RFB_MOD_NONE, true, false,
        RFB_NORM_SOURCE_KITTY);

    RFB_CHECK(!farsee_modifier_synth_inject(
        &rfb_state, &failed, RFB_MOD_NONE, synth_fake_rfb_send, &rfb));
    RFB_CHECK(!farsee_modifier_synth_inject(
        &rdp_state, &failed, RFB_MOD_NONE, synth_fake_rdp_send, &rdp));
    RFB_CHECK(farsee_modifier_synth_needs_reconciliation(&rfb_state));
    RFB_CHECK_EQ_UINT(farsee_modifier_synth_held(&rfb_state), RFB_MOD_SHIFT);

    RFB_CHECK(farsee_modifier_synth_inject(
        &rfb_state, &next, RFB_MOD_NONE, synth_fake_rfb_send, &rfb));
    RFB_CHECK(farsee_modifier_synth_inject(
        &rdp_state, &next, RFB_MOD_NONE, synth_fake_rdp_send, &rdp));

    check_protocol_parity(&rfb_state, &rdp_state, &rfb, &rdp);
    RFB_CHECK_EQ_UINT(rfb.trace_count, 5u);
    check_action(&rfb.trace[3], FARSEE_MODIFIER_SYNTH_ACTION_MODIFIER,
                 XK_Shift_L, 0u, RFB_MOD_SHIFT, false, false);
    check_action(&rfb.trace[4], FARSEE_MODIFIER_SYNTH_ACTION_PRIMARY,
                 (uint32_t)'b', (uint32_t)'b', RFB_MOD_NONE, true, false);
    RFB_CHECK(!farsee_modifier_synth_needs_reconciliation(&rfb_state));
}

RFB_TEST(modifier_synth,
         inject__primary_down_fails__cleans_up_and_reconciles)
{
    farsee_modifier_synth rfb_state;
    farsee_modifier_synth rdp_state;
    farsee_modifier_synth_init(&rfb_state);
    farsee_modifier_synth_init(&rdp_state);
    synth_protocol_fake rfb = {
        .fail_call = {[1] = true, [2] = true},
    };
    synth_protocol_fake rdp = {
        .fail_call = {[1] = true, [2] = true},
    };
    const rfb_norm_key failed = synth_key(
        (uint32_t)'a', (uint32_t)'a', RFB_MOD_CONTROL, true, false,
        RFB_NORM_SOURCE_KITTY);
    const rfb_norm_key next = synth_key(
        (uint32_t)'b', (uint32_t)'b', RFB_MOD_NONE, true, false,
        RFB_NORM_SOURCE_KITTY);

    RFB_CHECK(!farsee_modifier_synth_inject(
        &rfb_state, &failed, RFB_MOD_NONE, synth_fake_rfb_send, &rfb));
    RFB_CHECK(!farsee_modifier_synth_inject(
        &rdp_state, &failed, RFB_MOD_NONE, synth_fake_rdp_send, &rdp));
    check_protocol_parity(&rfb_state, &rdp_state, &rfb, &rdp);
    RFB_CHECK_EQ_UINT(rdp.ledger_count, 1u);
    RFB_CHECK_EQ_UINT(farsee_modifier_synth_held(&rfb_state),
                      RFB_MOD_CONTROL);
    RFB_CHECK(farsee_modifier_synth_needs_reconciliation(&rfb_state));

    RFB_CHECK(farsee_modifier_synth_inject(
        &rfb_state, &next, RFB_MOD_NONE, synth_fake_rfb_send, &rfb));
    RFB_CHECK(farsee_modifier_synth_inject(
        &rdp_state, &next, RFB_MOD_NONE, synth_fake_rdp_send, &rdp));

    check_protocol_parity(&rfb_state, &rdp_state, &rfb, &rdp);
    RFB_CHECK_EQ_UINT(rfb.trace_count, 5u);
    RFB_CHECK_EQ_UINT(rdp.ledger_count, 3u);
    check_action(&rfb.trace[0], FARSEE_MODIFIER_SYNTH_ACTION_MODIFIER,
                 XK_Control_L, 0u, RFB_MOD_CONTROL, true, false);
    check_action(&rfb.trace[1], FARSEE_MODIFIER_SYNTH_ACTION_PRIMARY,
                 (uint32_t)'a', (uint32_t)'a', RFB_MOD_NONE, true, false);
    check_action(&rfb.trace[2], FARSEE_MODIFIER_SYNTH_ACTION_MODIFIER,
                 XK_Control_L, 0u, RFB_MOD_CONTROL, false, false);
    check_action(&rfb.trace[3], FARSEE_MODIFIER_SYNTH_ACTION_MODIFIER,
                 XK_Control_L, 0u, RFB_MOD_CONTROL, false, false);
    check_action(&rfb.trace[4], FARSEE_MODIFIER_SYNTH_ACTION_PRIMARY,
                 (uint32_t)'b', (uint32_t)'b', RFB_MOD_NONE, true, false);
    RFB_CHECK(!farsee_modifier_synth_needs_reconciliation(&rfb_state));
}

RFB_TEST(modifier_synth,
         inject__key_up_release_fails__next_primary_reconciles_first)
{
    farsee_modifier_synth rfb_state;
    farsee_modifier_synth rdp_state;
    farsee_modifier_synth_init(&rfb_state);
    farsee_modifier_synth_init(&rdp_state);
    synth_protocol_fake rfb = {0};
    synth_protocol_fake rdp = {0};
    rfb_norm_key key = synth_key(
        (uint32_t)'a', (uint32_t)'a', RFB_MOD_CONTROL, true, false,
        RFB_NORM_SOURCE_KITTY);

    RFB_CHECK(farsee_modifier_synth_inject(
        &rfb_state, &key, RFB_MOD_NONE, synth_fake_rfb_send, &rfb));
    RFB_CHECK(farsee_modifier_synth_inject(
        &rdp_state, &key, RFB_MOD_NONE, synth_fake_rdp_send, &rdp));
    rfb.fail_call[3] = true;
    rdp.fail_call[3] = true;
    key.down = false;
    RFB_CHECK(!farsee_modifier_synth_inject(
        &rfb_state, &key, RFB_MOD_NONE, synth_fake_rfb_send, &rfb));
    RFB_CHECK(!farsee_modifier_synth_inject(
        &rdp_state, &key, RFB_MOD_NONE, synth_fake_rdp_send, &rdp));
    RFB_CHECK(farsee_modifier_synth_needs_reconciliation(&rfb_state));

    const rfb_norm_key next = synth_key(
        (uint32_t)'b', (uint32_t)'b', RFB_MOD_NONE, true, false,
        RFB_NORM_SOURCE_KITTY);
    RFB_CHECK(farsee_modifier_synth_inject(
        &rfb_state, &next, RFB_MOD_NONE, synth_fake_rfb_send, &rfb));
    RFB_CHECK(farsee_modifier_synth_inject(
        &rdp_state, &next, RFB_MOD_NONE, synth_fake_rdp_send, &rdp));

    check_protocol_parity(&rfb_state, &rdp_state, &rfb, &rdp);
    RFB_CHECK_EQ_UINT(rfb.trace_count, 6u);
    check_action(&rfb.trace[4], FARSEE_MODIFIER_SYNTH_ACTION_MODIFIER,
                 XK_Control_L, 0u, RFB_MOD_CONTROL, false, false);
    check_action(&rfb.trace[5], FARSEE_MODIFIER_SYNTH_ACTION_PRIMARY,
                 (uint32_t)'b', (uint32_t)'b', RFB_MOD_NONE, true, false);
}

RFB_TEST(modifier_synth,
         inject__primary_key_up_fails__retries_before_next_primary)
{
    farsee_modifier_synth rfb_state;
    farsee_modifier_synth rdp_state;
    farsee_modifier_synth_init(&rfb_state);
    farsee_modifier_synth_init(&rdp_state);
    synth_protocol_fake rfb = {0};
    synth_protocol_fake rdp = {0};
    rfb_norm_key key = synth_key(
        (uint32_t)'a', (uint32_t)'a', RFB_MOD_CONTROL, true, false,
        RFB_NORM_SOURCE_KITTY);

    RFB_CHECK(farsee_modifier_synth_inject(
        &rfb_state, &key, RFB_MOD_NONE, synth_fake_rfb_send, &rfb));
    RFB_CHECK(farsee_modifier_synth_inject(
        &rdp_state, &key, RFB_MOD_NONE, synth_fake_rdp_send, &rdp));
    rfb.fail_call[2] = true;
    rdp.fail_call[2] = true;
    key.down = false;
    RFB_CHECK(!farsee_modifier_synth_inject(
        &rfb_state, &key, RFB_MOD_NONE, synth_fake_rfb_send, &rfb));
    RFB_CHECK(!farsee_modifier_synth_inject(
        &rdp_state, &key, RFB_MOD_NONE, synth_fake_rdp_send, &rdp));
    RFB_CHECK(farsee_modifier_synth_needs_reconciliation(&rfb_state));
    RFB_CHECK_EQ_UINT(farsee_modifier_synth_held(&rfb_state), RFB_MOD_NONE);

    const rfb_norm_key next = synth_key(
        (uint32_t)'b', (uint32_t)'b', RFB_MOD_NONE, true, false,
        RFB_NORM_SOURCE_KITTY);
    RFB_CHECK(farsee_modifier_synth_inject(
        &rfb_state, &next, RFB_MOD_NONE, synth_fake_rfb_send, &rfb));
    RFB_CHECK(farsee_modifier_synth_inject(
        &rdp_state, &next, RFB_MOD_NONE, synth_fake_rdp_send, &rdp));

    check_protocol_parity(&rfb_state, &rdp_state, &rfb, &rdp);
    RFB_CHECK_EQ_UINT(rfb.trace_count, 6u);
    check_action(&rfb.trace[4], FARSEE_MODIFIER_SYNTH_ACTION_PRIMARY,
                 (uint32_t)'a', (uint32_t)'a', RFB_MOD_NONE, false, false);
    check_action(&rfb.trace[5], FARSEE_MODIFIER_SYNTH_ACTION_PRIMARY,
                 (uint32_t)'b', (uint32_t)'b', RFB_MOD_NONE, true, false);
    RFB_CHECK(!farsee_modifier_synth_needs_reconciliation(&rfb_state));
}

RFB_TEST(modifier_synth,
         inject__physical_or_caps_delivery_fails__requires_stop)
{
    const uint32_t keysyms[] = {XK_Shift_L, XK_Caps_Lock};
    for (size_t i = 0u; i < sizeof keysyms / sizeof keysyms[0]; i++) {
        farsee_modifier_synth state;
        farsee_modifier_synth_init(&state);
        synth_protocol_fake fake = {.fail_call = {[0] = true}};
        const rfb_norm_key physical = synth_key(
            keysyms[i], 0u, RFB_MOD_NONE, true, false,
            RFB_NORM_SOURCE_KITTY);
        const rfb_norm_key next = synth_key(
            (uint32_t)'a', (uint32_t)'a', RFB_MOD_NONE, true, false,
            RFB_NORM_SOURCE_KITTY);

        RFB_CHECK(!farsee_modifier_synth_inject(
            &state, &physical, RFB_MOD_NONE, synth_fake_rfb_send, &fake));
        RFB_CHECK(farsee_modifier_synth_requires_stop(&state));
        RFB_CHECK(!farsee_modifier_synth_inject(
            &state, &next, RFB_MOD_NONE, synth_fake_rfb_send, &fake));
        RFB_CHECK_EQ_UINT(fake.trace_count, 1u);
    }
}

RFB_TEST(modifier_synth,
         inject__physical_preflight_reconciliation_fails__requires_stop)
{
    farsee_modifier_synth state;
    farsee_modifier_synth_init(&state);
    synth_protocol_fake fake = {
        .fail_call = {[1] = true, [2] = true, [3] = true},
    };
    const rfb_norm_key failed_chord = synth_key(
        (uint32_t)'a', (uint32_t)'a',
        (uint16_t)(RFB_MOD_SHIFT | RFB_MOD_CONTROL), true, false,
        RFB_NORM_SOURCE_KITTY);
    const rfb_norm_key physical = synth_key(
        XK_Shift_L, 0u, RFB_MOD_NONE, true, false,
        RFB_NORM_SOURCE_KITTY);
    const rfb_norm_key later = synth_key(
        (uint32_t)'b', (uint32_t)'b', RFB_MOD_NONE, true, false,
        RFB_NORM_SOURCE_KITTY);

    RFB_CHECK(!farsee_modifier_synth_inject(
        &state, &failed_chord, RFB_MOD_NONE, synth_fake_rfb_send, &fake));
    RFB_CHECK(farsee_modifier_synth_needs_reconciliation(&state));
    RFB_CHECK(!farsee_modifier_synth_requires_stop(&state));
    RFB_CHECK(!farsee_modifier_synth_inject(
        &state, &physical, RFB_MOD_SHIFT, synth_fake_rfb_send, &fake));
    RFB_CHECK(farsee_modifier_synth_requires_stop(&state));
    RFB_CHECK_EQ_UINT(fake.trace_count, 4u);
    check_action(&fake.trace[3], FARSEE_MODIFIER_SYNTH_ACTION_MODIFIER,
                 XK_Shift_L, 0u, RFB_MOD_SHIFT, false, false);

    RFB_CHECK(!farsee_modifier_synth_inject(
        &state, &later, RFB_MOD_NONE, synth_fake_rfb_send, &fake));
    RFB_CHECK_EQ_UINT(fake.trace_count, 4u);

    farsee_modifier_synth primary_state;
    farsee_modifier_synth_init(&primary_state);
    synth_protocol_fake primary_fake = {
        .fail_call = {[1] = true, [2] = true},
    };
    rfb_norm_key pending_primary = synth_key(
        (uint32_t)'a', (uint32_t)'a', RFB_MOD_NONE, true, false,
        RFB_NORM_SOURCE_KITTY);
    RFB_CHECK(farsee_modifier_synth_inject(
        &primary_state, &pending_primary, RFB_MOD_NONE,
        synth_fake_rfb_send, &primary_fake));
    pending_primary.down = false;
    RFB_CHECK(!farsee_modifier_synth_inject(
        &primary_state, &pending_primary, RFB_MOD_NONE,
        synth_fake_rfb_send, &primary_fake));
    RFB_CHECK(farsee_modifier_synth_needs_reconciliation(&primary_state));
    RFB_CHECK(!farsee_modifier_synth_requires_stop(&primary_state));
    RFB_CHECK(!farsee_modifier_synth_inject(
        &primary_state, &physical, RFB_MOD_SHIFT,
        synth_fake_rfb_send, &primary_fake));
    RFB_CHECK(farsee_modifier_synth_requires_stop(&primary_state));
    RFB_CHECK_EQ_UINT(primary_fake.trace_count, 3u);
    check_action(&primary_fake.trace[2],
                 FARSEE_MODIFIER_SYNTH_ACTION_PRIMARY,
                 (uint32_t)'a', (uint32_t)'a', RFB_MOD_NONE, false, false);
    RFB_CHECK(!farsee_modifier_synth_inject(
        &primary_state, &later, RFB_MOD_NONE,
        synth_fake_rfb_send, &primary_fake));
    RFB_CHECK_EQ_UINT(primary_fake.trace_count, 3u);

    farsee_modifier_synth unknown_state;
    farsee_modifier_synth_init(&unknown_state);
    synth_protocol_fake unknown_fake = {0};
    const rfb_norm_key unknown_physical = synth_key(
        XK_Caps_Lock, 0u, UINT16_C(0x8000), true, false,
        RFB_NORM_SOURCE_KITTY);
    RFB_CHECK(!farsee_modifier_synth_inject(
        &unknown_state, &unknown_physical, RFB_MOD_NONE,
        synth_fake_rfb_send, &unknown_fake));
    RFB_CHECK(farsee_modifier_synth_requires_stop(&unknown_state));
    RFB_CHECK_EQ_UINT(unknown_fake.trace_count, 0u);
}

RFB_TEST(modifier_synth,
         adapters__real_rfb_rdp_queues__preserve_protocol_mapping)
{
    farsee_cmd_queue rfb_queue;
    farsee_cmd_queue rdp_queue;
    RFB_CHECK(farsee_cmd_queue_init(&rfb_queue));
    RFB_CHECK(farsee_cmd_queue_init(&rdp_queue));
    farsee_modifier_synth rfb_state;
    farsee_modifier_synth rdp_state;
    farsee_modifier_synth_init(&rfb_state);
    farsee_modifier_synth_init(&rdp_state);
    rfb_norm_key key = synth_key(
        (uint32_t)'a', 0x00E9u, RFB_MOD_CONTROL, true, true,
        RFB_NORM_SOURCE_KITTY);

    RFB_CHECK(farsee_modifier_synth_inject(
        &rfb_state, &key, RFB_MOD_NONE,
        farsee_modifier_synth_rfb_queue_send, &rfb_queue));
    RFB_CHECK(farsee_modifier_synth_inject(
        &rdp_state, &key, RFB_MOD_NONE,
        farsee_modifier_synth_rdp_queue_send, &rdp_queue));

    farsee_cmd rfb_mod;
    farsee_cmd rfb_primary;
    farsee_cmd rdp_mod;
    farsee_cmd rdp_primary;
    const uint64_t deadline = farsee_thread_monotonic_ms() + 1000u;
    RFB_CHECK(farsee_cmd_queue_pop(&rfb_queue, &rfb_mod, deadline, NULL));
    RFB_CHECK(farsee_cmd_queue_pop(&rfb_queue, &rfb_primary, deadline, NULL));
    RFB_CHECK(farsee_cmd_queue_pop(&rdp_queue, &rdp_mod, deadline, NULL));
    RFB_CHECK(farsee_cmd_queue_pop(&rdp_queue, &rdp_primary, deadline, NULL));
    RFB_CHECK_EQ_UINT(rfb_mod.key.logical, rdp_mod.key.logical);
    RFB_CHECK_EQ_INT(rfb_mod.key.action, FARSEE_KEY_PRESS);
    RFB_CHECK_EQ_INT(rdp_mod.key.action, FARSEE_KEY_PRESS);
    RFB_CHECK_EQ_UINT(rfb_primary.key.logical, rdp_primary.key.logical);
    RFB_CHECK_EQ_INT(rfb_primary.key.action, FARSEE_KEY_PRESS);
    RFB_CHECK_EQ_INT(rdp_primary.key.action, FARSEE_KEY_REPEAT);
    RFB_CHECK_EQ_UINT(rfb_primary.key.unicode, 0u);
    RFB_CHECK_EQ_UINT(rdp_primary.key.unicode, 0x00E9u);
    RFB_CHECK_EQ_UINT(farsee_modifier_synth_held(&rfb_state),
                      farsee_modifier_synth_held(&rdp_state));
    farsee_cmd_queue_destroy(&rfb_queue);
    farsee_cmd_queue_destroy(&rdp_queue);
}

RFB_TEST(modifier_synth,
         adapter__rdp_direct__updates_ledger_only_after_delivery)
{
    synth_rdp_adapter_fake fake = {.fail_call = {[1] = true}};
    farsee_modifier_synth_rdp_direct_adapter adapter = {
        .user = &fake,
        .deliver = synth_rdp_adapter_deliver,
        .ledger = synth_rdp_adapter_ledger,
    };
    const farsee_modifier_synth_action press = {
        .kind = FARSEE_MODIFIER_SYNTH_ACTION_PRIMARY,
        .keysym = (uint32_t)'a',
        .text = (uint32_t)'a',
        .modifier = RFB_MOD_NONE,
        .down = true,
        .repeat = false,
    };

    RFB_CHECK(farsee_modifier_synth_rdp_direct_send(&adapter, &press));
    RFB_CHECK(!farsee_modifier_synth_rdp_direct_send(&adapter, &press));
    RFB_CHECK_EQ_UINT(fake.trace_count, 2u);
    RFB_CHECK_EQ_UINT(fake.ledger_count, 1u);
}

RFB_TEST(modifier_synth,
         inject__capslock_and_unknown_bits__accepts_known_only)
{
    farsee_modifier_synth state;
    farsee_modifier_synth_init(&state);
    synth_protocol_fake fake = {0};
    rfb_norm_key key = synth_key(
        (uint32_t)'a', (uint32_t)'a', RFB_MOD_CAPSLOCK, true, false,
        RFB_NORM_SOURCE_KITTY);

    RFB_CHECK(farsee_modifier_synth_inject(
        &state, &key, RFB_MOD_NONE, synth_fake_rfb_send, &fake));
    RFB_CHECK_EQ_UINT(fake.trace_count, 1u);
    check_action(&fake.trace[0], FARSEE_MODIFIER_SYNTH_ACTION_PRIMARY,
                 (uint32_t)'a', (uint32_t)'a', RFB_MOD_NONE, true, false);
    key.modifiers = 0x8000u;
    RFB_CHECK(!farsee_modifier_synth_inject(
        &state, &key, RFB_MOD_NONE, synth_fake_rfb_send, &fake));
    RFB_CHECK_EQ_UINT(fake.trace_count, 1u);
    RFB_CHECK_EQ_UINT(farsee_modifier_synth_held(&state), RFB_MOD_NONE);
}

RFB_TEST(modifier_synth, inject__null_state_key_or_callback__fails_closed)
{
    farsee_modifier_synth state;
    farsee_modifier_synth_init(&state);
    synth_protocol_fake fake = {0};
    const rfb_norm_key key = synth_key(
        (uint32_t)'a', (uint32_t)'a', RFB_MOD_NONE, true, false,
        RFB_NORM_SOURCE_KITTY);

    farsee_modifier_synth_init(NULL);
    RFB_CHECK(!farsee_modifier_synth_inject(
        NULL, &key, RFB_MOD_NONE, synth_fake_rfb_send, &fake));
    RFB_CHECK(!farsee_modifier_synth_inject(
        &state, NULL, RFB_MOD_NONE, synth_fake_rfb_send, &fake));
    RFB_CHECK(!farsee_modifier_synth_inject(
        &state, &key, RFB_MOD_NONE, NULL, &fake));
    RFB_CHECK_EQ_UINT(fake.trace_count, 0u);
    RFB_CHECK_EQ_UINT(farsee_modifier_synth_held(NULL), RFB_MOD_NONE);
    RFB_CHECK(!farsee_modifier_synth_needs_reconciliation(NULL));
}
