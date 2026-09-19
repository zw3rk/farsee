// SPDX-License-Identifier: Apache-2.0
//
// F5 — input ledger + clipboard broker tests (§12, §13).

#include "farsee/farsee_input.h"
#include "farsee/farsee_clipboard.h"
#include "tests/test_framework/rfb_test.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// --- key ledger: press/release/release-all ---------------------------------

RFB_TEST(farsee_input, ledger__press_release_tracks_down_keys)
{
    farsee_key_ledger l;
    farsee_key_ledger_init(&l);
    farsee_key_event press_a = {.physical = 4, .action = FARSEE_KEY_PRESS};
    farsee_key_event press_b = {.physical = 5, .action = FARSEE_KEY_PRESS};
    farsee_key_event rep_b   = {.physical = 5, .action = FARSEE_KEY_REPEAT};
    RFB_CHECK(farsee_key_ledger_apply(&l, &press_a));
    RFB_CHECK(farsee_key_ledger_apply(&l, &press_b));
    // Repeat of an already-down key is idempotent.
    RFB_CHECK(farsee_key_ledger_apply(&l, &rep_b));
    RFB_CHECK_EQ_UINT(l.count, 2u);

    farsee_key_event rel_a = {.physical = 4, .action = FARSEE_KEY_RELEASE};
    RFB_CHECK(farsee_key_ledger_apply(&l, &rel_a));
    RFB_CHECK_EQ_UINT(l.count, 1u);
    // Releasing a key that isn't down is a no-op.
    farsee_key_event rel_x = {.physical = 99, .action = FARSEE_KEY_RELEASE};
    RFB_CHECK(farsee_key_ledger_apply(&l, &rel_x));
    RFB_CHECK_EQ_UINT(l.count, 1u);
}

RFB_TEST(farsee_input, ledger__release_all_emits_down_set_and_clears)
{
    farsee_key_ledger l;
    farsee_key_ledger_init(&l);
    farsee_key_event presses[] = {
        {.physical = 10, .action = FARSEE_KEY_PRESS},
        {.physical = 11, .action = FARSEE_KEY_PRESS},
        {.physical = 12, .action = FARSEE_KEY_PRESS},
    };
    for (size_t i = 0; i < sizeof(presses)/sizeof(presses[0]); ++i) {
        RFB_CHECK(farsee_key_ledger_apply(&l, &presses[i]));
    }
    farsee_physical_key released[8];
    size_t n = farsee_key_ledger_release_all(&l, released, 8);
    RFB_CHECK_EQ_UINT(n, 3u);
    RFB_CHECK_EQ_UINT(l.count, 0u);
    // The released set must contain exactly {10,11,12} in some order.
    bool seen[16] = {false};
    for (size_t i = 0; i < n; ++i) {
        RFB_CHECK(released[i] < 16);
        seen[released[i]] = true;
    }
    RFB_CHECK(seen[10] && seen[11] && seen[12]);
}

RFB_TEST(farsee_input, ledger__press_overflow_returns_false)
{
    farsee_key_ledger l;
    farsee_key_ledger_init(&l);
    bool ok = true;
    for (size_t i = 0; i < FARSEE_KEY_LEDGER_MAX + 4; ++i) {
        farsee_key_event e = {.physical = (uint32_t)(i + 1),
                              .action = FARSEE_KEY_PRESS};
        if (!farsee_key_ledger_apply(&l, &e)) {
            ok = false;
            break;
        }
    }
    RFB_CHECK(ok == false);
    RFB_CHECK_EQ_UINT(l.count, FARSEE_KEY_LEDGER_MAX);
}

// Do not reset the ledger after a partial remote release leaves held keys.
// Pure ledger: release_all clears; document that callers must not init after
// partial inject release — apply after full clear only when count==0.
RFB_TEST(farsee_input, ledger__overflow_apply_only_when_capacity)
{
    farsee_key_ledger l;
    farsee_key_ledger_init(&l);
    for (size_t i = 0; i < FARSEE_KEY_LEDGER_MAX; ++i) {
        farsee_key_event e = {.physical = (uint32_t)(i + 1),
                              .action = FARSEE_KEY_PRESS};
        RFB_CHECK(farsee_key_ledger_apply(&l, &e));
    }
    farsee_key_event neu = {.physical = 999u, .action = FARSEE_KEY_PRESS};
    RFB_CHECK(!farsee_key_ledger_apply(&l, &neu));
    // Simulate partial release: remove one slot only.
    farsee_key_event up = {.physical = 1u, .action = FARSEE_KEY_RELEASE};
    RFB_CHECK(farsee_key_ledger_apply(&l, &up));
    RFB_CHECK(l.count == FARSEE_KEY_LEDGER_MAX - 1u);
    // New down fits without wiping survivors.
    RFB_CHECK(farsee_key_ledger_apply(&l, &neu));
    RFB_CHECK(l.count == FARSEE_KEY_LEDGER_MAX);
    // Key 2 must still be present (not wiped by init).
    bool saw2 = false;
    for (size_t i = 0; i < l.count; ++i) {
        if (l.down[i] == 2u) {
            saw2 = true;
        }
    }
    RFB_CHECK(saw2);
}

// A corrupted count must not index past down[MAX-1].
RFB_TEST(farsee_input, ledger__corrupted_count_clamped)
{
    farsee_key_ledger l;
    farsee_key_ledger_init(&l);
    l.count = FARSEE_KEY_LEDGER_MAX + 8u;
    farsee_key_event e = {.physical = 1u, .action = FARSEE_KEY_PRESS};
    // apply clamps and reports overflow (full).
    RFB_CHECK(!farsee_key_ledger_apply(&l, &e));
    RFB_CHECK_EQ_UINT(l.count, FARSEE_KEY_LEDGER_MAX);

    farsee_physical_key out[FARSEE_KEY_LEDGER_MAX];
    l.count = FARSEE_KEY_LEDGER_MAX + 3u;
    size_t n = farsee_key_ledger_release_all(&l, out, FARSEE_KEY_LEDGER_MAX);
    RFB_CHECK(n <= FARSEE_KEY_LEDGER_MAX);
    RFB_CHECK_EQ_UINT(l.count, 0u);
}

RFB_TEST(farsee_input, ledger__no_physical_identity_ignored)
{
    farsee_key_ledger l;
    farsee_key_ledger_init(&l);
    farsee_key_event e = {.physical = 0, .action = FARSEE_KEY_PRESS};
    RFB_CHECK(farsee_key_ledger_apply(&l, &e));
    RFB_CHECK_EQ_UINT(l.count, 0u);  // physical==0 is untracked
}

// --- clipboard policy ------------------------------------------------------

RFB_TEST(farsee_clipboard, policy__default_is_disabled)
{
    farsee_clip_policy p = farsee_clip_policy_default();
    RFB_CHECK(p.direction == FARSEE_CLIP_DIRECTION_DISABLED);
    RFB_CHECK(p.sanitize_escapes == true);
    RFB_CHECK(farsee_clip_policy_allows(&p, FARSEE_CLIP_DIRECTION_LOCAL_TO_REMOTE) == false);
    RFB_CHECK(farsee_clip_policy_size_ok(&p, 1024 * 1024) == true);
    RFB_CHECK(farsee_clip_policy_size_ok(&p, (1024 * 1024) + 1) == false);
}

RFB_TEST(farsee_clipboard, policy__direction_enforced)
{
    farsee_clip_policy p = farsee_clip_policy_default();
    p.direction = FARSEE_CLIP_DIRECTION_LOCAL_TO_REMOTE;
    RFB_CHECK(farsee_clip_policy_allows(&p, FARSEE_CLIP_DIRECTION_LOCAL_TO_REMOTE));
    RFB_CHECK(farsee_clip_policy_allows(&p, FARSEE_CLIP_DIRECTION_REMOTE_TO_LOCAL) == false);
    p.direction = FARSEE_CLIP_DIRECTION_BIDIRECTIONAL;
    RFB_CHECK(farsee_clip_policy_allows(&p, FARSEE_CLIP_DIRECTION_LOCAL_TO_REMOTE));
    RFB_CHECK(farsee_clip_policy_allows(&p, FARSEE_CLIP_DIRECTION_REMOTE_TO_LOCAL));
}

// --- escape sanitization (§13.3) -------------------------------------------

// Convert CF_TEXT Latin-1 to UTF-8 so bare C1 becomes C2 8x/9x.
RFB_TEST(farsee_clipboard, latin1_to_utf8__expands_high_and_c1)
{
    static const uint8_t in[] = {'a', 0x9Bu, 'b', 0xE9u, 0};
    char *u = NULL;
    size_t n = farsee_latin1_to_utf8_alloc(in, sizeof(in), &u);
    RFB_CHECK(n != (size_t)-1);
    RFB_CHECK(u != NULL);
    // a, C2 9B, b, C3 A9
    RFB_CHECK_EQ_UINT(n, 6u);
    RFB_CHECK_EQ_INT((unsigned char)u[0], 'a');
    RFB_CHECK_EQ_INT((unsigned char)u[1], 0xC2u);
    RFB_CHECK_EQ_INT((unsigned char)u[2], 0x9Bu);
    RFB_CHECK_EQ_INT((unsigned char)u[3], 'b');
    RFB_CHECK_EQ_INT((unsigned char)u[4], 0xC3u);
    RFB_CHECK_EQ_INT((unsigned char)u[5], 0xA9u);

    char san[16];
    size_t sn = farsee_clip_sanitize_text(san, sizeof san, u, n);
    RFB_CHECK(sn >= 4u);
    RFB_CHECK_EQ_INT(san[0], 'a');
    RFB_CHECK_EQ_INT(san[1], '.'); // C1 neutralized
    RFB_CHECK_EQ_INT(san[2], 'b');
    free(u);
}

RFB_TEST(farsee_clipboard, latin1_to_utf8__null_args)
{
    char *u = (char *)(uintptr_t)1;
    RFB_CHECK(farsee_latin1_to_utf8_alloc(NULL, 1, &u) == (size_t)-1);
    RFB_CHECK(u == NULL);
    RFB_CHECK(farsee_latin1_to_utf8_alloc((const uint8_t *)"x", 1, NULL) ==
              (size_t)-1);
}

RFB_TEST(farsee_clipboard, sanitize__strips_control_bytes_keeps_printable)
{
    char out[64];
    // ESC, BEL, NUL replaced with '.'; letters/tabs/newlines kept. Use the
    // full 13-byte payload (note: NUL is in-band and replaced with '.').
    const char in[] = {'a','\x1b','b','\x07','c','\t','d','\n','e','\0','f',(char)0x7f,'g'};
    size_t n = farsee_clip_sanitize_text(out, sizeof(out), in, sizeof(in));
    RFB_CHECK_EQ_UINT(n, sizeof(in));
    RFB_CHECK_EQ_INT(out[0], 'a');   // a
    RFB_CHECK_EQ_INT(out[1], '.');   // ESC -> .
    RFB_CHECK_EQ_INT(out[2], 'b');
    RFB_CHECK_EQ_INT(out[3], '.');   // BEL -> .
    RFB_CHECK_EQ_INT(out[4], 'c');
    RFB_CHECK_EQ_INT(out[5], '\t');
    RFB_CHECK_EQ_INT(out[6], 'd');
    RFB_CHECK_EQ_INT(out[7], '\n');
    RFB_CHECK_EQ_INT(out[8], 'e');
    RFB_CHECK_EQ_INT(out[9], '.');   // NUL -> .
    RFB_CHECK_EQ_INT(out[10], 'f');
    RFB_CHECK_EQ_INT(out[11], '.');  // DEL -> .
    RFB_CHECK_EQ_INT(out[12], 'g');
    RFB_CHECK(out[n] == '\0');
}

RFB_TEST(farsee_clipboard, sanitize__in_place_safe)
{
    char buf[] = "AB\x1b""CD";
    size_t len = 5;
    size_t n = farsee_clip_sanitize_text(buf, sizeof(buf), buf, len);
    RFB_CHECK_EQ_INT(n, 5u);
    RFB_CHECK_EQ_INT(buf[0], 'A');
    RFB_CHECK_EQ_INT(buf[1], 'B');
    RFB_CHECK_EQ_INT(buf[2], '.');
    RFB_CHECK_EQ_INT(buf[3], 'C');
    RFB_CHECK_EQ_INT(buf[4], 'D');
}

RFB_TEST(farsee_clipboard, sanitize__null_or_tiny_out_returns_zero)
{
    RFB_CHECK_EQ_UINT(farsee_clip_sanitize_text(NULL, 10, "x", 1), 0u);
    char tiny[1];
    RFB_CHECK_EQ_UINT(farsee_clip_sanitize_text(tiny, 1, "x", 1), 0u);
}

// Emoji and C1 controls.
RFB_TEST(farsee_clipboard, sanitize__keeps_emoji_strips_utf8_c1)
{
    char out[32];
    // 😀 F0 9F 98 80
    const char emoji[] = { (char)0xF0, (char)0x9F, (char)0x98, (char)0x80 };
    size_t n = farsee_clip_sanitize_text(out, sizeof out, emoji, sizeof emoji);
    RFB_CHECK_EQ_UINT(n, 4u);
    RFB_CHECK(memcmp(out, emoji, 4) == 0);
    // a C2 9B b → a . b (C1 replaced)
    const char c1[] = { 'a', (char)0xC2, (char)0x9B, 'b' };
    n = farsee_clip_sanitize_text(out, sizeof out, c1, sizeof c1);
    RFB_CHECK_EQ_UINT(n, 3u);
    RFB_CHECK_EQ_INT(out[0], 'a');
    RFB_CHECK_EQ_INT(out[1], '.');
    RFB_CHECK_EQ_INT(out[2], 'b');
}
