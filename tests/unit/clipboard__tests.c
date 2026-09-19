// SPDX-License-Identifier: Apache-2.0
//
// Clipboard policy tests.

#include "rfb_test.h"
#include "farsee/clipboard.h"

#include <string.h>

// ===========================================================================
// Policy defaults
// ===========================================================================

RFB_TEST(clip_pol, default_policy__sensitive_disabled_caps_16mib) {
    rfb_clip_policy p = rfb_clip_policy_default();
    RFB_CHECK(!p.sensitive_enabled);
    RFB_CHECK(p.sanitize_escapes);
    RFB_CHECK(p.loop_suppress);
    RFB_CHECK_EQ_UINT(p.max_bytes, RFB_CLIP_DEFAULT_MAX_BYTES);
}

// ===========================================================================
// UTF-8 validation (RFC 3629)
// ===========================================================================

RFB_TEST(clip_utf8, valid__ascii__true) {
    static const uint8_t s[] = "hello";
    RFB_CHECK(rfb_clip_utf8_valid(s, 5));
}

RFB_TEST(clip_utf8, valid__multibyte__true) {
    // "héllo" — é = U+00E9 = C3 A9
    static const uint8_t s[] = { 'h', 0xC3u, 0xA9u, 'l', 'l', 'o' };
    RFB_CHECK(rfb_clip_utf8_valid(s, sizeof s));
}

RFB_TEST(clip_utf8, valid__emoji_4byte__true) {
    // U+1F600 😀 = F0 9F 98 80
    static const uint8_t s[] = { 0xF0u, 0x9Fu, 0x98u, 0x80u };
    RFB_CHECK(rfb_clip_utf8_valid(s, sizeof s));
}

RFB_TEST(clip_utf8, valid__empty__true) {
    RFB_CHECK(rfb_clip_utf8_valid(NULL, 0));
}

RFB_TEST(clip_utf8, invalid__lone_continuation_byte__false) {
    static const uint8_t s[] = { 0x80u };
    RFB_CHECK(!rfb_clip_utf8_valid(s, 1));
}

RFB_TEST(clip_utf8, invalid__truncated_2byte__false) {
    static const uint8_t s[] = { 0xC3u };  // expects one more byte
    RFB_CHECK(!rfb_clip_utf8_valid(s, 1));
}

RFB_TEST(clip_utf8, invalid__overlong__false) {
    // overlong encoding of '/' (0x2F) as 2-byte: C0 AF
    static const uint8_t s[] = { 0xC0u, 0xAFu };
    RFB_CHECK(!rfb_clip_utf8_valid(s, sizeof s));
}

RFB_TEST(clip_utf8, invalid__surrogate_half__false) {
    // U+D800 encoded as 3-byte (ED A0 80) — surrogates are invalid UTF-8
    static const uint8_t s[] = { 0xEDu, 0xA0u, 0x80u };
    RFB_CHECK(!rfb_clip_utf8_valid(s, sizeof s));
}

RFB_TEST(clip_utf8, invalid__beyond_max__false) {
    // U+110000 (one past the max) = F4 90 80 80
    static const uint8_t s[] = { 0xF4u, 0x90u, 0x80u, 0x80u };
    RFB_CHECK(!rfb_clip_utf8_valid(s, sizeof s));
}

// ===========================================================================
// UTF-8 repair
// ===========================================================================

RFB_TEST(clip_utf8, repair__valid_passthrough_unchanged) {
    static const uint8_t s[] = { 'h', 0xC3u, 0xA9u, 'l' };
    uint8_t out[16] = { 0 };
    size_t n = 999;
    RFB_CHECK(rfb_clip_utf8_repair(s, sizeof s, out, sizeof out, &n));
    RFB_CHECK_EQ_UINT(n, sizeof s);
    RFB_CHECK_MEM_EQ(out, s, sizeof s);
}

RFB_TEST(clip_utf8, repair__invalid_byte_replaced_with_replacement) {
    static const uint8_t s[] = { 'a', 0x80u, 'b' };  // lone continuation
    uint8_t out[16] = { 0 };
    size_t n = 0;
    RFB_CHECK(rfb_clip_utf8_repair(s, sizeof s, out, sizeof out, &n));
    // 'a' + U+FFFD (EF BF BD) + 'b' = 5 bytes
    RFB_CHECK_EQ_UINT(n, 5u);
    RFB_CHECK_EQ_UINT(out[0], (uint8_t)'a');
    RFB_CHECK_EQ_UINT(out[1], 0xEFu);
    RFB_CHECK_EQ_UINT(out[2], 0xBFu);
    RFB_CHECK_EQ_UINT(out[3], 0xBDu);
    RFB_CHECK_EQ_UINT(out[4], (uint8_t)'b');
}

RFB_TEST(clip_utf8, repair__output_too_small__returns_false) {
    static const uint8_t s[] = { 'a', 0x80u, 'b' };  // needs 5 bytes
    uint8_t out[3] = { 0 };
    size_t n = 0;
    RFB_CHECK(!rfb_clip_utf8_repair(s, sizeof s, out, sizeof out, &n));
}

// ===========================================================================
// Terminal escape sanitization
// ===========================================================================

RFB_TEST(clip_san, byte_is_dropped__esc_and_control__true) {
    RFB_CHECK(rfb_clip_byte_is_dropped(0x1Bu));   // ESC
    RFB_CHECK(rfb_clip_byte_is_dropped(0x00u));   // NUL
    RFB_CHECK(rfb_clip_byte_is_dropped(0x07u));   // BEL
    RFB_CHECK(rfb_clip_byte_is_dropped(0x7Fu));   // DEL
}

RFB_TEST(clip_san, byte_is_dropped__tab_lf_cr_kept__false) {
    RFB_CHECK(!rfb_clip_byte_is_dropped(RFB_CLIP_SAN_KEEP_TAB));
    RFB_CHECK(!rfb_clip_byte_is_dropped(RFB_CLIP_SAN_KEEP_LF));
    RFB_CHECK(!rfb_clip_byte_is_dropped(RFB_CLIP_SAN_KEEP_CR));
    RFB_CHECK(!rfb_clip_byte_is_dropped((uint8_t)'A'));
}

RFB_TEST(clip_san, sanitize__strips_escape_bytes_only) {
    // Sanitization strips ESC (0x1B) and C0 controls, rendering ANSI escape
    // sequences inert by removing their introducer. Printable params of the
    // escape sequence ([ 3 1 m) are NOT control bytes, so they survive; the
    // ESC removal is sufficient to neutralize injection.
    //   "a\x1b[31mred\x1b[0mb" → "a[31mred[0mb"  (ESC bytes dropped)
    static const uint8_t s[] = { 'a', 0x1Bu, '[', '3', '1', 'm', 'r', 'e', 'd',
                                 0x1Bu, '[', '0', 'm', 'b' };
    uint8_t out[32] = { 0 };
    size_t n = 0;
    RFB_CHECK(rfb_clip_sanitize(s, sizeof s, out, sizeof out, &n));
    RFB_CHECK_EQ_UINT(n, 12u);  // 14 bytes - 2 ESC = 12
    static const uint8_t exp[] = { 'a', '[', '3', '1', 'm', 'r', 'e', 'd',
                                   '[', '0', 'm', 'b' };
    RFB_CHECK_MEM_EQ(out, exp, 12u);
}

// Bare 0x80–0x9F are UTF-8 continuations and must not be dropped.
RFB_TEST(clip_san, sanitize__keeps_utf8_emoji_and_latin)
{
    // É = C3 89; € = E2 82 AC; 😀 = F0 9F 98 80
    static const uint8_t s[] = {
        0xC3u, 0x89u, 0xE2u, 0x82u, 0xACu, 0xF0u, 0x9Fu, 0x98u, 0x80u
    };
    uint8_t out[32] = { 0 };
    size_t n = 0;
    RFB_CHECK(rfb_clip_sanitize(s, sizeof s, out, sizeof out, &n));
    RFB_CHECK_EQ_UINT(n, sizeof s);
    RFB_CHECK_MEM_EQ(out, s, sizeof s);
    RFB_CHECK(!rfb_clip_byte_is_dropped(0x80u));
    RFB_CHECK(!rfb_clip_byte_is_dropped(0x9Fu));
}

// UTF-8 C1 (C2 9B = U+009B CSI) is stripped.
RFB_TEST(clip_san, sanitize__strips_utf8_c1_csi)
{
    static const uint8_t s[] = { 'a', 0xC2u, 0x9Bu, '3', '1', 'm', 'b' };
    uint8_t out[16] = { 0 };
    size_t n = 0;
    RFB_CHECK(rfb_clip_sanitize(s, sizeof s, out, sizeof out, &n));
    RFB_CHECK_EQ_UINT(n, 5u); // a 31 m b
    static const uint8_t exp[] = { 'a', '3', '1', 'm', 'b' };
    RFB_CHECK_MEM_EQ(out, exp, 5u);
}

RFB_TEST(clip_san, sanitize__keeps_tab_lf_cr) {
    static const uint8_t s[] = { 'a', '\t', 'b', '\n', 'c', '\r', 'd' };
    uint8_t out[16] = { 0 };
    size_t n = 0;
    RFB_CHECK(rfb_clip_sanitize(s, sizeof s, out, sizeof out, &n));
    RFB_CHECK_EQ_UINT(n, sizeof s);
    RFB_CHECK_MEM_EQ(out, s, sizeof s);
}

RFB_TEST(clip_san, sanitize__in_place_compaction) {
    uint8_t buf[] = { 'x', 0x1Bu, 'y' };
    size_t n = 0;
    RFB_CHECK(rfb_clip_sanitize(buf, sizeof buf, buf, sizeof buf, &n));
    RFB_CHECK_EQ_UINT(n, 2u);
    RFB_CHECK_EQ_UINT(buf[0], (uint8_t)'x');
    RFB_CHECK_EQ_UINT(buf[1], (uint8_t)'y');
}

// ===========================================================================
// Size-cap enforcement
// ===========================================================================

RFB_TEST(clip_size, size_ok__under_cap__true) {
    rfb_clip_policy p = rfb_clip_policy_default();
    RFB_CHECK(rfb_clip_size_ok(&p, 100));
    RFB_CHECK(rfb_clip_size_ok(&p, p.max_bytes));
}

RFB_TEST(clip_size, size_ok__over_cap__false) {
    rfb_clip_policy p = rfb_clip_policy_default();
    RFB_CHECK(!rfb_clip_size_ok(&p, p.max_bytes + 1));
}

RFB_TEST(clip_size, allow_outbound__normal__true) {
    rfb_clip_policy p = rfb_clip_policy_default();
    RFB_CHECK(rfb_clip_allow_outbound(&p, 50));
}

RFB_TEST(clip_size, allow_outbound__empty__false) {
    rfb_clip_policy p = rfb_clip_policy_default();
    RFB_CHECK(!rfb_clip_allow_outbound(&p, 0));
}

RFB_TEST(clip_size, allow_outbound__oversized__false) {
    rfb_clip_policy p = rfb_clip_policy_default();
    RFB_CHECK(!rfb_clip_allow_outbound(&p, p.max_bytes + 1));
}

// ===========================================================================
// Loop suppression
// ===========================================================================

RFB_TEST(clip_loop, fnv1a__known_vector) {
    // FNV-1a 32 of "" = 0x811c9dc5
    RFB_CHECK_EQ_UINT(rfb_clip_fnv1a32(NULL, 0), 0x811c9dc5u);
    // FNV-1a 32 of "a" = 0xe40c292c
    static const uint8_t a[] = { 'a' };
    RFB_CHECK_EQ_UINT(rfb_clip_fnv1a32(a, 1), 0xe40c292cu);
}

RFB_TEST(clip_loop, record_then_check_same__is_echo) {
    rfb_clip_loop l;
    rfb_clip_loop_init(&l);
    static const uint8_t s[] = "from server";
    rfb_clip_loop_record_inbound(&l, s, sizeof s - 1u);
    RFB_CHECK(rfb_clip_loop_is_echo(&l, s, sizeof s - 1u));
}

RFB_TEST(clip_loop, check_different__not_echo) {
    rfb_clip_loop l;
    rfb_clip_loop_init(&l);
    static const uint8_t in[] = "from server";
    static const uint8_t out[] = "from client";
    rfb_clip_loop_record_inbound(&l, in, sizeof in - 1u);
    RFB_CHECK(!rfb_clip_loop_is_echo(&l, out, sizeof out - 1u));
}

RFB_TEST(clip_loop, no_record__nothing_is_echo) {
    rfb_clip_loop l;
    rfb_clip_loop_init(&l);
    static const uint8_t s[] = "anything";
    RFB_CHECK(!rfb_clip_loop_is_echo(&l, s, sizeof s - 1u));
}

RFB_TEST(clip_loop, clear__stops_suppressing) {
    rfb_clip_loop l;
    rfb_clip_loop_init(&l);
    static const uint8_t s[] = "from server";
    rfb_clip_loop_record_inbound(&l, s, sizeof s - 1u);
    RFB_CHECK(rfb_clip_loop_is_echo(&l, s, sizeof s - 1u));
    rfb_clip_loop_clear(&l);
    RFB_CHECK(!rfb_clip_loop_is_echo(&l, s, sizeof s - 1u));
}

// ===========================================================================
// Public boundary combinations
// ===========================================================================

RFB_TEST(clip_utf8, valid__covers_scalar_and_continuation_boundaries)
{
    static const uint8_t lowest_three[] = { 0xE0u, 0xA0u, 0x80u };
    static const uint8_t before_surrogates[] = { 0xEDu, 0x9Fu, 0xBFu };
    static const uint8_t lowest_four[] = { 0xF0u, 0x90u, 0x80u, 0x80u };
    static const uint8_t highest_scalar[] = { 0xF4u, 0x8Fu, 0xBFu, 0xBFu };
    static const uint8_t overlong_three[] = { 0xE0u, 0x9Fu, 0xBFu };
    static const uint8_t low_continuation[] = { 0xC2u, 0x7Fu };
    static const uint8_t high_continuation[] = { 0xC2u, 0xC0u };

    RFB_CHECK(rfb_clip_utf8_valid(lowest_three, sizeof lowest_three));
    RFB_CHECK(rfb_clip_utf8_valid(before_surrogates,
                                  sizeof before_surrogates));
    RFB_CHECK(rfb_clip_utf8_valid(lowest_four, sizeof lowest_four));
    RFB_CHECK(rfb_clip_utf8_valid(highest_scalar, sizeof highest_scalar));
    RFB_CHECK(!rfb_clip_utf8_valid(overlong_three, sizeof overlong_three));
    RFB_CHECK(!rfb_clip_utf8_valid(low_continuation,
                                   sizeof low_continuation));
    RFB_CHECK(!rfb_clip_utf8_valid(high_continuation,
                                   sizeof high_continuation));
    RFB_CHECK(!rfb_clip_utf8_valid(NULL, 1u));
}

RFB_TEST(clip_utf8, repair__covers_null_optional_and_capacity_boundaries)
{
    static const uint8_t ascii[] = { 'A' };
    static const uint8_t invalid[] = { 0x80u };
    static const uint8_t valid_two[] = { 0xC3u, 0xA9u };
    uint8_t out[4] = { 0 };
    size_t n = 99u;

    RFB_CHECK(!rfb_clip_utf8_repair(NULL, 0u, out, sizeof out, &n));
    RFB_CHECK_EQ_UINT(n, 0u);
    n = 99u;
    RFB_CHECK(!rfb_clip_utf8_repair(ascii, sizeof ascii, NULL, 0u, &n));
    RFB_CHECK_EQ_UINT(n, 0u);
    RFB_CHECK(rfb_clip_utf8_repair(ascii, sizeof ascii, out, sizeof out,
                                   NULL));

    n = 99u;
    RFB_CHECK(!rfb_clip_utf8_repair(invalid, sizeof invalid, out, 0u, &n));
    RFB_CHECK_EQ_UINT(n, 0u);
    n = 99u;
    RFB_CHECK(!rfb_clip_utf8_repair(valid_two, sizeof valid_two, out, 1u,
                                    &n));
    RFB_CHECK_EQ_UINT(n, 1u);
    RFB_CHECK_EQ_UINT(out[0], 0xC3u);
}

RFB_TEST(clip_utf8, repair__covers_multibyte_failure_modes)
{
    static const uint8_t valid_three[] = { 0xE0u, 0xA0u, 0x80u };
    static const uint8_t valid_four[] = { 0xF4u, 0x8Fu, 0xBFu, 0xBFu };
    static const uint8_t truncated[] = { 0xE2u, 0x82u };
    static const uint8_t low_continuation[] = { 0xC2u, 0x7Fu };
    static const uint8_t high_continuation[] = { 0xC2u, 0xC0u };
    static const uint8_t overlong[] = { 0xE0u, 0x9Fu, 0xBFu };
    static const uint8_t surrogate[] = { 0xEDu, 0xA0u, 0x80u };
    static const uint8_t beyond_max[] = { 0xF4u, 0x90u, 0x80u, 0x80u };
    uint8_t out[32] = { 0 };
    size_t n = 0u;

    RFB_CHECK(rfb_clip_utf8_repair(valid_three, sizeof valid_three, out,
                                   sizeof out, &n));
    RFB_CHECK_EQ_UINT(n, sizeof valid_three);
    RFB_CHECK_MEM_EQ(out, valid_three, sizeof valid_three);
    RFB_CHECK(rfb_clip_utf8_repair(valid_four, sizeof valid_four, out,
                                   sizeof out, &n));
    RFB_CHECK_EQ_UINT(n, sizeof valid_four);
    RFB_CHECK_MEM_EQ(out, valid_four, sizeof valid_four);

    RFB_CHECK(rfb_clip_utf8_repair(truncated, sizeof truncated, out,
                                   sizeof out, &n));
    RFB_CHECK_EQ_UINT(n, 6u);
    RFB_CHECK(rfb_clip_utf8_repair(low_continuation,
                                   sizeof low_continuation, out,
                                   sizeof out, &n));
    RFB_CHECK_EQ_UINT(n, 4u);
    RFB_CHECK(rfb_clip_utf8_repair(high_continuation,
                                   sizeof high_continuation, out,
                                   sizeof out, &n));
    RFB_CHECK_EQ_UINT(n, 6u);
    RFB_CHECK(rfb_clip_utf8_repair(overlong, sizeof overlong, out,
                                   sizeof out, &n));
    RFB_CHECK_EQ_UINT(n, 9u);
    RFB_CHECK(rfb_clip_utf8_repair(surrogate, sizeof surrogate, out,
                                   sizeof out, &n));
    RFB_CHECK_EQ_UINT(n, 9u);
    RFB_CHECK(rfb_clip_utf8_repair(beyond_max, sizeof beyond_max, out,
                                   sizeof out, &n));
    RFB_CHECK_EQ_UINT(n, 12u);
    RFB_CHECK(rfb_clip_utf8_valid(out, n));
}

RFB_TEST(clip_san, sanitize__covers_null_optional_and_capacity_boundaries)
{
    static const uint8_t ascii[] = { 'A' };
    static const uint8_t lone_c2[] = { 0xC2u };
    static const uint8_t below_c1[] = { 0xC2u, 0x7Fu };
    static const uint8_t above_c1[] = { 0xC2u, 0xA0u };
    static const uint8_t dropped[] = { 0x1Bu };
    uint8_t out[4] = { 0 };
    size_t n = 99u;

    RFB_CHECK(!rfb_clip_sanitize(NULL, 0u, out, sizeof out, &n));
    RFB_CHECK_EQ_UINT(n, 0u);
    n = 99u;
    RFB_CHECK(!rfb_clip_sanitize(ascii, sizeof ascii, NULL, 0u, &n));
    RFB_CHECK_EQ_UINT(n, 0u);
    RFB_CHECK(rfb_clip_sanitize(ascii, sizeof ascii, out, sizeof out, NULL));

    RFB_CHECK(rfb_clip_sanitize(lone_c2, sizeof lone_c2, out, sizeof out,
                                &n));
    RFB_CHECK_EQ_UINT(n, 1u);
    RFB_CHECK_EQ_UINT(out[0], 0xC2u);
    RFB_CHECK(rfb_clip_sanitize(below_c1, sizeof below_c1, out, sizeof out,
                                &n));
    RFB_CHECK_EQ_UINT(n, 1u);
    RFB_CHECK_EQ_UINT(out[0], 0xC2u);
    RFB_CHECK(rfb_clip_sanitize(above_c1, sizeof above_c1, out, sizeof out,
                                &n));
    RFB_CHECK_EQ_UINT(n, 2u);
    RFB_CHECK_MEM_EQ(out, above_c1, sizeof above_c1);

    n = 99u;
    RFB_CHECK(!rfb_clip_sanitize(ascii, sizeof ascii, out, 0u, &n));
    RFB_CHECK_EQ_UINT(n, 0u);
    RFB_CHECK(rfb_clip_sanitize(dropped, sizeof dropped, out, 0u, &n));
    RFB_CHECK_EQ_UINT(n, 0u);
}

RFB_TEST(clip_size, public_policy__covers_null_sensitive_and_limit_modes)
{
    rfb_clip_policy p = rfb_clip_policy_default();

    RFB_CHECK(!rfb_clip_size_ok(NULL, 0u));
    RFB_CHECK(!rfb_clip_allow_outbound(NULL, 1u));
    p.sensitive_enabled = true;
    RFB_CHECK(!rfb_clip_allow_outbound(&p, 1u));
    p.sensitive_enabled = false;
    p.max_bytes = 0u;
    RFB_CHECK(rfb_clip_size_ok(&p, 0u));
    RFB_CHECK(!rfb_clip_allow_outbound(&p, 1u));
    p.max_bytes = SIZE_MAX;
    RFB_CHECK(rfb_clip_size_ok(&p, SIZE_MAX));
    RFB_CHECK(rfb_clip_allow_outbound(&p, SIZE_MAX));
}

RFB_TEST(clip_loop, public_state__covers_null_and_empty_suppression)
{
    static const uint8_t nonempty[] = { 'x' };
    rfb_clip_loop l;

    rfb_clip_loop_init(NULL);
    rfb_clip_loop_record_inbound(NULL, nonempty, sizeof nonempty);
    RFB_CHECK(!rfb_clip_loop_is_echo(NULL, nonempty, sizeof nonempty));
    rfb_clip_loop_clear(NULL);

    rfb_clip_loop_init(&l);
    rfb_clip_loop_record_inbound(&l, NULL, 0u);
    RFB_CHECK(l.has_last);
    RFB_CHECK_EQ_UINT(l.last_inbound_hash, 0x811c9dc5u);
    RFB_CHECK(rfb_clip_loop_is_echo(&l, NULL, 0u));
    RFB_CHECK(rfb_clip_loop_is_echo(&l, nonempty, 0u));
    RFB_CHECK(!rfb_clip_loop_is_echo(&l, nonempty, sizeof nonempty));
    rfb_clip_loop_clear(&l);
    RFB_CHECK(!l.has_last);
    RFB_CHECK_EQ_UINT(l.last_inbound_hash, 0u);
}
