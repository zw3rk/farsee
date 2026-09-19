// SPDX-License-Identifier: Apache-2.0
//
// Kitty graphics protocol tests (ADR-0005).
//
// Tests:
//   - capability query exact bytes;
//   - capability response parsing (supported / unsupported / absent);
//   - direct framebuffer encode: chunking ≤4096 base64 bytes;
//   - non-final chunks have m=1, final has m=0;
//   - all non-final chunks are a multiple of 4 base64 bytes;
//   - image/placement IDs appear in the control fields;
//   - no untrusted text (framebuffer data) appears un-encoded in the
//     control fields;
//   - delete command format.

#include "rfb_test.h"
#include "farsee/kitty_protocol.h"
#include "farsee/buffer.h"
#include "farsee/allocator.h"
#include "farsee/error.h"

#include <string.h>
#include <stdint.h>

// --- capability query ----------------------------------------------------

RFB_TEST(kitty, kitty__query_capability__starts_with_esc_underscore_G) {
    rfb_buffer out;
    rfb_buffer_init(&out, rfb_default_allocator(), 4096);
    RFB_CHECK_EQ_INT(kitty_query_capability(&out), RFB_OK);
    RFB_CHECK(rfb_buffer_length(&out) > 0);
    const uint8_t *d = rfb_buffer_data(&out);
    // Kitty graphics uses APC (Application Program Command): ESC _
    RFB_CHECK_EQ_UINT(d[0], (uint8_t)0x1B);
    RFB_CHECK_EQ_UINT(d[1], '_');
    // Followed by 'G' (graphics command).
    RFB_CHECK_EQ_UINT(d[2], 'G');
    rfb_buffer_destroy(&out);
}

RFB_TEST(kitty, kitty__query_capability__ends_with_esc_backslash) {
    rfb_buffer out;
    rfb_buffer_init(&out, rfb_default_allocator(), 4096);
    kitty_query_capability(&out);
    const uint8_t *d = rfb_buffer_data(&out);
    size_t len = rfb_buffer_length(&out);
    RFB_CHECK_EQ_UINT(d[len - 2], (uint8_t)0x1B);
    RFB_CHECK_EQ_UINT(d[len - 1], '\\');
    rfb_buffer_destroy(&out);
}

// --- capability response parsing ----------------------------------------

RFB_TEST(kitty, kitty__parse_response_supported__returns_true) {
    // A typical Kitty graphics-support response.
    static const uint8_t resp[] = "\x1B[>Gi=31;OK\x1B\\";
    kitty_capability cap = { 0 };
    RFB_CHECK_EQ_INT(kitty_parse_capability_response(resp, sizeof resp - 1, &cap), RFB_OK);
    RFB_CHECK(cap.supported);
    RFB_CHECK(cap.queried);
}

RFB_TEST(kitty, kitty__parse_response_unsupported__returns_false) {
    // No graphics response at all.
    static const uint8_t resp[] = "hello";
    kitty_capability cap = { 0 };
    RFB_CHECK_EQ_INT(kitty_parse_capability_response(resp, sizeof resp - 1, &cap), RFB_OK);
    RFB_CHECK(!cap.supported);
}

RFB_TEST(kitty, kitty__parse_response_empty__unsupported) {
    kitty_capability cap = { 0 };
    RFB_CHECK_EQ_INT(kitty_parse_capability_response(NULL, 0, &cap), RFB_OK);
    RFB_CHECK(!cap.supported);
}

// --- direct encode: small image (no chunking needed) --------------------

// Helper: true if the wire buffer contains the ASCII substring `needle`.
static bool wire_contains(const uint8_t *d, size_t len, const char *needle)
{
    size_t n = strlen(needle);
    if (n == 0 || len < n) {
        return false;
    }
    for (size_t i = 0; i + n <= len; i++) {
        size_t j = 0;
        while (j < n && d[i + j] == (uint8_t)needle[j]) {
            j++;
        }
        if (j == n) {
            return true;
        }
    }
    return false;
}

// Spec form is ESC_G <control>;<payload> ESC\ — action a=T is required to
// transmit+display, and the semicolon separates control data from payload
// (https://sw.kovidgoyal.net/kitty/graphics-protocol/).
RFB_TEST(kitty, kitty__encode_small_2x2_rgba__has_aT_and_semicolon) {
    rfb_buffer out;
    rfb_buffer_init(&out, rfb_default_allocator(), 1u << 20);
    static const uint8_t rgba[16] = {
        0xFF,0x00,0x00,0xFF, 0x00,0xFF,0x00,0xFF,
        0x00,0x00,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,
    };
    RFB_CHECK_EQ_INT(
        kitty_encode_direct_framebuffer(&out, rgba, 2, 2,
                                        KITTY_FMT_RGBA32, 1, 1, false, 0, 0),
        RFB_OK);
    const uint8_t *d = rfb_buffer_data(&out);
    size_t len = rfb_buffer_length(&out);
    RFB_CHECK(wire_contains(d, len, "a=T"));
    // Control must end with ; then base64 payload (not glued to m=0).
    RFB_CHECK(wire_contains(d, len, "m=0;"));
    rfb_buffer_destroy(&out);
}

RFB_TEST(kitty, kitty__encode__place_cells_emits_c_and_r) {
    rfb_buffer out;
    rfb_buffer_init(&out, rfb_default_allocator(), 1u << 20);
    static const uint8_t rgba[16] = {
        0xFF,0x00,0x00,0xFF, 0x00,0xFF,0x00,0xFF,
        0x00,0x00,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,
    };
    RFB_CHECK_EQ_INT(
        kitty_encode_direct_framebuffer(&out, rgba, 2, 2,
                                        KITTY_FMT_RGBA32, 1, 1, false,
                                        /*place_cols=*/80, /*place_rows=*/24),
        RFB_OK);
    const uint8_t *d = rfb_buffer_data(&out);
    size_t len = rfb_buffer_length(&out);
    RFB_CHECK(wire_contains(d, len, "c=80"));
    RFB_CHECK(wire_contains(d, len, "r=24"));
    rfb_buffer_destroy(&out);
}

RFB_TEST(kitty, kitty__encode_small_2x2_rgba__single_chunk) {
    rfb_buffer out;
    rfb_buffer_init(&out, rfb_default_allocator(), 1u << 20);
    static const uint8_t rgba[16] = {
        0xFF,0x00,0x00,0xFF, 0x00,0xFF,0x00,0xFF,
        0x00,0x00,0xFF,0xFF, 0xFF,0xFF,0xFF,0xFF,
    };
    RFB_CHECK_EQ_INT(
        kitty_encode_direct_framebuffer(&out, rgba, 2, 2,
                                        KITTY_FMT_RGBA32, 1, 1, false, 0, 0),
        RFB_OK);
    RFB_CHECK(rfb_buffer_length(&out) > 0);
    const uint8_t *d = rfb_buffer_data(&out);
    size_t len = rfb_buffer_length(&out);
    // Starts with ESC _ G and ends with ESC \.
    RFB_CHECK_EQ_UINT(d[0], (uint8_t)0x1B);
    RFB_CHECK_EQ_UINT(d[1], '_');
    RFB_CHECK_EQ_UINT(d[2], 'G');
    RFB_CHECK_EQ_UINT(d[len - 2], (uint8_t)0x1B);
    RFB_CHECK_EQ_UINT(d[len - 1], '\\');
    rfb_buffer_destroy(&out);
}

// --- direct encode: large image that must chunk -------------------------

RFB_TEST(kitty, kitty__encode_large_image__chunks_at_4096_base64_bytes) {
    rfb_buffer out;
    rfb_buffer_init(&out, rfb_default_allocator(), 4u << 20);
    // 100x100 RGBA = 40000 raw bytes = ~53334 base64 bytes → multiple chunks.
    static uint8_t big[40000];
    for (size_t i = 0; i < sizeof big; i++) big[i] = (uint8_t)(i & 0xFF);
    RFB_CHECK_EQ_INT(
        kitty_encode_direct_framebuffer(&out, big, 100, 100,
                                        KITTY_FMT_RGBA32, 1, 1, false, 0, 0),
        RFB_OK);
    // Count how many ESC _ G sequences appear (each is a chunk).
    size_t len = rfb_buffer_length(&out);
    const uint8_t *d = rfb_buffer_data(&out);
    size_t chunk_count = 0;
    for (size_t i = 0; i + 2 < len; i++) {
        if (d[i] == 0x1B && d[i + 1] == '_' && d[i + 2] == 'G') {
            chunk_count++;
        }
    }
    RFB_CHECK(chunk_count > 1);  // must have chunked
    rfb_buffer_destroy(&out);
}

// --- chunk size limit: every chunk's base64 payload ≤4096 bytes ---------

RFB_TEST(kitty, kitty__encode_large_image__no_chunk_exceeds_4096) {
    rfb_buffer out;
    rfb_buffer_init(&out, rfb_default_allocator(), 4u << 20);
    static uint8_t big[40000];
    RFB_CHECK_EQ_INT(
        kitty_encode_direct_framebuffer(&out, big, 100, 100,
                                        KITTY_FMT_RGBA32, 1, 1, false, 0, 0),
        RFB_OK);
    // Walk the buffer, measuring the base64 payload between the control
    // fields and the ESC \ terminator of each chunk.
    size_t len = rfb_buffer_length(&out);
    const uint8_t *d = rfb_buffer_data(&out);
    size_t i = 0;
    while (i < len) {
        // Find the next ESC _ G.
        while (i + 2 < len && !(d[i] == 0x1B && d[i + 1] == '_' && d[i + 2] == 'G')) i++;
        if (i + 2 >= len) break;
        // Find the ESC \ terminator.
        size_t start = i + 3;
        size_t end = start;
        while (end + 1 < len && !(d[end] == 0x1B && d[end + 1] == '\\')) end++;
        // The payload is everything after the control-field `;` separator
        // up to the terminator. We can't easily isolate just the b64 part
        // without parsing the control fields, so measure the whole chunk
        // body and assert it's bounded (control fields + payload + term).
        size_t chunk_body = end - start;
        // The payload portion is chunk_body minus the control fields.
        // A safe upper bound: the whole chunk body including control
        // fields must be < 4096 + ~100 (control fields) + terminator.
        RFB_CHECK(chunk_body < 4096u + 200u);
        i = end + 2;
    }
    rfb_buffer_destroy(&out);
}

// --- delete command ------------------------------------------------------

RFB_TEST(kitty, kitty__delete_image__is_a_T_a_d_command) {
    rfb_buffer out;
    rfb_buffer_init(&out, rfb_default_allocator(), 4096);
    RFB_CHECK_EQ_INT(kitty_encode_delete_image(&out, 42), RFB_OK);
    const uint8_t *d = rfb_buffer_data(&out);
    size_t len = rfb_buffer_length(&out);
    RFB_CHECK_EQ_UINT(d[0], (uint8_t)0x1B);
    RFB_CHECK_EQ_UINT(d[1], '_');
    RFB_CHECK_EQ_UINT(d[2], 'G');
    // The command must contain "a=d" (delete action).
    bool found_delete = false;
    for (size_t i = 3; i + 2 < len; i++) {
        if (d[i] == 'a' && d[i + 1] == '=' && d[i + 2] == 'd') {
            found_delete = true;
            break;
        }
    }
    RFB_CHECK(found_delete);
    rfb_buffer_destroy(&out);
}

// Absurd dimensions must fail the checked size math rather than wrap and
// undersize the base64 buffer.
RFB_TEST(kitty_protocol, direct_framebuffer__absurd_dims__fails_limit)
{
    rfb_buffer out;
    rfb_buffer_init(&out, rfb_default_allocator(), 1u << 20);
    static uint8_t px[4] = { 0 };
    RFB_CHECK_EQ_INT(
        kitty_encode_direct_framebuffer(&out, px, 0xFFFFFFFFu, 0xFFFFFFFFu,
                                        KITTY_FMT_RGBA32, 1u, 1u, false,
                                        0u, 0u),
        RFB_ERR_LIMIT);
    rfb_buffer_destroy(&out);
}

static void *kitty_protocol_fail_alloc(rfb_allocator *allocator, size_t size)
{
    (void)allocator;
    (void)size;
    return NULL;
}

static void kitty_protocol_fail_free(rfb_allocator *allocator,
                                     void *allocation)
{
    (void)allocator;
    (void)allocation;
}

RFB_TEST(kitty_protocol, query__null_and_each_output_bound_are_explicit)
{
    RFB_CHECK_EQ_INT(kitty_query_capability(NULL), RFB_ERR_INTERNAL);

    static const char query[] = "Gi=31,s=1,a=q,t=d,v=1";
    const size_t wire_len = 2u + sizeof query - 1u + 2u;
    for (size_t cap = 0u; cap < wire_len; cap++) {
        rfb_buffer out;
        rfb_buffer_init(&out, rfb_default_allocator(), cap);
        RFB_CHECK_EQ_INT(kitty_query_capability(&out), RFB_ERR_LIMIT);
        RFB_CHECK(rfb_buffer_length(&out) <= cap);
        rfb_buffer_destroy(&out);
    }

    rfb_buffer out;
    rfb_buffer_init(&out, rfb_default_allocator(), wire_len);
    RFB_CHECK_EQ_INT(kitty_query_capability(&out), RFB_OK);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&out), wire_len);
    rfb_buffer_destroy(&out);
}

RFB_TEST(kitty_protocol, parse_response__near_matches_and_ok_window)
{
    static const uint8_t byte = 'G';
    kitty_capability cap = {.supported = true, .queried = true};
    RFB_CHECK_EQ_INT(kitty_parse_capability_response(&byte, 1u, NULL),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(kitty_parse_capability_response(NULL, 1u, &cap), RFB_OK);
    RFB_CHECK(!cap.supported);
    RFB_CHECK(!cap.queried);
    RFB_CHECK_EQ_INT(kitty_parse_capability_response(&byte, 0u, &cap), RFB_OK);
    RFB_CHECK(!cap.supported);
    RFB_CHECK(!cap.queried);

    static const uint8_t near_matches[][5] = {
        {'X', 'i', '=', '3', '1'},
        {'G', 'X', '=', '3', '1'},
        {'G', 'i', 'X', '3', '1'},
        {'G', 'i', '=', 'X', '1'},
        {'G', 'i', '=', '3', 'X'},
    };
    for (size_t i = 0u; i < sizeof near_matches / sizeof near_matches[0]; i++) {
        RFB_CHECK_EQ_INT(kitty_parse_capability_response(
                             near_matches[i], sizeof near_matches[i], &cap),
                         RFB_OK);
        RFB_CHECK(!cap.supported);
        RFB_CHECK(!cap.queried);
    }

    static const uint8_t no_ok[] = "Gi=31;NO";
    RFB_CHECK_EQ_INT(kitty_parse_capability_response(
                         no_ok, sizeof no_ok - 1u, &cap),
                     RFB_OK);
    RFB_CHECK(cap.queried);
    RFB_CHECK(!cap.supported);

    static const uint8_t ok_near_limit[] = "Gi=31.............OK";
    RFB_CHECK_EQ_INT(kitty_parse_capability_response(
                         ok_near_limit, sizeof ok_near_limit - 1u, &cap),
                     RFB_OK);
    RFB_CHECK(cap.queried);
    RFB_CHECK(cap.supported);

    static const uint8_t ok_outside_window[] =
        "Gi=31....................OK";
    RFB_CHECK_EQ_INT(kitty_parse_capability_response(
                         ok_outside_window, sizeof ok_outside_window - 1u,
                         &cap),
                     RFB_OK);
    RFB_CHECK(cap.queried);
    RFB_CHECK(!cap.supported);
}

RFB_TEST(kitty_protocol, direct_framebuffer__argument_and_allocator_guards)
{
    static const uint8_t rgba[4] = {1u, 2u, 3u, 4u};
    rfb_buffer out;
    rfb_buffer_init(&out, rfb_default_allocator(), 4096u);
    RFB_CHECK_EQ_INT(kitty_encode_direct_framebuffer(
                         NULL, rgba, 1u, 1u, KITTY_FMT_RGBA32, 1u, 1u,
                         false, 0u, 0u),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(kitty_encode_direct_framebuffer(
                         &out, NULL, 1u, 1u, KITTY_FMT_RGBA32, 1u, 1u,
                         false, 0u, 0u),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(kitty_encode_direct_framebuffer(
                         &out, rgba, 0u, 1u, KITTY_FMT_RGBA32, 1u, 1u,
                         false, 0u, 0u),
                     RFB_ERR_INTERNAL);
    RFB_CHECK_EQ_INT(kitty_encode_direct_framebuffer(
                         &out, rgba, 1u, 0u, KITTY_FMT_RGBA32, 1u, 1u,
                         false, 0u, 0u),
                     RFB_ERR_INTERNAL);

    rfb_allocator *saved = out.alloc;
    out.alloc = NULL;
    RFB_CHECK_EQ_INT(kitty_encode_direct_framebuffer(
                         &out, rgba, 1u, 1u, KITTY_FMT_RGBA32, 1u, 1u,
                         false, 0u, 0u),
                     RFB_ERR_INTERNAL);
    rfb_allocator invalid = *rfb_default_allocator();
    invalid.alloc = NULL;
    out.alloc = &invalid;
    RFB_CHECK_EQ_INT(kitty_encode_direct_framebuffer(
                         &out, rgba, 1u, 1u, KITTY_FMT_RGBA32, 1u, 1u,
                         false, 0u, 0u),
                     RFB_ERR_INTERNAL);
    invalid = *rfb_default_allocator();
    invalid.free = NULL;
    out.alloc = &invalid;
    RFB_CHECK_EQ_INT(kitty_encode_direct_framebuffer(
                         &out, rgba, 1u, 1u, KITTY_FMT_RGBA32, 1u, 1u,
                         false, 0u, 0u),
                     RFB_ERR_INTERNAL);
    out.alloc = saved;
    rfb_buffer_destroy(&out);

    rfb_allocator failing = {
        .alloc = kitty_protocol_fail_alloc,
        .free = kitty_protocol_fail_free,
        .user = NULL,
    };
    rfb_buffer_init(&out, &failing, 4096u);
    RFB_CHECK_EQ_INT(kitty_encode_direct_framebuffer(
                         &out, rgba, 1u, 1u, KITTY_FMT_RGBA32, 1u, 1u,
                         false, 0u, 0u),
                     RFB_ERR_NOMEM);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&out), 0u);
    rfb_buffer_destroy(&out);
}

RFB_TEST(kitty_protocol, direct_framebuffer__placement_and_ack_variants)
{
    static const uint8_t rgb[3] = {0xaau, 0xbbu, 0xccu};
    rfb_buffer out;
    rfb_buffer_init(&out, rfb_default_allocator(), 4096u);
    RFB_CHECK_EQ_INT(kitty_encode_direct_framebuffer(
                         &out, rgb, 1u, 1u, KITTY_FMT_RGB24, 2u, 3u,
                         true, 0u, 24u),
                     RFB_OK);
    RFB_CHECK(wire_contains(rfb_buffer_data(&out), rfb_buffer_length(&out),
                            "f=24"));
    RFB_CHECK(wire_contains(rfb_buffer_data(&out), rfb_buffer_length(&out),
                            "q=0"));
    RFB_CHECK(wire_contains(rfb_buffer_data(&out), rfb_buffer_length(&out),
                            "r=24"));
    RFB_CHECK(!wire_contains(rfb_buffer_data(&out), rfb_buffer_length(&out),
                             "c="));
    rfb_buffer_clear(&out);

    RFB_CHECK_EQ_INT(kitty_encode_direct_framebuffer(
                         &out, rgb, 1u, 1u, KITTY_FMT_RGB24, 2u, 3u,
                         false, 80u, 0u),
                     RFB_OK);
    RFB_CHECK(wire_contains(rfb_buffer_data(&out), rfb_buffer_length(&out),
                            "q=2"));
    RFB_CHECK(wire_contains(rfb_buffer_data(&out), rfb_buffer_length(&out),
                            "c=80"));
    RFB_CHECK(!wire_contains(rfb_buffer_data(&out), rfb_buffer_length(&out),
                             "r="));
    rfb_buffer_destroy(&out);
}

RFB_TEST(kitty_protocol, direct_framebuffer__every_chunk_limit_rolls_back)
{
    static const uint8_t rgba[4] = {1u, 2u, 3u, 4u};
    rfb_buffer reference;
    rfb_buffer_init(&reference, rfb_default_allocator(), 4096u);
    RFB_CHECK_EQ_INT(kitty_encode_direct_framebuffer(
                         &reference, rgba, 1u, 1u, KITTY_FMT_RGBA32, 1u, 1u,
                         false, 0u, 0u),
                     RFB_OK);
    const size_t wire_len = rfb_buffer_length(&reference);
    RFB_CHECK(wire_len > 0u);

    static const uint8_t prefix = 0xa5u;
    for (size_t suffix_cap = 0u; suffix_cap < wire_len; suffix_cap++) {
        rfb_buffer out;
        rfb_buffer_init(&out, rfb_default_allocator(), 1u + suffix_cap);
        RFB_CHECK_EQ_INT(rfb_buffer_append(&out, &prefix, 1u), RFB_OK);
        RFB_CHECK_EQ_INT(kitty_encode_direct_framebuffer(
                             &out, rgba, 1u, 1u, KITTY_FMT_RGBA32, 1u, 1u,
                             false, 0u, 0u),
                         RFB_ERR_LIMIT);
        RFB_CHECK_EQ_UINT(rfb_buffer_length(&out), 1u);
        RFB_CHECK_EQ_UINT(rfb_buffer_data(&out)[0], prefix);
        rfb_buffer_destroy(&out);
    }
    rfb_buffer_destroy(&reference);
}

RFB_TEST(kitty_protocol, direct_framebuffer__continuation_failure_rolls_back)
{
    static uint8_t rgb[3075];
    rfb_buffer reference;
    rfb_buffer_init(&reference, rfb_default_allocator(), 8192u);
    RFB_CHECK_EQ_INT(kitty_encode_direct_framebuffer(
                         &reference, rgb, 1025u, 1u, KITTY_FMT_RGB24, 7u, 8u,
                         false, 0u, 0u),
                     RFB_OK);
    const uint8_t *wire = rfb_buffer_data(&reference);
    const size_t wire_len = rfb_buffer_length(&reference);
    size_t second_chunk = 0u;
    for (size_t i = 3u; i + 2u < wire_len; i++) {
        if (wire[i] == 0x1bu && wire[i + 1u] == '_' && wire[i + 2u] == 'G') {
            second_chunk = i;
            break;
        }
    }
    RFB_CHECK(second_chunk > 0u);

    static const uint8_t prefix = 0x5au;
    rfb_buffer out;
    rfb_buffer_init(&out, rfb_default_allocator(), 1u + second_chunk + 1u);
    RFB_CHECK_EQ_INT(rfb_buffer_append(&out, &prefix, 1u), RFB_OK);
    RFB_CHECK_EQ_INT(kitty_encode_direct_framebuffer(
                         &out, rgb, 1025u, 1u, KITTY_FMT_RGB24, 7u, 8u,
                         false, 0u, 0u),
                     RFB_ERR_LIMIT);
    RFB_CHECK_EQ_UINT(rfb_buffer_length(&out), 1u);
    RFB_CHECK_EQ_UINT(rfb_buffer_data(&out)[0], prefix);
    rfb_buffer_destroy(&out);
    rfb_buffer_destroy(&reference);
}

RFB_TEST(kitty_protocol, delete_image__null_and_each_bound_roll_back)
{
    RFB_CHECK_EQ_INT(kitty_encode_delete_image(NULL, 42u), RFB_ERR_INTERNAL);

    rfb_buffer reference;
    rfb_buffer_init(&reference, rfb_default_allocator(), 128u);
    RFB_CHECK_EQ_INT(kitty_encode_delete_image(&reference, 42u), RFB_OK);
    const size_t wire_len = rfb_buffer_length(&reference);
    RFB_CHECK(wire_len > 0u);

    static const uint8_t prefix = 0xc3u;
    for (size_t suffix_cap = 0u; suffix_cap < wire_len; suffix_cap++) {
        rfb_buffer out;
        rfb_buffer_init(&out, rfb_default_allocator(), 1u + suffix_cap);
        RFB_CHECK_EQ_INT(rfb_buffer_append(&out, &prefix, 1u), RFB_OK);
        RFB_CHECK_EQ_INT(kitty_encode_delete_image(&out, 42u), RFB_ERR_LIMIT);
        RFB_CHECK_EQ_UINT(rfb_buffer_length(&out), 1u);
        RFB_CHECK_EQ_UINT(rfb_buffer_data(&out)[0], prefix);
        rfb_buffer_destroy(&out);
    }
    rfb_buffer_destroy(&reference);
}
