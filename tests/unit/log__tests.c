// SPDX-License-Identifier: Apache-2.0
//
// G1 — remote-text escape tests (plan.md §G1, §6.3: "remote-text escaping
// for control bytes and ESC"). RED step.
//
// Every byte outside printable ASCII must be escaped so no terminal escape
// sequence can be smuggled into a diagnostic. ESC (0x1B) is the canonical
// attacker byte; it must never appear verbatim in the output.

#include "rfb_test.h"
#include "farsee/log.h"
#include <string.h>

RFB_TEST(log, log_escape__printable_ascii__passes_verbatim) {
    char out[64];
    const char *in = "Hello, World!";
    size_t n = rfb_log_escape_remote(in, strlen(in), out, sizeof out);
    RFB_CHECK_EQ_UINT(n, strlen(in));
    RFB_CHECK(strcmp(out, "Hello, World!") == 0);
}

RFB_TEST(log, log_escape__escape_byte_0x1b__becomes_hex) {
    char out[16];
    static const uint8_t in[1] = { 0x1B };
    size_t n = rfb_log_escape_remote(in, 1, out, sizeof out);
    RFB_CHECK_EQ_UINT(n, 4u);
    RFB_CHECK(strcmp(out, "\\x1B") == 0);
    // CRITICAL: no raw ESC byte in the output.
    RFB_CHECK(strchr(out, 0x1B) == NULL);
}

RFB_TEST(log, log_escape__newline__becomes_backslash_n) {
    char out[8];
    static const uint8_t in[1] = { '\n' };
    size_t n = rfb_log_escape_remote(in, 1, out, sizeof out);
    RFB_CHECK_EQ_UINT(n, 2u);
    RFB_CHECK(strcmp(out, "\\n") == 0);
}

RFB_TEST(log, log_escape__carriage_return__becomes_backslash_r) {
    char out[8];
    static const uint8_t in[1] = { '\r' };
    size_t n = rfb_log_escape_remote(in, 1, out, sizeof out);
    RFB_CHECK_EQ_UINT(n, 2u);
    RFB_CHECK(strcmp(out, "\\r") == 0);
}

RFB_TEST(log, log_escape__tab__becomes_backslash_t) {
    char out[8];
    static const uint8_t in[1] = { '\t' };
    size_t n = rfb_log_escape_remote(in, 1, out, sizeof out);
    RFB_CHECK_EQ_UINT(n, 2u);
    RFB_CHECK(strcmp(out, "\\t") == 0);
}

RFB_TEST(log, log_escape__backslash__is_doubled) {
    char out[8];
    static const uint8_t in[1] = { '\\' };
    size_t n = rfb_log_escape_remote(in, 1, out, sizeof out);
    RFB_CHECK_EQ_UINT(n, 2u);
    RFB_CHECK(strcmp(out, "\\\\") == 0);
}

RFB_TEST(log, log_escape__csi_sequence__cannot_survive) {
    // A typical attacker CSI: ESC [ 31 m (red text)
    static const uint8_t in[5] = { 0x1B, '[', '3', '1', 'm' };
    char out[64];
    size_t n = rfb_log_escape_remote(in, sizeof in, out, sizeof out);
    RFB_CHECK(n > 0);
    // No raw ESC byte in the output at all.
    RFB_CHECK(strchr(out, 0x1B) == NULL);
    // No bare '[' immediately after the ESC escape either.
    RFB_CHECK(strcmp(out, "\x1B[31m") != 0);
}

RFB_TEST(log, log_escape__non_ascii_byte__becomes_hex) {
    char out[8];
    static const uint8_t in[1] = { 0xFF };
    size_t n = rfb_log_escape_remote(in, 1, out, sizeof out);
    RFB_CHECK_EQ_UINT(n, 4u);
    RFB_CHECK(strcmp(out, "\\xFF") == 0);
}

RFB_TEST(log, log_escape__null_byte__becomes_hex_x00) {
    char out[8];
    static const uint8_t in[1] = { 0 };
    size_t n = rfb_log_escape_remote(in, 1, out, sizeof out);
    RFB_CHECK_EQ_UINT(n, 4u);
    RFB_CHECK(strcmp(out, "\\x00") == 0);
}

RFB_TEST(log, log_escape__output_too_small__returns_needed_length_and_truncates_safely) {
    static const uint8_t in[4] = { 'A', 'B', 'C', 'D' };
    char out[3];  // room for 2 chars + terminator
    size_t n = rfb_log_escape_remote(in, 4, out, sizeof out);
    RFB_CHECK_EQ_UINT(n, 4u);  // would need 4 bytes
    RFB_CHECK_EQ_UINT(out[2], '\0');  // null-terminated, no overrun
}

RFB_TEST(log, log_escape__tmp_buffer__returns_null_terminated) {
    static const uint8_t in[3] = { 'X', 0x1B, 'Y' };
    const char *s = rfb_log_escape_remote_tmp(in, 3);
    RFB_CHECK(s != NULL);
    RFB_CHECK(strchr(s, 0x1B) == NULL);  // ESC escaped
    RFB_CHECK(strstr(s, "X") != NULL);
    RFB_CHECK(strstr(s, "Y") != NULL);
}
