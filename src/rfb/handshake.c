// SPDX-License-Identifier: Apache-2.0
//
// farsee — classic RFB version and security negotiation (plan.md §G2,
// §11; RFC 6143 §7.1, §7.2.2).
//
// Implements banner parsing/formatting and the incremental handshake for
// security types None and VNC Authentication.

#include "farsee/handshake.h"
#include "farsee/bytes.h"
#include "farsee/secret.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

rfb_handshake_policy rfb_handshake_policy_default(void)
{
    rfb_handshake_policy p;
    p.allow_none_auth = false;  // plan.md §G2: None only on explicit opt-in
    p.allow_vnc_auth  = true;
    p.shared_flag     = true;
    return p;
}

void rfb_handshake_init(rfb_handshake *h, const rfb_handshake_policy *policy,
                        rfb_allocator *alloc)
{
    if (h == NULL) {
        return;
    }
    memset(h, 0, sizeof *h);
    h->state = RFB_HS_READ_PROTOCOL_VERSION;
    h->version = RFB_VERSION_UNKNOWN;
    h->policy = (policy != NULL) ? *policy : rfb_handshake_policy_default();
    h->selected_security = RFB_SECURITY_INVALID;
    h->last_error = RFB_OK;
    h->server_security_count = 0;
    h->des = rfb_des_default_provider();
    rfb_buffer_init(&h->failure_reason, alloc, 4096);
}

void rfb_handshake_destroy(rfb_handshake *h)
{
    if (h == NULL) {
        return;
    }
    // Zeroize secrets (plan.md §6.3).
    rfb_secret_zero(h->password, sizeof h->password);
    rfb_secret_zero(h->challenge, sizeof h->challenge);
    rfb_secret_zero(h->response, sizeof h->response);
    rfb_buffer_destroy(&h->failure_reason);
}

void rfb_handshake_set_password(rfb_handshake *h,
                                const uint8_t *password, size_t n)
{
    if (h == NULL) {
        return;
    }
    // Zero-pad to 8 bytes with secret wipe, then copy up to 8 bytes.
    rfb_secret_zero(h->password, sizeof h->password);
    if (password != NULL && n > 0) {
        size_t copy_n = n < sizeof h->password ? n : sizeof h->password;
        memcpy(h->password, password, copy_n);
    }
    h->password_set = true;
}

void rfb_handshake_set_des_provider(rfb_handshake *h, rfb_des_ecb_encrypt_fn des)
{
    if (h != NULL) {
        h->des = des;
    }
}

static void clear_vnc_auth_secrets(rfb_handshake *h)
{
    rfb_secret_zero(h->challenge, sizeof h->challenge);
    rfb_secret_zero(h->response, sizeof h->response);
    rfb_secret_zero(h->password, sizeof h->password);
    h->password_set = false;
}

static rfb_error fail_vnc_auth(rfb_handshake *h, rfb_error error)
{
    clear_vnc_auth_secrets(h);
    h->state = RFB_HS_FAILED;
    h->last_error = error;
    return error;
}

// --- Banner grammar (RFC 6143 §7.1.1) -----------------------------------
//
// The 12-byte banner is exactly:
//   "RFB "        4 bytes  (magic + space)
//   "xxx"         3 bytes  (major, ASCII digits)
//   "."           1 byte
//   "yyy"         3 bytes  (minor, ASCII digits)
//   "\n"          1 byte
// Total = 12.
//
// We accept exactly 003.003, 003.007, 003.008. Anything else that is
// syntactically valid is RFB_ERR_UNSUPPORTED (plan.md §11: never blindly
// echo an unknown version). Anything syntactically invalid is
// RFB_ERR_PROTOCOL.

static bool ascii_is_digit(uint8_t c)
{
    return c >= '0' && c <= '9';
}

// Map a major/minor pair to our version enum, or RFB_VERSION_UNKNOWN if
// not a recognized canonical version.
static rfb_version recognize_version(uint8_t maj0, uint8_t maj1, uint8_t maj2,
                                     uint8_t min0, uint8_t min1, uint8_t min2)
{
    // Canonical versions all have major "003".
    if (maj0 != '0' || maj1 != '0' || maj2 != '3') {
        return RFB_VERSION_UNKNOWN;
    }
    // Minor "003", "007", "008".
    if (min0 == '0' && min1 == '0') {
        if (min2 == '3') return RFB_VERSION_3_3;
        if (min2 == '7') return RFB_VERSION_3_7;
        if (min2 == '8') return RFB_VERSION_3_8;
    }
    return RFB_VERSION_UNKNOWN;
}

rfb_error rfb_parse_banner(const uint8_t *in, size_t in_len,
                           rfb_version *out_version)
{
    if (out_version == NULL) {
        return RFB_ERR_INTERNAL;
    }
    *out_version = RFB_VERSION_UNKNOWN;
    if (in == NULL) {
        return RFB_ERR_PROTOCOL;
    }
    if (in_len != 12) {
        return RFB_ERR_PROTOCOL;  // the parser requires the full banner
    }
    // Fixed positions:
    //   [0..2] = 'R','F','B'
    //   [3]    = ' '
    //   [4..6] = major digits
    //   [7]    = '.'
    //   [8..10]= minor digits
    //   [11]   = '\n'
    static const uint8_t MAGIC[4] = { 'R', 'F', 'B', ' ' };
    if (memcmp(in, MAGIC, sizeof MAGIC) != 0) {
        return RFB_ERR_PROTOCOL;
    }
    if (in[7] != '.') {
        return RFB_ERR_PROTOCOL;
    }
    if (in[11] != '\n') {
        return RFB_ERR_PROTOCOL;
    }
    // All six version-field bytes must be ASCII digits.
    uint8_t const *maj = in + 4;
    uint8_t const *min = in + 8;
    for (int i = 0; i < 3; i++) {
        if (!ascii_is_digit(maj[i]) || !ascii_is_digit(min[i])) {
            return RFB_ERR_PROTOCOL;
        }
    }
    rfb_version v = recognize_version(maj[0], maj[1], maj[2],
                                      min[0], min[1], min[2]);
    if (v == RFB_VERSION_UNKNOWN) {
        // Syntactically valid but not a canonical version: actionable
        // unsupported error (plan.md §11). The caller surfaces this with
        // the banner bytes escaped for diagnostics.
        return RFB_ERR_UNSUPPORTED;
    }
    *out_version = v;
    return RFB_OK;
}

rfb_error rfb_format_banner(rfb_version v, uint8_t *out, size_t out_cap)
{
    if (out == NULL) {
        return RFB_ERR_INTERNAL;
    }
    if (out_cap < 12) {
        return RFB_ERR_LIMIT;
    }
    uint8_t minor = 0;
    switch (v) {
    case RFB_VERSION_3_3: minor = '3'; break;
    case RFB_VERSION_3_7: minor = '7'; break;
    case RFB_VERSION_3_8: minor = '8'; break;
    case RFB_VERSION_UNKNOWN: return RFB_ERR_PROTOCOL;
    }
    // Layout: "RFB 003.00X\n" where X = minor digit.
    // Positions 0-9 are the fixed prefix; position 10 is the minor; 11 is \n.
    static const uint8_t PREFIX[10] = { 'R','F','B',' ','0','0','3','.','0','0' };
    memcpy(out, PREFIX, 10);
    out[10] = minor;
    out[11] = '\n';
    return RFB_OK;
}

// --- Incremental state machine -------------------------------------------
//
// Each state handler is a small function that consumes what input it can
// (possibly zero), appends output, and either advances the state or asks
// for more input by returning RFB_OK without changing state. The top-level
// rfb_handshake_step dispatches on the current state.
//
// Conventions:
//   - input bytes are consumed from the front via rfb_buffer_consume;
//   - output bytes are appended via rfb_buffer_append;
//   - on any protocol error the state moves to FAILED and last_error is set.

// Helper: snapshot the input pointer/length to build a reader over the
// current front of the buffer.
static rfb_reader input_reader(const rfb_buffer *b)
{
    return rfb_reader_make(rfb_buffer_data(b), rfb_buffer_length(b));
}

// Read exactly 12 bytes and parse the banner. Emits our banner (same
// version) and advances to the security-list state.
static rfb_error step_read_protocol_version(rfb_handshake *h,
                                            rfb_buffer *input,
                                            rfb_buffer *output)
{
    if (rfb_buffer_length(input) < 12) {
        return RFB_OK;  // need more input
    }
    rfb_reader r = input_reader(input);
    rfb_version v = RFB_VERSION_UNKNOWN;
    rfb_error e = rfb_parse_banner(rfb_buffer_data(input), 12, &v);
    if (e != RFB_OK) {
        h->state = RFB_HS_FAILED;
        h->last_error = e;
        return e;
    }
    h->version = v;
    // Consume the 12 input bytes.
    rfb_buffer_consume(input, 12);
    // Emit our banner (we negotiate toward the same version).
    uint8_t out[12];
    // The parser above produced a recognized version and out is exactly the
    // required size, so formatting cannot fail here.
    (void)rfb_format_banner(v, out, sizeof out);
    e = rfb_buffer_append(output, out, 12);
    if (e != RFB_OK) {
        return e;  // output queue full
    }
    // Next state depends on version. 3.3 sends a single u32 security type;
    // 3.7/3.8 send a list (count + bytes).
    h->state = RFB_HS_READ_SECURITY_TYPES;
    (void)r;
    return RFB_OK;
}

// 3.7/3.8: parse count + security-type list, then emit the selection.
// 3.3:    parse a single u32 security type; no selection is emitted.
static rfb_error step_read_security_types(rfb_handshake *h,
                                          rfb_buffer *input,
                                          rfb_buffer *output)
{
    if (h->version == RFB_VERSION_3_3) {
        // RFC 6143 §7.1.3 (3.3): a single u32 security type, already chosen
        // by the server. No security-type list, no client selection.
        if (rfb_buffer_length(input) < 4) {
            return RFB_OK;  // need more input
        }
        rfb_reader r = input_reader(input);
        uint32_t sec = 0;
        // The exact four-byte precheck above proves this read succeeds.
        (void)rfb_read_u32(&r, &sec);
        rfb_buffer_consume(input, 4);
        if (sec == 0) {
            // RFC 6143 §7.1.3: 3.3 zero means "connection failed" and a
            // u32-length reason string follows. Route through the shared
            // failure-reason reader (as the 3.7/3.8 count==0 case does) so
            // the diagnostic is captured in failure_reason and the reason
            // bytes are drained before the terminal failure. That step
            // always ends FAILED/AUTH.
            h->state = RFB_HS_READ_SECURITY_FAILURE_REASON;
            return RFB_OK;  // the failure-reason step will read + fail
        }
        if (sec > 0xFFu) {
            h->state = RFB_HS_FAILED;
            h->last_error = RFB_ERR_PROTOCOL;
            return RFB_ERR_PROTOCOL;
        }
        // Apply the same policy as the list path.
        uint8_t type = (uint8_t)sec;
        if (type == RFB_SECURITY_NONE && !h->policy.allow_none_auth) {
            h->state = RFB_HS_FAILED;
            h->last_error = RFB_ERR_UNSUPPORTED;
            return RFB_ERR_UNSUPPORTED;
        }
        if (type == RFB_SECURITY_VNC && !h->policy.allow_vnc_auth) {
            h->state = RFB_HS_FAILED;
            h->last_error = RFB_ERR_UNSUPPORTED;
            return RFB_ERR_UNSUPPORTED;
        }
        if (type != RFB_SECURITY_NONE && type != RFB_SECURITY_VNC) {
            h->state = RFB_HS_FAILED;
            h->last_error = RFB_ERR_UNSUPPORTED;
            return RFB_ERR_UNSUPPORTED;
        }
        h->selected_security = (rfb_security_type)type;
        // For 3.3 we advance straight to the challenge (VNC) or result (None).
        if (h->selected_security == RFB_SECURITY_VNC) {
            h->state = RFB_HS_READ_VNC_CHALLENGE;
        } else {
            // 3.3 None: RFC says the connection is "accepted" with no result
            // u32. We go straight to DONE.
            h->state = RFB_HS_DONE;
        }
        return RFB_OK;
    }

    // 3.7/3.8: u8 count, then count bytes of security types.
    if (rfb_buffer_length(input) < 1) {
        return RFB_OK;
    }
    rfb_reader r = input_reader(input);
    uint8_t count = 0;
    // The one-byte precheck above proves this read succeeds.
    (void)rfb_read_u8(&r, &count);
    if (count == 0) {
        // RFC 6143 §7.1.2: a zero count means the server is refusing the
        // connection outright; a failure-reason string (u32 length +
        // bytes) follows. We consume the count byte and transition to the
        // failure-reason reader to capture the reason, which always ends
        // in FAILED.
        rfb_buffer_consume(input, 1);
        h->state = RFB_HS_READ_SECURITY_FAILURE_REASON;
        return RFB_OK;  // the failure-reason step will read + fail
    }
    if (rfb_buffer_length(input) < 1u + (size_t)count) {
        return RFB_OK;  // need the full list
    }
    // Read the count + the list bytes.
    rfb_reader r2 = input_reader(input);
    uint8_t cnt = 0;
    (void)rfb_read_u8(&r2, &cnt);
    uint8_t types[256];
    for (uint8_t i = 0; i < cnt; i++) {
        uint8_t t = 0;
        // The full-list precheck above proves each element read succeeds.
        (void)rfb_read_u8(&r2, &t);
        types[i] = t;
    }
    rfb_buffer_consume(input, 1u + (size_t)cnt);
    h->server_security_count = cnt;
    memcpy(h->server_security_types, types, cnt);

    // Select the best security type we support and that policy permits.
    // Preference: VNC auth over None (None is only selected when it is the
    // sole option AND the user opted in).
    bool have_vnc = false;
    bool have_none = false;
    for (uint8_t i = 0; i < cnt; i++) {
        if (types[i] == RFB_SECURITY_VNC) have_vnc = true;
        if (types[i] == RFB_SECURITY_NONE) have_none = true;
    }
    rfb_security_type selected = RFB_SECURITY_INVALID;
    if (have_vnc && h->policy.allow_vnc_auth) {
        selected = RFB_SECURITY_VNC;
    } else if (have_none && h->policy.allow_none_auth) {
        selected = RFB_SECURITY_NONE;
    }
    if (selected == RFB_SECURITY_INVALID) {
        h->state = RFB_HS_FAILED;
        h->last_error = RFB_ERR_UNSUPPORTED;
        return RFB_ERR_UNSUPPORTED;
    }
    h->selected_security = selected;
    // Emit the single-byte selection.
    uint8_t sel = (uint8_t)selected;
    rfb_error e = rfb_buffer_append(output, &sel, 1);
    if (e != RFB_OK) {
        return e;
    }
    // Advance based on what we selected.
    if (selected == RFB_SECURITY_VNC) {
        h->state = RFB_HS_READ_VNC_CHALLENGE;
    } else {
        // None: 3.8 sends a security-result u32 next; 3.7 does not.
        if (h->version == RFB_VERSION_3_8) {
            h->state = RFB_HS_READ_SECURITY_RESULT;
        } else {
            h->state = RFB_HS_DONE;  // 3.7 None: straight to DONE
        }
    }
    return RFB_OK;
}

// Read the 16-byte VNC challenge, compute the response, emit it, advance
// to the security-result state.
static rfb_error step_read_vnc_challenge(rfb_handshake *h,
                                         rfb_buffer *input,
                                         rfb_buffer *output)
{
    if (rfb_buffer_length(input) < 16) {
        return RFB_OK;  // need more input
    }
    rfb_reader r = input_reader(input);
    // The exact 16-byte precheck above proves this read succeeds.
    (void)rfb_read_bytes(&r, h->challenge, 16);
    rfb_buffer_consume(input, 16);
    // Compute the response. If no password was set, fail closed (the CLI
    // must supply one before this state is entered).
    if (!h->password_set || h->des == NULL) {
        return fail_vnc_auth(h, RFB_ERR_AUTH);
    }
    if (!rfb_vnc_auth_respond(h->password, h->challenge, h->response, h->des)) {
        return fail_vnc_auth(h, RFB_ERR_INTERNAL);
    }
    rfb_error e = rfb_buffer_append(output, h->response, 16);
    if (e != RFB_OK) {
        return fail_vnc_auth(h, e);
    }
    // Zeroize secrets now that the response is queued. Password is no longer
    // needed for SecurityResult wait.
    clear_vnc_auth_secrets(h);
    // VNC Authentication always receives a SecurityResult on 3.3/3.7/3.8.
    // RFC 6143 Appendix A.1: RFB 3.3 omits SecurityResult only for
    // security type None; type 2 (VNC Auth) still gets the 4-byte result.
    // Only 3.8 adds a reason string on failure; 3.3/3.7 just send the u32.
    // Skipping the result on 3.3 misaligns ServerInit (success result
    // becomes width/height) and misclassifies auth rejection.
    h->state = RFB_HS_READ_SECURITY_RESULT;
    return RFB_OK;
}

// Read the 4-byte security-result u32 (3.8 None; VNC Auth on 3.3/3.7/3.8).
// 0 = OK -> DONE. Nonzero = failure; in 3.8 a reason string follows.
static rfb_error step_read_security_result(rfb_handshake *h, rfb_buffer *input,
                                           rfb_buffer *output)
{
    (void)output;
    if (rfb_buffer_length(input) < 4) {
        return RFB_OK;  // need more input
    }
    rfb_reader r = input_reader(input);
    uint32_t result = 0;
    // The exact four-byte precheck above proves this read succeeds.
    (void)rfb_read_u32(&r, &result);
    rfb_buffer_consume(input, 4);
    if (result == 0) {
        h->state = RFB_HS_DONE;
        return RFB_OK;
    }
    // Failed. In 3.8 a reason string follows; in 3.7 no reason is sent.
    if (h->version == RFB_VERSION_3_8) {
        h->state = RFB_HS_READ_SECURITY_FAILURE_REASON;
        return RFB_OK;  // wait for the reason string
    }
    // 3.7: no reason string, fail immediately.
    h->state = RFB_HS_FAILED;
    h->last_error = RFB_ERR_AUTH;
    return RFB_ERR_AUTH;
}

// Read the u32 length + reason bytes of a 3.8 auth failure. The reason is
// stored (escaped later) in failure_reason. Always ends in FAILED.
static rfb_error step_read_security_failure_reason(rfb_handshake *h,
                                                   rfb_buffer *input,
                                                   rfb_buffer *output)
{
    (void)output;
    // First read the length if we haven't yet.
    if (rfb_buffer_length(input) < 4) {
        return RFB_OK;
    }
    rfb_reader r = input_reader(input);
    uint32_t len = 0;
    // The exact four-byte precheck above proves this peek succeeds.
    (void)rfb_peek_u32(&r, 0, &len);
    // Cap the reason length (plan.md §6.4: server name/clipboard/etc. all
    // have hard limits; a 1 MiB cap is generous for a reason string).
    if (len > 1024u * 1024u) {
        h->state = RFB_HS_FAILED;
        h->last_error = RFB_ERR_LIMIT;
        return RFB_ERR_LIMIT;
    }
    if (rfb_buffer_length(input) < 4u + (size_t)len) {
        return RFB_OK;  // need the full reason
    }
    // Consume length + bytes.
    uint32_t got_len = 0;
    (void)rfb_read_u32(&r, &got_len);
    // Retain the permitted prefix. Asking rfb_buffer_append for the full
    // server length would make its hard-limit check reject the whole reason
    // instead of truncating it. Allocation failure remains a real handshake
    // failure and must not be hidden behind the authentication result.
    if (got_len > 0) {
        const uint8_t *reason_ptr = rfb_buffer_data(input) + 4;
        size_t available = h->failure_reason.hard_limit -
                           h->failure_reason.length;
        size_t keep = (size_t)got_len < available
                    ? (size_t)got_len : available;
        rfb_error append_error = rfb_buffer_append(&h->failure_reason,
                                                   reason_ptr, keep);
        if (append_error != RFB_OK) {
            h->state = RFB_HS_FAILED;
            h->last_error = append_error;
            return append_error;
        }
    }
    rfb_buffer_consume(input, 4u + (size_t)got_len);
    h->state = RFB_HS_FAILED;
    h->last_error = RFB_ERR_AUTH;
    return RFB_ERR_AUTH;
}

rfb_error rfb_handshake_step(rfb_handshake *h,
                             rfb_buffer *input,
                             rfb_buffer *output)
{
    if (h == NULL || input == NULL || output == NULL) {
        return RFB_ERR_INTERNAL;
    }
    switch (h->state) {
    case RFB_HS_READ_PROTOCOL_VERSION:
        return step_read_protocol_version(h, input, output);
    case RFB_HS_READ_SECURITY_TYPES:
        return step_read_security_types(h, input, output);
    case RFB_HS_READ_VNC_CHALLENGE:
        return step_read_vnc_challenge(h, input, output);
    case RFB_HS_READ_SECURITY_RESULT:
        return step_read_security_result(h, input, output);
    case RFB_HS_READ_SECURITY_FAILURE_REASON:
        return step_read_security_failure_reason(h, input, output);
    // Explicit-write states are not used by this incremental model (writes
    // are folded into the read states that produce them). They are kept
    // for completeness with plan.md §11's state list.
    case RFB_HS_WRITE_PROTOCOL_VERSION:
    case RFB_HS_WRITE_SECURITY_SELECTION:
    case RFB_HS_WRITE_VNC_RESPONSE:
        return RFB_OK;
    case RFB_HS_DONE:
    case RFB_HS_FAILED:
        return RFB_OK;  // terminal states are stable no-ops
    }
    // Reject an invalid numeric state that is outside rfb_hs_state.
    h->state = RFB_HS_FAILED;
    h->last_error = RFB_ERR_INTERNAL;
    return RFB_ERR_INTERNAL;
}
