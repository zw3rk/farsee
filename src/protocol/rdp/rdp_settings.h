// SPDX-License-Identifier: Apache-2.0
//
// Farsee RDP settings + channel allowlist (R1 gate, §15.4, §10.6).
//
// PRIVATE to src/protocol/rdp/. A Farsee-owned settings bundle that is
// mapped FROM a Farsee profile and TO FreeRDP settings. The mapper is a
// pure function, fully testable without a live RDP server. The channel
// allowlist (§10.6) keeps every optional redirection channel OFF by
// default; only a baseline desktop's required channels may be enabled.

#ifndef FARSEE_SRC_PROTOCOL_RDP_RDP_SETTINGS_H
#define FARSEE_SRC_PROTOCOL_RDP_RDP_SETTINGS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// RDP security level (maps to FreeRDP's authentication/transport policy).
typedef enum {
    FARSEE_RDP_SECURITY_TLS_NLA = 0,   // TLS + CredSSP/NLA (default, §15.4)
    FARSEE_RDP_SECURITY_TLS      = 1,  // TLS without NLA
    FARSEE_RDP_SECURITY_RDP      = 2,  // legacy RDP security (never default)
} farsee_rdp_security_level;

// Optional redirection channels (§10.6). All OFF by default. Each may only
// be enabled by an explicit, separately-gated decision.
typedef struct rdp_channel_allowlist {
    bool clipboard_text;   // plain-text clipboard (R5 gate)
    // Everything below is OFF and out of first-RDP-release scope (§10.6).
    bool drive_redirection;
    bool printer_redirection;
    bool smartcard_redirection;
    bool serial_port_redirection;
    bool parallel_port_redirection;
    bool printer;
    bool microphone_capture;
    bool audio_capture;
    bool audio_playback;
    bool usb_redirection;
    bool generic_device_redirection;
    bool file_clipboard;
    bool rich_clipboard_formats;
} rdp_channel_allowlist;

// The Farsee-owned settings bundle. Plain values; secrets (password) are
// NOT stored here — they come from the F6 credential provider at runtime.
typedef struct farsee_rdp_settings {
    char hostname[256];
    uint16_t port;                  // default 3389
    char username[128];
    char domain[64];
    farsee_rdp_security_level security;
    bool require_tls;               // §15.4 default true
    bool require_nla;               // §15.4 default true
    bool allow_legacy_rdp_security;// §15.4 default false
    uint32_t desktop_width;         // requested initial desktop size
    uint32_t desktop_height;
    // TCP connect / NLA transport budget for FreeRDP_TcpConnectTimeout
    // (milliseconds). 0 → leave FreeRDP default. CLI --connect-timeout.
    uint32_t connect_timeout_ms;
    rdp_channel_allowlist channels;
} farsee_rdp_settings;

// The safe defaults (§15.4): TLS+NLA required, legacy off, 1 desktop,
// every redirection channel OFF, plain-text clipboard OFF (enabled by R5).
farsee_rdp_settings farsee_rdp_settings_defaults(void);

// Initialize settings from a host (+ optional user/domain). Applies the
// safe defaults, then sets the endpoint. Returns false on bad args.
bool farsee_rdp_settings_init_for_host(farsee_rdp_settings *s, const char *hostname,
                                uint16_t port, const char *username,
                                const char *domain);

// Validate a settings bundle. Returns false if security posture is unsafe:
// legacy RDP security allowed without TLS, or NLA disabled while TLS is on
// in a way that violates §15.4, or dimensions are zero/oversized.
bool farsee_rdp_settings_valid(const farsee_rdp_settings *s);

// Apply the channel allowlist policy (§10.6): returns true iff NO high-risk
// redirection channel is enabled (drive/printer/smartcard/serial/parallel/
// mic/usb/generic/file-clipboard/rich-formats). clipboard_text is allowed.
bool farsee_rdp_settings_channels_within_baseline(const farsee_rdp_settings *s);

#ifdef __cplusplus
}
#endif

#endif  // FARSEE_SRC_PROTOCOL_RDP_RDP_SETTINGS_H
