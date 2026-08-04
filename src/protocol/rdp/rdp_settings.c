// SPDX-License-Identifier: Apache-2.0
//
// Farsee RDP settings implementation (R1 gate, §15.4, §10.6).

#include "rdp_settings.h"

#include <stddef.h>
#include <string.h>

farsee_rdp_settings farsee_rdp_settings_defaults(void)
{
    farsee_rdp_settings s;
    s.hostname[0] = '\0';
    s.port = 3389;                          // RDP default
    s.username[0] = '\0';
    s.domain[0] = '\0';
    s.security = FARSEE_RDP_SECURITY_TLS_NLA;
    s.require_tls = true;                   // §15.4
    s.require_nla = true;                   // §15.4
    s.allow_legacy_rdp_security = false;    // §15.4
    s.desktop_width = 1280;
    s.desktop_height = 800;
    s.connect_timeout_ms = 0;  // FreeRDP default unless CLI sets it
    // §10.6: every optional redirection channel OFF by default.
    s.channels.clipboard_text = false;      // enabled by R5
    s.channels.drive_redirection = false;
    s.channels.printer_redirection = false;
    s.channels.smartcard_redirection = false;
    s.channels.serial_port_redirection = false;
    s.channels.parallel_port_redirection = false;
    s.channels.printer = false;
    s.channels.microphone_capture = false;
    s.channels.audio_capture = false;
    s.channels.audio_playback = false;
    s.channels.usb_redirection = false;
    s.channels.generic_device_redirection = false;
    s.channels.file_clipboard = false;
    s.channels.rich_clipboard_formats = false;
    return s;
}

static void copy_bounded(char *dst, size_t cap, const char *src)
{
    if (dst == NULL || cap == 0) {
        return;
    }
    dst[0] = '\0';
    if (src == NULL) {
        return;
    }
    size_t n = strlen(src);
    if (n >= cap) {
        n = cap - 1;
    }
    memcpy(dst, src, n);
    dst[n] = '\0';
}

bool farsee_rdp_settings_init_for_host(farsee_rdp_settings *s, const char *hostname,
                                uint16_t port, const char *username,
                                const char *domain)
{
    if (s == NULL || hostname == NULL || hostname[0] == '\0') {
        return false;
    }
    *s = farsee_rdp_settings_defaults();
    copy_bounded(s->hostname, sizeof(s->hostname), hostname);
    if (port != 0) {
        s->port = port;
    }
    copy_bounded(s->username, sizeof(s->username), username);
    copy_bounded(s->domain, sizeof(s->domain), domain);
    return true;
}

bool farsee_rdp_settings_valid(const farsee_rdp_settings *s)
{
    if (s == NULL || s->hostname[0] == '\0') {
        return false;
    }
    // §15.4: TLS required by default. Legacy RDP security may only be
    // allowed as an explicit, separately-named unsafe option; even then
    // it must not be the path when TLS is required.
    if (s->allow_legacy_rdp_security && s->require_tls) {
        return false;  // contradictory: can't require TLS and allow legacy
    }
    if (s->security == FARSEE_RDP_SECURITY_RDP && !s->allow_legacy_rdp_security) {
        return false;  // legacy selected but not explicitly allowed
    }
    if (s->desktop_width == 0 || s->desktop_height == 0) {
        return false;
    }
    if (s->desktop_width > 16384u || s->desktop_height > 16384u) {
        return false;
    }
    return true;
}

bool farsee_rdp_settings_channels_within_baseline(const farsee_rdp_settings *s)
{
    if (s == NULL) {
        return false;
    }
    const rdp_channel_allowlist *c = &s->channels;
    // clipboard_text is the only allowed optional channel in the baseline.
    if (c->drive_redirection || c->printer_redirection ||
        c->smartcard_redirection || c->serial_port_redirection ||
        c->parallel_port_redirection || c->printer ||
        c->microphone_capture || c->audio_capture ||
        c->usb_redirection || c->generic_device_redirection ||
        c->file_clipboard || c->rich_clipboard_formats) {
        return false;
    }
    return true;
}
