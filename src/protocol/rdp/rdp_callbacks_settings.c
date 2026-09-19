// SPDX-License-Identifier: Apache-2.0
//
// FreeRDP instance settings owned by the callback connection boundary.

#include "rdp_callbacks_settings.h"

#include <freerdp/freerdp.h>
#include <freerdp/settings.h>

#include <stdint.h>

bool rdp_callbacks_apply_instance_settings(
    void *freerdp_instance, const rdp_callback_context *cbctx)
{
    freerdp *inst = (freerdp *)freerdp_instance;
    if (inst == NULL || cbctx == NULL || cbctx->settings == NULL ||
        inst->context == NULL) {
        return false;
    }
    rdpSettings *s = inst->context->settings;

    // §10.6: disable every non-allowlisted redirection channel. Baseline
    // allows only clipboard_text; everything else is OFF.
    const rdp_channel_allowlist *c = &cbctx->settings->channels;
    freerdp_settings_set_bool(s, FreeRDP_RedirectDrives,
                              c->drive_redirection);
    freerdp_settings_set_bool(s, FreeRDP_RedirectPrinters,
                              c->printer_redirection);
    freerdp_settings_set_bool(s, FreeRDP_RedirectSmartCards,
                              c->smartcard_redirection);
    freerdp_settings_set_bool(s, FreeRDP_RedirectSerialPorts,
                              c->serial_port_redirection);
    freerdp_settings_set_bool(s, FreeRDP_RedirectParallelPorts,
                              c->parallel_port_redirection);
    freerdp_settings_set_bool(s, FreeRDP_RedirectClipboard,
                              c->clipboard_text);
    freerdp_settings_set_bool(s, FreeRDP_AudioCapture, c->audio_capture);
    freerdp_settings_set_bool(s, FreeRDP_AudioPlayback, c->audio_playback);

    // FreeRDP's generic client loader enables rdpdr when any of these
    // dependency flags are set. They are independent of the explicit device
    // toggles above and some default to on. Farsee does not allow rdpdr, so
    // pin every implicit trigger off before LoadChannels runs.
    freerdp_settings_set_bool(s, FreeRDP_DeviceRedirection, FALSE);
    freerdp_settings_set_bool(s, FreeRDP_RedirectHomeDrive, FALSE);
    freerdp_settings_set_bool(s, FreeRDP_NetworkAutoDetect, FALSE);
    freerdp_settings_set_bool(s, FreeRDP_SupportHeartbeatPdu, FALSE);
    freerdp_settings_set_bool(s, FreeRDP_SupportMultitransport, FALSE);
    if (!farsee_rdp_settings_channels_within_baseline(cbctx->settings)) {
        return false;
    }

    // §15.4: default to TLS with NLA and disable legacy RDP security.
    freerdp_settings_set_bool(s, FreeRDP_UseRdpSecurityLayer,
                              cbctx->settings->allow_legacy_rdp_security);
    freerdp_settings_set_bool(s, FreeRDP_TlsSecurity,
                              cbctx->settings->require_tls);
    freerdp_settings_set_bool(
        s, FreeRDP_NlaSecurity,
        cbctx->settings->security == FARSEE_RDP_SECURITY_TLS_NLA);

    freerdp_settings_set_string(s, FreeRDP_ServerHostname,
                                cbctx->settings->hostname);
    freerdp_settings_set_uint32(s, FreeRDP_ServerPort,
                                (UINT32)cbctx->settings->port);
    freerdp_settings_set_uint32(s, FreeRDP_DesktopWidth,
                                cbctx->settings->desktop_width);
    freerdp_settings_set_uint32(s, FreeRDP_DesktopHeight,
                                cbctx->settings->desktop_height);

    // GDI decodes into a full BGRA8888 primary buffer for publication.
    freerdp_settings_set_bool(s, FreeRDP_SoftwareGdi, TRUE);
    freerdp_settings_set_bool(s, FreeRDP_SupportGraphicsPipeline, FALSE);
    freerdp_settings_set_uint32(s, FreeRDP_ColorDepth, 32);
    freerdp_settings_set_bool(s, FreeRDP_BitmapCacheEnabled, TRUE);

    // Pin mode must observe every peer certificate, including certificates
    // that FreeRDP would otherwise accept from its CA or private store. Make
    // Farsee's host:port known_hosts policy the sole certificate authority in
    // that mode. Keep FreeRDP's normal CA + hostname validation for all other
    // policies; Farsee cannot replace those checks outside explicit TOFU pin.
    const BOOL external_certificate_management =
        cbctx->policy != NULL && cbctx->policy->tofu_pin_store ? TRUE : FALSE;
    if (!freerdp_settings_set_bool(s, FreeRDP_ExternalCertificateManagement,
                                   external_certificate_management)) {
        return false;
    }

    // Ignore remains false so approved callbacks return session-only and
    // FreeRDP never persists a second trust decision beside Farsee's pin.
    freerdp_settings_set_bool(s, FreeRDP_IgnoreCertificate, FALSE);
    freerdp_settings_set_bool(s, FreeRDP_TcpKeepAlive, TRUE);

    if (cbctx->settings->connect_timeout_ms > 0u) {
        freerdp_settings_set_uint32(s, FreeRDP_TcpConnectTimeout,
                                    cbctx->settings->connect_timeout_ms);
    }

    if (cbctx->credentials != NULL) {
        if (cbctx->credentials->username != NULL) {
            freerdp_settings_set_string(s, FreeRDP_Username,
                                        cbctx->credentials->username);
        }
        if (cbctx->credentials->domain != NULL &&
            cbctx->credentials->domain[0] != '\0') {
            freerdp_settings_set_string(s, FreeRDP_Domain,
                                        cbctx->credentials->domain);
        }
    }
    return true;
}

bool rdp_callbacks_apply_settings(rdp_freerdp_ctx *ctx,
                                  const rdp_callback_context *cbctx)
{
    if (ctx == NULL) {
        return false;
    }
    return rdp_callbacks_apply_instance_settings(
        rdp_freerdp_instance_opaque(ctx), cbctx);
}
