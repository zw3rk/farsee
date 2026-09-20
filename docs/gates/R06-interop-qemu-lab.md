# R6 — RDP interoperability

- **Status:** machine coverage and the Windows 11 ARM matrix pass; independent xrdp coverage remains open
- **Evidence:** this card, the current source tree, and tests under `tests/`

## Scope

Exercises the live RDP path against independent xrdp and Windows endpoints.
The matrix covers credential success and failure, TLS and certificate
policy, resize, latency, Windows TLS+NLA connection, and first-frame delivery.
The extended manual endpoint matrix remains incomplete.

## 2026-09-19 Windows VM evidence

UTM 4.7.5 initially described the existing Windows 11 ARM lab bundle as newer
or incompatible. The disk image was not the cause. The third drive entry lacked
its required `Identifier`; assigning a UUID made the bundle valid again. The
repaired configuration starts the guest, and its QCOW2 image passes `qemu-img
check` with no errors. A direct X.224 negotiation selected HYBRID/NLA.
After the implicit `rdpdr` triggers were disabled, a Developer ID-signed
release CLI progressed through negotiation, TLS, and CredSSP to the Windows
account-policy boundary. The earlier
missing-`librdpdr-client.dylib` failure did not recur.

The guest account then returned the Windows password-expired result. The lab
account was repaired through an elevated recovery session. The final guest has
NLA enabled, refuses remote use of blank passwords, and has no accessibility
utility debugger override. The VM was shut down cleanly after testing.

An earlier Developer ID-signed release CLI then completed a TLS+NLA session
with the correct password and published 212 frames at 1280x800. The same binary
rejected an incorrect password with exit status 4 and
`ERRCONNECT_LOGON_FAILURE`. This closes credential success, credential failure,
and first-frame delivery for this Windows endpoint. Resize, clipboard, and the
full manual matrix remain open.

The checked-in unattended and direct-deployment paths now mark only the lab
account as password-never-expires. This prevents rebuilt test guests from aging
into the same account-policy boundary; it does not repair the already
provisioned guest.

## 2026-09-20 current-candidate evidence

The pre-documentation Developer ID-signed release CLI completed a cold TLS+NLA
session in 14.3 seconds and published 32 frames at 1280x800. The signed
developer CLI completed the same session in 10.8 seconds and published 35
frames. A separate resize run published 26 frames at 1024x768. An incorrect
password failed with exit status 4 and `ERRCONNECT_LOGON_FAILURE`.

A fresh pin run created a private configuration directory and a mode-0600,
one-record pin store. A later run accepted the unchanged pin and delivered
frames. Sessions with clipboard-channel negotiation enabled and disabled
published 132 and 105 frames respectively. These runs prove channel policy and
session stability; clipboard content transfer remains unverified.

Real-PTY checks passed for leader-key disconnect, `SIGINT`, `SIGTERM`, and
`SIGHUP`. Each path restored the original terminal attributes and disabled
mouse reporting, Kitty keyboard mode, and the hidden-cursor state. A resize
from 100x40 to 120x50 preserved output and exited cleanly.

Cold guest activation needed a 60-second internal connection deadline. Earlier
30-second no-frame results are superseded by the successful runs above. The
following manual rows remain `NOT RUN`: controlled certificate replacement,
clipboard content in both directions, visual resize quality, independent
standard-stream flag inspection, peer disconnect, and visible pointer, scroll,
and keyboard correctness. The guest was paused after testing. UTM could not
save machine state because the emulated NVMe device does not support snapshots;
the guest was not force-powered off.

### 2026-09-20 exact-head access recheck

The exact signed head candidate at
`2051d2e25af67581770d9d3263ced862a47d255b` reached the Windows 11 ARM lab and
advanced to credential validation. The operator-supplied credential and the
credential retained on the unattended-install medium both returned
`ERRCONNECT_LOGON_FAILURE`. The guest console independently rejected the
operator-supplied credential, which distinguishes the current access failure
from a Farsee-only authentication defect.

The VM configuration was restored to its original normal-boot form after a
read-only recovery inspection. Temporary recovery media were removed, the
guest shut down cleanly, and its original QCOW2 image passed `qemu-img check`
without errors. The image was not modified. Current-head Windows framebuffer,
input, clipboard, resize, certificate-replacement, peer-disconnect, and
terminal-restoration acceptance remain uncredited until authorized guest
access is restored.

## 2026-09-20 exact signed Windows matrix completion

Authorized access was recovered only on a disposable clone. The original
Windows 11 ARM guest remained stopped and unchanged. The exact signed candidate
`b89d4fdbaf023e198101a89b506c0c0b960ad085` completed the Windows matrix:

- correct credentials delivered 172 frames at 1280x800; an incorrect password
  failed with exit 4 and `ERRCONNECT_LOGON_FAILURE`;
- a 1024x768 run delivered 148 frames, and separate clipboard-on and
  clipboard-off runs delivered 190 and 104 frames;
- a captured 1280x800 framebuffer showed a complete Windows desktop;
- visible keyboard text remained ordered, pointer motion and click reached the
  intended controls, and wheel input scrolled a 34-line document from line 12
  to line 1;
- clipboard text passed in both directions, and the host pasteboard was
  restored after each check;
- leader quit, `SIGINT`, `SIGTERM`, and `SIGHUP` all stopped cleanly and emitted
  the expected terminal cleanup controls;
- the live PTY resized from 80x24 to 120x50 and then 100x40 while presentation
  continued;
- server sign-out ended cleanly with `ERRINFO_LOGOFF_BY_USER` after 153 frames;
- first-use pinning created a mode-0600 pin and delivered 203 frames. An actual
  guest certificate rotation and reboot made that unchanged pin fail closed
  with exit 4. The ignore-policy control delivered 189 frames with the new
  certificate.

The task-owned clone and all temporary credentials, recovery files, captures,
logs, and disk copies were deleted after the matrix. The original guest was
still stopped, was not modified by this work, and passed `qemu-img check` with
no errors. This completes the Windows 11 ARM endpoint matrix for the exact
candidate. Independent xrdp coverage remains unavailable and is not claimed.

## `--cert pin` escalation packet (resolved)

### Verified facts

- More than five fresh-home attempts against the same healthy Windows endpoint
  failed before credential exchange with exit status 4 and
  `ERRCONNECT_TLS_CONNECT_FAILED`.
- `--cert ignore` against that endpoint completes TLS+NLA and publishes frames.
- Both an absent `.farsee` directory and a pre-created mode-0700 directory give
  the same pin failure. No Farsee `rdp_known_hosts` file is created.
- A FreeRDP trace identifies the self-signed Windows lab certificate, reports
  FreeRDP's endpoint-keyed certificate-store path, and aborts with `certificate
  not trusted`.
- Farsee installs `VerifyX509Certificate` and leaves
  `FreeRDP_IgnoreCertificate` false. It does not enable
  `FreeRDP_ExternalCertificateManagement`.
- The pinned FreeRDP 3.15.0 `tls_verify_certificate` implementation calls
  `VerifyX509Certificate` as the sole certificate-policy owner only when
  `ExternalCertificateManagement` is true. Otherwise it first consults its
  internal CA, hostname, and certificate stores, then calls the callback with
  the resulting flags when its store reports first use or change.
- In this run FreeRDP detects the expected IP-address/CN mismatch and supplies
  `VERIFY_CERT_FLAG_MISMATCH`. Farsee currently maps that flag to `CHANGED`.
  Pin mode rejects `CHANGED`, so the callback returns rejection before it can
  write the first-use Farsee pin.

### Tried variants

The failure reproduced with the release binary, the developer binary, a fully
absent fresh home, a fresh home with `.farsee` created in advance, and repeated
VM boots. A developer trace changed logging only. The control case used the
same endpoint, account, password source, and presenter with `--cert ignore`.

### Exact failure

Farsee intends its callback and host-keyed store to own TOFU policy, but the
FreeRDP setting that selects external certificate management is off. FreeRDP
therefore applies its internal hostname classification before calling Farsee.
The callback receives this first observation with the hostname-mismatch flag,
classifies it as a changed certificate, and rejects it. This makes `--cert pin`
unusable for a normal self-signed Windows RDP certificate addressed by IP, even
though direct callback and known-hosts unit tests pass.

### Independent review

An independent senior review confirmed the failure sequence from the trace and
the pinned FreeRDP source. It recommended enabling
`FreeRDP_ExternalCertificateManagement` only for `--cert pin`. Changing the
meaning of FreeRDP's hostname-mismatch flag would fix this endpoint but would
not let pin mode inspect a CA-valid certificate or a certificate already in
FreeRDP's store. Enabling external management for every policy would bypass
FreeRDP's CA and hostname validation where Farsee cannot replace it safely.

The implementation therefore enables external management only when
`tofu_pin_store` is true. Pin mode receives every full-chain PEM certificate,
keys the fingerprint to Farsee's host and port, returns session-only approval,
and leaves FreeRDP's private certificate store non-authoritative. Default and
ignore policies retain FreeRDP's normal CA, hostname, and store processing.

### Post-fix verification

- The focused callback suite passed 43 of 43 tests. New regressions prove that
  only pin policy enables external certificate management and that PreConnect
  restores the intended value after deliberate mutation.
- Two independent fresh homes created `.farsee/rdp_known_hosts` on first
  certificate observation and passed TLS. Windows later returned an activation
  timeout on those first desktop attempts; retrying each unchanged pin
  completed the session with 194 and 33 frames at 1280x800 respectively.
- Replacing one hexadecimal digit in a disposable pin caused immediate
  `ERRCONNECT_TLS_CONNECT_FAILED`. The rejected pin file was not overwritten.
- An ignore-policy control completed with 44 frames and did not change the
  disposable Farsee pin file.
- Pin-mode runs did not create or consult a FreeRDP server-certificate record
  under the disposable home.

FreeRDP supplies the complete certificate chain in PEM form. Farsee hashes the
exact callback bytes. A chain or PEM representation change therefore produces
a different pin and fails closed.

### Reproduction

Use a private password file and a disposable home; do not put the password in
the command line or environment:

```sh
home_dir=$(mktemp -d)
chmod 700 "$home_dir"
IFS= read -r lab_host <path-to-private-host-file
IFS= read -r lab_user <path-to-private-user-file
exec 3<path-to-private-password-file
HOME="$home_dir" timeout 45 build/dev/bin/farsee \
  --log-level trace --cert pin --presenter null --password-fd 3 \
  "rdp://$lab_user@$lab_host"
status=$?
exec 3<&-
printf 'exit=%s\n' "$status"
```

## Verification

Machine checks live in the test suite and `make ci`. Gate status is authoritative in
`docs/implementation-status.md`.
