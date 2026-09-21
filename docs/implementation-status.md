# Implementation status

## Live product path

`CLI → connect/auth → SHARED-MT protocol, present, and input workers`

The session publishes frames. The application owns presentation. The separate
engine/reactor path remains scaffold code and is not the CLI entry point.
RFB and RDP use one private live presenter owner for selection, construction,
and lifecycle while preserving their distinct v1 and v2 frontend contracts.
RFB and RDP use one callback-driven modifier transaction state machine. It
fails closed on physical modifier delivery and reconciles failed primary or
synthetic releases before later input.
FreeRDP instance-setting application has a private owner. A repository gate
keeps the remediated callback wiring file within the 1,000-line guideline.
RDP live input, terminal suspension, and shared-shell operations have a
private owner. The same repository gate keeps `rdp_live.c` within 1,000 lines.
RFB live logging, input injection, and shared-shell operations have a private
owner. The same repository gate keeps `rfb_live.c` within 1,000 lines.
Remote log escaping uses caller-owned storage. It has no process-global or
shared temporary buffer.
RFB session input serialization, command drain, held-input tracking, and
teardown release have a private owner. The repository size gate protects it.
View-only command queues emit no input. Failed held-key releases retain every
unsent key, and ledger-full recovery admits releases before the new key-down.
RFB transport setup, connected-fd adoption, classic authentication, Apple
connect orchestration, and connect lifecycle have a private owner. The
repository size gate protects it. Connect completion always forgets borrowed
credential pointers. Coalesced classic handshake input remains processable.
RFB output queueing, framebuffer requests, post-ServerInit setup, Apple record
setup, record opening, and rekey transactions have a private wire owner. The
repository size gate protects it.
RFB framebuffer decoding, Apple wake policy, engine hooks, and frame-slot
publication have a private frame owner. Capture scheduling, mutation control,
transport admission, and capture-clock ownership are also isolated. The
remaining session file owns the normal protocol loop, lifecycle, pacing/link
metrics, and public state access. Every RFB session production file is now
protected by the 1,000-line size gate.
Process-wide fatal-signal, terminal, and standard-stream restoration has a
private owner. The same repository gate keeps `live_shell.c` within 1,000 lines.
Production CLI and presenter paths cannot write framebuffer dumps. Removed
dump options fail closed. Test framebuffer capture is memory-only. Production
record/setup paths cannot write plaintext evidence; capture scheduling and
mutation control remain independent of diagnostic files. Product startup
refuses to parse arguments or acquire credentials unless it verifies the
platform core-dump protections.
Inherited environment-driven diagnostic probes are absent from the product.
Private RFB capture artifact and mutation-control interfaces are linked only
into developer, sanitizer, coverage, and fuzz products. Release products omit
those objects and reject mutation-control configuration. Optimized tests use
explicit test-only session objects to keep the diagnostic contracts covered.
FreeRDP/WinPR WLog is fixed off in release builds. Its CLI controls exist only
in explicit RDP-enabled developer, sanitizer, coverage, and fuzz builds, and
those builds reject the controls for resolved RFB targets.
RFB and RDP use one password-acquisition owner for file descriptors and the
controlling-terminal prompt. It closes credential descriptors, rejects an
empty password when authentication requires one, and zeroizes the full owned
allocation after use. Acquisition keeps the complete password. Only the
classic VNC handshake copies the first eight bytes required by RFC 6143.
Deterministic Apple authentication and server providers live under
`tests/fakes/`. Neither their implementations nor their headers are part of
the product source or public-header sets.

| Path | Status |
|------|--------|
| `rdp://` with Kitty | Live through `rdp_live` |
| Classic `vnc://` | Live through `rfb_live` |
| Apple security type 33 | Preferred live RSA1, SPKI/TOFU, SRP, and post-auth record path |
| Apple security type 36 | Compatibility path: cleartext username, no SPKI/TOFU pin, SRP M2 verification, wrap-key, and post-auth records |
| Apple `0x03f3` | Type-0 command and image planes decode and paint; unsupported forms fail closed |
| Apple `0x0450` | Profile-1000 alpha cursor decoded and composited into the copied presentation frame; a non-canonical ServerInit pixel format is rejected when this encoding is decoded |
| Status band | Scale, RTT, and receive rate |

The default Apple security policy prefers type 33. Type 36 is available as an
automatic fallback or through explicit `--apple-security 36` selection. It
does not provide the type-33 host-pin check, so operators must treat endpoint
selection and the cleartext username as part of the compatibility risk.

## Build and verification

Use the Nix development environment and the root Makefile. The full candidate
gate is `nix develop --command make ci`.

The repository includes unit, component, integration, sanitizer, fuzz, static
analysis, dependency, license, and release-policy checks. A release decision
must use fresh results from the candidate tree rather than counts copied into
this document.

Release packaging binds the staged binary to a recomputed dynamic-library
closure and the reviewed dependency manifest. The deterministic SPDX document
contains only libraries in that closure. Its namespace binds the complete
canonical document and binary digest. The final artifact gate also requires
reviewed notice bytes, an exact archive inventory and metadata, final-content
trace scans, and matching checksums. Reproducibility compares two complete
artifact sets, not only the executables. The no-RDP package uses the same gates
with its smaller runtime closure and feature-aware test inventory.

The build and test matrix covers macOS and Linux. The machine-readable release
policy currently permits published artifacts only for `aarch64-darwin` and
`x86_64-darwin`. Release staging fails closed elsewhere. This avoids treating
Linux system runtimes as approved dependencies when their licenses are outside
the locked artifact allowlist. Linux optimized builds, sanitizers, TSAN, and
ordinary Nix-package checks remain required CI evidence.

Coverage uses the exact closed product link set, including zero-hit product
objects. The report fails on coverage-data inconsistencies, source-inventory
drift, extraction failure, or report-generation failure. Product source files
contain no `LCOV_EXCL_*` exclusions. Per-module ratchets do not replace the 85%
line and 80% branch release policy in `plan.md`.

### Retained-source verification evidence

The following repository-local checks passed on 2026-09-18 and 2026-09-19
after the Apple type-36 and `0x0450` update:

- On macOS arm64, the development Clang, GCC, optimized-release, and
  Apple-Clang ASan/UBSan suites passed all 2,333 registered C tests. The
  development and optimized no-RDP suites passed all 2,077 registered C tests.
  Each applicable build also passed all 201 Python tool tests and the shell
  tool self-tests.
- Apple preservation covers 1,024 focused tests. Its inventory SHA-256 is
  `e1bf445913ca3c16044140e09aa33af54cfa0bd9fc5220a16b8c96f39e493d7c`.
- The macOS default runtime closure contains 13 libraries. The no-RDP closure
  contains four libraries. Both passed the license policy.
- The default and no-RDP release binaries and complete artifact sets were
  byte-for-byte reproducible across clean build directories.
- Integration, license, binary-policy, current-content, reachable-history,
  secret, and Apple-preservation checks passed. Coverage was 19,292 of 21,653
  lines (89.1%) and 12,198 of 15,239 branches (80.0%). All module ratchets
  passed, and static analysis covered 131 production files. All 17 fuzz targets
  passed the five-second smoke run and the 60-second sustained run.
- On Linux arm64, the current default Nix package built successfully after the
  type-36 and `0x0450` update. Earlier Clang and GCC runs each passed all 2,313
  C tests. The earlier no-RDP and leak-enabled ASan/UBSan suites each passed all
  2,059 C tests, and the focused thread-sanitizer gate passed without a
  diagnostic. Those earlier Linux test results remain regression evidence
  rather than current-candidate acceptance.

On 2026-09-02, the predecessor default and no-RDP artifact sets were
byte-for-byte reproducible. Their SBOM, archive, notes, checksum, binary,
license, and trace audits passed. The 2026-09-01 baseline also ran all 17 fuzz
targets for 60 seconds each. These older results are regression evidence, not
final acceptance evidence for the current commit.

### 2026-09-20 post-cleanup candidate evidence

The post-history-cleanup source candidate produced the following fresh results:

- The macOS arm64 and Linux arm64 default Nix packages built successfully. The
  Linux build ran on the configured Linux builder.
- All 17 fuzz targets completed a 60-second sustained run. The build retained
  17 logs, 17 per-target artifact directories, and the evolved corpora. No
  failure artifact was produced.
- Default and no-RDP complete artifact sets were byte-for-byte reproducible.
  Their release audits passed. The runtime closures contained 13 and four
  libraries respectively.
- The full macOS gate passed 2,338 registered C tests and 211 Python tool
  tests. Clang, GCC, optimized release, no-RDP development and release,
  Apple-Clang ASan/UBSan, coverage, fuzz smoke, license, current-content,
  reachable-history, secret, integration, static-analysis, and header-boundary
  gates all passed. Coverage was 19,329 of 21,696 lines (89.1%) and 12,216 of
  15,268 branches (80.0%); every module floor passed.
- On the Windows 11 ARM lab, signed release and developer builds delivered
  frames at 1280x800, resize delivered frames at 1024x768, an incorrect
  password failed as expected, and fresh and unchanged certificate pins worked.
  PTY disconnect, signals, resize, and terminal restoration passed. Clipboard
  channel-on and channel-off sessions were stable, but clipboard content was
  not checked. Controlled certificate replacement, peer disconnect, and visual
  input and fidelity checks remain open.
- On the authorized macOS endpoint, a Developer ID-signed post-cleanup
  candidate at revision `004c45ac770bcc26947a6c92eb3fe55128b6e362`
  passed the identity-bound signature check, forced type 36, entered protected
  records, and displayed a complete 3840x2160 RGBA frame. The client requested
  `0x0450`, but the server did not send that encoding during this test run, so
  live cursor composition remains open. Visual input and clipboard
  content checks were not run. The exact-candidate recheck confirmed that
  revision `8de3cb6` restores `O_NONBLOCK` for the live PTY topology. Darwin's
  kernel added its private `FWASWRITTEN` bookkeeping bit after terminal output;
  that bit is not an inherited nonblocking mode or a user-settable status flag.
- A later exact signed head recheck at revision
  `2051d2e25af67581770d9d3263ced862a47d255b` again completed forced type-36
  authentication and protected-record activation. The endpoint returned only
  black full-size updates across protected-record, cleartext, and private
  post-auth modes. Independently observed pointer and keyboard state did not
  change, clipboard transfer failed in both directions, and no `0x0450`
  rectangle was observed. These failures keep the rows open without proving
  whether the changed behavior is in the client or the current endpoint state.
- The same head candidate reached the Windows 11 ARM lab's credential boundary,
  but both available credentials were stale and the guest console independently
  rejected the operator-supplied value. The original guest image remains
  unchanged and passes `qemu-img check`; current-head Windows fidelity rows
  remain open until authorized guest access is restored.
- Authorized access was then recovered on a disposable clone. The exact
  Developer ID-signed candidate
  `b89d4fdbaf023e198101a89b506c0c0b960ad085` completed the Windows 11 ARM
  matrix: correct and incorrect credentials, visible 1280x800 output,
  1024x768 output, keyboard, pointer, wheel, clipboard in both directions,
  terminal resize, leader exit, all three shutdown signals, clean server
  sign-out, first-use pinning, and rejection after an actual certificate
  rotation. The unchanged pin failed closed with exit 4, while an ignore-policy
  control delivered 189 frames with the new certificate. The original guest
  stayed stopped and unchanged and again passed `qemu-img check`. The clone and
  all temporary credentials, captures, logs, recovery files, and disk copies
  were deleted. Independent xrdp coverage remains unavailable and is not
  claimed.
- The same signed candidate passed the identity-bound macOS acceptance target,
  forced type 36, attached to the shared desktop, and activated protected
  records. Its extended Apple matrix recorded black full-size updates, no
  observed `0x0450`, and no working visual input or clipboard transfer.
- A 2026-09-21 live diagnostic against the same authorized endpoint corrected
  the black-frame diagnosis. Cleartext and protected ZRLE/Raw modes decoded a
  visible 3840x2160 framebuffer. Private `0x03f3` mode alone stayed black: the
  DCT decoder rejected the observed `001` DC-reuse selector. The corrected
  decoder preserved all three DC predictors, decoded the following AC payload,
  and produced a non-black third protected frame with 32,399 of 32,400 sampled
  pixels non-black. This diagnostic used a dirty development build, so an exact
  signed-candidate recheck is still required. Live `0x0450`, input, and
  clipboard acceptance remain open.

The signing identity is approved. Extended live interoperability, manual
acceptance, and independent release approval remain pending. A Linux release
runtime closure is not an acceptance target while Linux is absent from the
published artifact allowlist.

The macOS acceptance target now performs a bounded live Apple session and
emits a sanitized protected-record result bound to the binary's version,
revision, SHA-256 digest, and approved Developer ID certificate. The manual
release workflow can create an annotated tag and GitHub release after all
machine-readable approvals pass and publication is explicitly selected.
Neither capability changes the pending approval or manual-fidelity status.

## Release status

**Blocked.** The Apple feature set is not approved for release. Release requires
the ADR-0013 repository-owner governance decision and any required counsel
review. See `docs/provenance.md`.

Basic authorized macOS interoperability passed under G26. Type-33 covers a
rendered framebuffer and basic input. An exact signed type-36 candidate covers
authentication, protected-record activation, and framebuffer delivery. Live
`0x0450` plus extended Apple input and clipboard checks remain partial. The
Windows 11 ARM RDP matrix passes; independent xrdp coverage remains unavailable.
G26 completion does not clear the separate provenance, packaging, dependency,
documentation, or final acceptance gates.

The correctness, security, packaging, dependency, documentation, and history
gates must all pass before release.
