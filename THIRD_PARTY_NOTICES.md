# Third-Party Notices

This file lists all third-party material shipped with, or linked into,
`farsee` release artifacts, together with the license and provenance of
each. It is updated before any new dependency is merged (plan.md §5.4).

The project license is Apache-2.0 (see `LICENSE`).

## Policy

Only licenses on the plan.md §5.4 allowlist may be linked into release
artifacts:

- Apache-2.0
- MIT
- ISC
- BSD-2-Clause
- BSD-3-Clause
- zlib
- CC0-1.0 / Unlicense (after provenance review)

GPL, AGPL, and LGPL dependencies are not permitted in release artifacts under
the current allowlist. Build- and test-only tools are documented separately
below and do not enter release artifacts.

## System libraries (linked, not vendored)

These are provided by the host or by the Nix devShell at build/runtime. They
are linked but their source is **not** included in this repository.

### Apple platform runtime — macOS system libraries

- **Upstream:** Apple, shipped as part of macOS.
- **Version:** the supported host macOS release and SDK.
- **License:** Apple system library terms. These paths are an explicit platform
  runtime exception rather than a dependency-license allowlist entry.
- **Use:** the final macOS binary resolves the Carbon, CoreFoundation, and
  Foundation frameworks plus `libSystem.B.dylib` and `libobjc.A.dylib`.
- **Distribution:** farsee links to these host paths and does not redistribute
  the libraries.
- **Closure policy:** `release/dependencies.json` lists every accepted absolute
  path. No directory-prefix exemption is used.

### zlib 1.3.1 — ZRLE inflation

- **Upstream:** https://zlib.net/
- **Version:** 1.3.1 (pinned nixpkgs `zlib`).
- **License:** zlib license (SPDX: `Zlib`) — on the §5.4 allowlist.
- **Use:** `inflateInit`, `inflate`, `inflateReset` for the ZRLE decoder (G8).
- **Provenance:** plan.md §5.5 names zlib explicitly as the ZRLE dependency.
- **ADR:** docs/adr/0002-crypto-provider.md covers provider and dependency
  policy. The product's zlib use is specified directly in plan.md §5.5.

### OpenSSL 3.4.3 — cryptographic provider

- **Upstream:** https://www.openssl.org/
- **Version:** 3.4.3 (pinned nixpkgs `openssl`).
- **License:** Apache-2.0 — on the §5.4 allowlist.
- **Use:** Provider for hashes, HMAC, PBKDF2, RSA, AES, random generation,
  constant-time comparison, and modular arithmetic in the Apple
  authentication and record protocols on every platform. On Linux it also
  provides DES for classic VNC Authentication.
- **Provenance:** RFC 6143 §7.2.2 (public spec); OpenSSL API documentation.
- **ADR:** docs/adr/0002-crypto-provider.md.

### Apple CommonCrypto — VNC Authentication provider (macOS)

- **Upstream:** Apple system framework, shipped with macOS.
- **Version:** current macOS SDK.
- **License:** Apple system library (redistribution governed by the macOS
  SDK agreement; we only link against the system framework, we do not
  redistribute it).
- **Use:** `CCCrypt` supplies DES-ECB for classic VNC Authentication on
  macOS. The Apple authentication path uses OpenSSL as described above.
- **Provenance:** Apple CommonCrypto headers (`<CommonCrypto/...>`).
- **ADR:** docs/adr/0002-crypto-provider.md.

### FreeRDP 3.15.0 — RDP engine backend (optional, `FARSEE_WITH_RDP=1`)

- **Upstream:** https://github.com/FreeRDP/FreeRDP
- **Version:** **3.15.0** (nixpkgs `freerdp`, `nixos-25.05` pin).
  pkg-config modules: `freerdp3`, `freerdp-client3`, `winpr3`.
- **License:** Apache-2.0 (SPDX: `Apache-2.0`) — on the §5.4 allowlist.
- **Use:** the RDP engine adapter (`src/protocol/rdp/`) links
  `-lfreerdp3`/`-lfreerdp-client3`/`-lwinpr3` and consumes the instance,
  context, settings,
  event, GDI, input, and channel APIs. Farsee's RFB engine does not use
  FreeRDP; only the RDP backend uses it (§10.7).
- **Provenance:** consumed as a linked library via the nix devShell; no
  FreeRDP source is vendored into this repository. Adapter code is written
  against the Microsoft Open Specifications (MS-RDPBCGR et al.) and the
  published FreeRDP API docs.
- **Enabled build features:** client library, software GDI, static client
  channels, `cliprdr`, OpenSSL, cJSON, and uriparser. Server, proxy, X11,
  SDL, audio, video, FFmpeg, H.264, camera, CUPS, PC/SC, USB, FUSE, and
  device-redirection features are disabled in the release dependency.
- **Closure policy:** `release/dependencies.json` and its configured
  system-library rules define the audit policy. The release gate resolves the
  binary's dynamic-library closure against that policy. A final,
  platform-specific closure result is required before release.
- **ADR:** docs/adr/0008-freerdp-integration.md (ADR-0008).

### cJSON 1.7.18 — FreeRDP JSON support

- **Upstream:** https://github.com/DaveGamble/cJSON
- **Version:** 1.7.18 (pinned nixpkgs `cjson`).
- **License:** MIT — on the §5.4 allowlist.
- **Use:** Linked by the minimized FreeRDP client library.

### uriparser 0.9.8 — FreeRDP URI parsing

- **Upstream:** https://github.com/uriparser/uriparser
- **Version:** 0.9.8 (pinned nixpkgs `uriparser`).
- **License:** BSD-3-Clause — on the §5.4 allowlist.
- **Use:** Linked by the minimized FreeRDP client library.

## Vendored material

None. The project does not vendor any third-party source.

## Test-only tooling (not shipped)

The following are used only for tests or developer tooling and never enter
release artifacts:

- Python 3 standard library (PSF license) — scripted integration server and
  fixtures. Not linked into `farsee`.
- lcov / genhtml (GPL). Used only to render coverage HTML locally; it is
  **not** a build or runtime dependency of any release artifact and is not
  redistributed. Coverage numbers themselves are produced from gcov data
  which the compilers emit; lcov is a convenience viewer only.
- Clang/GCC, clang-tidy, coreutils, gdb — build/analysis tooling provided by
  the Nix devShell. Not redistributed.

## Change log

| Date       | Change                                          | Gate |
| ---------- | ----------------------------------------------- | ---- |
| 2026-07-21 | Initial notices created. zlib/OpenSSL/CommonCrypto declared. | G0   |
| 2026-08-24 | Pin versions and declare minimized FreeRDP runtime closure. | Release closure |
