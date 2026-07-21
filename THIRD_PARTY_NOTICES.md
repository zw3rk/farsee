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

No GPL, AGPL, or LGPL code is read, copied, translated, adapted, or linked.

## System libraries (linked, not vendored)

These are provided by the host or by the Nix devShell at build/runtime. They
are linked but their source is **not** included in this repository.

### zlib — ZRLE inflation

- **Upstream:** https://zlib.net/
- **Version:** 1.3.x (nixpkgs `zlib`).
- **License:** zlib license (SPDX: `Zlib`) — on the §5.4 allowlist.
- **Use:** `inflateInit`, `inflate`, `inflateReset` for the ZRLE decoder (G8).
- **Provenance:** plan.md §5.5 names zlib explicitly as the ZRLE dependency.
- **ADR:** docs/adr/0002-crypto-provider.md covers the broader
  dependency policy; ZRLE/zlib is recorded in docs/adr/0008-zrle-zlib.md
  (created when G8 begins).

### OpenSSL 3.x — VNC Authentication provider (Linux / cross-platform)

- **Upstream:** https://www.openssl.org/
- **Version:** 3.6.x (nixpkgs `openssl`).
- **License:** Apache-2.0 — on the §5.4 allowlist.
- **Use:** DES key transform + DES-ECB encrypt of the VNC Authentication
  challenge (RFC 6143 §7.2.2). Used only as the optional Linux/cross
  crypto provider; macOS uses CommonCrypto instead.
- **Provenance:** RFC 6143 §7.2.2 (public spec); OpenSSL API documentation.
- **ADR:** docs/adr/0002-crypto-provider.md.

### Apple CommonCrypto — VNC Authentication provider (macOS)

- **Upstream:** Apple system framework, shipped with macOS.
- **Version:** current macOS SDK.
- **License:** Apple system library (redistribution governed by the macOS
  SDK agreement; we only link against the system framework, we do not
  redistribute it).
- **Use:** `CCDigest`/`CCCrypt` for the VNC Authentication DES transform.
- **Provenance:** Apple CommonCrypto headers (`<CommonCrypto/...>`).
- **ADR:** docs/adr/0002-crypto-provider.md.

### FreeRDP 3.x — RDP engine backend (optional, `FARSEE_WITH_RDP=1`)

- **Upstream:** https://github.com/FreeRDP/FreeRDP
- **Version:** **3.15.0** (nixpkgs `freerdp`, `nixos-25.05` pin).
  pkg-config modules: `freerdp3`, `winpr3`.
- **License:** Apache-2.0 (SPDX: `Apache-2.0`) — on the §5.4 allowlist.
- **Use:** the RDP engine adapter (`src/protocol/rdp/`) links
  `-lfreerdp3`/`-lwinpr3` and consumes the instance, context, settings,
  event, GDI, input, and channel APIs. Farsee's RFB engine remains
  independently implemented; only the RDP backend uses FreeRDP (§10.7).
- **Provenance:** consumed as a linked library via the nix devShell; no
  FreeRDP source is vendored into this repository. Adapter code is written
  against the Microsoft Open Specifications (MS-RDPBCGR et al.) and the
  published FreeRDP API docs.
- **Transitive dependencies:** the nixpkgs `freerdp` package pulls codec/
  system libraries (OpenSSL, zlib, libssh, ffmpeg codec libs, etc.).
  Farsee's adapter enables ONLY the channels required for a baseline
  desktop (§10.6); drive/printer/smart-card/USB/mic/camera/generic-device
  redirection are disabled in settings and never invoked.
- **ADR:** docs/adr/0008-freerdp-integration.md (ADR-RDP-001).

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
