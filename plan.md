# Implementation Plan: Clean-Room C11 RFB/VNC Client (Kitty presentation)

**Project:** `farsee` · **Status:** controlling requirements specification  
**Targets:** traditional VNC / Apple Screen Sharing RFB path / RDP (see ADRs) ·
POSIX macOS/Linux · Kitty graphics · Apache-2.0 · clean-room  
**C standard:** Curated C11 (no VLA / Annex K / threads.h / `_Generic`)  
**Build:** Nix + Makefile (ADR-0006). Full gate: `nix develop --command make ci`.

Gate evidence: `docs/gates/` · Status: `docs/implementation-status.md` ·
Live arch: ADR-0010 / ADR-0011 (SHARED-MT product path).

---

## 1. Document role

This file is the product and engineering contract. Process for agents lives in
`CLAUDE.md` / `AGENTS.md`. Do not treat model-vendor notes as requirements.

---

## 2. Product objective

Independent RFB/VNC (and RDP) client that:

- connects using standards and project-owned tests — not GPL/AGPL sources;
- decodes into a canonical persistent RGBA8 framebuffer;
- sends keyboard, pointer, wheel, clipboard; handles Bell / ServerCutText;
- presents via Kitty (direct PTY + POSIX SHM);
- is safe against hostile network input (bounded, incremental parsers).

First RFB release is **traditional RFB**, not Apple High Performance Screen Sharing.

---

## 3. Definition of done (initial RFB release)

Machine-verifiable G0–G10 + G12 hardening pass; G11 either PASS on hardware or
explicitly `NEEDS-HARDWARE` with automation present.

Must provide: RFB 3.3/3.7/3.8; vendor-banner policy; VNC Auth (type 2) and
opt-in None (type 1); ServerInit / SetPixelFormat; Raw, CopyRect, ZRLE;
Cursor, DesktopSize; input + clipboard + Bell; nonblocking session with
bounded queues; null/dump + Kitty direct + Kitty SHM presenters; CLI;
strict warnings, ASan/UBSan, coverage, fuzz, docs; no high/critical defects;
no GPL/AGPL/LGPL in release artifacts.

Must **not** claim: encrypted VNC; Apple-account auth; HDR; audio; HEVC;
guaranteed 4K60 via PTY; AHPSS compatibility.

---

## 4. Scope boundaries

### 4.1 In scope

POSIX macOS/Linux; IPv4/IPv6 TCP; tunnel via user SSH/VPN; traditional VNC
password path; Raw/CopyRect/ZRLE; exact wire→RGBA8; Kitty RGB/RGBA + `t=s`
SHM; standard RFB input; SGR mouse (prefer pixel mode); bounded process.

### 4.2 Deferred but supported architecturally

Hextile, Tight (no default lossy JPEG), ExtendedDesktopSize, extended
clipboard, VeNCrypt/TLS, Sixel, tmux, native window presenters, full Apple
30–36 productization, AHPSS media.

### 4.3 Non-goals for the first goal run

Copy/translate GPL VNC code; hand-rolled crypto without approved provider +
KATs; VNC server; Windows-hosted binary as first host; optimize before a
correct instrumented baseline; fake hardware PASS by inspection.

---

## 5. Clean-room and license policy

### 5.1 Project license

Apache-2.0.

### 5.2 Allowed sources

RFC 6143 + errata; IANA RFB; official Kitty graphics spec; POSIX/platform
docs; Apple public Screen Sharing / Remote Management docs; project-owned
captures, redacted transcripts, and synthetic tests.

### 5.3 Prohibited

Reading, copying, translating, adapting, or using tests from LibVNCClient,
TigerVNC, termvnc, iShareScreen, or any GPL/AGPL/LGPL VNC implementation.

### 5.4 Dependency allowlist

Apache-2.0, MIT, ISC, BSD-2/3, zlib, CC0/Unlicense (and equivalent). New dep
requires ADR + license check + `THIRD_PARTY_NOTICES.md` update.

### 5.5 Initial dependency policy

Prefer platform crypto (CommonCrypto / OpenSSL via provider), zlib for ZRLE,
optional FreeRDP for RDP (ADR-0008). No opportunistic deps.

### 5.6 Provenance

Record non-obvious observations in `docs/provenance.md` and `docs/apple/`
with CAPTURED / INFERRED / UNKNOWN / CONFLICTING labels.

---

## 6. Security posture and threat model

See `docs/threat-model.md` and `SECURITY.md`. Summary:

### 6.1 Assets

Process memory, terminal, password, clipboard, keystrokes, framebuffer
confidentiality, SHM namespace, local session availability.

### 6.2–6.3 Threats and mitigations

Checked sizes; bounds before pixel write; ZRLE output caps; hard limits on
names/clipboard/compressed lengths; incremental parsers; escape remote text
before terminal/logs; unpredictable private SHM; no password on argv; bounded
queues; signal-safe terminal restore; honest “no session encryption” docs.

### 6.4 Default hard limits

| Limit | Default |
|-------|---------|
| framebuffer width/height | 16,384 px |
| framebuffer bytes (absolute / policy) | 1 GiB / 256 MiB |
| desktop name | 1 MiB |
| clipboard payload | 16 MiB |
| compressed rectangle payload | 256 MiB |
| queued outbound / presentation | 8 MiB / 128 MiB |
| rects per FramebufferUpdate | 65,535 |
| max terminal response | 4 KiB |

Boundary tests at limit−1 / limit / limit+1.

---

## 7. Platform and compatibility target

### 7.1 Hosts

macOS and Linux, Clang and GCC under Nix; macOS ASan uses Apple Clang
(`MACOS_ASAN_CC`).

### 7.2 Terminals

Kitty graphics protocol required for presentation gates.

### 7.3 Remote hosts

Classic VNC; Apple Screen Sharing RFB dialect as documented; RDP via FreeRDP.

### 7.4 Compatibility rule

Default-deny unknown banners/features; map known vendors only with tests.

---

## 8. Architecture principles

1. Pure protocol core (no Kitty/socket knowledge in RFB parsers).  
2. Incremental, resumable parsers.  
3. Persistent canonical RGBA8 framebuffer (ADR-0003).  
4. Presenter abstraction (`rfb_presenter_ops` / v2 adapter).  
5. **Product live path = SHARED-MT** (ADR-0010): protocol / present / input.  
6. Explicit ownership; session publishes frames, app owns present.  
7. No hidden globals; fail closed.  
8. Deterministic injectable tests.  
9. Measure before optimize.

---

## 9. Repository layout

Authoritative layout is the tree itself. Public headers: `include/farsee/`.
Sources: `src/{core,rfb,fb,io,crypto,tty,present,farsee,protocol/rdp,app}/`.
Tests: `tests/`. Gates/ADRs: `docs/`. Driver: `Makefile` + `flake.nix`.

---

## 10. Core interfaces

### 10.1 Byte reader

Bounded big-endian reads; failed atomic read leaves offset unchanged; never
cast wire buffers to packed structs.

### 10.2 Checked arithmetic

`add` / `mul` / `rect_bytes` for every wire-derived size; overflow → error.

### 10.3 Framebuffer

Transactional RGBA8 resize; black-opaque init; single chokepoint for
width×height×bpp.

### 10.4 Damage

Accumulate damage; cap-to-full-frame; emit only after committed pixels.

### 10.5 Presenter

Null, dump, Kitty direct, Kitty SHM; no mutation of authoritative FB.

### 10.6 Incremental session parser

Every call consumes ≥1 byte, changes state, or finishes; never busy-loops.

---

## 11. Protocol state machine

Handshake (version → security → auth → ClientInit) then ServerInit then
update/input loop. Unknown lengths/types → typed error → clean disconnect.
Security None only with explicit opt-in. Secrets zeroized on all paths.

---

## 12. Pixel and framebuffer policy

### 12.1 Canonical format

RGBA8, 8 bits/channel, opaque alpha unless Cursor mask provides alpha.

### 12.2 Requested wire format

Prefer 32 bpp true-color; accept validated 8/16/32 bpp server formats.

### 12.3 Conversion

Integer scaling only; all endian/bpp combinations under test; mask
non-overlap; zero maxima rejected.

---

## 13. TDD operating method

### 13.1 Red → green → refactor

No production line without a failing test that demands it.

### 13.2 Bug-fix rule

Permanent regression test **before** the fix; stays green forever.

### 13.3 No test cheating

No weaken/skip/delete without ADR; no sleeps for races; no production
fixture special-cases; no reducing coverage thresholds to pass.

### 13.4 Test naming

Behaviour-oriented names; suite per component.

### 13.5 Gate evidence

Each gate: `docs/gates/GXX-*.md` with scope, mapping, red→green record,
commands/results, coverage/sanitizers, PASS/FAIL/NEEDS-HARDWARE.

---

## 14. Test architecture

Unit, component (fragmentation), transcript/golden, scripted server
integration, socket fault injection, allocation failure, property tests,
fuzz targets (`tests/fuzz/`), performance counters. Fake clocks; no flaky
sleeps. Project harness: `tests/test_framework/` + generated registry.

---

## 15. Build and quality configuration

### 15.1 C language

Curated C11 (`-std=c11 -pedantic -Werror=vla`). POSIX client APIs.

### 15.2 Required warnings (as errors)

`-Wall -Wextra -Wpedantic -Werror -Wconversion -Wsign-conversion -Wshadow
-Wstrict-prototypes -Wmissing-prototypes -Wold-style-definition -Wundef
-Wformat=2 -Wformat-security -Wcast-align -Wcast-qual -Wwrite-strings
-Wpointer-arith -Wswitch-enum -Wvla -fno-common` (see Makefile).

### 15.3 Forbidden patterns

VLA; `sprintf`/`strcpy`/`strcat`; unchecked wire sizes; packed wire casts;
Annex K `_s`; `<threads.h>`; `_Generic`.

### 15.4 Build modes

`dev`, `release`, `asan-ubsan`, `coverage`, `fuzz` via Makefile (not CMake).

### 15.5 Coverage thresholds

Checked arithmetic / readers: 100% line where practical. Project target:
≥85% line / ≥80% branch excluding justified platform-only paths. Exclusions
require comment + gate justification.

---

# 16. Implementation gates

Full checklists and red→green records: **`docs/gates/`**. Status:
`docs/implementation-status.md`. Summary of required outcomes:

| Gate | Outcome |
|------|---------|
| **G0** | License, Nix+Makefile, harness, license checker, CI, status file |
| **G1** | checked math, bytes, buffer, errors, allocator, secret, log escape |
| **G2** | version negotiate, security select, VNC Auth providers, fuzz handshake |
| **G3** | ServerInit, pixel format, RGBA8 FB, SetPixelFormat/Encodings, null/dump |
| **G4** | FBUpdate, Raw, CopyRect, damage, golden + fuzz |
| **G5** | nonblocking connect, outbound queue, lifecycle integration |
| **G6** | Key/Pointer/CutText, Bell, Cursor, DesktopSize |
| **G7** | Kitty direct base64 path, capability, fake terminal reconstruct |
| **G8** | ZRLE all subencodings, zlib adapter, fuzz |
| **G9** | one-outstanding request, damage, pacing, metrics |
| **G10** | Kitty POSIX SHM, 0600 unpredictable name, cleanup, direct fallback |
| **G11** | real macOS acceptance (or NEEDS-HARDWARE with scripts) |
| **G12** | hardening, CLI docs, fuzz/static/license audit, release checklist |

Later program: F0–F8 contracts, R0–R6 RDP, Apple G14–G28 — evidence under
`docs/gates/`; product live path SHARED-MT (ADR-0010), not F-engine scaffold.

Each gate still requires: tests first (positive + negative), ASan/UBSan clean
where applicable, evidence file marked PASS / NEEDS-HARDWARE / FAIL.

---

## 17. CLI contract

`farsee` parses target URL/flags, credentials via tty or `--password-fd` (no
password in argv/URL for production), protocol select (VNC/RDP), dump or live
Kitty session. Exact flags: `USAGE.md`. `--version` and protocol capabilities
for G12.

---

## 18. Request pacing baseline

One outstanding FramebufferUpdateRequest; coalesce damage; max present FPS;
backpressure when queues full; never unbounded retransmit of static desktop.

---

## 19. Keyboard strategy

Normalize terminal input to RFB KeyEvent; macOS fidelity matrix where gated
(G21); release held keys on disconnect.

---

## 20. Mouse and viewport

SGR mouse → PointerEvent; wheel as button events; optional view scale in live
UI; do not full-frame on mere cursor move when damage is local.

---

## 21. Kitty presentation strategy

### 21.1 Direct

RGB/RGBA commands, ≤4096-byte base64 chunks, m=0/1 continuation, acks.

### 21.2 SHM

One-shot `t=s`, private unpredictable objects, cleanup on all paths, bounded
in-flight table, fallback to direct.

### 21.3 Partial updates

Prefer damage-bounded presents; full frame when coalesced or on resize.

---

## 22. Performance targets and interpretation

Fidelity > marketing FPS. Report metrics honestly. SHM must reduce PTY bytes
vs direct on large frames. No 4K60 PTY claim without evidence.

---

## 23–24. (Process)

Agent process, anti-drift, and iteration protocol: **`CLAUDE.md`**. Control
files: this plan, `docs/implementation-status.md`, `docs/gates/`, ADRs, tests.

---

## 25. Risk register (condensed)

| Risk | Mitigation |
|------|------------|
| GPL contamination | clean-room, provenance, license checker |
| length overflow / bombs | G1 checked math, G8 caps, fuzz |
| TCP fragmentation | incremental tests every protocol gate |
| macOS dialect | capture → observation → synthetic test |
| PTY overload | G9 pacing, G10 SHM |
| raw-mode leave | lifecycle + signal restore |
| false encryption claim | SECURITY.md, known-limitations |

---

## 26–27. (Process)

Gate review checklists and human supervision: use Definition of Done (§3),
gate evidence (§13.5), and `SENIOR-ESCALATION.md` when blocked.

---

## 28. Future: Apple High Performance Screen Sharing

Separate engine/phase — not another RFB rectangle decoder. New clean-room
plan, license review, and media threat model required before production media
code. Do not distort classical RFB core.

---

## 29. (Removed)

Historical `/goal` paste text removed; use this plan + `CLAUDE.md`.

---

## 30. Primary references

- RFC 6143: https://datatracker.ietf.org/doc/html/rfc6143  
- RFC 6143 errata: https://www.rfc-editor.org/errata/rfc6143  
- IANA RFB: https://www.iana.org/assignments/rfb/rfb.xhtml  
- Kitty graphics: https://sw.kovidgoyal.net/kitty/graphics-protocol/  
- Apple Remote Desktop / Screen Sharing public docs  

---

## 31. Success

Gates G0–G10 automated + G12 machine-verifiable green; G11 honest about
hardware; clean-room and license clean; docs match behaviour.
