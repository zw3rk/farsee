# Implementation status

**Updated:** 2026-08-05 · Evidence: `docs/gates/` · Live arch: ADR-0010 / ADR-0011

## Live product path

`CLI → connect/auth → farsee_mt_run` (protocol · present · input).  
Session **publishes** frames; app owns present. Scaffold F-engine/reactor is unit-tested only (not CLI entry).

| Path | Status |
|------|--------|
| `rdp://` Kitty | SHARED-MT via `rdp_live` |
| `vnc://` classic | SHARED-MT via `rfb_live` |
| type-33 | Live RSA1+SRP + cleartext MVP; ChaCha post-auth open |
| status band | scale % · RTT ms · KiB/s (`link_rate_pub`; see USAGE.md) |

## Architecture gates (F / R / S)

| Gate | Scope | Status |
|------|--------|--------|
| F0–F6 | Contracts (error, reactor, workers, display, input, security) | ✅ contracts; live wiring deferred for engine/reactor |
| F7 | Transport / TLS / VeNCrypt | ✅ contracts · 🔶 interop NEEDS-HARDWARE |
| F8 | RFB engine adapter | ✅ unit · ⏸ not CLI entry |
| R0–R5 | FreeRDP dep + bridges | ✅ |
| R6 | Interop | ✅ xrdp · ✅ Windows first frame · 🟡 full matrix partial |
| S0 | SPICE policy | 📋 proposed (ADR-0009) |

## RFB / Apple gates (G)

| Gate | Status | Gate | Status |
|------|--------|------|--------|
| G0–G6 | ✅ | G14–G16 | ✅ |
| G7 | ✅ / 🔶 HW | G17 | ✅ (AES-CBC vs ChaCha known divergence) |
| G8 | ✅ all subencodings | G18 / G18A | ✅ integrated (+ HW for RSA1) |
| G9 | ✅ | G19 | ✅ integrated · 🔶 real macOS |
| G10 | ✅ / 🔶 HW | G21 / G22 / G25 | ✅ (G21/G22 partial HW) |
| G11 | 🔶 HW | G26–G28 | see `docs/gates/` |
| G12 | ✅ machine-verifiable | | |

Legend: ✅ PASS · 🟡 partial · 🔶 NEEDS-HARDWARE · ⏸ deferred · 📋 planning

## Build

Nix `flake.nix` + `Makefile` (ADR-0006). Full gate: `nix develop --command make ci`.

## Blockers

None on the authorized host toolchain.
