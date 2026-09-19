# ADR-0008: FreeRDP 3.x integration, version pin, license, and source policy

- **Status:** Accepted
- **Upstream:** FreeRDP — https://github.com/FreeRDP/FreeRDP
- **Pinned version:** **FreeRDP 3.15.0**, declared in
  `release/dependencies.json`
- **Provisioning:** the `nixos-25.05` flake input and the minimized
  `mkFarseeFreeRDP` derivation
- **FreeRDP:** Apache-2.0 ✅ (on the plan.md §5.4 allowlist).

## Context

Farsee's production RDP engine uses a pinned FreeRDP 3.x library build. RDP
includes core and extension protocols such as TLS, CredSSP/NLA, MCS/GCC,
channels, and graphics. Farsee owns the terminal presentation, security policy,
and deterministic adapter boundaries. FreeRDP supplies the RDP client engine.

## Decision

1. Use FreeRDP **3.15.0** from the pinned `nixos-25.05` flake input.
   Production builds do not track the FreeRDP development branch.
2. Use the minimized `mkFarseeFreeRDP` derivation. It keeps the client
   library, software GDI, static client channels, and `cliprdr`, while the
   flake disables server, GUI, media, audio, print, smart-card, USB, and
   device-redirection features that are outside the product scope.
3. Keep FreeRDP optional behind `FARSEE_WITH_RDP`. The normal build enables
   it, and CI also verifies the no-RDP build.
4. Confine FreeRDP and WinPR types to `src/protocol/rdp/`. Farsee-owned
   interfaces expose only project types.
5. Treat `release/dependencies.json` and the final binary closure audit as
   authoritative for release dependencies and licenses.

## Consequences

- R1–R6 can use the in-process FreeRDP adapter.
- `FARSEE_WITH_RDP` is a build dimension, and CI preserves the no-RDP build.
- Independent Windows and xrdp interoperability evidence remains a separate
  release requirement. This ADR does not waive that requirement.
