# ADR-RDP-001: FreeRDP 3.x integration, version pin, license, and source policy

**Status:** Approved (operator-directed — unblock the RDP program)
- **Upstream:** FreeRDP — https://github.com/FreeRDP/FreeRDP
- **Pinned version:** **FreeRDP 3.15.0** (`FREERDP_VERSION="3.15.0"`,
- **Provisioning:** `nixos-25.05` (the project's existing flake input) via
- **Do not track FreeRDP `master` in production builds** (§15.3). Updates go
- **FreeRDP:** Apache-2.0 ✅ (on the plan.md §5.4 allowlist).

## Context

Farsee's first production RDP engine integrates a **pinned, reviewed FreeRDP 3.x library build** rather than implementing the full RDP family from scratch (§15.1). Rationale (§15.1): RDP is a family of core and extension protocols (TLS, CredSSP/NLA, MCS/GCC, channels, graphics, …), not a framebuffer encoding; Farsee's differentiator is terminal-native presentation, strict policy, and deterministic adapters — not a second implementation of every RDP wire layer. FreeRDP is Apache-2.0 and designed as an RDP library and client platform.

## Decision

Farsee's first production RDP engine integrates a **pinned, reviewed FreeRDP 3.x library build** rather than implementing the full RDP family from scratch (§15.1). Rationale (§15.1): RDP is a family of core and extension protocols (TLS, CredSSP/NLA, MCS/GCC, channels, graphics, …), not a framebuffer encoding; Farsee's differentiator is terminal-native presentation, strict policy, and deterministic adapters — not a second implementation of every RDP wire layer. FreeRDP is Apache-2.0 and designed as an RDP library and client platform.

## Consequences

- The RDP program (R1–R6) is unblocked for in-process adapter work. - `FARSEE_WITH_RDP` becomes a real build dimension; the no-RDP build is preserved and CI-enforced. - R2–R6 still require independent Windows endpoints + xrdp for `PASS_INTEROP` evidence (§15.19) — a hardware/credential gate this ADR does NOT waive.
