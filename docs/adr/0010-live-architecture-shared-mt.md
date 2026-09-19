# ADR-0010: SHARED-MT is the product multi-protocol seam

- **Status:** Accepted · **Date:** 2026-07-29  
- **Supersedes (in part):** ADR-0004 single-threaded live default  
- **Related:** `docs/architecture.md`, engine/reactor gate records under `docs/gates/`

## Context

The engine and reactor modules have unit-tested contracts, while the shipping
live path already uses `farsee_mt_run`. A scaffold gate result does not prove
that the product binary uses that scaffold.

## Decision

1. **SHARED-MT is the product seam** for interactive Kitty sessions (RFB,
   type-33 as wired, RDP): protocol · present · input threads;
   `farsee_frame_slot` (latest-wins); cmd/inject queues.
2. **Auth/connect stay on main** before `farsee_mt_run`.
3. **Session publishes frames only; app owns present** (open / present / close).
4. The engine/reactor path remains scaffold until a vertical slice ADR;
   quarantine ≠ delete (ADR-0011).
5. `rdp_worker` is a lifecycle stub; live FreeRDP is
   `rdp_live` / facade / MT, not that stub.

## Consequences

Architecture docs and status must label scaffold-gate results as contracts-only
unless a slice lands. Do not delete scaffold artifacts to resolve dualism without
a new ADR.
