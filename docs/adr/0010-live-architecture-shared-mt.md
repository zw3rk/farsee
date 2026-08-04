# ADR-0010: SHARED-MT is the product multi-protocol seam

- **Status:** Accepted · **Date:** 2026-07-29  
- **Supersedes (in part):** ADR-0004 single-threaded live default  
- **Related:** `docs/architecture.md`, F/R gates under `docs/gates/`

## Context

F0–F8 delivered unit-tested contracts (engine, reactor, …) while the
shipping live path already used `farsee_mt_run`. Reading “F-gate PASS” as
“product wired” misled operators.

## Decision

1. **SHARED-MT is the product seam** for interactive Kitty sessions (RFB,
   type-33 as wired, RDP): protocol · present · input threads;
   `farsee_frame_slot` (latest-wins); cmd/inject queues.
2. **Auth/connect stay on main** before `farsee_mt_run`.
3. **Session publishes frames only; app owns present** (open / present / close).
4. F-engine/reactor remain scaffold until a vertical slice ADR; quarantine
   ≠ delete (ADR-0011).
5. `rdp_worker` is the R1 lifecycle stub; live FreeRDP is
   `rdp_live` / facade / MT, not that stub.

## Consequences

Architecture docs and status must label F-gates as contracts-only unless
a slice lands. Do not delete F artifacts to resolve dualism without a new ADR.
