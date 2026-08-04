# ADR-0011: Scaffold quarantine and live-shell freeze

- **Status:** Accepted
- **Date:** 2026-07-30
- **Related:** ADR-0010 (SHARED-MT product seam)

## Context

Peer reviews of the 2026-07-30 maintainability audit agreed that: 1. SHARED-MT is the live product seam (ADR-0010). 2. F0–F8 engine/reactor modules and several RFB/RDP stubs are **contract-tested but not product-linked**. 3. Unifying twin live shells without demux tests risks shipping regressions (including silent input loss on RDP). 4. Gate policy forbids **deleting** F-gate artifacts; quarantine ≠ delete.

## Decision

1. **Product binary** (`farsee`) links only live modules. Explicit **scaffold** sources are linked into **tests / fuzz / tools** only: - F-scaffold: `farsee_engine`, `farsee_reactor`, `farsee_queue`, `farsee_transport`, `farsee_tls`, `farsee_wakeup`, `rfb_engine_adapter`, `farsee_lifecycle`, `farsee_capability` - RFB test products: `fake_apple_server`, `apple_session` (G17 path; not live type-33 cleartext) - RDP stub: `rdp_worker`
2. **Freeze** new protocol-specific TTY/demux/leader/status code in `rfb_live.c` / `rdp_live.c`. New shared behaviour lands in a future `live_shell` (or pure helpers) with tests first.
3. **Security selection:** production and Apple helper paths use `farsee_rfb_select_security` as the single pure policy. Legacy `apple_select_security_type` is a thin wrapper for t

## Consequences

- `nm farsee` must not show scaffold engine/reactor/fake_apple/rdp_worker symbols by default. - F-gate and Apple G17 tests stay green via the test link set. - Live-shell unification is a **later** phase gated on demux characterization tests.
