# ADR-0011: Scaffold quarantine and live-shell freeze

- **Status:** Accepted
- **Date:** 2026-07-30
- **Related:** ADR-0010 (SHARED-MT product seam)

## Context

SHARED-MT is the live product seam (ADR-0010). The engine/reactor modules and
several RFB/RDP stubs are **contract-tested but not product-linked**. Unifying
the two live shells requires demultiplexer tests to prevent silent input loss.
Gate records for scaffold modules remain available while quarantined.

## Decision

1. **Product binary** (`farsee`) links only live modules. Explicit scaffold
   sources are linked into tests, fuzz targets, and tools only:
   - Scaffold modules: `farsee_engine`, `farsee_reactor`, `farsee_queue`,
     `farsee_transport`, `farsee_tls`, `farsee_wakeup`, `rfb_engine_adapter`,
     `farsee_lifecycle`, and `farsee_capability`;
   - RFB test products: `fake_apple_server` and `apple_session`; and
   - RDP stub: `rdp_worker`.
2. **Freeze** new protocol-specific TTY, demultiplexer, leader, and status code
   in `rfb_live.c` and `rdp_live.c`. Put shared behavior in `live_shell` or pure
   helpers, with tests first.
3. **Security selection:** production and Apple helper paths use
   `farsee_rfb_select_security` as the single pure policy. Focused tests and
   fuzzing use the compatibility `apple_select_security_type` wrapper.

## Consequences

- `nm farsee` must not show scaffold engine, reactor, `fake_apple_server`, or
  `rdp_worker` symbols by default.
- Scaffold and Apple record-layer tests remain in the test link set.
- Do not unify the live shells until demultiplexer characterization tests
  pass.
