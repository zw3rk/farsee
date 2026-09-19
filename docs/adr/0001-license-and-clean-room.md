# ADR-0001: License and clean-room policy

- **Status:** Accepted · **Date:** 2026-07-21

## Context

Permissive distribution without GPL-family entanglement (plan.md §5).

## Decision

1. **License: Apache-2.0** (`LICENSE` + `NOTICE`).  
2. **Clean-room sources only:** RFC 6143 + errata, IANA RFB, Kitty graphics
   spec, POSIX/platform docs, Apple public Screen Sharing docs, project-owned
   wire vectors and synthetic tests.
3. **Prohibited:** read, copy, translate, adapt, or reuse tests from software
   whose license is outside the project allowlist.
4. **Prohibited under ADR-0013:** inspect executable contents,
   symbols, runtime internals, memory, or control flow of proprietary software
   to obtain protocol or algorithm facts. The allowlist in §2 is exhaustive.
   Observing wire output through documented interfaces remains allowed.

## Consequences

SPDX headers on sources; `tools/check_license.py`; provenance updates before
new external facts influence code. Contamination is a release blocker.

ADR-0013 records the current Apple provenance status. The Apple feature
set remains blocked from release until the repository owner records the required
governance decision and any required counsel review.
