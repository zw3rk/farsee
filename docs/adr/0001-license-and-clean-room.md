# ADR-0001: License and clean-room policy

- **Status:** Accepted · **Date:** 2026-07-21

## Context

Permissive distribution without GPL-family entanglement (plan.md §5).

## Decision

1. **License: Apache-2.0** (`LICENSE` + `NOTICE`).  
2. **Clean-room sources only:** RFC 6143 + errata, IANA RFB, Kitty graphics
   spec, POSIX/platform docs, Apple public Screen Sharing docs, project-owned
   captures and synthetic tests.  
3. **Prohibited:** read/copy/translate/adapt/tests from LibVNCClient, TigerVNC,
   termvnc, or any GPL/AGPL/LGPL VNC implementation.

## Consequences

SPDX headers on sources; `tools/check_license.py`; provenance updates before
new external facts influence code. Contamination is a release blocker.
