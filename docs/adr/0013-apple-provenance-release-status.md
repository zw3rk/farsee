# ADR-0013: Apple release decision status

- **Status:** Accepted · **Date:** 2026-08-18
- **Amends:** ADR-0001

## Decision

The established Apple implementation and product behavior remain protected.
On 2026-09-18, the repository owner approved additive completion of Apple
security type 36 and Apple encoding 0x0450. The preservation manifest records
the prior semantic digests and the exact files changed by that decision. It
must not hide an approved change by replacing the prior baseline.

The Apple feature set is not approved for release. Release requires a written
repository-owner governance decision under this ADR and any required counsel review.
The machine-readable `release/approval.json` record must then name the status
as approved and record every required external approval before automation can
sign or upload a candidate. Each approval includes an approver, decision date,
and evidence reference. The record binds those decisions to one full source
revision and release version. After that source revision, only the approval
record itself may change before release.

## Consequences

- Preserve all Apple protocol APIs, wire constants, functional tests, and
  required fixtures.
- Treat the Apple feature set as a release blocker until the decision above is
  recorded and approved.
