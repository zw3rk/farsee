# Apple provenance status register

**Status: BLOCKED**

The Apple feature set is not approved for release. Release requires a written
repository-owner governance decision under ADR-0013 and any required counsel
review.

`release/approval.json` is the automation authority. It binds every approval
to one full source revision and release version. Only an approval-record-only
commit may follow that source boundary. Each positive decision must name its
approver, date, and evidence reference. The signing identity is approved. The
record remains blocked until the owner, Apple provenance review, and independent
final review approvals are recorded. The release workflow is manual and stops
before building, signing, or uploading a candidate while that record is blocked.
