# G12 — Hardening, release engineering, and audit

- **Status:** BLOCKED for the current release candidate
- **Evidence:** this card, the current source tree, and tests under `tests/`

## Scope

Fuzz and sanitizer dimensions; dependency and license audits; secure-use and
CLI documentation; threat-model review; version and capability output; safe
crash diagnostics; installation and release-package verification. Current
release blockers are listed in `docs/implementation-status.md`.


## Key paths

- `docs/known-limitations.md`
- `src/app/main.c`
- `tools/check_license.py`
- `tools/macos_acceptance.sh`
## Verification

Machine checks live in the test suite and `make ci`. Gate status is authoritative in
`docs/implementation-status.md`.

The manual release workflow can build and sign a candidate, then create an
annotated tag and GitHub release only when the approval record passes and the
operator explicitly selects publication. The publication job has the only
`contents: write` permission.

The sustained fuzz target copies each seed corpus into its release build
directory. It keeps the evolved corpus, full logs, and per-target libFuzzer
crash, timeout, and resource-failure artifacts together under
`fuzz-release/`. The smoke target uses the same explicit artifact routing so a
failure cannot leave its reproducer at the repository root.
