# G0 — Repository, policy, and reproducible build baseline

- **Status:** ✅ PASS
- **Evidence:** this card · full history in git · tests under `tests/`

## Scope

Create a trustworthy empty-project baseline before any protocol code: preserve existing user files; choose Apache-2.0; create the build system and presets; create the minimal test harness with one passing smoke test; add formatting configuration; create security/contribution/provenance/ADR skeletons; create `docs/implementation-status.md`; create CI workflows; add the license checker; record exact tool versions.


## Key paths

- `docs/adr/0001-license-and-clean-room.md`
- `docs/adr/0001..0006-*.md`
- `docs/adr/0006-makefile-and-nix-build-system.md`
- `docs/implementation-status.md`
- `docs/provenance.md`
- `src/app/version.c`
- `tests/fixtures/license/{good_apache,bad_gpl}.c`
- `tests/unit/build__smoke.c`
- `tests/unit/harness__self_test.c`
- `tools/check_license.py`
- `tools/check_std_c11.sh`
- `tools/check_warnings.sh`
- `tools/coverage.sh`
- `tools/gen_test_registry.py`
- `tools/llvm-gcov.sh`
## Verification

Machine checks live in the test suite and `make ci`. Do not re-expand this
card with red→green narrative; status is authoritative in
`docs/implementation-status.md`.
