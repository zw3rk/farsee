# G25 — Adversarial Security, Fuzzing, Fault-Injection, and Downgrade Audit

- **Status:** PASS_MACHINE_SCOPE; bounded sustained macOS campaign passed
- **Evidence:** this card, the current source tree, and tests under `tests/`

## Scope

Adversarial checks cover classic RFB and Apple session paths. The gate includes
fuzz targets for record, session-control, clipboard, known-hosts, security
negotiation, and RSA envelope inputs; fault and unit tests cover cleanup,
cryptographic bounds, downgrade rejection, record errors, and secret canaries.

## Key paths

- `docs/gates/G25-security-hardening.md`
- `docs/security/threat-model.md`
- `tests/fuzz/fuzz_*.c`
- `tests/fuzz/fuzz_apple_record.c`
- `tests/fuzz/fuzz_apple_session_control.c`
- `tests/fuzz/fuzz_clipboard_policy.c`
- `tests/fuzz/fuzz_known_hosts.c`
- `tests/fuzz/fuzz_rfb_security_negotiation.c`
- `tests/fuzz/fuzz_rsa1_envelope.c`
- `tests/unit/security_cleanup__tests.c`
- `tests/unit/security_crypto_bounds__tests.c`
- `tests/unit/security_downgrade__tests.c`
- `tests/unit/security_record_oracle__tests.c`
- `tests/unit/security_secret_canary__tests.c`

## Verification

Machine checks live in the test suite and `make ci`. The sanitized macOS
candidate completed all 17 fuzz targets for 60 seconds per target. Linux
sanitizer acceptance remains a separate release requirement. Gate status is
authoritative in `docs/implementation-status.md`.
