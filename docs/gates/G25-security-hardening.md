# G25 — Adversarial Security, Fuzzing, Fault-Injection, and Downgrade Audit

- **Status:** PASS_ISOLATED
- **Evidence:** this card · full history in git · tests under `tests/`

## Scope

Adversarial security, fuzzing, fault-injection, and downgrade audit covering all classic RFB (RFC 6143) and Apple (003.889 dialect) paths. This is an **audit gate**: it adds tests, fuzz harnesses, and documentation. It does **not** modify any `src/` production code, the Makefile, or any existing test.


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

Machine checks live in the test suite and `make ci`. Do not re-expand this
card with red→green narrative; status is authoritative in
`docs/implementation-status.md`.
