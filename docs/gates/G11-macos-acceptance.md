# G11 — Real macOS interoperability and fidelity acceptance

- **Status:** PASS_BASIC_HARDWARE; extended fidelity matrix remains open
- **Evidence:** this card, the current source tree, and tests under `tests/`

## Scope

Validate the client against an authorized macOS Screen Sharing server. G26
records successful authentication, framebuffer rendering, and input. The
extended fidelity and sustained-session matrix remains incomplete.


## Key paths

- `tests/macos/keyboard_matrix.md`
- `tools/macos_acceptance.sh`

The Makefile `macos-acceptance` target runs a bounded, view-only type-36
session against the active shared desktop with the null presenter. It requires
an authorized host and a password descriptor. Its sanitized result proves
protected-record activation without recording endpoint or credential data.
Pixel fidelity and input remain manual acceptance work.

## 2026-09-19 hardware evidence

An earlier release CLI was signed temporarily with the approved Developer ID
Application identity and connected directly, without a relay, to the authorized
Apple silicon host. The bounded view-only acceptance run forced security type
36 and the shared-desktop attach mode. It reported `RECORD_LAYER: active` and
`RESULT: PASS` after entering the protected Apple record path. The run used the
null presenter, so it does not clear the manual `0x0450` pixel-fidelity or input
checks.

A follow-up run used the Kitty direct presenter and the private encoding list.
Protected records remained active, but the authorized host supplied no
framebuffer or cursor data during bounded shared-desktop and login-session
runs. A cleartext control run received initial framebuffer traffic from the
same host. The result does not clear `0x0450` fidelity: a live private cursor
rectangle and visible composited frame are still required.

## 2026-09-20 current-candidate retry

A pre-documentation candidate run forced type 36, shared-desktop attach, and
protected records with a 60-second connection deadline. The client exited
before protected-record activation and reported `RESULT: FAIL`. It received no
framebuffer or cursor data. The cause is not established, so the earlier
protected-record result remains historical evidence rather than
current-candidate acceptance.

Focused machine suites still pass: 23 type-36 tests, seven private-cursor
decoder tests, and three cursor-compositor tests. They establish the retained
implementation contracts, but they do not replace live acceptance. The current
sanitized output also cannot distinguish a private `0x0450` cursor rectangle
from a standard Cursor rectangle. Type-36 framebuffer delivery and input, plus
a visible composited `0x0450` cursor, remain open.

## 2026-09-20 post-cleanup candidate pass

A Developer ID-signed post-cleanup candidate forced type 36, shared-desktop
attachment, and protected records through the official bounded acceptance
target. It reported `RECORD_LAYER: active` and `RESULT: PASS`. This supersedes
the failed retry for authentication, protected-record activation, and bounded
session entry.

The run used the null presenter and view-only mode. It did not record a
framebuffer, cursor rectangle, or input result. Type-36 framebuffer delivery
and input, plus visible composited `0x0450` cursor fidelity, remain open.

## Verification

Machine checks live in the test suite and `make ci`. Gate status is authoritative in
`docs/implementation-status.md`.
