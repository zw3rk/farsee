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
Before it connects, it verifies the embedded version and revision, records the
binary SHA-256 digest, and verifies the code-signing certificate against the
approved identity in `release/approval.json`. Pixel fidelity and input remain
manual acceptance work.

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
session entry. That runner version did not emit the candidate digest, embedded
revision, or certificate fingerprint. The result is valid protocol evidence,
but it is not exact-candidate release evidence.

The run used the null presenter and view-only mode. It did not record a
framebuffer, cursor rectangle, or input result. Type-36 framebuffer delivery
and input, plus visible composited `0x0450` cursor fidelity, remain open.

The current runner fails closed unless the selected binary matches the expected
version and revision and the approved Developer ID certificate. Each frozen
release candidate must pass that identity-bound run.

## 2026-09-20 identity-bound framebuffer pass

The Developer ID-signed candidate at revision
`175bc6baf5037019654787de273220d1667cd45a` passed the exact identity check,
forced type 36, attached to the shared desktop, entered protected records, and
delivered a complete 3840x2160 RGBA frame. The visible output matched the
authorized macOS login screen.

The candidate requested ZRLE, Raw, and `0x0450`. A debugger breakpoint on the
private cursor decoder had no hits after pointer movement and full-frame
delivery. This proves that the request was sent, but it does not prove live
decode or composition because the server did not send a `0x0450` rectangle in
this test run. Visual input, clipboard content, and cursor fidelity
remain open.

The bounded leader-key exit restored terminal modes and emitted the expected
mouse, keyboard, and cursor restoration controls. Kitty output backpressure
caused the presenter to fail, and a shared PTY open-file description retained
`O_NONBLOCK`. Revision `8de3cb6` adds a regression and fixes the aliased-stream
restoration order. The fixed path needs an exact-candidate live recheck.

The exact recheck at revision
`004c45ac770bcc26947a6c92eb3fe55128b6e362` passed the signed identity gate,
type-36 protected-record path, shared-desktop attach, and visible framebuffer
check again. The client requested `0x0450`; the decoder breakpoint again had no
hit because the server sent no observed private-cursor rectangle.

The recheck also passed standard-stream restoration. `O_NONBLOCK` was clear on
all standard streams after exit. Darwin added its kernel-private
`FWASWRITTEN` bit to the written PTY descriptors; this bit is kernel bookkeeping,
not a user-settable status flag. The earlier full-value `F_GETFL` comparison
therefore produced a false failure.

## 2026-09-20 signed current-candidate bounded recheck

The exact Developer ID-signed candidate
`b89d4fdbaf023e198101a89b506c0c0b960ad085` had SHA-256
`88432f1f33c34d16343f6733abba1097d2b70b8d56808fda8d5d864c3e280f64`.
The official identity-bound acceptance target forced type 36, attached to the
shared desktop, activated protected records, and reported `RESULT: PASS`.

No production source changed between the earlier visible-frame candidate and
the later black-frame candidate. The current endpoint behavior therefore
remains an external acceptance blocker rather than evidence of a newly isolated
source regression: tested protected-record, cleartext, and private sessions
returned only black full-size updates, no `0x0450` rectangle was observed, and
visual input and clipboard transfer could not be established. These extended
rows remain open.

## Verification

Machine checks live in the test suite and `make ci`. Gate status is authoritative in
`docs/implementation-status.md`.
