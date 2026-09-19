# G27 — Release readiness

- **Status:** BLOCKED
- **Evidence:** this card, the current source tree, and tests under `tests/`

## Scope

G26 has passed its basic authorized hardware scope. Release readiness remains
blocked by the provenance decision in ADR-0013 and by incomplete live-platform,
signing, independent-review, and final acceptance gates. The repository-local
current-content and reachable-history trace checks pass on `master`; they must
run again on the final candidate and do not clear the remaining gates.

## Verification

Machine checks live in the test suite and `make ci`. Gate status is authoritative in
`docs/implementation-status.md`.

## Manual final acceptance

Run this matrix from the exact candidate commit in a real PTY. Use only
password descriptors or environment variables documented by the acceptance
targets. Do not record hostnames, account names, credentials, screen contents,
or raw protocol output in the repository.

1. Record `git rev-parse HEAD`, `farsee --version`, the terminal application,
   operating-system version, and `stty -g`. Use neutral endpoint classes such
   as “authorized macOS host” or “Windows 11 ARM lab”.
2. Run `make macos-acceptance` with the authorized macOS variables from
   `USAGE.md`. Then manually verify a visible frame, pointer movement, scroll,
   keyboard rows from `tests/macos/keyboard_matrix.md`, clipboard in both
   directions, terminal resize, leader-key disconnect, peer disconnect, and
   `SIGINT`, `SIGTERM`, and `SIGHUP` shutdown.
3. Run `make rdp-interop` for the baseline matrix. After the operator rotates
   the test endpoint certificate, run it again with
   `RDP_INTEROP_PHASE=changed-cert`. Manually verify a visible frame, pointer,
   keyboard, clipboard, terminal resize, leader-key disconnect, peer
   disconnect, and the three shutdown signals.
4. After every exit, compare `stty -g` with the initial value. Confirm that
   echo, canonical mode, mouse reporting, Kitty keyboard mode, cursor state,
   and standard-stream flags were restored.

For each row, record `PASS`, `FAIL`, or `NOT RUN`, the candidate commit, the
endpoint class, and a short sanitized observation. `NOT RUN` does not satisfy
the gate. Keep generated RDP records under the build directory until a human
has reviewed them for publication.
