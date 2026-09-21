# G27 — Release readiness

- **Status:** BLOCKED
- **Evidence:** this card, the current source tree, and tests under `tests/`

## Scope

G26 has passed its basic authorized hardware scope. Release readiness remains
blocked by the provenance decision in ADR-0013 and by incomplete live-platform,
Apple extended-fidelity, final-artifact signing, independent-review, and final
acceptance gates. The
Developer ID signing identity is approved. The repository-local current-content
and reachable-history trace checks pass on `master`; they must run again on the
final candidate and do not clear the remaining gates.

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

### 2026-09-20 matrix progress

The signed Apple recheck used exact candidate
`004c45ac770bcc26947a6c92eb3fe55128b6e362` against the authorized macOS
endpoint.

| Row | Result | Sanitized observation |
|-----|--------|-----------------------|
| Candidate identity and signature | PASS | Embedded revision, binary digest, and approved Developer ID identity matched. |
| Type 36 and shared-desktop attach | PASS | Protected records became active. |
| Visible framebuffer | PASS | A complete 3840x2160 RGBA frame showed the expected macOS login UI. |
| Apple `0x0450` receive and composition | NOT RUN | The client requested `0x0450`, but the server sent no observed `0x0450` rectangle. The decoder requires the canonical pixel format and rejects this encoding after a non-canonical ServerInit. |
| Pointer, scroll, and keyboard fidelity | NOT RUN | No safe visual input matrix was performed. |
| Clipboard in both directions | NOT RUN | The session used clipboard-off; no Aqua pasteboard automation seam was available. |
| Terminal resize and peer disconnect | NOT RUN | These rows were not exercised in this session. |
| Leader-key disconnect | PASS | The bounded leader command stopped the session. |
| Terminal modes and control sequences | PASS | `stty` and the expected mouse, keyboard, and cursor controls were restored. |
| Standard-stream flags | PASS | `O_NONBLOCK` was clear after exit. Darwin's added `FWASWRITTEN` bit is kernel bookkeeping, not a user-settable status flag. |

All `NOT RUN` rows remain release blockers.

### 2026-09-20 head-candidate recheck

The exact signed head candidate
`2051d2e25af67581770d9d3263ced862a47d255b` had SHA-256
`dcc0dbde678785ac9074fef6929d28b8f9a160534b2cb8c572592fd56851c054`
and the approved Developer ID identity. The automated macOS acceptance target
passed. The following additional live checks used the same binary.

| Row | Result | Sanitized observation |
|-----|--------|-----------------------|
| Type 36 and shared-desktop attach | PASS | The peer completed SRP authentication and activated protected records. |
| Visible framebuffer | FAIL | Repeated full-size updates remained uniformly black in protected-record, cleartext, and private post-auth modes. The same endpoint had returned visible content to the earlier signed candidate, so this result does not isolate client behavior from current endpoint state. |
| Apple `0x0450` receive and composition | NOT RUN | No `0x0450` rectangle was observed. The black framebuffer state prevented live composition acceptance. |
| Pointer, scroll, and keyboard fidelity | FAIL | The server accepted the automatic post-ServerInit pointer sequence, but subsequent pointer and keyboard events did not change independently observed console state. Scroll fidelity could not be established. |
| Clipboard in both directions | FAIL | Both directions left the destination pasteboard unchanged in protected-record and cleartext sessions. Original pasteboard contents were restored after the checks. |
| Leader-key disconnect and terminal restoration | PASS | The live input loop processed the bounded leader command, exited, and restored terminal state. |
| Terminal resize and peer disconnect | NOT RUN | These rows were not repeated against this exact head candidate. |

The exact signed head candidate also reached the Windows 11 ARM lab over RDP,
but both the operator-supplied credential and the unattended-install credential
were stale. RDP returned `ERRCONNECT_LOGON_FAILURE`, and the guest console
independently rejected the operator-supplied credential. The original guest
disk passed `qemu-img check` and remains unchanged. No Windows fidelity row can
be credited to this head candidate until authorized guest access is restored.

### 2026-09-20 signed current-candidate Windows completion

The exact Developer ID-signed candidate
`b89d4fdbaf023e198101a89b506c0c0b960ad085` had SHA-256
`88432f1f33c34d16343f6733abba1097d2b70b8d56808fda8d5d864c3e280f64`
and the approved signing identity. Testing used a disposable clone of the
Windows 11 ARM lab. The original guest remained stopped and unchanged; after
the matrix, it still passed `qemu-img check`. The disposable clone and its
temporary recovery material were deleted.

| Row | Result | Sanitized observation |
|-----|--------|-----------------------|
| Candidate identity and signature | PASS | Embedded revision, binary digest, and approved Developer ID identity matched. |
| Correct and incorrect credentials | PASS | Correct credentials delivered frames; an incorrect password failed with exit 4 and the expected logon failure. |
| Visible framebuffer and desktop size | PASS | A complete 1280x800 Windows desktop was independently inspected. A separate 1024x768 run delivered frames at the requested size. |
| Pointer, scroll, and keyboard fidelity | PASS | Pointer motion reached the intended pixel, a click opened the application File menu, wheel input scrolled a 34-line document from line 12 to line 1, and all 34 numbered ASCII lines were visible and ordered. |
| Clipboard in both directions | PASS | Pre-connect host text pasted into the remote application, and a remote PowerShell clipboard value reached the host pasteboard. The original host pasteboard was restored after each check. |
| First-use pin and certificate replacement | PASS | First use created a mode-0600 pin and delivered 203 frames. After an actual guest certificate rotation and reboot, the unchanged pin failed closed with exit 4. An ignore-policy control then delivered 189 frames. |
| Leader key and shutdown signals | PASS | Leader quit plus `SIGINT`, `SIGTERM`, and `SIGHUP` each stopped the session and emitted the expected mouse, Kitty keyboard, cursor, and graphics cleanup sequences. |
| Terminal resize and standard-stream restoration | PASS | The live PTY changed from 80x24 to 120x50 and then 100x40 while presentation continued. Exit restored terminal controls; prior exact-candidate flag inspection showed `O_NONBLOCK` clear. |
| Peer disconnect | PASS | A server-initiated sign-out ended the session cleanly with `ERRINFO_LOGOFF_BY_USER` after 153 frames. A guest reboot also produced an admin-initiated peer end and restored the terminal. |

The Windows manual matrix is complete for this candidate. Its recorded Apple
matrix remains incomplete: the signed run returned black full-size updates,
did not emit `0x0450`, and did not establish visual input or clipboard
behavior. The automated identity-bound type-36 protected-record target passed.

A later 2026-09-21 development diagnostic showed that the endpoint and the
protected ZRLE/Raw path delivered visible frames. It isolated private-mode
black output to an `0x03f3` DCT selector defect and verified a non-black private
frame after the repair. Because that diagnostic used a dirty development
build, it does not replace the exact signed-candidate matrix. Live `0x0450`,
input, and clipboard rows remain open.
