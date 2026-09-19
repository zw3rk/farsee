# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/). Versioning: semver.

## [Unreleased]

### Security
- First-use Apple type-33 host keys fail closed with the SPKI fingerprint
  printed; `--accept-new-host` opts in to accept-and-pin. Mismatched keys
  abort. Apple security type 36 now completes the supported identity and SRP
  exchange, verifies the server proof, and enters the shared post-auth path.
- RELEASE_ALL/teardown key-ups are sealed through the Apple record layer
  — held keysyms no longer appear in cleartext beside sealed records.
- SRP challenges below 1000 PBKDF2 iterations are rejected (server-driven
  KDF downgrade for offline dictionary attacks); success-path SRP
  intermediates are zeroized.
- `--password-fd` readers close the descriptor immediately; a would-block
  on the overflow probe fails closed instead of silently truncating.
- Product startup sets and verifies zero soft and hard core-dump limits before
  parsing. Linux also sets and verifies the process as non-dumpable, so piped
  core handlers cannot bypass the resource limit. Any failure refuses startup.
  Inherited Apple plaintext, key, and frame-dump controls cannot enable product
  output.

### Fixed
- Apple private encoding `0x0450` now decodes the supported profile-1000
  premultiplied pixel and alpha planes into a separate straight-RGBA8 cursor,
  then composites it into the copied presentation frame without changing the
  authoritative framebuffer.
- Capture scheduler: a fully written FramebufferUpdateRequest now closes
  its drain before the step reads, so the server's answer to that request
  is classified as its response. `rfb_io_queue_bytes` drains what it
  appends, so the request was already on the wire while the scheduler
  still reported `REQUEST_DRAINING`; a reply that arrived inside that
  window — routine on loopback, and reached whenever the client was
  descheduled — was rejected as `RFB_CAPTURE_FAILURE_UNSOLICITED_FBU`.
  This surfaced as load-correlated capture integration failures in which
  any expected failure code collapsed to 1, and as spurious aborts on the
  success paths. A short write still leaves the request draining.
- Release verification and runtime hardening: every verification gate can fail
  (fuzz-smoke exit statuses + sanitizer-instrumented fuzz builds,
  enforced coverage ratchet, static-analyzer exit status, CI parity with
  `make ci`, header dependency tracking, registry regeneration on
  `FARSEE_WITH_RDP` toggles); reactor one-shot timers and cross-removal
  dispatch no longer call NULL callbacks and dead fds surface HUP/ERR;
  the interactive password prompt restores the terminal across terminal
  signals, and fatal signals restore mouse/keyboard tty modes;
  `rfb_peek_u16/u32` no longer underflow past the end; pixel-format
  validation runs shift checks before mask computation (UB on hostile
  ServerInit); ZRLE commits rects atomically and implements the RFC
  CPIXEL top-byte rule; an obsolete disconnected MVS decoder is deleted while
  the live Apple MVS path remains;
  wheel-notch math, CSI-u field parsing, RDP desk-size publication and
  timeout/deadline arithmetic are bounded; the nix source filter keeps
  local media and scratch out of store imports (~700MB → 6.5MB);
  clipboard state is per-instance instead of process-global (two sessions
  can no longer clobber each other's policy); the reactor polls in chunks
  past the 16-fd cap (more than 16 waitables used to starve every fd
  event); fuzz-smoke fails on an empty target directory.
- Release acceptance now binds a selected pre-signed macOS candidate to its
  embedded version and revision, SHA-256 digest, and approved Developer ID
  certificate before connecting. Candidate paths pass through Make's
  environment without shell parsing. The runner recognizes both product
  record-activation messages. The release workflow also rejects a Nix package
  whose embedded version differs from the requested release version.

### Added
- Live status band (scale %, RTT, KiB/s) for RFB/RDP Kitty sessions.
- RDP live path (FreeRDP + SHARED-MT) and Windows framebuffer validation.
- Type-33 protected post-auth (opt-in `--apple-postauth=records`): AES-128-CBC
  records after `0x044f` with unkeyed SHA-1 packet checksum,
  sealed C→S FBUR, and ZRLE paint under encryption.
- Test-runner `--filter` matches suites, fails on empty matches, and
  supports `FARSEE_TEST_TIMEOUT_S` fail-fast.

### Changed
- Docs reduced to short status, gate cards, ADRs, and compact `plan.md`.
- README: KGP-capable terminal list; softer public wording (policy stays in ADR-0001).
- Modern path defaults to classic encodings (ZRLE+Raw); the private encoding list is opt-in.
- Protected post-auth without a wrap key fails closed (no silent cleartext).
- Deterministic Apple providers are test adapters, not product sources or
  public headers.
- Release staging uses a machine-readable platform allowlist. Linux remains a
  build and test host but cannot publish artifacts under the current license
  policy. The optimized and reproducible no-RDP artifact paths have dedicated
  gates.

## [0.1.0-dev] — 2026-07-22

Initial public RFB/VNC terminal client (gates G0–G12 machine path), Kitty
presenters, Apple type-33 MVP, and RDP integration. See
`docs/implementation-status.md`.
