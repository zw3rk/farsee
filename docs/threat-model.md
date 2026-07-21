# Threat model

This document is the controlling security analysis referenced by
`SECURITY.md`, the gates, and `docs/adr/`. It mirrors plan.md §6 with
concrete traceability to mitigations and tests.

## Assets

- Process memory and the host filesystem.
- Terminal state and the terminal emulator itself.
- The VNC password.
- Clipboard contents (both directions).
- Keystrokes.
- Remote framebuffer confidentiality.
- The shared-memory namespace (`/farsee-...` objects).
- Availability of the local terminal session (no DoS by runaway queue).

## Primary threats and mitigations

| Threat                                            | Mitigation                                                            | Tested in          |
| ------------------------------------------------- | --------------------------------------------------------------------- | ------------------ |
| Integer overflow in rectangle/image-size math     | checked `add`/`mul`/`rect_bytes`; every wire-derived size flows through it | G1, G3, G4         |
| Out-of-bounds read/write during pixel conversion  | reader-based decode; bounds-validated rectangles before any write     | G3, G4             |
| Out-of-bounds in CopyRect overlap                 | overlap-safe row ordering; reference-model comparison                 | G4                 |
| ZRLE decompression bomb / corrupt stream          | output-size cap tied to tile dimensions; zlib errors → typed protocol error | G8                 |
| Unbounded server name / clipboard / compressed-len| configurable hard limits with boundary tests at −1/+1                 | G1, G3, G6         |
| Parser desync under fragmented TCP input          | incremental state machines; fragmentation-at-every-byte tests         | G2, G4, G5         |
| Terminal escape injection from server-controlled text | escaping/rejection for control bytes before any diagnostic        | G1 (logging), G3   |
| Predictable / wrong-permission SHM names          | `/`-prefixed unpredictable names; `O_CREAT\|O_EXCL`; mode `0600`     | G10                |
| Leaked VNC password (logs, argv, core dumps)      | never an argv; URL userinfo passwords rejected at production entry (`farsee_cli_url_password_*`); tty/`--password-fd` only; zeroized buffer; logs scrubbed | G2, cli_target unit |
| Queue growth / memory exhaustion under update flood | bounded input/output/damage/presentation queues; coalescing          | G5, G9             |
| Unsafe terminal restoration after crash/signal    | signal-safe restoration helper; lifecycle failure injection           | G7                 |
| Replay/interception of legacy VNC Authentication  | documentation: trusted LAN or tunnel; no false encryption claim       | SECURITY.md, G11   |

## Default hard limits (plan.md §6.4)

| Limit                            | Default      |
| -------------------------------- | ------------ |
| framebuffer width                | 16,384 px    |
| framebuffer height               | 16,384 px    |
| framebuffer bytes (absolute)     | 1 GiB        |
| framebuffer bytes (policy)       | 256 MiB      |
| desktop name                     | 1 MiB        |
| clipboard payload                | 16 MiB       |
| compressed rectangle payload     | 256 MiB      |
| queued outbound bytes            | 8 MiB        |
| queued presentation bytes        | 128 MiB      |
| rectangles per FramebufferUpdate | 65,535       |
| maximum terminal response length | 4 KiB        |

Every limit has boundary tests at limit−1, limit, limit+1.

## Out of scope (first release)

Encrypted VNC transport (TLS/VeNCrypt), Apple High Performance Screen
Sharing, Tight/JPEG, HDR, audio, Sixel, tmux passthrough. These do not
weaken the threat model above; they are simply not implemented.
