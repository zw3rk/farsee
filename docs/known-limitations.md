# Known limitations

## Intentional non-goals (plan.md §4.2–4.3)

- Encrypted VNC transport (TLS/VeNCrypt) — use trusted LAN or SSH/VPN
- Apple High Performance Screen Sharing (AHPSS)
- Tight/JPEG, Hextile, HDR, audio, Sixel, tmux passthrough
- ExtendedDesktopSize; extended clipboard beyond basic RFB/RDP text
- Windows-hosted binary (Windows is a supported *remote* via RDP)

## Current gaps

- PTY raw-mode edge cases: G11-style manual acceptance
- Type-33 post-auth ChaCha records: not fully productized (cleartext MVP ships)
- R6 Windows interop matrix: partial beyond first-frame CLI
- F-layer engine/reactor: scaffold only; live path is SHARED-MT (ADR-0010/0011)

## Do not claim

Encrypted VNC · Apple-account auth · HDR/audio/HEVC · guaranteed 4K60 via PTY · AHPSS compatibility
