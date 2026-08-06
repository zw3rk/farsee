# farsee — usage

C11 RFB/VNC (and RDP) client for Kitty graphics (KGP) terminals.
See `README.md` for a short list of terminals that implement KGP.

## Quick start

```sh
nix develop
make release
./build/release/bin/farsee --version
./build/release/bin/farsee 192.168.1.50          # VNC, prompts for password
./build/release/bin/farsee rdp://user@host       # RDP
```

**Never** put a password on argv or in a URL (`user:pass@host`). Production
entry rejects URL userinfo passwords (exit 2). Use the TTY prompt or
`--password-fd N`.

```sh
nix develop --command make install PREFIX=$HOME/.local
```

Requires Nix flakes. No system-wide package installs.

## Target forms

| Form | Notes |
|------|--------|
| `host[:port]` | Default port 5900 (RFB) or 3389 (RDP) by protocol |
| `vnc://` / `rfb://` / `rdp://host[:port]` | Explicit protocol |
| `…://user@host` | Username OK; password in URL **rejected** |

## Common options

| Flag | Meaning |
|------|---------|
| `--password-fd N` | Read password from FD N (preferred automation) |
| `--user NAME` | Username (RDP / Apple) |
| `--auth auto\|vnc\|apple` | RFB security selection policy |
| `--dump-frame PATH` | Write one RGBA/PPM frame and exit (no Kitty) |
| `--view-scale PCT` | Live view scale percent |
| `-v` / `--verbose` | Extra diagnostics |
| `--version` | Build id / version |
| `--protocol-capabilities` | Machine-readable capability list |

Full flag list: `farsee --help` (source of truth may grow; keep this table
as the operator summary).

## Live status band

During Kitty sessions the status line shows host/port help plus:

- **scale %** — view scale  
- **RTT ms** — TCP RTT when the kernel reports a sample on an established
  socket (omitted = no sample)  
- **KiB/s** — downlink over a 250 ms latched window (`link_rate_pub`)

Protocol thread latches rate; present/input only load atomics. See ADR-0010.

## Secrets

- Password: TTY or `--password-fd` only; zeroized after use  
- Known-hosts / TOFU: fail-closed on change (see SECURITY.md)

## Build targets

`make help` · `make test` · `make asan-ubsan` · `make ci`  
Always: `nix develop --command make <target>`.

## Lab helpers

- Windows RDP VM: `tools/start_windows_rdp_vm.sh` (see R6 gate card)  
- Apple probes: `tools/apple/`, `tools/probe_rsa1.py` (authorized hosts only)
