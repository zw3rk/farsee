# farsee

Clean-room Apache-2.0 C11 RFB/VNC + RDP terminal client for
[Kitty graphics](https://sw.kovidgoyal.net/kitty/graphics-protocol/).

This is **not** Apple High Performance Screen Sharing (AHPSS). Classic VNC
Authentication proves password knowledge only — it is **not** session
encryption. See [`SECURITY.md`](SECURITY.md).

## Install / run

```sh
nix run github:zw3rk/farsee -- --version
nix run github:zw3rk/farsee -- vnc://host.example:5900
nix run github:zw3rk/farsee -- rdp://user@host.example
```

Password is never taken from argv or a URL. Use the TTY prompt (echo off) or
`--password-fd N`. Production rejects URL userinfo passwords.

## Develop

```sh
nix develop
make help
make test
make ci
```

Hermetic toolchain via the flake (`flake.nix`); all work goes through the
Makefile (`make help`).

## Common targets

| Target | What it does |
| ------ | ------------ |
| `make help` | Full target catalogue |
| `make` / `make build` | Dev build (Clang, strict warnings) |
| `make test` | Build and run the unit suite |
| `make ci` | Full release-candidate gate |
| `make asan-ubsan` | Address + UBSan build and tests |
| `make release` | Optimized release binary |
| `make coverage` / `make coverage-report` | Coverage build + report |
| `make fuzz-smoke` | Brief corpus run per fuzz target |
| `make check-license` | SPDX + third-party notices |
| `make clean` | Remove build outputs |

## Scope

- **Classic VNC** (RFB 3.3/3.7/3.8): VNC Auth, Raw / CopyRect / ZRLE, Cursor,
  DesktopSize, input, clipboard, Bell
- **Apple Screen Sharing type-33** MVP (cleartext post-auth path)
- **RDP** via FreeRDP
- **Live graphics** require a Kitty-compatible terminal (or `--dump-frame`)

## Known limitations

No VNC TLS/VeNCrypt; type-33 ships as a cleartext MVP. Details:
[`docs/known-limitations.md`](docs/known-limitations.md).

## Documentation

| Doc | Role |
| --- | ---- |
| [`USAGE.md`](USAGE.md) | CLI, flags, runtime paths |
| [`plan.md`](plan.md) | Controlling requirements |
| [`docs/implementation-status.md`](docs/implementation-status.md) | Gate status |
| [`SECURITY.md`](SECURITY.md) | Secure-use guide |
| [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) | Dependencies & licenses |

## License

Apache-2.0 — see [`LICENSE`](LICENSE). No GPL/AGPL/LGPL VNC sources are
read, copied, or linked (ADR-0001).
