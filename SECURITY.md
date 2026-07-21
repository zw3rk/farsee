# Security

Threat model: `docs/threat-model.md`. This file is the operator secure-use guide.

## VNC Auth is not encryption

Security type 2 proves password knowledge; it does **not** encrypt the
session. Use only on a trusted LAN, SSH tunnel, or VPN. The client never
claims encrypted transport.

## Passwords

- Never on argv or in URL userinfo (production rejects URL passwords).
- TTY prompt (echo off) or `--password-fd N`.
- Zeroized on all exit paths; never logged.
- Prefer a disposable VNC password, not your login password.

## `--allow-none-auth`

Type 1 (None) is off by default. Enable only on loopback or an already
authenticated tunnel.

## Kitty SHM

`shm_open` with `O_CREAT|O_EXCL`, mode `0600`, unpredictable names; unlink
on cleanup; bounded in-flight; fallback to direct base64.

## Reporting

Private issue or contacts in `NOTICE`. Coordinate disclosure for high/critical.
