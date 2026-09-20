# Security

Threat model: `docs/threat-model.md`. This file is the operator secure-use guide.

## VNC Auth is not encryption

Security type 2 proves password knowledge; it does **not** encrypt the
session. Use only on a trusted LAN, SSH tunnel, or VPN. The client never
claims encrypted transport.

## Apple security types

Prefer Apple security type 33. It checks and pins the server SPKI with TOFU
before it sends the encrypted username. Verify a new fingerprint through a
separate trusted channel.

Apple security type 36 has no SPKI or TOFU host pin. Its identity frame sends
the username in cleartext before the SRP exchange. The password is not sent;
the client publishes record keys only after it verifies the server's SRP M2
proof. Use `--apple-security 36` only as an explicit compatibility choice. The
default `auto` policy prefers type 33 and can use type 36 only as a fallback
when the server does not offer type 33.

## Passwords

- Never on argv or in URL userinfo (production rejects URL passwords).
- TTY prompt (echo off) or `--password-fd N`.
- Zeroized on all exit paths; never logged.
- Prefer a disposable VNC password, not your login password.

## Core dumps

Production startup disables core dumps and verifies the resulting platform
state before it parses arguments or acquires credentials. There is no runtime
or environment override. Do not use live credentials in a separate developer
build that enables core dumps.

## FreeRDP/WinPR library logs

Optimized release builds force FreeRDP/WinPR WLog off and reject all CLI log
controls. Developer, sanitizer, coverage, and fuzz builds that include FreeRDP
can enable WLog for diagnosis. Treat that output as sensitive because
dependency diagnostics can contain endpoint or session details. These builds
reject WLog controls when the resolved target protocol is RFB.

## RDP certificates

`--cert pin` records the first full-chain PEM fingerprint for the RDP host and
port in `~/.farsee/rdp_known_hosts`. Later sessions reject a different
fingerprint before credentials are sent. Pin mode uses only this Farsee store;
it does not let FreeRDP persist a second trust decision. This is TOFU: pin mode
does not perform CA or certificate-name validation. Verify the first-use
fingerprint through a separate trusted channel.

`--cert ignore` approves an untrusted or changed certificate for that session
only and never writes a pin. Use it only when another trusted layer verifies
the endpoint.

## `--allow-none-auth`

Type 1 (None) is off by default. Enable only on loopback or an already
authenticated tunnel.

## Kitty SHM

`shm_open` with `O_CREAT|O_EXCL`, mode `0600`, unpredictable names; unlink
on cleanup; bounded in-flight; fallback to direct base64.

## Reporting

Report a suspected vulnerability by email to `moritz@zw3rk.com`. Use the
subject `farsee security report`. Do not include credentials or live secrets.
We will acknowledge the report and coordinate disclosure for high-severity and
critical issues.
