# R6 — Independent RDP interop lab (QEMU + HVF)

- **Status:** ##  **PASS_INTEROP_XRDP** (xrdp, 7 matrix cases) · **PASS_INTEROP_WINDOWS** (Farsee CLI first frame)
- **Evidence:** this card · full history in git · tests under `tests/`

## Scope

(see plan.md / implementation-status)


## Key paths

- `docs/gates/interop-evidence/farsee-windows-connect.log`
- `docs/gates/interop-evidence/farsee-windows-first-frame-800x600.png`
- `docs/gates/interop-evidence/farsee-windows-first-frame-800x600.rgba`
- `docs/gates/interop-evidence/farsee-windows-settled-800x600.rgba`
- `docs/gates/interop-evidence/freerdp-windows-connect.log`
- `docs/gates/interop-evidence/repair-rdp-log.txt`
- `docs/gates/interop-evidence/windows-canonical-x224.pcap`
- `docs/gates/interop-evidence/windows-net-rdp-rst.pcap`
- `docs/gates/interop-evidence/xrdp-*.txt`
- `src/app/main.c`
## Verification

Machine checks live in the test suite and `make ci`. Do not re-expand this
card with red→green narrative; status is authoritative in
`docs/implementation-status.md`.
