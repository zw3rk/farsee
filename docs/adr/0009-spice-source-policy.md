# ADR-0009: SPICE protocol source policy and clean-room scope

**Status:** Proposed

## Context

SPICE is a candidate future protocol after RDP. During R6 Windows provisioning a concrete need appeared: VM display/input during firmware/installer/recovery when no in-guest protocol (RDP, VNC) is up. The SPICE protocol is used by QEMU, UTM, GNOME Boxes, and virt-manager for virtual machine display. It operates at a different layer than RFB/VNC or RDP — it speaks to the hypervisor's virtual GPU, not to a guest OS service.

## Decision

1. **SPICE is approved as a future Farsee protocol engine** under a new gate series S0+.
2. **The SPICE engine will be clean-room derived** from the official protocol specification and project-owned captures only. No LGPL/GPL source will be read.
3. **The initial scope** is minimal: Main + Display + Inputs + Cursor channels over local Unix socket. All other channels (audio, clipboard, USB, smartcard, file transfer) are explicitly disabled.
4. **The dependency policy** (plan.md §5.4 allowlist: Apache-2.0, MIT, ISC, BSD, zlib, CC0/Unlicense) will be checked before linking any SPICE-related library. If no allowlisted library exists, Farsee will implement the protocol from the specification.
5. **S0 is a planning gate** — it produces this ADR, a protocol document inventory, and capture-based t

## Consequences

- A Farsee SPICE engine enables automated VM provisioning, firmware debugging, and pre-OS recovery — capabilities that RFB/VNC and RDP cannot provide. - The clean-room constraint means slower initial development (no reference implementation to study), but preserves Farsee's Apache-2.0 licensing and avoids LGPL/GPL contamination. - SPICE work is sequenced after R6 (RDP interop) and does not block the RDP milestone.
