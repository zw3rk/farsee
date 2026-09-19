# ADR-0009: SPICE protocol source policy and clean-room scope

- **Status:** Proposed

## Context

SPICE is a candidate future protocol after RDP. It can provide VM display and
input during firmware, installation, and recovery, when no in-guest protocol
such as RDP or VNC is available. QEMU, UTM, GNOME Boxes, and virt-manager use
SPICE for virtual-machine display. SPICE communicates with the hypervisor's
virtual GPU instead of a guest OS service.

## Decision

1. **SPICE is proposed as a future Farsee protocol engine** under a new S0+
   gate series.
2. **The SPICE engine will use** the official protocol specification and
   documented interoperability tests only. No LGPL/GPL source will be read.
3. **The initial scope** is Main, Display, Inputs, and Cursor channels over a
   local Unix socket. Audio, clipboard, USB, smart-card, and file-transfer
   channels are disabled.
4. **The dependency policy** uses the `plan.md` §5.4 license allowlist. If no
   allowlisted library exists, Farsee will implement the protocol from the
   specification.
5. **S0 is a planning gate.** It produces this ADR, a protocol document
   inventory, and an interoperability test plan.

## Consequences

- A Farsee SPICE engine enables automated VM provisioning, firmware debugging,
  and pre-OS recovery where an in-guest protocol is unavailable.
- The source policy can increase initial development time, but it preserves
  the project's Apache-2.0 license boundary and excludes LGPL/GPL source.
- SPICE work follows R6 interoperability work and does not block the RDP
  milestone.
