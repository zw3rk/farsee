# Senior escalation

Consult an independent senior reviewer before more speculative production
changes or declaring a gate blocked when **any** of these holds:

1. **Proven component still fails E2E** — unit/golden/live-byte evidence is
   solid, but the real server rejects after ≥5 exhausted variants.
2. **Crypto reverse-engineering impasse** — undocumented Apple detail not
   resolvable from RFCs, project captures, or approved memos after
   disassembly still leaves the formula ambiguous.
3. **Evidence vs behaviour contradiction** — captures prove a value, server
   still rejects (protocol flow / state-machine misunderstanding likely).
4. **macOS security framework interaction** — failure may be OD / SecureToken /
   Keychain / authd, not pure RFB.

## Before escalating

- Evidence packet under `docs/apple/` or `docs/gates/`: proven facts, tried
  variants, exact failure, open questions, repro commands.
- Clean tree, green tests; no half-baked speculative changes.
- Escalation is advisory; the worker keeps ownership.

No active escalation.
