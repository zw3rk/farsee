# Senior escalation

Consult an independent senior reviewer before more speculative production
changes or declaring a gate blocked when **any** of these holds:

1. **Protocol failure persists** — unit and integration tests pass, but the
   endpoint rejects the protocol after five documented attempts.
2. **Incomplete approved specification** — a required detail is absent from
   the approved public specifications and synthetic wire vectors.
3. **Test/specification contradiction** — tests and the approved specification
   require incompatible behaviour.
4. **Platform security interaction** — failure may involve platform credential
   or key storage rather than RFB.

## Before escalating

- Technical packet under `docs/apple/` or `docs/gates/`: verified facts, tried
  variants, exact failure, open questions, and reproduction commands.
- Clean tree, green tests; no half-baked speculative changes.
- Escalation is advisory; the worker keeps ownership.
