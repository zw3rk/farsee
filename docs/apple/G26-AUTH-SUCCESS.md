# Authorized Apple interoperability status

G26 basic hardware coverage passed on an authorized macOS system. The type-33
product path completed RSA1/SRP authentication, verified the server proof,
entered the RFB session, rendered a framebuffer, and accepted input. A later
forced type-36 run completed direct identity/SRP authentication, verified the
server proof, derived the wrap key, and activated protected post-authentication
records. The bounded type-36 run used the null presenter, so it did not repeat
the framebuffer or input acceptance.

The supported contracts are documented in `docs/apple/apple-wire-spec.md` and
covered by the current focused tests. This functional result does not change
the separate provenance release status in ADR-0013.
