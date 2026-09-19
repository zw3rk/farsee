# Apple security type 36

Security type 36 is admitted by the session's security-selection policy. The
default policy admits both Apple types and prefers 33. The
`--apple-security=36` policy withdraws type 33 and fails closed unless the peer
offers type 36.

The type-36 path sends the identity envelope, validates the Apple SRP
challenge, sends the client proof, verifies the server proof and result, derives
the wrap key, and enters the shared post-auth path. Invalid lengths, reserved
bytes, proofs, and result values fail closed.

The wire contract is in `docs/apple/apple-wire-spec.md`. The retained
implementation uses the existing cryptographic provider and Apple SRP key
schedule; it does not add a new cryptographic primitive.
