# Contributing

Read `plan.md`, `AGENTS.md`, and ADR-0001 (clean-room).

```sh
nix develop
make help
make ci            # must pass before a change is complete
make check-license
```

**TDD:** red → green → refactor. Every bug gets a permanent −/+ regression
first. No weakening/skipping tests, no `sleep` to hide races, no fixture
special-cases in production code.

**Clean-room:** no GPL/AGPL/LGPL VNC sources. Base protocol work on the
permitted sources in `docs/provenance.md` and add synthetic tests.

**Commits:** small, imperative subject, why in body. No push without ask.
