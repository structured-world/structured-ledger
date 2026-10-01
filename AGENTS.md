# Contributor and reviewer guide

Rules a change in this repository must meet. Reviewers check them; the gate script
(`scripts/check.sh`) checks the mechanical ones.

## Specifications

- Every behavior decided by a specification (CTAP 2.1/2.2, WebAuthn L3, CBOR) carries a code
  comment naming the specification and section.
- The pull request description states the scope and acceptance checks of the change; a behavior
  change without them is incomplete.

## Code

- Protocol logic lives in `crates/ctap`, which is `#![no_std]` with `alloc`; `std` only behind the
  `std` feature for host users. The device crate `app` only adapts the Ledger SDK to the platform
  traits.
- Untrusted input (CTAPHID packets, CBOR, credential IDs, backup blobs) is bounded by the received
  length; no allocation sized by a field the attacker controls beyond that.
- Secrets (derived keys, private keys, CredRandom, PIN material) live in RAM only for the command
  that needs them and are zeroised on every exit path, including errors.
- No `unwrap` outside tests; `expect` only for internal invariants with the invariant stated.
- Arithmetic: `checked_*` with explicit handling; `saturating_*` only where clamping is the specified
  behavior, with a comment saying so.
- Typed errors in libraries; every CTAP failure maps to a specified status code.
- Comments explain the code under them in one or two sentences; no plans, history or issue numbers
  (a specification reference is the exception).

## Tests

- Test bodies live in sibling files (`foo/tests.rs`, declared with `#[cfg(test)] mod tests;`), never
  inline in production files.
- Each test states what it checks. Expected values come from specification vectors or an independent
  computation, never from the code under test.
- A bug fix starts with a test that fails without the fix.
- `cargo nextest run` for Rust tests; `cargo test --doc` for doc tests.

## Commits and pull requests

- Conventional commits: `type(scope): summary` in English, imperative, at most 50 characters, no
  phase or step markers in titles.
- A pull request lists the acceptance checks it ran.
- Breaking changes carry `!` in the pull request title.
