# structured-ledger

A FIDO2 / passkey authenticator application for Ledger devices, written in Rust.

- Discoverable credentials (passkeys) that are not silently lost on application updates.
- A key origin chosen on the device for every credential: **device-only** (random, never leaves the
  secure element, reported as single-device) or **seed-recoverable** (reproducible from the recovery
  phrase, reported as backed up).
- CTAP 2.1 with the CTAP 2.2 extensions current relying parties request (`hmac-secret-mc` for the
  WebAuthn PRF extension), credential management, client PIN.
- Encrypted backup and restore of the discoverable index through a host tool.
- Targets: Nano S Plus, Nano X, Stax, Flex, Nano Gen5.

**Status:** implementation in progress.

## Building

Device builds use Ledger's `ledger-app-dev-tools` image; host crates build with the repository
toolchain. The single check that every change must pass:

```sh
scripts/check.sh
```

## License

Apache-2.0, see [LICENSE](LICENSE).
