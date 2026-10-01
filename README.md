# Structured Passkeys

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

## Layout

| Path | Crate | Role |
|---|---|---|
| `crates/ctap` | `structured-passkeys-ctap` | Protocol logic, `no_std` with `alloc`, tested on the host |
| `app` | `structured-passkeys-app` | Device application on the Ledger Rust SDK |
| `cli` | `structured-passkeys` | Host companion tool |

## Building

Host crates build with the repository toolchain (`rust-toolchain.toml`). The device application
builds in Ledger's `ledger-app-dev-tools` image, a Linux container, with the toolchain that image
pins:

```sh
scripts/device-build.sh                                                   # Linux with Docker
STRUCTURED_PASSKEYS_LINUX=<ssh destination> scripts/linux/check.sh device   # elsewhere, through a Linux host
```

The single check that every change must pass:

```sh
scripts/check.sh
```

## Loading onto a device

Nano S Plus, Stax, Flex and Nano Gen5 accept the application after an on-device warning; the Nano X
accepts only applications signed by Ledger. With the device unlocked and on its dashboard:

```sh
uvx --from ledgerblue python -m ledgerblue.runScript --scp \
  --fileName target/device/apex_p/release/structured-passkeys-app.apdu \
  --elfFile target/device/apex_p/release/structured-passkeys-app
uvx --from ledgerwallet ledgerctl list
```

The paths are those `scripts/linux/check.sh device` copies back; after `scripts/device-build.sh`
they are under `app/target/` instead.

## License

Apache-2.0, see [LICENSE](LICENSE).

Ledger, Ledger Nano, Ledger Stax and Ledger Flex are trademarks of Ledger SAS. This project is
independent and not affiliated with or endorsed by Ledger.
