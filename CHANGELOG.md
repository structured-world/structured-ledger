# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0](https://github.com/structured-world/structured-passkeys/releases/tag/v0.1.0) - 2026-10-03

### Added

- *(ctap)* NVM store for config, index and device keys
- *(app)* say why the selection screen names no website
- *(app)* authenticatorSelection waiting for the user
- *(app)* FIDO HID interface on the device
- *(app)* run the IO stack in the application
- add workspace, device app skeleton and gate

### Fixed

- *(app)* settle index entries after every write

### Other

- *(app)* mark a superseded request instead of counting
- *(app)* keepalive cadence follows the OS ticker
- *(deps)* update ledger_device_sdk to 1.38.0
- rename project to Structured Passkeys
