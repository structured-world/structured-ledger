#!/usr/bin/env bash
# Prints Ledger's dev-tools image (toolchain, cargo-ledger, Speculos) used by the device build and
# the Speculos check. Pinned by digest so a given revision always builds and runs with the same
# tools; move it deliberately: `docker buildx imagetools inspect <image>:latest` prints the current
# digest.
echo ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools@sha256:0ed357a6f66a1df949649803ea79e5a224f3f551a496adb3b73af22088781452
