#!/usr/bin/env bash
# Prints Ledger's dev-tools image (toolchain, cargo-ledger, Speculos) used by the device build and
# the Speculos check. Always the latest image, as Ledger's reusable build for the catalog uses: the
# build that matters is the one Ledger ships, and Ledger's checks require the newest SDK anyway,
# so pinning an older image would only test a build nobody releases.
echo ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest
