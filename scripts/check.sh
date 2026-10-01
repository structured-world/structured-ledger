#!/usr/bin/env bash
# Mechanical gate run by CI and local checks. Every check that a change must pass
# before review is listed here and nowhere else; a new crate, device target or test
# suite is added to this script in the change that introduces it.
#
# Device builds need Ledger's Linux dev-tools image: on Linux they run here, on
# macOS on the Linux check host named by STRUCTURED_PASSKEYS_LINUX
# (scripts/linux/check.sh). Without that host the gate fails instead of
# skipping them.
set -euo pipefail
cd "$(dirname "$0")/.."

# The device crate builds only for Ledger targets, so host checks leave it out.
host=(--workspace --exclude structured-passkeys-app --all-features)

run() {
    echo "== $*"
    "$@"
}

run scripts/check-links.sh
run shellcheck scripts/*.sh scripts/linux/*.sh
run cargo fmt --all --check
run cargo clippy "${host[@]}" --all-targets -- -D warnings
run cargo nextest run "${host[@]}"
run cargo test --doc "${host[@]}"
run cargo build -p structured-passkeys-ctap --target thumbv7em-none-eabihf --no-default-features

case "$(uname -s)" in
    Linux) run scripts/device-build.sh ;;
    *)
        if [[ -z "${STRUCTURED_PASSKEYS_LINUX:-}" ]]; then
            echo "device builds need the Linux check host: set STRUCTURED_PASSKEYS_LINUX" >&2
            exit 1
        fi
        run scripts/linux/check.sh device
        ;;
esac
