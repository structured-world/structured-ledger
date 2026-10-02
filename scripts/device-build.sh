#!/usr/bin/env bash
# Builds and lints the device application for every Ledger target in Ledger's
# dev-tools image, the image and toolchain Ledger deploys with. Linux only: the
# image is a Linux container.
#
# Artifacts (ELF, .hex, .apdu, .sha256) land in app/target/<target>/release/.
# The container runs as root, as the image expects; its output is handed back
# to the calling user afterwards, whatever the result.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
image=$("$root/scripts/dev-tools-image.sh")

docker pull --quiet "$image" >/dev/null
docker run --rm \
    --volume "$root:/app" \
    --workdir /app/app \
    --env OWNER="$(id -u):$(id -g)" \
    "$image" bash -c '
        status=0
        for target in nanosplus nanox stax flex apex_p; do
            echo "== cargo ledger build $target"
            cargo ledger build "$target" -- --locked || status=1
            echo "== cargo clippy $target"
            cargo clippy --release --locked --target "$target" -- -D warnings || status=1
        done
        if [[ -d target ]]; then
            chown -R "$OWNER" target || status=1
        fi
        exit "$status"
    '
