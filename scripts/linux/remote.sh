#!/usr/bin/env bash
# Remote half of scripts/linux/check.sh, run on the Linux check host.
#
#   remote.sh <run dir> <bundle ref> device
#
# Checks the snapshot out into <run dir>/src, runs the action there and packs
# the device artifacts into <run dir>/artifacts.tar for the local side to
# fetch. The local side removes <run dir> afterwards.
set -uo pipefail

dir="$1"
ref="$2"
action="$3"

src="$dir/src"
mkdir "$src" || exit 1
cd "$src" || exit 1
git init -q || exit 1
git fetch -q "$dir/snapshot.bundle" "$ref" || exit 1
git checkout -q --detach FETCH_HEAD || exit 1

status=0
case "$action" in
    device)
        bash scripts/device-build.sh || status=1
        # One directory per target: the ELF and what cargo-ledger derived from it.
        files=()
        for target in nanosplus nanox stax flex apex_p; do
            release="app/target/$target/release"
            for file in "$release"/structured-ledger-app "$release"/structured-ledger-app.{hex,apdu,sha256}; do
                [[ -f "$file" ]] && files+=("${file#app/target/}")
            done
        done
        if [[ ${#files[@]} -gt 0 ]]; then
            tar -c -f "$dir/artifacts.tar" -C app/target "${files[@]}" || status=1
        fi
        ;;
    *)
        echo "unknown action $action" >&2
        status=2
        ;;
esac

if [[ $status -eq 0 ]]; then
    echo "== PASSED"
else
    echo "== FAILED"
fi
exit "$status"
