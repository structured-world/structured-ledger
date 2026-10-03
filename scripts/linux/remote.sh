#!/usr/bin/env bash
# Remote half of scripts/linux/check.sh, run on the Linux check host.
#
#   remote.sh <run dir> <bundle ref> device|speculos|golden
#
# Checks the snapshot out into <run dir>/src, runs the action there and packs
# the device artifacts into <run dir>/artifacts.tar for the local side to
# fetch. `speculos` builds as `device` does, then runs every build in Speculos
# (scripts/speculos-check.sh). `golden` runs Speculos writing the screen
# snapshots instead of comparing them, and packs tests/snapshots into
# <run dir>/snapshots.tar. The local side removes <run dir> afterwards.
#
# The local side starts this script detached from its SSH session, so a dropped
# connection does not stop the run: it writes its process group to <run dir>/pid
# and, whatever the way it ends, its exit status to <run dir>/status, which the
# local side polls. Containers are named after the run directory, so stopping a
# run removes exactly its own containers.
set -uo pipefail

dir="$1"
ref="$2"
action="$3"

# Started through setsid, so this process leads its own process group.
echo "$$" >"$dir/pid"
# Written last and renamed into place, so a status file is always complete and
# the log before it is final.
# Older shellcheck releases report this as SC2317, newer ones as SC2329.
# shellcheck disable=SC2317,SC2329 # called by the EXIT trap
write_status() {
    local code=$?
    echo "$code" >"$dir/status.tmp" && mv "$dir/status.tmp" "$dir/status"
}
trap write_status EXIT
CHECK_CONTAINER_PREFIX=$(basename "$dir")
export CHECK_CONTAINER_PREFIX

src="$dir/src"
mkdir "$src" || exit 1
cd "$src" || exit 1
git init -q || exit 1
git fetch -q "$dir/snapshot.bundle" "$ref" || exit 1
git checkout -q --detach FETCH_HEAD || exit 1

status=0
case "$action" in
    device | speculos | golden)
        bash scripts/device-build.sh || status=1
        if [[ "$action" == speculos && $status -eq 0 ]]; then
            bash scripts/speculos-check.sh || status=1
        fi
        if [[ "$action" == golden && $status -eq 0 ]]; then
            SPECULOS_GOLDEN=1 bash scripts/speculos-check.sh || status=1
            tar -c -f "$dir/snapshots.tar" -C tests snapshots || status=1
        fi
        # One directory per target: the ELF and what cargo-ledger derived from it.
        files=()
        for target in nanosplus nanox stax flex apex_p; do
            release="app/target/$target/release"
            for file in "$release"/structured-passkeys-app "$release"/structured-passkeys-app.{hex,apdu,sha256}; do
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
