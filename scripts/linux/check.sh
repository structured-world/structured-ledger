#!/usr/bin/env bash
# Runs the checks that need Ledger's Linux dev-tools image on the project's
# Linux check host over SSH, without pushing anything.
#
#   STRUCTURED_LEDGER_LINUX=<ssh destination> scripts/linux/check.sh device
#
# `device` builds and lints the device application for every target
# (scripts/device-build.sh) and copies the artifacts back into
# target/device/<target>/ of this checkout.
#
# The working tree is snapshotted as it is, uncommitted and untracked files
# included (ignored files excluded), through a temporary index: HEAD, the index
# and the files of the checkout stay untouched. The snapshot travels as a git
# bundle into a directory of this run's own, so runs started at the same time
# do not meet. Everything the run put on the host is removed afterwards
# whatever the result, and a failed removal fails the run, since the host is
# shared. The dev-tools image itself stays: it is a tool the host keeps, like a
# toolchain.
#
# STRUCTURED_LEDGER_LINUX is an SSH destination that can run docker.
set -euo pipefail

destination="${STRUCTURED_LEDGER_LINUX:?set STRUCTURED_LEDGER_LINUX to the SSH destination of the Linux check host}"
action="${1:?action: device}"

case "$action" in
    device) ;;
    *)
        echo "unknown action $action: device" >&2
        exit 2
        ;;
esac

root=$(git rev-parse --show-toplevel)
work=$(mktemp -d)
ref="refs/structured-ledger-check/snapshot-$$"
ssh_options=(-o BatchMode=yes -o LogLevel=ERROR -o ConnectTimeout=15)
# Random, not the local process id: runs from different machines must not meet
# under one name. `mkdir` below refuses an existing directory all the same.
run_id="structured-ledger-check-$(od -An -N4 -tx1 /dev/urandom | tr -d ' \n')"
remote_dir="/tmp/$run_id"
# Set while the remote directory may exist.
remote_pending=0

# Removes the local snapshot and the remote directory; a failed remote removal
# fails the run.
# shellcheck disable=SC2329 # called by the EXIT trap
cleanup() {
    local rc=$?
    # The ref is absent when the run stopped before creating it.
    git -C "$root" update-ref -d "$ref" 2>/dev/null || true
    rm -rf "$work"
    if [[ $remote_pending -eq 1 ]]; then
        # shellcheck disable=SC2029 # the path is meant to be expanded here
        if ! ssh "${ssh_options[@]}" "$destination" "rm -rf $remote_dir"; then
            echo "remote directory $remote_dir could not be removed" >&2
            rc=1
        fi
    fi
    exit "$rc"
}
trap cleanup EXIT

# Snapshot through a temporary index so the real index is not touched.
export GIT_INDEX_FILE="$work/index"
git -C "$root" read-tree HEAD
git -C "$root" add -A
tree=$(git -C "$root" write-tree)
unset GIT_INDEX_FILE
commit=$(git -C "$root" commit-tree "$tree" -p HEAD -m "working tree snapshot")
git -C "$root" update-ref "$ref" "$commit"
git -C "$root" bundle create "$work/snapshot.bundle" "$ref" 2>/dev/null

# Pending before the mkdir: its connection may drop after the directory exists,
# and the cleanup tolerates a directory that was never created.
remote_pending=1
# shellcheck disable=SC2029 # the path is meant to be expanded here
ssh "${ssh_options[@]}" "$destination" "mkdir -m 700 $remote_dir"
# shellcheck disable=SC2029 # the path is meant to be expanded here
ssh "${ssh_options[@]}" "$destination" "cat > $remote_dir/snapshot.bundle" <"$work/snapshot.bundle"
# The remote half comes from the snapshot, so the run executes exactly the tree
# it reports.
# shellcheck disable=SC2029 # the path is meant to be expanded here
git -C "$root" show "$commit:scripts/linux/remote.sh" |
    ssh "${ssh_options[@]}" "$destination" "cat > $remote_dir/remote.sh"

echo "snapshot ${commit:0:12} of $(git -C "$root" rev-parse --short HEAD) with local changes"
status=0
# shellcheck disable=SC2029 # the paths are meant to be expanded here
ssh "${ssh_options[@]}" "$destination" "bash $remote_dir/remote.sh $remote_dir $ref $action" ||
    status=$?

# Artifacts come back even from a failed run: the targets that built are worth
# looking at.
artifacts="$root/target/device"
rm -rf "$artifacts"
mkdir -p "$artifacts"
# shellcheck disable=SC2029 # the path is meant to be expanded here
if ssh "${ssh_options[@]}" "$destination" "test -f $remote_dir/artifacts.tar && cat $remote_dir/artifacts.tar" >"$work/artifacts.tar" &&
    [[ -s "$work/artifacts.tar" ]]; then
    tar -x -f "$work/artifacts.tar" -C "$artifacts"
    echo "artifacts in $artifacts"
else
    echo "no artifacts came back" >&2
    status=1
fi
exit "$status"
