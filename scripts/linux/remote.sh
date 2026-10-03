#!/usr/bin/env bash
# Remote half of scripts/linux/check.sh, run on the Linux check host; it owns
# everything about a run on the host, so the local side only calls it.
#
#   remote.sh launch <run dir> <bundle ref> device|speculos|golden
#   remote.sh state <run dir>
#   remote.sh stop <run dir>
#
# `launch` starts the run detached from the SSH session (setsid, nohup), its
# output appended to <run dir>/run.log; launching again is harmless, because the
# run takes <run dir>/pid exclusively and a second one exits at once. The run
# checks the snapshot out into <run dir>/src, runs the action there and packs
# the device artifacts into <run dir>/artifacts.tar. `speculos` builds as
# `device` does, then runs every build in Speculos (scripts/speculos-check.sh).
# `golden` runs Speculos writing the screen snapshots instead of comparing them,
# and packs tests/snapshots into <run dir>/snapshots.tar. However the run ends,
# its exit status lands in <run dir>/status.
#
# `state` prints `starting` (not launched yet), `running`, `done <status>` or
# `lost` (ended without a status). `stop` stops a live run and its containers,
# then removes <run dir>; it fails when anything could not be removed.
set -uo pipefail

mode="${1:?mode: launch, state or stop}"
dir="${2:?run dir}"
# Containers carry the run's name, so a stop removes exactly its own.
name=$(basename "$dir")

# Whether <run dir>/pid names a live process of this run: a process id the run
# no longer holds may belong to another process by now.
alive() {
    local pid cmdline
    pid=$(cat "$dir/pid" 2>/dev/null) || return 1
    [[ "$pid" =~ ^[0-9]+$ ]] || return 1
    # stderr goes first, so a process gone between the checks stays quiet.
    cmdline=$(tr '\0' ' ' 2>/dev/null <"/proc/$pid/cmdline") || return 1
    [[ "$cmdline" == *"$dir/remote.sh run $dir "* ]]
}

# Whether a process of group $1 is still running. A zombie member does not
# count: `kill -0` still finds it until its parent reaps it, which an orphan in
# a container without a reaping init never gets.
group_running() {
    local file stat state pgrp
    for file in /proc/[0-9]*/stat; do
        stat=$(cat "$file" 2>/dev/null) || continue
        # The fields after the command name, which may hold spaces and parentheses.
        read -r state _ pgrp _ <<<"${stat##*) }"
        if [[ "$pgrp" == "$1" && "$state" != Z ]]; then
            return 0
        fi
    done
    return 1
}

case "$mode" in
    launch)
        setsid nohup bash "$dir/remote.sh" run "$dir" "${3:?ref}" "${4:?action}" \
            >>"$dir/run.log" 2>&1 </dev/null &
        exit 0
        ;;
    state)
        if [[ -f "$dir/status" ]]; then
            echo "done $(cat "$dir/status")"
        elif [[ ! -f "$dir/pid" ]]; then
            echo starting
        elif alive; then
            echo running
        # The run may have written its status just now.
        elif [[ -f "$dir/status" ]]; then
            echo "done $(cat "$dir/status")"
        else
            echo lost
        fi
        exit 0
        ;;
    stop)
        status=0
        if alive; then
            # The run leads its process group (setsid), which its docker clients are in.
            group=$(cat "$dir/pid")
            kill -TERM -- "-$group" 2>/dev/null
            for _ in $(seq 1 50); do
                group_running "$group" || break
                sleep 0.2
            done
        fi
        # Only a container that does not exist is no error: a daemon that cannot
        # answer leaves the containers unknown.
        for container in "$name-build" "$name-speculos"; do
            if ! found=$(docker ps --all --quiet --filter "name=^/$container\$"); then
                echo "cannot list containers to remove $container" >&2
                status=1
            elif [[ -n "$found" ]] && ! docker rm --force "$container" >/dev/null; then
                status=1
            fi
        done
        rm -rf "$dir" || status=1
        exit "$status"
        ;;
    run) ;;
    *)
        echo "unknown mode $mode" >&2
        exit 2
        ;;
esac

ref="${3:?ref}"
action="${4:?action}"

# The process id file is taken exclusively (a hard link fails on an existing
# name), complete from its first moment: a second launch exits here.
echo "$$" >"$dir/pid.$$" || exit 1
if ! ln "$dir/pid.$$" "$dir/pid" 2>/dev/null; then
    rm -f "$dir/pid.$$"
    exit 0
fi
rm -f "$dir/pid.$$"
# Older shellcheck releases report this as SC2317, newer ones as SC2329.
# shellcheck disable=SC2317,SC2329 # called by the EXIT trap
write_status() {
    local code=$?
    # Renamed into place, so a status file is always complete and the log before it final.
    echo "$code" >"$dir/status.tmp" && mv "$dir/status.tmp" "$dir/status"
}
trap write_status EXIT
CHECK_CONTAINER_PREFIX="$name"
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
        # The check script itself, against a fake host on this machine; not
        # again inside the runs that test makes.
        if [[ -z "${CHECK_TEST_NESTED:-}" ]]; then
            bash scripts/linux/check-test.sh || status=1
        fi
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
