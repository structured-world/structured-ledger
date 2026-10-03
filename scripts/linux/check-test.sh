#!/usr/bin/env bash
# Tests scripts/linux/check.sh against a fake check host on this machine: an
# `ssh` that runs each command locally and drops chosen connections, and a
# `docker` whose build writes the artifacts after a delay. Linux only, like the
# check host itself (setsid, /proc).
#
#   scripts/linux/check-test.sh
#
# Cases:
#   - connections dropped before and after their command ran, the start of the
#     run among them: the run completes once, its artifacts come back and the
#     host is left clean;
#   - a run that dies without writing its status: the check fails instead of
#     polling forever, and the host is left clean;
#   - a stopped check (SIGTERM; a background job of this script ignores
#     SIGINT): the remote run and its directory are gone.
set -euo pipefail

root=$(git rev-parse --show-toplevel)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir "$tmp/bin"

# ssh [options] <destination> <command>: runs the command here. The calls whose
# numbers FAKE_SSH_DROPS lists ("3b,5a": call 3 drops before its command runs,
# call 5 after) end with 255, as ssh does on a lost connection.
cat >"$tmp/bin/ssh" <<'EOF'
#!/usr/bin/env bash
command="${!#}"
count_file="$FAKE_HOST_STATE/ssh-calls"
call=$(( $(cat "$count_file" 2>/dev/null || echo 0) + 1 ))
echo "$call" >"$count_file"
for drop in ${FAKE_SSH_DROPS//,/ }; do
    if [[ "$drop" == "${call}b" ]]; then
        exit 255
    fi
    if [[ "$drop" == "${call}a" ]]; then
        bash -c "$command" >/dev/null 2>&1 || true
        exit 255
    fi
done
exec bash -c "$command"
EOF

# docker pull|run|ps|rm: `run` writes every target's artifacts into the mounted
# checkout after FAKE_DOCKER_SECONDS; `ps` knows no containers.
cat >"$tmp/bin/docker" <<'EOF'
#!/usr/bin/env bash
case "$1" in
    run)
        shift
        app=""
        while [[ $# -gt 0 ]]; do
            if [[ "$1" == --volume ]]; then
                app="${2%%:*}"
                shift
            fi
            shift
        done
        echo "fake container"
        sleep "${FAKE_DOCKER_SECONDS:-0}"
        for target in nanosplus nanox stax flex apex_p; do
            release="$app/app/target/$target/release"
            mkdir -p "$release"
            for file in structured-passkeys-app structured-passkeys-app.hex structured-passkeys-app.apdu structured-passkeys-app.sha256; do
                echo "$target" >"$release/$file"
            done
        done
        ;;
    pull | rm) ;;
    ps) ;;
    *) exit 1 ;;
esac
EOF
chmod +x "$tmp/bin/ssh" "$tmp/bin/docker"
export PATH="$tmp/bin:$PATH"
export STRUCTURED_PASSKEYS_LINUX=fake-host
# The fake host is this machine, so its runs see this: they skip this test.
export CHECK_TEST_NESTED=1
# A connection that stays down ends the check quickly here.
export CHECK_RECONNECT_SECONDS=20

failures=0
fail() {
    echo "FAIL: $*" >&2
    failures=$((failures + 1))
}

# Starts one check in the background with fresh fake host state; sets `check`
# (its process id) and `out` (its output file).
start_check() {
    local name=$1
    export FAKE_HOST_STATE="$tmp/$name"
    mkdir -p "$FAKE_HOST_STATE"
    out="$tmp/$name.out"
    (cd "$root" && exec scripts/linux/check.sh device) >"$out" 2>&1 &
    check=$!
}

# The remote directory the check reported, once it did.
run_dir() {
    sed -n 's/^remote run in fake-host://p' "$out"
}

# Waits up to $1 seconds for the command after it to succeed.
wait_for() {
    local deadline=$((SECONDS + $1))
    shift
    until "$@"; do
        if ((SECONDS >= deadline)); then
            return 1
        fi
        sleep 0.2
    done
}

# The run reported its directory and took its process id file there.
run_started() {
    local dir
    dir=$(run_dir)
    [[ -n "$dir" && -f "$dir/pid" ]]
}

# The check process has ended.
check_ended() {
    ! kill -0 "$check" 2>/dev/null
}

# The process group $1 has no process left.
group_gone() {
    ! kill -0 -- "-$1" 2>/dev/null
}

# Dropped connections: the snapshot upload, the start (after it ran), and polls.
FAKE_SSH_DROPS="2b,4a,6b,7a,9b" FAKE_DOCKER_SECONDS=3 start_check drops
if wait "$check"; then
    dir=$(run_dir)
    [[ $(grep -c '^== PASSED' "$out") -eq 1 ]] || fail "drops: the run did not complete exactly once"
    [[ -f "$root/target/device/apex_p/release/structured-passkeys-app" ]] || fail "drops: no artifacts"
    [[ -n "$dir" && ! -e "$dir" ]] || fail "drops: $dir left on the host"
else
    fail "drops: the check failed"
    cat "$out" >&2
fi

# A run killed before it writes its status.
FAKE_SSH_DROPS="" FAKE_DOCKER_SECONDS=30 start_check lost
if wait_for 30 run_started; then
    dir=$(run_dir)
    kill -KILL -- "-$(cat "$dir/pid")"
    if wait_for 40 check_ended; then
        wait "$check" && fail "lost: the check passed"
        [[ ! -e "$dir" ]] || fail "lost: $dir left on the host"
    else
        fail "lost: the check kept polling a dead run"
        kill -TERM "$check"
        wait "$check" || true
    fi
else
    fail "lost: the run did not start"
    kill -TERM "$check" 2>/dev/null || true
    wait "$check" || true
fi

# A stopped check.
FAKE_SSH_DROPS="" FAKE_DOCKER_SECONDS=30 start_check stopped
if wait_for 30 run_started; then
    dir=$(run_dir)
    group=$(cat "$dir/pid")
    kill -TERM "$check"
    wait "$check" && fail "stopped: the check passed"
    [[ ! -e "$dir" ]] || fail "stopped: $dir left on the host"
    wait_for 10 group_gone "$group" || fail "stopped: the remote run is still alive"
else
    fail "stopped: the run did not start"
    kill -TERM "$check" 2>/dev/null || true
    wait "$check" || true
fi

if [[ $failures -ne 0 ]]; then
    echo "$failures check-test failures" >&2
    exit 1
fi
echo "check-test: all cases pass"
