#!/usr/bin/env bash
# Runs every device build of the application in Speculos, inside Ledger's
# dev-tools image, and checks that it answers the Ledger HID channel and shows
# its home screen:
#   - BOLOS GET_APP_NAME_AND_VERSION (B0 01) answers the app name and 9000,
#   - the current screen shows the app name.
# Expects the artifacts of scripts/device-build.sh in app/target/<target>/release/.
# Linux only: the image is a Linux container.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
image=ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest

docker pull --quiet "$image" >/dev/null
docker run --rm \
    --volume "$root:/app" \
    --workdir /app \
    "$image" bash -c '
        name="Structured Passkeys"
        name_hex=$(printf "%s" "$name" | od -An -tx1 | tr -d " \n")
        status=0
        for target in nanosplus nanox stax flex apex_p; do
            case "$target" in
                nanosplus) model=nanosp ;;
                *) model="$target" ;;
            esac
            elf="app/target/$target/release/structured-passkeys-app"
            echo "== speculos $target"
            if [[ ! -f "$elf" ]]; then
                echo "missing $elf"
                status=1
                continue
            fi
            speculos --model "$model" --display headless --api-port 5000 --apdu-port 9999 "$elf" \
                >"/tmp/speculos-$target.log" 2>&1 &
            pid=$!
            ready=0
            for _ in $(seq 1 60); do
                if curl -sf http://127.0.0.1:5000/events >/dev/null; then
                    ready=1
                    break
                fi
                sleep 1
            done
            if [[ $ready -eq 0 ]]; then
                echo "speculos did not start"
                cat "/tmp/speculos-$target.log"
                status=1
            else
                reply=$(curl -sf -X POST -H "Content-Type: application/json" \
                    -d "{\"data\":\"b001000000\"}" http://127.0.0.1:5000/apdu || true)
                data=$(printf "%s" "$reply" | jq -r ".data // \"\"")
                if [[ "$data" == *"$name_hex"* && "$data" == *9000 ]]; then
                    echo "B0 01: $data"
                else
                    echo "B0 01 failed: $reply"
                    status=1
                fi
                screen=$(curl -sf "http://127.0.0.1:5000/events?currentscreenonly=true" || true)
                # Nano screens split the name over lines, keeping a trailing space.
                if printf "%s" "$screen" | jq -e --arg n "$name" "[.events[].text] | join(\" \") | gsub(\"\\\\s+\"; \" \") | contains(\$n)" >/dev/null; then
                    echo "home screen shows \"$name\""
                else
                    echo "home screen check failed: $screen"
                    status=1
                fi
            fi
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
        done
        exit "$status"
    '
