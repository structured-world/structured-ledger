#!/usr/bin/env bash
# Runs every device build of the application in Speculos, inside Ledger's
# dev-tools image, and checks that it answers the Ledger HID channel and shows
# its home screen:
#   - BOLOS GET_APP_NAME_AND_VERSION (B0 01) answers the app name and 9000,
#   - an instruction the app does not implement (E0 01) answers exactly 6D00,
#   - the current screen shows the app name.
# Expects the artifacts of scripts/device-build.sh in app/target/<target>/release/.
# Linux only: the image is a Linux container.
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
image=$("$root/scripts/dev-tools-image.sh")

docker pull --quiet "$image" >/dev/null
docker run --rm \
    --volume "$root:/app" \
    --workdir /app \
    "$image" bash -c '
        name="Structured Passkeys"
        name_hex=$(printf "%s" "$name" | od -An -tx1 | tr -d " \n")
        # Sends one APDU (hex) and prints the response with its status word; every
        # request has a deadline so an app that never answers fails the check.
        apdu() {
            curl -sf --max-time 10 -X POST -H "Content-Type: application/json" \
                -d "{\"data\":\"$1\"}" http://127.0.0.1:5000/apdu | jq -r ".data // \"\""
        }
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
                if curl -sf --max-time 5 http://127.0.0.1:5000/events >/dev/null; then
                    ready=1
                    break
                fi
                # Speculos exited during startup: no point waiting out the loop.
                if ! kill -0 "$pid" 2>/dev/null; then
                    break
                fi
                sleep 1
            done
            if [[ $ready -eq 0 ]]; then
                echo "speculos did not start"
                cat "/tmp/speculos-$target.log"
                status=1
            else
                data=$(apdu b001000000)
                if [[ "$data" == *"$name_hex"* && "$data" == *9000 ]]; then
                    echo "B0 01: $data"
                else
                    echo "B0 01 failed: \"$data\""
                    status=1
                fi
                # An instruction the app does not implement: ISO/IEC 7816-4 5.6, SW 6D00.
                data=$(apdu e001000000)
                if [[ "$data" == 6d00 ]]; then
                    echo "E0 01: $data"
                else
                    echo "E0 01 failed, expected 6d00: \"$data\""
                    status=1
                fi
                screen=$(curl -sf --max-time 10 "http://127.0.0.1:5000/events?currentscreenonly=true" || true)
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
