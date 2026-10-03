#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = ["fido2==2.2.1"]
# ///
"""Checks the FIDO HID interface of the application through python-fido2.

    fido_check.py             the Ledger FIDO HID device connected to this host
    fido_check.py --speculos  the application in Speculos started with `--transport U2F
                              --apdu-port 9999`, whose APDU port then carries the FIDO HID
                              reports

Checks: INIT allocates a channel and reports CTAPHID protocol 2 with CBOR and without MSG; PING
echoes 1-byte and 7609-byte payloads (the largest CTAPHID message); getInfo parses with strict
CBOR checks and reports the application AAGUID and a 7609-byte maxMsgSize.

authenticatorSelection (CTAP 2.2 §6.9), a request waiting for the user: while it waits, keepalives
with status UPNEEDED arrive about every 100 ms (§11.2.9.1.7); CTAPHID_CANCEL ends it with
CTAP2_ERR_KEEPALIVE_CANCEL; no answer ends it with CTAP2_ERR_USER_ACTION_TIMEOUT after 30 seconds;
confirming answers CTAP2_OK and refusing CTAP2_ERR_OPERATION_DENIED. In Speculos the script
answers the screen itself through the Speculos API and compares the selection screen with the
snapshot of the model in `--snapshots` (`--golden` writes it instead); on a device it asks the
person at the device to answer.
"""

import argparse
import json
import os
import socket
import struct
import sys
import threading
import time
import urllib.request
from pathlib import Path

from fido2.ctap import CtapError
from fido2.ctap2 import Ctap2
from fido2.hid import CAPABILITY, CtapHidDevice, list_descriptors, open_connection
from fido2.hid.base import CtapHidConnection, HidDescriptor

LEDGER_VENDOR_ID = 0x2C97
# The APDU and API ports scripts/speculos-check.sh gives Speculos.
SPECULOS_APDU_PORT = 9999
SPECULOS_API = "http://127.0.0.1:5000"
AAGUID = bytes.fromhex("8f920f839da2486194d77f3c9945d532")
MAX_MESSAGE = 7609
REPORT = 64
# CTAPHID_KEEPALIVE (§11.2.9.2.1) and its status "user presence needed".
KEEPALIVE = 0x80 | 0x3B
STATUS_UPNEEDED = 2
# §11.2.9.1.7: keepalives SHOULD go at least every 100 ms. The device sends one per OS tick,
# which runs a few milliseconds slow on hardware; the margin covers that and scheduling on the
# host.
KEEPALIVE_GAP_MS = 100
KEEPALIVE_SLACK_MS = 50
# The user action timeout of the application, and how much later the error may arrive.
USER_ACTION_TIMEOUT_S = 30
TIMEOUT_SLACK_S = 5
# The texts of the selection screen.
SELECTION_TITLE = "Allow security key access?"
SELECTION_CONFIRM = "Allow"
SELECTION_REJECT = "Don't allow"


class KeepaliveLog:
    """Arrival times of the keepalive packets a connection reads, with their status."""

    def __init__(self):
        self.lock = threading.Lock()
        self.arrivals: list[tuple[float, int]] = []

    def note(self, packet: bytes) -> None:
        if len(packet) > 7 and packet[4] == KEEPALIVE:
            with self.lock:
                self.arrivals.append((time.monotonic(), packet[7]))

    def clear(self) -> None:
        with self.lock:
            self.arrivals.clear()

    def gaps_ms(self) -> list[float]:
        with self.lock:
            times = [at for at, _ in self.arrivals]
        return [(later - earlier) * 1000 for earlier, later in zip(times, times[1:])]

    def statuses(self) -> set[int]:
        with self.lock:
            return {status for _, status in self.arrivals}


class SpeculosConnection(CtapHidConnection):
    """FIDO HID reports through the Speculos APDU socket: each report travels with a 4-byte
    big-endian length; Speculos announces 2 bytes less than it sends."""

    def __init__(self, keepalives: KeepaliveLog):
        self.keepalives = keepalives
        self.sock = socket.create_connection(("127.0.0.1", SPECULOS_APDU_PORT))
        # Longer than the user action timeout, so the timeout error itself can arrive.
        self.sock.settimeout(USER_ACTION_TIMEOUT_S + 2 * TIMEOUT_SLACK_S)

    def _read(self, size: int) -> bytes:
        data = b""
        while len(data) < size:
            chunk = self.sock.recv(size - len(data))
            if not chunk:
                raise ConnectionError("Speculos closed the connection")
            data += chunk
        return data

    def write_packet(self, data: bytes) -> None:
        self.sock.sendall(struct.pack(">I", len(data)) + bytes(data))

    def read_packet(self) -> bytes:
        size = struct.unpack(">I", self._read(4))[0] + 2
        packet = self._read(size)
        if len(packet) != REPORT:
            raise ConnectionError(f"a {len(packet)}-byte report instead of {REPORT}")
        self.keepalives.note(packet)
        return packet

    def close(self) -> None:
        self.sock.close()


class LoggedConnection(CtapHidConnection):
    """A device connection that notes the keepalives it reads."""

    def __init__(self, inner: CtapHidConnection, keepalives: KeepaliveLog):
        self.inner = inner
        self.keepalives = keepalives

    def write_packet(self, data: bytes) -> None:
        self.inner.write_packet(data)

    def read_packet(self) -> bytes:
        packet = self.inner.read_packet()
        self.keepalives.note(packet)
        return packet

    def close(self) -> None:
        self.inner.close()


def connect(speculos: bool, keepalives: KeepaliveLog) -> CtapHidDevice:
    if speculos:
        descriptor = HidDescriptor("speculos", 0, 0, REPORT, REPORT, "Speculos", None)
        return CtapHidDevice(descriptor, SpeculosConnection(keepalives))
    ledgers = [d for d in list_descriptors() if d.vid == LEDGER_VENDOR_ID]
    if len(ledgers) != 1:
        raise SystemExit(f"expected one Ledger FIDO HID device, found {len(ledgers)}")
    descriptor = ledgers[0]
    print(f"enumerated {descriptor.product_name} ({descriptor.vid:04x}:{descriptor.pid:04x})")
    return CtapHidDevice(descriptor, LoggedConnection(open_connection(descriptor), keepalives))


def api(path: str, body: dict | None = None) -> bytes:
    """A request to the Speculos API: GET without a body, POST with one."""
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(
        SPECULOS_API + path, data=data, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        return response.read()


def screen_texts() -> list[dict]:
    return json.loads(api("/events?currentscreenonly=true"))["events"]


def screen_shows(text: str) -> bool:
    joined = " ".join(event["text"] for event in screen_texts())
    return text in " ".join(joined.split())


def button(text: str) -> dict | None:
    """The text element of the current screen that reads exactly `text`: a button label, not a
    title that happens to contain the same word."""
    for event in screen_texts():
        if event["text"].strip() == text:
            return event
    return None


def wait_for_screen(text: str) -> None:
    for _ in range(100):
        if screen_shows(text):
            return
        time.sleep(0.1)
    raise SystemExit(f"FAILED: the screen never showed {text!r}: {screen_texts()}")


class SpeculosUser:
    """Answers the selection screen through the Speculos API, as the person would."""

    def __init__(self, model: str):
        self.nano = model in ("nanosp", "nanox")

    def answer(self, confirm: bool) -> None:
        wanted = SELECTION_CONFIRM if confirm else SELECTION_REJECT
        if self.nano:
            # The choice steps through its pages with the right button and takes the shown
            # one with both buttons.
            for _ in range(6):
                if button(wanted) is not None:
                    api("/button/both", {"action": "press-and-release"})
                    return
                api("/button/right", {"action": "press-and-release"})
                time.sleep(0.2)
            raise SystemExit(f"FAILED: no page offers {wanted!r}")
        event = button(wanted)
        if event is None:
            raise SystemExit(f"FAILED: no button reads {wanted!r}: {screen_texts()}")
        api("/finger", {"action": "press-and-release", "x": event["x"], "y": event["y"]})


class PersonAtDevice:
    """Asks the person at the device to answer the selection screen."""

    def answer(self, confirm: bool) -> None:
        wanted = SELECTION_CONFIRM if confirm else SELECTION_REJECT
        print(f"   on the device, choose {wanted!r}", flush=True)


def selection(ctap: Ctap2, cancel: threading.Event | None = None) -> int:
    """Runs authenticatorSelection and returns its CTAP status."""
    try:
        ctap.selection(event=cancel)
        return CtapError.ERR.SUCCESS
    except CtapError as error:
        return error.code


def check_selection(device: CtapHidDevice, keepalives: KeepaliveLog, user, snapshot) -> None:
    ctap = Ctap2(device)

    # Cancel: the host gives up after a second of keepalives.
    keepalives.clear()
    cancel = threading.Event()
    threading.Timer(1.0, cancel.set).start()
    status = selection(ctap, cancel)
    check(status == CtapError.ERR.KEEPALIVE_CANCEL, f"selection: CANCEL ends it ({status!r})")
    gaps = keepalives.gaps_ms()
    check(
        len(gaps) >= 5 and max(gaps) <= KEEPALIVE_GAP_MS + KEEPALIVE_SLACK_MS,
        f"selection: keepalives every {max(gaps, default=0):.0f} ms at most over {len(gaps)} gaps",
    )
    check(
        keepalives.statuses() == {STATUS_UPNEEDED},
        f"selection: keepalive status {sorted(keepalives.statuses())} is UPNEEDED",
    )

    # Confirm and refuse; the screen is compared with its snapshot while it waits.
    for confirm, expected in ((True, CtapError.ERR.SUCCESS), (False, CtapError.ERR.OPERATION_DENIED)):

        def answer(confirm: bool = confirm) -> None:
            if snapshot is not None and confirm:
                snapshot()
            user.answer(confirm)

        timer = threading.Timer(1.0, answer)
        timer.start()
        status = selection(ctap)
        timer.join()
        check(status == expected, f"selection: {'confirm' if confirm else 'refuse'} answers {status!r}")

    # No answer.
    started = time.monotonic()
    status = selection(ctap)
    waited = time.monotonic() - started
    check(
        status == CtapError.ERR.USER_ACTION_TIMEOUT
        and USER_ACTION_TIMEOUT_S <= waited <= USER_ACTION_TIMEOUT_S + TIMEOUT_SLACK_S,
        f"selection: no answer times out after {waited:.1f} s ({status!r})",
    )


def check(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"FAILED: {message}")
    print(f"ok: {message}")


def snapshot_check(model: str, directory: Path, golden: bool):
    """Compares the shown selection screen with the model's snapshot, or writes it with
    `golden`."""
    path = directory / model / "selection.png"

    def compare() -> None:
        wait_for_screen(SELECTION_TITLE)
        shot = api("/screenshot")
        if golden:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(shot)
            print(f"ok: selection screen written to {path}")
            return
        check(path.is_file() and path.read_bytes() == shot, f"selection screen matches {path}")

    return compare


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--speculos", action="store_true")
    parser.add_argument("--model", help="Speculos model, for the screen and the snapshot")
    parser.add_argument("--snapshots", type=Path, help="directory of the screen snapshots")
    parser.add_argument("--golden", action="store_true", help="write the snapshots instead")
    args = parser.parse_args()

    keepalives = KeepaliveLog()
    device = connect(args.speculos, keepalives)
    check(device.version == 2, f"INIT: channel {device._channel_id:#x}, CTAPHID protocol 2")
    capabilities = CAPABILITY(device.capabilities)
    check(
        CAPABILITY.CBOR in capabilities and CAPABILITY.NMSG in capabilities,
        f"INIT: capabilities {capabilities!r} (CBOR, no MSG)",
    )
    for length in (1, MAX_MESSAGE):
        payload = os.urandom(length)
        check(device.ping(payload) == payload, f"PING echoes {length} bytes")

    info = Ctap2(device).info
    check(bytes(info.aaguid) == AAGUID, f"getInfo: AAGUID {bytes(info.aaguid).hex()}")
    check(info.max_msg_size == MAX_MESSAGE, f"getInfo: maxMsgSize {info.max_msg_size}")

    if args.speculos:
        if args.model is None:
            raise SystemExit("--speculos needs --model for the screen")
        user = SpeculosUser(args.model)
        snapshot = (
            snapshot_check(args.model, args.snapshots, args.golden)
            if args.snapshots is not None
            else None
        )
    else:
        user = PersonAtDevice()
        snapshot = None
    check_selection(device, keepalives, user, snapshot)
    device.close()


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"FAILED: {error!r}", file=sys.stderr)
        sys.exit(1)
