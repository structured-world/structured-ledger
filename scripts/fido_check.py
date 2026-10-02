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
"""

import argparse
import os
import socket
import struct
import sys

from fido2.ctap2 import Ctap2
from fido2.hid import CAPABILITY, CtapHidDevice, list_descriptors, open_connection
from fido2.hid.base import CtapHidConnection, HidDescriptor

LEDGER_VENDOR_ID = 0x2C97
# The APDU port scripts/speculos-check.sh gives Speculos.
SPECULOS_APDU_PORT = 9999
AAGUID = bytes.fromhex("8f920f839da2486194d77f3c9945d532")
MAX_MESSAGE = 7609
REPORT = 64


class SpeculosConnection(CtapHidConnection):
    """FIDO HID reports through the Speculos APDU socket: each report travels with a 4-byte
    big-endian length; Speculos announces 2 bytes less than it sends."""

    def __init__(self):
        self.sock = socket.create_connection(("127.0.0.1", SPECULOS_APDU_PORT))
        self.sock.settimeout(10)

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
        return packet

    def close(self) -> None:
        self.sock.close()


def connect(speculos: bool) -> CtapHidDevice:
    if speculos:
        descriptor = HidDescriptor("speculos", 0, 0, REPORT, REPORT, "Speculos", None)
        return CtapHidDevice(descriptor, SpeculosConnection())
    ledgers = [d for d in list_descriptors() if d.vid == LEDGER_VENDOR_ID]
    if len(ledgers) != 1:
        raise SystemExit(f"expected one Ledger FIDO HID device, found {len(ledgers)}")
    descriptor = ledgers[0]
    print(f"enumerated {descriptor.product_name} ({descriptor.vid:04x}:{descriptor.pid:04x})")
    return CtapHidDevice(descriptor, open_connection(descriptor))


def check(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"FAILED: {message}")
    print(f"ok: {message}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--speculos", action="store_true")
    args = parser.parse_args()

    device = connect(args.speculos)
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
    device.close()


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"FAILED: {error!r}", file=sys.stderr)
        sys.exit(1)
