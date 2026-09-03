"""Regressions for AP TAP-to-802.11 destination handling."""

import os
import sys
from types import SimpleNamespace

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "LDN"))

import ldn
from ldn import wlan
from frlgsim.transport import HostTransport


class _StopTransmit(Exception):
    pass


def _run_immediate(coroutine):
    """Drive a coroutine whose test doubles never actually suspend."""
    try:
        coroutine.send(None)
    except StopIteration as result:
        return result.value
    raise AssertionError("test coroutine unexpectedly suspended")


def test_tap_destination_is_forwarded_to_data_sender():
    target = wlan.MACAddress("3c:a9:ab:f7:3c:06")
    ethernet = wlan.EthernetFrame(
        target=target,
        source=wlan.MACAddress("3c:33:00:60:94:93"),
        protocol=wlan.ETH_P_IP,
        payload=b"ip packet",
    )

    class Tap:
        async def read(self):
            return ethernet.encode()

    seen = []
    network = object.__new__(ldn.APNetwork)
    network._tap = Tap()

    async def send_data_frame(data, destination):
        seen.append((data, destination))
        raise _StopTransmit

    network._send_data_frame = send_data_frame

    async def run():
        try:
            await network._transmit_data_frames()
        except _StopTransmit:
            pass

    _run_immediate(run())

    assert len(seen) == 1
    snap = wlan.SNAPHeader()
    snap.decode(seen[0][0])
    assert snap.protocol == wlan.ETH_P_IP
    assert snap.payload == b"ip packet"
    assert seen[0][1] == target


def test_kernel_encrypted_unicast_keeps_pairwise_destination():
    target = wlan.MACAddress("3c:a9:ab:f7:3c:06")
    sent = []

    class Monitor:
        def address(self):
            return wlan.MACAddress("3c:33:00:60:94:93")

        async def send_frame(self, frame, *, encrypt=False):
            sent.append((frame, encrypt))

    network = object.__new__(ldn.APNetwork)
    network._monitor = Monitor()
    network._key = b"key-present"
    network._param = SimpleNamespace(skip_encryption=True)
    network._data_nonce = 0

    _run_immediate(network._send_data_frame(b"snap packet", target))

    assert len(sent) == 1
    frame, encrypt = sent[0]
    assert frame.target == target
    assert frame.payload == b"snap packet"
    assert encrypt is True


def test_host_transport_removes_participant_on_leave_event():
    logs = []
    host = HostTransport(log=logs.append)
    participant = SimpleNamespace(
        ip_address="169.254.31.2",
        mac_address=bytes.fromhex("3ca9abf73c06"),
        name=b"Chase",
    )
    join = type("JoinEvent", (), {"index": 1, "participant": participant})()
    leave = type("LeaveEvent", (), {"index": 1})()

    host._on_event(join, None)
    assert host.participants == [
        (1, "169.254.31.2", bytes.fromhex("3ca9abf73c06"), b"Chase")
    ]
    host._on_event(leave, None)
    assert host.participants == []
    assert logs[-1] == "[host] console left: idx=1"


if __name__ == "__main__":
    for name, value in sorted(globals().items()):
        if name.startswith("test_") and callable(value):
            value()
    print("LDN host data tests: OK")
