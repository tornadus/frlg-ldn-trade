"""FRLG discovery application data and periodic 802.11 beacon injection."""

import argparse
import socket
import struct
import threading
import time

from . import beacon, transport


# Captured from a native FireRed Direct Corner leader. Unknown record fields are
# intentionally preserved; only documented identity/session fields are changed.
CAPTURED_TRADE_BEACON = bytes.fromhex(
    "005c160058000000000000000000000000000000000101000000050143686173650000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000686c5a68656c76623476354358455a232323232368642323232323232323"
)

RADIOTAP_HEADER = struct.pack("<BBHI", 0, 0, 8, 0)
BROADCAST = b"\xff" * 6
SUPPORTED_RATES = bytes((0x82, 0x84, 0x8B, 0x96, 0x24, 0x30, 0x48, 0x6C))
RSN_PSK_CCMP = bytes.fromhex(
    "0100" "000fac04" "0100" "000fac04" "0100" "000fac02" "0c00")


def parse_mac(value):
    try:
        result = bytes.fromhex(value.replace(":", ""))
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid MAC address: {value}") from exc
    if len(result) != 6:
        raise argparse.ArgumentTypeError(f"invalid MAC address: {value}")
    return result


def read_interface_mac(interface):
    with open(f"/sys/class/net/{interface}/address", encoding="ascii") as stream:
        return parse_mac(stream.read().strip())


def _element(element_id, data):
    if len(data) > 255:
        raise ValueError("information element is too long")
    return bytes((element_id, len(data))) + data


def build_wifi_beacon(bssid, channel, sequence, ssid_length=32, dtim_period=3):
    header = struct.pack(
        "<HH6s6s6sH", 0x0080, 0, BROADCAST, bssid, bssid,
        (sequence & 0xFFF) << 4)
    timestamp = (time.monotonic_ns() // 1_000) & 0xFFFFFFFFFFFFFFFF
    fixed = struct.pack("<QHH", timestamp, 100, 0x0511)
    elements = b"".join((
        _element(0, b"\x00" * ssid_length),
        _element(1, SUPPORTED_RATES),
        _element(3, bytes((channel,))),
        _element(5, bytes((0, dtim_period, 0, 0))),
        _element(48, RSN_PSK_CCMP),
    ))
    return RADIOTAP_HEADER + header + fixed + elements


def build_trade_app_data(profile, host_session_id):
    """Build inactive and active discovery records for one host session."""
    app_data = bytearray(beacon.mutate_beacon(
        CAPTURED_TRADE_BEACON, name=profile.discovery_name,
        trainer_id=profile.discovery_trainer_id))
    pia_name = profile.session_name.encode("utf-8")[:64]
    app_data[0x17:0x1B] = len(pia_name).to_bytes(4, "big")
    app_data[0x1B] = beacon.PIA_NAME_UTF8
    app_data[0x1C:beacon.PIA_HDR] = b"\x00" * 64
    app_data[0x1C:0x1C + len(pia_name)] = pia_name

    record = bytearray(transport._b85_decode(
        app_data[beacon.PIA_HDR:])[:beacon.RECORD_SIZE]).ljust(
            beacon.RECORD_SIZE, b"\x00")
    record[10:12] = bytes(host_session_id)[:2].ljust(2, b"\x00")
    inactive = bytes(app_data[:beacon.PIA_HDR]) + beacon.b85_encode(bytes(record))
    return inactive, activate_trade_app_data(inactive, host_session_id)


def activate_trade_app_data(app_data, host_session_id):
    """Apply only the native post-connect activity and RFU-session changes."""
    app_data = bytearray(app_data)
    active_header = bytearray(app_data[:beacon.PIA_HDR])
    if len(active_header) > 0x16:
        active_header[0x16] = 2
    record = bytearray(transport._b85_decode(
        app_data[beacon.PIA_HDR:])[:beacon.RECORD_SIZE]).ljust(
            beacon.RECORD_SIZE, b"\x00")
    record[10:12] = bytes(host_session_id)[:2].ljust(2, b"\x00")
    record[17] |= 0x80
    return bytes(active_header) + beacon.b85_encode(bytes(record))


class BeaconInjector:
    """Own the userspace beacon thread required by affected Wi-Fi drivers."""

    def __init__(self, monitor="ldn-mon", ap="ldn", channel=1,
                 ssid_length=32, dtim_period=3, log=print):
        self.monitor = monitor
        self.ap = ap
        self.channel = channel
        self.ssid_length = ssid_length
        self.dtim_period = dtim_period
        self.log = log
        self.sent = 0
        self.error = None
        self._stop = threading.Event()
        self._started = threading.Event()
        self._thread = None

    def start(self, timeout=5):
        self._thread = threading.Thread(
            target=self._run, name="ldn-beacon-injector", daemon=True)
        self._thread.start()
        if not self._started.wait(timeout):
            raise RuntimeError("802.11 beacon injector did not start")
        if self.error is not None:
            raise RuntimeError(f"802.11 beacon injector failed: {self.error}")
        return self

    def _run(self):
        tx = None
        try:
            bssid = read_interface_mac(self.ap)
            tx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
            tx.bind((self.monitor, 0))
            self.log(f"[host] injecting periodic 802.11 beacons on {self.monitor}: "
                     f"bssid={bssid.hex(':')} channel={self.channel} interval=100 TU")
            self._started.set()
            sequence = 0
            deadline = time.monotonic()
            while not self._stop.is_set():
                tx.send(build_wifi_beacon(
                    bssid, self.channel, sequence, self.ssid_length, self.dtim_period))
                sequence = (sequence + 1) & 0xFFF
                self.sent += 1
                deadline += 0.1024
                self._stop.wait(max(0.0, deadline - time.monotonic()))
        except BaseException as exc:
            self.error = exc
            self._started.set()
        finally:
            if tx is not None:
                tx.close()

    def stop(self):
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2)
        self.log(f"[host] stopped 802.11 beacon injection after {self.sent} beacon(s)")
