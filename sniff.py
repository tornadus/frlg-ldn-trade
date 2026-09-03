#!/usr/bin/env python3
"""LDN advertisement sniffer - air-side ground truth on a second radio (the MT7601U is perfect for
this: monitor mode is the one relevant thing its driver supports).

Puts an adapter in monitor mode on a fixed channel and prints every LDN advertisement action frame
(vendor-specific, Nintendo OUI: payload starts `7f 00 22 aa 04 00 01 01`), with source MAC, length,
rate, and a hexdump on first sight / change. Optionally archives ALL captured frames to a pcap
(radiotap linktype) for Wireshark.

Two uses (debug runbook, MYSTERY_GIFT_DISTRIBUTOR.md):
  1. While frlgtrade_host.py hosts on ANOTHER adapter: verify our advertisements are actually on air at
     ~10/s. Silence here = monitor-TX/injection problem, even if the spike printed "AP up".
  2. Against a REAL console hosting (e.g. the trade Direct Corner, or another Switch sharing a
     Wonder Card): capture a genuine advertisement. (NOTE: the LDN advertisement body is encrypted -
     the application_data/beacon inside is NOT directly readable here. For a decrypted beacon use
     the join path's `_dump_beacon`; the sniffer's value is presence/cadence/source, and the pcap.)

    sudo ./.venv/bin/python sniff.py --phy phy0 --channel 6 --pcap air.pcap

Ctrl-C to stop (tears down the monitor vif).
"""

import argparse
import os
import socket
import struct
import subprocess
import sys
import time

LDN_ACTION_HDR = bytes([0x7F, 0x00, 0x22, 0xAA, 0x04, 0x00, 0x01, 0x01])
ETH_P_ALL = 0x0003

MGMT_SUBTYPES = {0: "assoc-req", 1: "assoc-resp", 4: "probe-req", 5: "probe-resp",
                 8: "beacon", 10: "disassoc", 11: "auth", 12: "deauth", 13: "action"}


def sh(cmd):
    subprocess.run(cmd, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def setup_monitor(phy, ifname, channel):
    sh(["iw", "dev", ifname, "del"])
    subprocess.run(["iw", "phy", phy, "interface", "add", ifname, "type", "monitor"], check=True)
    sh(["ip", "link", "set", ifname, "up"])
    subprocess.run(["iw", "dev", ifname, "set", "channel", str(channel)], check=True)


def teardown(ifname):
    sh(["iw", "dev", ifname, "del"])


class PcapWriter:
    """Minimal pcap (not pcapng) writer, linktype 127 = LINKTYPE_IEEE802_11_RADIOTAP."""

    def __init__(self, path):
        self.f = open(path, "wb")
        self.f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 127))

    def write(self, frame):
        ts = time.time()
        sec, usec = int(ts), int((ts % 1) * 1_000_000)
        self.f.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)) + frame)

    def close(self):
        self.f.close()


def parse_frame(frame):
    """radiotap + 802.11 mgmt parse -> (subtype_name, src_mac, action_payload|None)."""
    if len(frame) < 4:
        return None
    rt_len = int.from_bytes(frame[2:4], "little")
    dot11 = frame[rt_len:]
    if len(dot11) < 24:
        return None
    fc = int.from_bytes(dot11[0:2], "little")
    ftype, subtype = (fc >> 2) & 0x3, (fc >> 4) & 0xF
    if ftype != 0:                                  # management frames only
        return None
    src = dot11[10:16]
    payload = dot11[24:] if subtype == 13 else None  # action frame body
    return MGMT_SUBTYPES.get(subtype, f"mgmt-{subtype}"), src, payload


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--phy", default="phy0", help="phy to sniff on (default phy0 = the MT7601U)")
    ap.add_argument("--ifname", default="ldn-sniff", help="monitor vif name to create")
    ap.add_argument("--channel", type=int, default=6, help="channel to park on (host's channel; "
                    "the ldn lib picks from 1/6/11 - pin the host with --channel to match)")
    ap.add_argument("--pcap", default="", help="also archive every captured frame to this pcap")
    ap.add_argument("--mgmt", action="store_true",
                    help="also print per-second counts of ALL mgmt frames (probe reqs = the console "
                    "is scanning; assoc/auth = it is trying to join)")
    args = ap.parse_args()

    if os.geteuid() != 0:
        ap.error("must run as root (monitor mode); re-run with sudo")

    setup_monitor(args.phy, args.ifname, args.channel)
    print(f"[sniff] monitoring {args.phy} ({args.ifname}) on channel {args.channel}; "
          f"filtering LDN advertisements ({LDN_ACTION_HDR.hex()})")
    pcap = PcapWriter(args.pcap) if args.pcap else None

    rx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    rx.bind((args.ifname, 0))
    rx.settimeout(1.0)

    seen = {}                       # src_mac -> (count, last_body) for LDN adverts
    mgmt_counts = {}
    last_report = time.time()
    try:
        while True:
            try:
                frame = rx.recv(65535)
            except socket.timeout:
                frame = None
            if frame:
                if pcap:
                    pcap.write(frame)
                parsed = parse_frame(frame)
                if parsed:
                    subtype, src, payload = parsed
                    mgmt_counts[subtype] = mgmt_counts.get(subtype, 0) + 1
                    if payload and payload.startswith(LDN_ACTION_HDR):
                        mac = ":".join(f"{b:02x}" for b in src)
                        count, last = seen.get(mac, (0, None))
                        if last != payload:
                            print(f"[sniff] LDN advert from {mac} ({len(payload)}B)"
                                  f"{' NEW/CHANGED' if last is not None else ''}:")
                            print(f"        {payload.hex()}")
                        seen[mac] = (count + 1, payload)
            now = time.time()
            if now - last_report >= 5:
                for mac, (count, _b) in seen.items():
                    print(f"[sniff] {mac}: {count} LDN adverts total")
                if args.mgmt and mgmt_counts:
                    print(f"[sniff] mgmt frames seen: {mgmt_counts}")
                last_report = now
    except KeyboardInterrupt:
        print("\n[sniff] stopping...")
    finally:
        rx.close()
        if pcap:
            pcap.close()
            print(f"[sniff] pcap written: {args.pcap}")
        teardown(args.ifname)
        print(f"[sniff] totals: {mgmt_counts}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
