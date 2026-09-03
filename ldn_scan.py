#!/usr/bin/env python3
"""Isolation test #1 (RECEIVE path): does the dongle's monitor RX + the LDN library's
parse/decrypt work at all? This uses the library's own `ldn.scan` directly — NONE of our
frlgsim beacon/transport code is involved.

Point a REAL LDN host at us and see if we list it:
  - Easiest: on the FRLG console, go to the trade Union/Direct Corner and pick the side that
    WAITS for a partner. In an FRLG trade the waiting console is the RFU parent = the LDN host,
    so it starts advertising a network we should see here.
  - Or any nearby Switch hosting a local-wireless game.

If a network shows up:
  * the dongle's monitor RECEIVE path works, and
  * `application_data`/`local_communication_id`/`scene_id`/`channel`/`version` printed below are the
    AUTHORITATIVE real values to mirror when we host (feed them back into the host side).

    sudo -E ./.venv/bin/python ldn_scan.py                 # auto phy, channels 1,6,11
    sudo -E ./.venv/bin/python ldn_scan.py --channels 1,2,3,4,5,6,7,8,9,10,11
"""
import argparse
import os
import subprocess
import sys

import trio

import ldn
from frlgsim.transport import find_ap_phy, list_phys
from frlgsim.host_support import resolve_keys

STALE_VIFS = ["ldn", "ldn-mon", "ldn-tap"]

ACCEPT = {ldn.ACCEPT_ALL: "ALL", ldn.ACCEPT_NONE: "NONE",
          ldn.ACCEPT_BLACKLIST: "BLACKLIST", ldn.ACCEPT_WHITELIST: "WHITELIST"}


def _cleanup_stale():
    for name in STALE_VIFS:
        subprocess.run(["iw", "dev", name, "del"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--phy", default="auto", help="wifi phy to scan on ('auto' = first AP-capable)")
    ap.add_argument("--keys", default="~/.switch/prod.keys")
    ap.add_argument("--channels", default="1,6,11", help="comma-separated channels to dwell on")
    ap.add_argument("--dwell", type=float, default=0.110, help="seconds per channel")
    args = ap.parse_args()

    if os.geteuid() != 0:
        ap.error("must run as root (monitor mode needs the raw radio); re-run with sudo -E")

    phy = find_ap_phy(log=print) if args.phy == "auto" else args.phy
    if phy is None:
        print(f"[scan] no AP-capable phy found. Present phys: {', '.join(list_phys()) or 'none'}")
        return 1
    keys_path = resolve_keys(args.keys)
    if not os.path.exists(keys_path):
        print(f"[scan] prod.keys not found at {keys_path!r}"); return 2
    channels = [int(c) for c in args.channels.split(",") if c.strip()]

    print(f"[scan] phy={phy} keys={keys_path} channels={channels} dwell={args.dwell}s")
    _cleanup_stale()
    keys = ldn.load_keys(keys_path)

    async def run():
        return await ldn.scan(keys, phyname=phy, channels=channels, dwell_time=args.dwell)

    nets = trio.run(run)
    print(f"\n[scan] found {len(nets)} network(s)")
    for i, n in enumerate(nets):
        print(f"\n--- network {i} ---")
        print(f"  local_communication_id : {n.local_communication_id:016x}")
        print(f"  scene_id               : {n.scene_id}")
        print(f"  version                : {n.version}")
        print(f"  channel                : {n.channel}   band {n.band}")
        print(f"  accept_policy          : {ACCEPT.get(n.accept_policy, n.accept_policy)}")
        print(f"  participants           : {n.num_participants}/{n.max_participants}")
        print(f"  ssid                   : {n.ssid.hex()}")
        print(f"  host address           : {n.address}")
        print(f"  application_data       : ({len(n.application_data)} B)")
        print(f"    {n.application_data.hex()}")
    if not nets:
        print("[scan] nothing seen. Checklist: is a real LDN host actually up right now? Is it on one")
        print("       of the dwell channels above (try --channels 1..11)? Is NetworkManager leaving")
        print("       the radio alone (sudo systemctl stop NetworkManager if unsure)?")
    return 0


if __name__ == "__main__":
    sys.exit(main())
