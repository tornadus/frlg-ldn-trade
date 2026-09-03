#!/usr/bin/env bash
# Collect a shareable debug report for the LDN hosting failure (ENOTSUP at create_ap) -
# everything the LDN library author would ask for, in one file, with ZERO frlg-ldn-trade
# code involved (the repro is the library's own LDN/examples/host.py).
#
#   sudo ./ldn_debug_report.sh [phy]        (default phy0; writes ldn-debug-report.txt)
#
# Sections:
#   1. kernel/distro + adapter (usb id, driver)     - the environment
#   2. full `iw phy` info + `iw dev` + `iw reg`     - what the driver declares to nl80211
#   3. plain-iw AP vif creation                     - the failure, reproduced with no Python at all
#   4. plain-iw MONITOR vif creation (control)      - proves the command form/permissions are fine
#   5. upstream LDN/examples/host.py                - the library author's own hosting example
set -u

PHY="${1:-phy0}"
OUT="ldn-debug-report.txt"
USER_HOME=$(eval echo "~${SUDO_USER:-$USER}")

if [ "$(id -u)" -ne 0 ]; then
    echo "Run with sudo (vif-creation experiments need root): sudo $0 $PHY" >&2
    exit 1
fi

exec > >(tee "$OUT") 2>&1

section() { echo; echo "========== $1 =========="; }

section "date / kernel / distro"
date -Is
uname -a
. /etc/os-release 2>/dev/null && echo "distro: ${PRETTY_NAME:-?}"

section "adapter: USB id + kernel driver"
lsusb | grep -iE "wireless|wlan|802|ralink|mediatek|realtek|atheros" || lsusb
DRVPATH=$(readlink -f "/sys/class/ieee80211/$PHY/device/driver" 2>/dev/null || true)
echo "driver path: ${DRVPATH:-not found}"
DRV=$(basename "${DRVPATH:-}")
[ -n "$DRV" ] && modinfo "$DRV" 2>/dev/null | grep -E "^filename|^description|^version"

section "iw phy $PHY info (FULL - what the driver registers with nl80211)"
iw phy "$PHY" info

section "iw dev / iw reg get"
iw dev
iw reg get

section "ldn package version + reference-repo commit"
./.venv/bin/pip show ldn 2>/dev/null | sed -n '1,2p'
git -C LDN log -1 --format="LDN repo @ %h %ad %s" --date=short 2>/dev/null

section "EXPERIMENT 1: plain iw creates an AP vif (no Python, no ldn library)"
echo "+ iw phy $PHY interface add ldn-ap-test type __ap"
if iw phy "$PHY" interface add ldn-ap-test type __ap; then
    echo "UNEXPECTED SUCCESS - AP vif created; cleaning up"
    iw dev ldn-ap-test del
fi

section "EXPERIMENT 2 (control): plain iw creates a MONITOR vif"
echo "+ iw phy $PHY interface add ldn-mon-test type monitor"
if iw phy "$PHY" interface add ldn-mon-test type monitor; then
    echo "monitor vif created OK (control passes - only the AP type is rejected)"
    iw dev ldn-mon-test del
fi

section "EXPERIMENT 3: upstream LDN/examples/host.py (the library's own hosting example)"
echo "+ HOME=$USER_HOME timeout 30 ./.venv/bin/python LDN/examples/host.py"
HOME="$USER_HOME" timeout 30 ./.venv/bin/python LDN/examples/host.py
echo "(exit code: $?)"

echo
echo "Report written to $OUT"
