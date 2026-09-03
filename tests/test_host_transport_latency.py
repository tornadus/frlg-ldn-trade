"""Offline checks for the host's latency-sensitive receive wait."""

import os
import sys
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from frlgsim import transport


def _host_with_rx(rx):
    host = object.__new__(transport.HostTransport)
    host._rx = rx
    host._stop = mock.Mock()
    return host


def test_wait_readable_wakes_on_tap_packet():
    rx = object()
    host = _host_with_rx(rx)
    with mock.patch.object(transport.select, "select", return_value=([rx], [], [])) as select:
        assert host.wait_readable(0.05) is True
    select.assert_called_once_with([rx], [], [], 0.05)


def test_wait_readable_timeout_and_negative_clamp():
    host = _host_with_rx(object())
    with mock.patch.object(transport.select, "select", return_value=([], [], [])) as select:
        assert host.wait_readable(-1) is False
    assert select.call_args.args[3] == 0.0


def test_host_udp_tx_is_pinned_to_ldn_tap():
    tx = mock.Mock()
    rx = mock.Mock()
    host = object.__new__(transport.HostTransport)
    host.iface = "ldn-tap"
    with mock.patch.object(transport.socket, "socket", side_effect=[tx, rx]):
        host._setup_sockets()
    tx.setsockopt.assert_any_call(
        transport.socket.SOL_SOCKET, transport.socket.SO_BINDTODEVICE, b"ldn-tap\x00")
    tx.bind.assert_called_once_with(("0.0.0.0", transport.PIA_PORT))
    rx.bind.assert_called_once_with(("ldn-tap", 0))


if __name__ == "__main__":
    for name, value in sorted(globals().items()):
        if name.startswith("test_") and callable(value):
            value()
    print("host transport latency tests: OK")
