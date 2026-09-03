"""Byte-exact regressions for the Pia 6.39 leader Session acceptance."""

import os
import sys
from types import SimpleNamespace

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from frlgsim import beacon, pia_connect, transport
from frlgsim import crypto as cryptomod
from frlgsim.host_beacon import (CAPTURED_TRADE_BEACON,
                                 activate_trade_app_data,
                                 build_trade_app_data)
from frlgsim.host_pia import (PiaNonceSequence, build_host_rtt,
                              build_messages, build_net_probe,
                              build_net_property_update,
                              build_session_acceptance, decode_datagram,
                              reliable_output_batches)
from frlgsim.config import TrainerProfile
from frlgsim.reliable import ReliableEmission, FLAGSA_CTRL, FLAGSA_GBA


JOIN = bytes.fromhex(
    "00060100030505010a030d070f00005838a074cc3c33006094930000c4930000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "ab3c06f7a93c000000c6010100a9fe580230390000000000000001000000000000"
    "00000000000301454d55")

UPDATE = bytes.fromhex(
    "05000001000003ab3c06f7a93c000000c602000001000000000000ab3c06f7a9"
    "3c000000c6a9fe5801303900000000000000000000000000000000000000000000"
    "000000000000000000000000000000010100001002a2c791dcd379c1c7ef629871"
    "079a000000050143686173653c33006094930000c493a9fe580230390100010000"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "01010000000000000000000100000000000000000000000301454d55")

RESPONSE = bytes.fromhex(
    "020d070100000000d067a5b2ab3c06f7a93c000000c63c33006094930000c493"
    "0100010000")

NATIVE_NET_PROPERTY = bytes.fromhex(
    "0150007a00000001000000001e1d14d900020006000000000000570f01010000005c"
    "0000001e005c16005800000000000000000000000000000000010200000005014368"
    "61736500000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000686c5a68656c"
    "76623476784c435e7123232323233d3c2823232323232323")


def test_parse_native_session_join():
    join = pia_connect.parse_session_join(JOIN)
    assert join is not None
    assert join["source_constant_id"] == bytes.fromhex("3c33006094930000")
    assert join["source_var"] == 0xC493
    assert join["destination_constant_id"] == bytes.fromhex("ab3c06f7a93c0000")
    assert join["destination_var"] == 0x00C6
    assert join["ip"] == "169.254.88.2" and join["port"] == 12345
    assert join["players"][0]["name"] == b"EMU"


def test_session_update_matches_native_leader():
    join = pia_connect.parse_session_join(JOIN)
    actual = pia_connect.build_session_update(
        join, bytes.fromhex("ab3c06f7a93c0000"), 0x00C6, "169.254.88.1", "Chase",
        host_player_id=bytes.fromhex("1002a2c791dcd379c1c7ef629871079a"))
    assert actual == UPDATE


def test_session_join_response_matches_native_leader():
    join = pia_connect.parse_session_join(JOIN)
    actual = pia_connect.build_session_join_response(
        join, bytes.fromhex("ab3c06f7a93c0000"), 0x00C6, bytes.fromhex("d067a5b2"))
    assert actual == RESPONSE


def test_native_host_nonce_allocation_matches_fire_red_order():
    """Net N, response N+1, update N+2; update is returned for transmission first."""
    host = SimpleNamespace(
        ssid=bytes.fromhex("5c42961f018902911a2f1c9548c8e9c4"),
        our_ip="169.254.88.1",
        our_mac=bytes.fromhex("3ca9abf73c06"),
        participants=[(1, "169.254.88.2", bytes.fromhex("3c3300609493"), "EMU")],
        max_participants=6,
    )
    initial = int.from_bytes(bytes.fromhex("04c5a33f290b14e2"), "big")
    nonces = PiaNonceSequence(native=True, initial=initial)
    net = build_net_probe(host, nonce_source=nonces)
    join = pia_connect.parse_session_join(JOIN)
    update, response = build_session_acceptance(
        host, cryptomod.PiaCrypto(host.ssid), join, "Chase", nonces)

    assert cryptomod.PiaHeader.unpack(net).nonce8 == bytes.fromhex("04c5a33f290b14e2")
    assert cryptomod.PiaHeader.unpack(response).nonce8 == bytes.fromhex("04c5a33f290b14e3")
    assert cryptomod.PiaHeader.unpack(update).nonce8 == bytes.fromhex("04c5a33f290b14e4")


def test_session_acceptance_pair_can_be_rebuilt_and_retried_response_first():
    join = pia_connect.parse_session_join(JOIN)
    host = SimpleNamespace(
        ssid=bytes.fromhex("5c42961f018902911a2f1c9548c8e9c4"),
        our_ip="169.254.88.1",
        our_mac=bytes.fromhex("3ca9abf73c06"),
        broadcast="169.254.88.255",
        participants=[(1, join["ip"], bytes.fromhex("3c3300609493"), b"EMU")],
        max_participants=6,
        sent=[],
    )
    host.send = lambda datagram, dst: host.sent.append((datagram, dst))
    nonces = PiaNonceSequence(native=True, initial=1)
    crypto = cryptomod.PiaCrypto(host.ssid)

    for _ in range(2):
        update, response = build_session_acceptance(
            host, crypto, join, "Chase", nonces)
        # Transport ordering is deliberately outside the pure Pia helper.
        host.send(response, join["ip"])
        host.send(update, host.broadcast)

    assert [dst for _, dst in host.sent] == [
        join["ip"], host.broadcast, join["ip"], host.broadcast]
    # Every rebuilt datagram uses a fresh native Pia nonce.
    assert [cryptomod.PiaHeader.unpack(d).nonce8 for d, _ in host.sent] == [
        bytes.fromhex("0000000000000001"),
        bytes.fromhex("0000000000000002"),
        bytes.fromhex("0000000000000003"),
        bytes.fromhex("0000000000000004"),
    ]


def test_initial_and_active_beacons_share_rfu_leader_session_id():
    """The discovered parent ID must be the one returned in RFU A."""
    session_id = bytes.fromhex("b7f1")
    profile = TrainerProfile("EMU", tid=0x5678, sid=0x1234)
    initial, active = build_trade_app_data(profile, session_id)
    initial_record = transport._b85_decode(initial[beacon.PIA_HDR:])[:beacon.RECORD_SIZE]

    assert initial_record[10:12] == session_id
    assert initial[0x16] == 1
    assert not initial_record[17] & 0x80

    active_record = transport._b85_decode(active[beacon.PIA_HDR:])[:beacon.RECORD_SIZE]
    assert active_record[10:12] == session_id
    assert active[0x16] == 2
    assert active_record[17] & 0x80


def test_host_rtt_response_uses_session_channel_and_echoes_request():
    host = SimpleNamespace(
        ssid=bytes.fromhex("5c42961f018902911a2f1c9548c8e9c4"),
        our_ip="169.254.88.1",
    )
    request = bytes.fromhex("0000003e9c96ce96fe000000000004d46e000000c6")
    response = pia_connect.build_rtt_response(request)
    nonces = PiaNonceSequence(native=True, initial=0x1234)
    crypto = cryptomod.PiaCrypto(host.ssid)
    datagram = build_host_rtt(host, crypto, response, 0x7171, 2, nonces)

    header = cryptomod.PiaHeader.unpack(datagram)
    assert (header.dst, header.src, header.pktid, header.footer) == (0x0001, 0x00C6, 2, 2)
    assert header.nonce8 == bytes.fromhex("0000000000001234")
    decoded, error = decode_datagram(datagram, host.our_ip, crypto)
    assert error is None
    decoded_header, messages = decoded
    assert decoded_header.flags == 0x50
    assert len(messages) == 1 and messages[0].proto == pia_connect.PROTO_RTT
    assert messages[0].payload == response


def test_host_rtt_origination_replaces_only_type_and_systime():
    template = bytes.fromhex("0000003e9c96ce96fe000000000004d46e000000c6")
    request = pia_connect.build_rtt_request(template, 0x10001)
    assert request[:8] == template[:8]
    assert request[8:16] == bytes.fromhex("0100010000000000")
    assert request[16:] == template[16:]


def test_reliable_control_ack_ends_its_pia_batch():
    data1 = ReliableEmission(0xFFF0, FLAGSA_GBA, 0xFFF0, b"A")
    ack = ReliableEmission(0xFFF0, FLAGSA_CTRL, 0xFFF1, b"ack")
    data2 = ReliableEmission(0xFFF1, FLAGSA_GBA, 0xFFF0, b"T")
    assert reliable_output_batches([data1, ack, data2]) == [[data1, ack], [data2]]

    retransmit = ReliableEmission(
        0xFFF2, FLAGSA_GBA, 0xFFF0, b"retry", retransmitted=True)
    assert reliable_output_batches([data1, retransmit, data2]) == [
        [data1, retransmit], [data2]
    ]


def test_reliable_pia_batches_preserve_ack_and_retransmit_message_flags():
    host = SimpleNamespace(
        ssid=bytes.fromhex("5c42961f018902911a2f1c9548c8e9c4"),
        our_ip="169.254.88.1",
    )
    crypto = cryptomod.PiaCrypto(host.ssid)
    data = ReliableEmission(0xFFF0, FLAGSA_GBA, 0xFFF0, b"A")
    retransmit = ReliableEmission(
        0xFFF1, FLAGSA_GBA, 0xFFF0, b"retry", retransmitted=True)
    ack = ReliableEmission(0xFFF0, FLAGSA_CTRL, 0xFFF2, b"ack")
    datagram = build_messages(
        host, crypto,
        [(pia_connect.PROTO_RELIABLE, e.serialize(), e.message_flags)
         for e in (data, retransmit, ack)],
        dst_var=0x7171, src_var=0x00C6, footer_var=0x7171,
        nonce_source=PiaNonceSequence(native=True, initial=1))
    decoded, error = decode_datagram(datagram, host.our_ip, crypto)
    assert error is None
    _, messages = decoded
    assert [message.msgflags for message in messages] == [0x00, 0x20, 0x40]


def test_net_property_update_matches_native_leader_layout():
    app_data = NATIVE_NET_PROPERTY[38:]
    host = SimpleNamespace(
        ssid=bytes.fromhex("5c42961f018902911a2f1c9548c8e9c4"),
        participants=[(1, "169.254.127.2", b"mac", b"Chase")],
        max_participants=6,
        SCENE_ID=22287,
    )
    payload = build_net_property_update(host, app_data)
    assert payload == NATIVE_NET_PROPERTY


def test_active_beacon_matches_native_session_and_activity_transition():
    actual = activate_trade_app_data(CAPTURED_TRADE_BEACON, bytes.fromhex("b7f1"))
    assert actual == NATIVE_NET_PROPERTY[38:]


if __name__ == "__main__":
    for name, value in sorted(globals().items()):
        if name.startswith("test_") and callable(value):
            value()
    print("pia host session tests: OK")
