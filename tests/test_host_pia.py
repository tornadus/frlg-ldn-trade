"""Transport-independent tests for host-side Pia framing and state."""

from types import SimpleNamespace
from unittest import mock

from frlgsim import crypto, pia_connect, reliable
from frlgsim.host_pia import (
    HostPeerProtocol,
    PIA_HOST_VAR,
    PiaNonceSequence,
    build_message,
    build_messages,
    decode_datagram,
    reliable_output_batches,
)
from frlgsim.reliable import FLAGSA_CTRL, FLAGSA_GBA, ReliableEmission


def _network():
    return SimpleNamespace(
        ssid=bytes.fromhex("5c42961f018902911a2f1c9548c8e9c4"),
        our_ip="169.254.88.1",
        our_mac=bytes.fromhex("3ca9abf73c06"),
        broadcast="169.254.88.255",
        participants=[],
        max_participants=6,
    )


def test_nonce_modes_increment_wrap_and_generate_random_bytes():
    native = PiaNonceSequence(native=True, initial=0xFFFFFFFFFFFFFFFF)
    assert native.take() == b"\xff" * 8
    assert native.take() == b"\x00" * 8
    assert native.take() == b"\x00" * 7 + b"\x01"
    with mock.patch("frlgsim.host_pia.os.urandom", lambda size: b"R" * size):
        random = PiaNonceSequence(native=False)
        assert random.take() == random.take() == b"R" * 8


def test_reliable_batches_end_at_control_and_retransmit_emissions():
    data1 = ReliableEmission(0xFFF0, FLAGSA_GBA, 0xFFF0, b"A")
    ack = ReliableEmission(0xFFF0, FLAGSA_CTRL, 0xFFF1, b"ack")
    data2 = ReliableEmission(0xFFF1, FLAGSA_GBA, 0xFFF0, b"T")
    assert reliable_output_batches([data1, ack, data2]) == [[data1, ack], [data2]]

    retransmit = ReliableEmission(
        0xFFF2, FLAGSA_GBA, 0xFFF0, b"retry", retransmitted=True)
    assert reliable_output_batches([data1, retransmit, data2]) == [
        [data1, retransmit], [data2]
    ]


def test_build_and_decode_messages_round_trip_padding_and_flags():
    network = _network()
    pia_crypto = crypto.PiaCrypto(network.ssid)
    datagram = build_messages(
        network,
        pia_crypto,
        [(pia_connect.PROTO_RTT, b"request"),
         (pia_connect.PROTO_RELIABLE, b"payload", 0x20)],
        dst_var=0x7171,
        src_var=PIA_HOST_VAR,
        pktid=9,
        footer_var=0x7171,
        establishing=True,
        nonce_source=PiaNonceSequence(native=True, initial=7),
    )
    decoded, error = decode_datagram(datagram, network.our_ip, pia_crypto)
    assert error is None
    header, messages = decoded
    assert (header.dst, header.src, header.pktid, header.footer) == (
        0x7171, PIA_HOST_VAR, 9, 2)
    assert header.nonce8 == b"\x00" * 7 + b"\x07"
    assert [(message.proto, message.payload, message.msgflags) for message in messages] == [
        (pia_connect.PROTO_RTT, b"request", 0),
        (pia_connect.PROTO_RELIABLE, b"payload", 0x20),
    ]


def test_decode_rejects_non_ff_padding():
    network = _network()
    pia_crypto = crypto.PiaCrypto(network.ssid)
    message = reliable.build_message(pia_connect.PROTO_RTT, b"request")
    pad = (-len(message)) % 16
    plaintext = message + b"\xff" * (pad - 1) + b"\x00"
    header = crypto.PiaHeader(
        dst=0x7171, src=PIA_HOST_VAR, pktid=9,
        nonce8=b"N" * 8, flags=pad << 4, footer=0)
    datagram = pia_crypto.encrypt(plaintext, network.our_ip, header)
    decoded, error = decode_datagram(datagram, network.our_ip, pia_crypto)
    assert decoded is None
    assert error == f"invalid {pad}-byte padding"


def test_peer_rejects_malformed_session_without_mutating_identity():
    network = _network()
    session = SimpleNamespace(trade=SimpleNamespace(established=False))
    profile = SimpleNamespace(session_name="EMU")
    logs = []
    peer = HostPeerProtocol(network, profile, session, b"app", log=logs.append)
    peer.on_participant_joined()
    malformed = build_message(
        network, peer.pia_crypto, pia_connect.PROTO_SESSION,
        bytes([pia_connect.SESSION_JOIN_REQUEST]),
        dst_var=PIA_HOST_VAR, src_var=0x7171,
        nonce_source=PiaNonceSequence(native=True, initial=1))
    assert peer.receive(malformed, network.our_ip, now=1.0) == []
    assert not peer.session_join_seen
    assert peer.session_join is None
    assert peer.guest_var is None and peer.guest_ip is None
    assert peer.drain() == []
    assert any("malformed or unsupported Session join" in line for line in logs)
