"""Focused, offline regressions for host identity and Pia wire helpers."""

from dataclasses import FrozenInstanceError
import os
import sys
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from frlgsim import beacon, crypto, linkplayer, pia_connect, reliable, transport
from frlgsim.host_beacon import build_trade_app_data, parse_mac
from frlgsim.host_pia import (
    HostPeerProtocol,
    PiaNonceSequence,
    PIA_HOST_VAR,
    build_message,
    build_messages,
    decode_datagram,
    reliable_output_batches,
)
from frlgsim.config import DEFAULT_TRAINER, TrainerProfile
from frlgsim.reliable import FLAGSA_CTRL, FLAGSA_GBA, ReliableEmission


def _profile(**overrides):
    values = {
        "name": "Red",
        "tid": 0x1234,
        "sid": 0xABCD,
        "gender": 1,
        "version": "firered",
        "language": "english",
        "has_national_dex": True,
        "has_completed_game": True,
    }
    values.update(overrides)
    return TrainerProfile(**values)


def test_default_trainer_preserves_live_identity():
    assert DEFAULT_TRAINER.name == "EMU"
    assert DEFAULT_TRAINER.tid == 0x8822
    assert DEFAULT_TRAINER.sid == 0x47ED
    assert DEFAULT_TRAINER.version == "leafgreen"
    assert DEFAULT_TRAINER.trainer_id == 0x47ED8822


def test_profile_rejects_invalid_human_configuration():
    invalid = [
        {"name": ""},
        {"name": "ABCDEFGH"},
        {"name": "RED_"},
        {"tid": -1},
        {"tid": 0x10000},
        {"tid": 1.5},
        {"tid": True},
        {"sid": -1},
        {"sid": 0x10000},
        {"sid": None},
        {"gender": 2},
        {"gender": False},
        {"version": "emerald"},
        {"language": "japanese"},
        {"has_national_dex": 1},
        {"has_completed_game": None},
    ]
    for overrides in invalid:
        try:
            _profile(**overrides)
        except ValueError:
            pass
        else:
            raise AssertionError(f"invalid profile accepted: {overrides!r}")


def test_profile_is_immutable():
    profile = _profile()
    try:
        profile.name = "Leaf"
    except FrozenInstanceError:
        pass
    else:
        raise AssertionError("frozen TrainerProfile accepted an assignment")


def test_identity_is_consistent_across_discovery_link_player_and_card():
    profile = _profile()
    player = profile.to_link_player()
    packed = player.pack(name_pad=linkplayer.HOST_NAME_PAD)
    block = profile.build_link_player_block(name_pad=linkplayer.HOST_NAME_PAD)
    card = profile.build_trainer_card(
        mon_species=[1, 2, 3], name_pad=linkplayer.HOST_NAME_PAD)
    inactive, active = build_trade_app_data(profile, b"\xb7\xf1")
    record = transport._b85_decode(inactive[beacon.PIA_HDR:])[:beacon.RECORD_SIZE]

    assert player.name == profile.name
    assert profile.discovery_name == profile.session_name == profile.name
    assert profile.discovery_trainer_id == profile.tid
    assert player.trainer_id == profile.trainer_id == 0xABCD1234
    assert player.version == linkplayer.VERSION_FIRE_RED
    assert player.language == linkplayer.LANGUAGE_ENGLISH
    assert player.gender == profile.gender
    assert player.progress_flags == player.progress_flags_copy == 0x11
    assert packed[8:16] == bytes.fromhex("CC D9 D8 FF FF FF FF FF")
    assert block[16:44] == packed

    assert int.from_bytes(card[linkplayer.TC_OFF_TRAINER_ID:
                               linkplayer.TC_OFF_TRAINER_ID + 2], "little") == profile.tid
    assert card[linkplayer.TC_OFF_PLAYER_NAME:
                linkplayer.TC_OFF_PLAYER_NAME + 8] == packed[8:16]
    assert card[linkplayer.TC_OFF_VERSION] == linkplayer.VERSION_FIRE_RED & 0xFF
    assert card[linkplayer.TC_OFF_GENDER] == profile.gender

    assert int.from_bytes(record[0:2], "little") == profile.tid
    assert record[2:10] == packed[8:16]
    assert record[10:12] == b"\xb7\xf1"
    assert beacon.decode_pia_header(inactive)["nickname"] == profile.name
    assert inactive[0x16] == 1 and not record[17] & 0x80

    active_record = transport._b85_decode(active[beacon.PIA_HDR:])[:beacon.RECORD_SIZE]
    assert active[0x16] == 2 and active_record[17] & 0x80
    assert active_record[:17] == record[:17]


def test_session_player_info_uses_the_same_profile_name():
    profile = _profile(name="Red")
    player_info = pia_connect._build_player_info(b"P" * 16, profile.name)
    name_size = int.from_bytes(player_info[16:20], "big")
    assert player_info[20] == beacon.PIA_NAME_UTF8
    assert player_info[21:21 + name_size] == profile.name.encode("utf-8")


def test_native_nonce_sequence_increments_and_wraps():
    nonces = PiaNonceSequence(native=True, initial=0xFFFFFFFFFFFFFFFF)
    assert nonces.take() == b"\xff" * 8
    assert nonces.take() == b"\x00" * 8
    assert nonces.take() == b"\x00" * 7 + b"\x01"


def test_random_nonce_mode_returns_eight_bytes():
    with mock.patch("frlgsim.host_pia.os.urandom", lambda size: b"R" * size):
        nonces = PiaNonceSequence(native=False, initial=123)
        assert nonces.take() == b"R" * 8
        assert nonces.take() == b"R" * 8


def test_reliable_batches_honor_limit_and_end_at_flagged_emissions():
    emissions = [
        ReliableEmission(i, FLAGSA_GBA, 0, bytes([i]))
        for i in range(7)
    ]
    emissions[4] = ReliableEmission(4, FLAGSA_CTRL, 0, b"ack")
    assert [len(batch) for batch in reliable_output_batches(emissions, limit=3)] == [3, 2, 2]
    assert reliable_output_batches([], limit=3) == []
    try:
        reliable_output_batches(emissions, limit=0)
    except ValueError:
        pass
    else:
        raise AssertionError("zero-sized Reliable batch limit was accepted")


def test_build_and_decode_messages_round_trip_footer_padding_and_flags():
    network = SimpleNamespace(
        ssid=bytes.fromhex("5c42961f018902911a2f1c9548c8e9c4"),
        our_ip="169.254.88.1",
    )
    pia_crypto = crypto.PiaCrypto(network.ssid)
    nonce = PiaNonceSequence(native=True, initial=7)
    datagram = build_messages(
        network,
        pia_crypto,
        [(pia_connect.PROTO_RTT, b"request"),
         (pia_connect.PROTO_RELIABLE, b"payload", 0x20)],
        dst_var=0x7171,
        src_var=0x00C6,
        pktid=9,
        footer_var=0x7171,
        establishing=True,
        nonce_source=nonce,
    )

    decoded, error = decode_datagram(datagram, network.our_ip, pia_crypto)
    assert error is None
    header, messages = decoded
    assert (header.dst, header.src, header.pktid, header.footer) == (0x7171, 0x00C6, 9, 2)
    assert header.nonce8 == b"\x00" * 7 + b"\x07"
    assert header.flags & 2
    assert [(message.proto, message.payload, message.msgflags) for message in messages] == [
        (pia_connect.PROTO_RTT, b"request", 0),
        (pia_connect.PROTO_RELIABLE, b"payload", 0x20),
    ]


def test_decode_rejects_non_ff_padding():
    network = SimpleNamespace(
        ssid=bytes.fromhex("5c42961f018902911a2f1c9548c8e9c4"),
        our_ip="169.254.88.1",
    )
    pia_crypto = crypto.PiaCrypto(network.ssid)
    message = reliable.build_message(pia_connect.PROTO_RTT, b"request")
    pad = (-len(message)) % 16
    assert pad
    plaintext = message + b"\xff" * (pad - 1) + b"\x00"
    header = crypto.PiaHeader(
        dst=0x7171,
        src=0x00C6,
        pktid=9,
        nonce8=b"N" * 8,
        flags=pad << 4,
        footer=0,
    )
    datagram = pia_crypto.encrypt(plaintext, network.our_ip, header)

    decoded, error = decode_datagram(datagram, network.our_ip, pia_crypto)
    assert decoded is None
    assert error == f"invalid {pad}-byte padding"


def test_peer_ignores_malformed_session_join_without_changing_identity():
    network = SimpleNamespace(
        ssid=bytes.fromhex("5c42961f018902911a2f1c9548c8e9c4"),
        our_ip="169.254.88.1",
        our_mac=bytes.fromhex("3ca9abf73c06"),
        broadcast="169.254.88.255",
        participants=[],
        max_participants=6,
    )
    session = SimpleNamespace(trade=SimpleNamespace(established=False))
    logs = []
    peer = HostPeerProtocol(network, _profile(), session, b"app", log=logs.append)
    peer.on_participant_joined()
    malformed = build_message(
        network,
        peer.pia_crypto,
        pia_connect.PROTO_SESSION,
        bytes([pia_connect.SESSION_JOIN_REQUEST]),
        dst_var=PIA_HOST_VAR,
        src_var=0x7171,
        nonce_source=PiaNonceSequence(native=True, initial=1),
    )

    # ``build_message`` uses network.our_ip as AES-GCM associated data, so
    # receive it from that address in this transport-independent unit test.
    assert peer.receive(malformed, network.our_ip, now=1.0) == []
    assert not peer.session_join_seen
    assert peer.session_join is None
    assert peer.guest_var is None and peer.guest_ip is None
    assert peer.drain() == []
    assert any("malformed or unsupported Session join" in line for line in logs)


def test_parse_mac_reports_invalid_cli_values():
    for value in ("bad", "00:11:22:33:44", "00:11:22:33:44:zz"):
        try:
            parse_mac(value)
        except Exception as error:
            assert "invalid MAC address" in str(error)
        else:
            raise AssertionError(f"invalid MAC accepted: {value!r}")


if __name__ == "__main__":
    for name, value in sorted(globals().items()):
        if name.startswith("test_") and callable(value):
            value()
    print("host profile/Pia helper tests: OK")
