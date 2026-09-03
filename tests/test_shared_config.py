from dataclasses import FrozenInstanceError

import frlgtrade
from frlgsim import config, linkplayer


def test_default_profile_is_completed_and_matches_legacy_identity():
    profile = config.DEFAULT_TRAINER
    assert (profile.name, profile.version) == ("EMU", "leafgreen")
    assert (profile.tid, profile.sid) == (0x8822, 0x47ED)
    assert profile.trainer_id == 0x47ED8822
    assert profile.progress_flags == 0x11


def test_trainer_id_accepts_decimal_tid_and_tid_sid():
    assert config.parse_trainer_id("0") == (0, None)
    assert config.parse_trainer_id("65535") == (65535, None)
    assert config.parse_trainer_id("12345:34567") == (12345, 34567)
    one = config.profile_from_overrides(trainer_id=(12345, None))
    both = config.profile_from_overrides(trainer_id=(12345, 34567))
    assert (one.tid, one.sid) == (12345, config.DEFAULT_TRAINER.sid)
    assert (both.tid, both.sid) == (12345, 34567)
    assert both.trainer_id == (34567 << 16) | 12345


def test_trainer_id_rejects_invalid_syntax_and_ranges():
    invalid = ("", "-1", "0x1234", "1:", ":1", "1:2:3", "65536", "1:65536")
    for value in invalid:
        try:
            config.parse_trainer_id(value)
        except ValueError:
            pass
        else:
            raise AssertionError(f"invalid trainer ID accepted: {value!r}")


def test_profile_is_immutable_and_serialization_padding_is_role_specific():
    profile = config.profile_from_overrides(
        ot="Red", version="firered", trainer_id=(12345, 34567))
    try:
        profile.name = "Leaf"
    except FrozenInstanceError:
        pass
    else:
        raise AssertionError("frozen TrainerProfile accepted assignment")
    player = profile.to_link_player()
    assert player.trainer_id == (34567 << 16) | 12345
    assert player.version == linkplayer.VERSION_FIRE_RED
    assert player.pack(name_pad=0x00)[8:16] == bytes.fromhex("CC D9 D8 FF 00 00 00 00")
    assert player.pack(name_pad=0xFF)[8:16] == bytes.fromhex("CC D9 D8 FF FF FF FF FF")


def test_joiner_cli_builds_full_config_from_identity_overrides():
    parser = frlgtrade.build_parser()
    args = parser.parse_args([
        "--live", "--ot", "Red", "--version", "firered",
        "--id=12345:34567", "one.pk3", "two.pk3",
    ])
    run = frlgtrade._build_run_config(parser, args)
    assert (run.profile.name, run.profile.version) == ("Red", "firered")
    assert (run.profile.tid, run.profile.sid) == (12345, 34567)
    assert run.plan.party_paths == ("one.pk3", "two.pk3")
    assert isinstance(run.role, config.JoinerOptions)
