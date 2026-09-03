"""Shared immutable configuration for FRLG joiner and host roles."""

import argparse
from dataclasses import dataclass, replace

from . import charmap, linkplayer


VERSIONS = {
    "firered": linkplayer.VERSION_FIRE_RED,
    "leafgreen": linkplayer.VERSION_LEAF_GREEN,
}
LANGUAGES = {"english": linkplayer.LANGUAGE_ENGLISH}


@dataclass(frozen=True)
class TrainerProfile:
    name: str
    tid: int
    sid: int
    gender: int = 0
    version: str = "leafgreen"
    language: str = "english"
    has_national_dex: bool = True
    has_completed_game: bool = True

    def __post_init__(self):
        if not isinstance(self.name, str):
            raise ValueError("trainer name must be a string")
        encoded = charmap.encode(self.name)
        if not self.name or charmap.decode(encoded) != self.name:
            raise ValueError("trainer name contains unsupported Gen III characters")
        if len(encoded) > 7:
            raise ValueError("trainer name must encode to at most 7 Gen III characters")
        if (type(self.tid) is not int or type(self.sid) is not int
                or not 0 <= self.tid <= 0xFFFF or not 0 <= self.sid <= 0xFFFF):
            raise ValueError("TID and SID must each fit in 16 bits")
        if type(self.gender) is not int or self.gender not in (0, 1):
            raise ValueError("gender must be 0 (male) or 1 (female)")
        if self.version not in VERSIONS:
            raise ValueError(f"version must be one of {', '.join(VERSIONS)}")
        if self.language not in LANGUAGES:
            raise ValueError(f"language must be one of {', '.join(LANGUAGES)}")
        if type(self.has_national_dex) is not bool:
            raise ValueError("has_national_dex must be a bool")
        if type(self.has_completed_game) is not bool:
            raise ValueError("has_completed_game must be a bool")

    @property
    def trainer_id(self):
        return (self.sid << 16) | self.tid

    @property
    def progress_flags(self):
        return ((1 if self.has_national_dex else 0)
                | (0x10 if self.has_completed_game else 0))

    @property
    def discovery_name(self):
        return self.name

    @property
    def discovery_trainer_id(self):
        return self.tid

    @property
    def session_name(self):
        return self.name

    def to_link_player(self):
        return linkplayer.LinkPlayer(
            name=self.name,
            trainer_id=self.trainer_id,
            version=VERSIONS[self.version],
            progress_flags=self.progress_flags,
            progress_flags_copy=self.progress_flags,
            gender=self.gender,
            player_id=0,
            language=LANGUAGES[self.language],
        )

    def build_link_player_block(self, *, name_pad=0x00):
        return linkplayer.build_block(self.to_link_player(), name_pad=name_pad)

    def build_trainer_card(self, mon_species=None, *, name_pad=0x00):
        return linkplayer.build_trainer_card(
            self.to_link_player(), mon_species=mon_species, name_pad=name_pad)


DEFAULT_TRAINER = TrainerProfile(
    name="EMU", tid=0x8822, sid=0x47ED, gender=0,
    version="leafgreen", language="english",
    has_national_dex=True, has_completed_game=True)


@dataclass(frozen=True)
class TradePlan:
    party_paths: tuple
    output_path: str = "received.pk3"
    output_size: int = 100
    output_format: str = "pk3"
    trade_slot: int = 1
    offered_slots: tuple | None = None
    trades: int = 1
    anim_delay: int | None = None
    trust_pia: bool = False

    def __post_init__(self):
        if not 1 <= len(self.party_paths) <= 6:
            raise ValueError("party must contain 1..6 Pokemon files")
        if not 1 <= self.trades <= 6 or self.trades > len(self.party_paths):
            raise ValueError("trades must be 1..6 and cannot exceed party size")
        if self.output_size not in (80, 100):
            raise ValueError("output_size must be 80 or 100")
        if self.output_format not in ("pk3", "ek3"):
            raise ValueError("output_format must be pk3 or ek3")
        if type(self.trade_slot) is not int or not 0 <= self.trade_slot < len(self.party_paths):
            raise ValueError("trade_slot must reference the configured party")
        if self.anim_delay is not None \
                and (type(self.anim_delay) is not int or self.anim_delay < 0):
            raise ValueError("anim_delay must be a non-negative integer")
        if self.offered_slots is not None:
            if len(self.offered_slots) != self.trades:
                raise ValueError("offered_slots must contain one slot per trade")
            if len(set(self.offered_slots)) != len(self.offered_slots):
                raise ValueError("offered_slots must be distinct")
            if any(type(slot) is not int or not 0 <= slot < len(self.party_paths)
                   for slot in self.offered_slots):
                raise ValueError("offered_slots must reference the configured party")


@dataclass(frozen=True)
class LdnConfig:
    password: bytes | None = None
    phy: str = "phy0"
    keys_path: str = "~/.switch/prod.keys"
    local_comm_id: int | None = None
    capture_path: str | None = None

    def __post_init__(self):
        if self.password is not None and not isinstance(self.password, bytes):
            raise ValueError("password must be bytes or None")
        if self.local_comm_id is not None and (
                type(self.local_comm_id) is not int
                or not 0 <= self.local_comm_id <= 0xFFFFFFFFFFFFFFFF):
            raise ValueError("local_comm_id must fit in 64 bits")


@dataclass(frozen=True)
class JoinerOptions:
    live: bool = True
    replay_path: str | None = None
    self_id: int = 1
    decline: bool = False
    refuse_illegit: bool = False
    compress: bool = False
    connect_id: bytes | None = None

    def __post_init__(self):
        if self.live == bool(self.replay_path):
            raise ValueError("select exactly one of live mode or replay_path")
        if self.self_id != 1:
            raise ValueError("joiner self_id must be 1")
        if self.connect_id is not None and len(self.connect_id) != 2:
            raise ValueError("connect_id must contain exactly two bytes")


@dataclass(frozen=True)
class HostOptions:
    channel: int = 1
    scene_id: int | None = None
    max_participants: int = 6
    skip_preflight: bool = False
    skip_encryption: bool = False
    native_nonce_sequence: bool = False
    session_response_first: bool = False

    def __post_init__(self):
        if type(self.channel) is not int or not 1 <= self.channel <= 14:
            raise ValueError("channel must be 1..14")
        if type(self.max_participants) is not int or not 2 <= self.max_participants <= 8:
            raise ValueError("max_participants must be 2..8")
        if self.scene_id is not None and (
                type(self.scene_id) is not int or not 0 <= self.scene_id <= 0xFFFF):
            raise ValueError("scene_id must fit in 16 bits")


@dataclass(frozen=True)
class TradeRunConfig:
    profile: TrainerProfile
    plan: TradePlan
    ldn: LdnConfig
    role: JoinerOptions | HostOptions


def parse_trainer_id(value):
    """Parse decimal ``TID`` or ``TID:SID`` and return both overrides."""
    parts = value.split(":")
    if len(parts) not in (1, 2) or any(not part or not part.isdecimal() for part in parts):
        raise ValueError("ID must be decimal TID or TID:SID")
    values = tuple(int(part, 10) for part in parts)
    if any(number > 0xFFFF for number in values):
        raise ValueError("TID and SID must each be between 0 and 65535")
    return values[0], values[1] if len(values) == 2 else None


def trainer_id_argument(value):
    try:
        return parse_trainer_id(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def add_identity_arguments(parser):
    parser.add_argument("--ot", default=None, help="trainer name; defaults to DEFAULT_TRAINER")
    parser.add_argument("--version", choices=tuple(VERSIONS), default=None,
                        help="game version; defaults to DEFAULT_TRAINER")
    parser.add_argument("--id", type=trainer_id_argument, metavar="TID[:SID]", default=None,
                        help="decimal trainer ID, optionally followed by decimal secret ID")


def profile_from_overrides(*, ot=None, version=None, trainer_id=None,
                           base=DEFAULT_TRAINER):
    changes = {}
    if ot is not None:
        changes["name"] = ot
    if version is not None:
        changes["version"] = version
    if trainer_id is not None:
        tid, sid = trainer_id
        changes["tid"] = tid
        if sid is not None:
            changes["sid"] = sid
    return replace(base, **changes)
