"""LinkPlayerBlock - the 60-byte player record exchanged in S1 [link.c:343,557-563].

    LinkPlayerBlock (60B) = magic1[16] "GameFreak inc.\\0\\0"
                          + struct LinkPlayer (28B)
                          + magic2[16] "GameFreak inc.\\0\\0"

The host strcmp-validates BOTH magics against "GameFreak inc." [link.c:1626-1631, on the
wireless trade path via LinkPlayerFromBlock], dropping to CB2_LinkError on mismatch - so the
joiner MUST emit both. On the wireless path the host pulls this with SEND_BLOCK_REQ type NONE,
which sends a fixed 200-byte buffer (count=17); the 60-byte block sits at offset 0 and the
remaining 140 bytes are buffer residue. Verified byte-exact against the reference capture
(OUT=EMU/LeafGreen, IN=HOST/FireRed).
"""

from dataclasses import dataclass

from . import charmap

GAMEFREAK_MAGIC = b"GameFreak inc.\x00\x00"      # 16 bytes: "GameFreak inc." + null + 0 pad
assert len(GAMEFREAK_MAGIC) == 16

VERSION_FIRE_RED = 0x4004                        # gGameVersion(4) + 0x4000
VERSION_LEAF_GREEN = 0x4005                      # gGameVersion(5) + 0x4000
LANGUAGE_ENGLISH = 2
LP_FIELD2 = 0x8000                               # gLocalLinkPlayer.lp_field_2
HOST_NAME_PAD = 0xFF                             # robust host-role fixed-field terminators

LINK_PLAYER_SIZE = 28
LINK_PLAYER_BLOCK_SIZE = 60
PARTY_SIZE = 6                                   # struct TrainerCard.monSpecies[PARTY_SIZE]


@dataclass
class LinkPlayer:
    """struct LinkPlayer (28B) [include/link.h:158-171]. Defaults match the capture's joiner
    (EMU / LeafGreen); only the magics + a valid version really matter to the host - the rest
    is the sim's cosmetic trainer profile."""
    name: str = "EMU"
    trainer_id: int = 0x47ED8822             # full 32-bit OT id (capture EMU value)
    version: int = VERSION_LEAF_GREEN
    field2: int = LP_FIELD2
    progress_flags: int = 0
    never_read: int = 0
    progress_flags_copy: int = 0
    gender: int = 0
    link_type: int = 0
    player_id: int = 0
    language: int = LANGUAGE_ENGLISH

    def pack(self, *, name_pad=0x00):
        """Serialize the 28-byte structure.

        ``name_pad`` controls bytes after the mandatory 0xFF string terminator.
        Native zero-initialized LinkPlayer storage normally leaves them as
        zero.  A peer may safely use 0xFF instead: every byte is then a valid
        Gen III end-of-string marker, which is useful for a host crossing an
        RFU bridge where the fixed-width name is consumed by several UI paths.
        """
        return (self.version.to_bytes(2, "little")
                + self.field2.to_bytes(2, "little")
                + (self.trainer_id & 0xFFFFFFFF).to_bytes(4, "little")
                + charmap.encode(self.name, width=8, pad=name_pad)
                + bytes([self.progress_flags & 0xFF, self.never_read & 0xFF,
                         self.progress_flags_copy & 0xFF, self.gender & 0xFF])
                + (self.link_type & 0xFFFFFFFF).to_bytes(4, "little")
                + (self.player_id & 0xFFFF).to_bytes(2, "little")
                + (self.language & 0xFFFF).to_bytes(2, "little"))

    @classmethod
    def unpack(cls, b):
        return cls(
            version=int.from_bytes(b[0:2], "little"),
            field2=int.from_bytes(b[2:4], "little"),
            trainer_id=int.from_bytes(b[4:8], "little"),
            name=charmap.decode(b[8:16]),
            progress_flags=b[16], never_read=b[17], progress_flags_copy=b[18], gender=b[19],
            link_type=int.from_bytes(b[20:24], "little"),
            player_id=int.from_bytes(b[24:26], "little"),
            language=int.from_bytes(b[26:28], "little"),
        )


def build_block(link_player, *, name_pad=0x00):
    """LinkPlayer -> 60-byte LinkPlayerBlock (both GameFreak magics)."""
    blk = GAMEFREAK_MAGIC + link_player.pack(name_pad=name_pad) + GAMEFREAK_MAGIC
    assert len(blk) == LINK_PLAYER_BLOCK_SIZE
    return blk


# --- Trainer card (union-room -> trade-center ENTRY: Task_ExchangeCards) ----------------------
# struct TrainerCard [include/trainer_card.h:6-48] is 0x60=96 bytes: TrainerCardRSE @0x00..0x38
# (gender@0x00, stars@0x01, hasPokedex@0x02, ..., trainerId u16 @0x0E, ..., playerName[8] @0x30..0x38)
# + version u8 @0x38 + ... + monSpecies[PARTY_SIZE] u16 @0x54..0x60. CreateTrainerCardInBuffer
# [union_room.c:1863-1870] does TrainerCard_GenerateCardForLinkPlayer(dest) THEN writes a wonder-card
# u16 at *(dest + sizeof(struct TrainerCard)) = offset 96, so the BLOCK_REQ_SIZE_100 buffer is the
# 96-byte card + a 2-byte wonder-card id + 2 bytes residue = 100 bytes. ACTIVITY_TRADE calls it with
# setWonderCard=TRUE [union_room.c:1932], so the wonder-card u16 = GetWonderCardFlagId() (0 when the
# player has no wonder card - the common case; the sim has none, so 0). This is COSMETIC to the trade
# (CopyTrainerCardData populates gTrainerCards[i] for the card-view UI; it gates no trade byte), but
# the host PULLS it before the trade menu exists, so the sim must SUPPLY a structurally-valid 100B
# card when pulled with reqtype BLOCK_REQ_SIZE_100 [union_room.c:1758-1759; link.c:187; link_rfu_2.c:
# 1172-1173]. The exact non-cosmetic fields (stars/playtime/...) are not observable offline and the
# host never validates them on the trade path, so we fill only the structurally meaningful ones (OT,
# trainerId, version) and zero the rest.
TRAINER_CARD_SIZE = 0x60                 # sizeof(struct TrainerCard) = 96
TRAINER_CARD_BLOCK_SIZE = 100            # BLOCK_REQ_SIZE_100 buffer [link.c:187]
TC_OFF_GENDER = 0x00
TC_OFF_STARS = 0x01
TC_OFF_TRAINER_ID = 0x0E                 # TrainerCardRSE.trainerId (u16)
TC_OFF_PLAYER_NAME = 0x30                # TrainerCardRSE.playerName[PLAYER_NAME_LENGTH+1]
TC_OFF_VERSION = 0x38                    # TrainerCard.version (u8)
TC_OFF_MON_SPECIES = 0x54               # TrainerCard.monSpecies[PARTY_SIZE] (u16[6])
TC_OFF_WONDER_CARD = TRAINER_CARD_SIZE   # u16 written by CreateTrainerCardInBuffer @ offset 96


def build_trainer_card(link_player, wonder_card_id=0, mon_species=None, *, name_pad=0x00):
    """Build the 100-byte BLOCK_REQ_SIZE_100 trainer-card buffer the host pulls in Task_ExchangeCards
    [union_room.c:1753-1789,1863-1870]. Reuses the LinkPlayer's OT name / trainerId / version so the
    card matches the LinkPlayerBlock identity (the host's CopyTrainerCardData expects them aligned).
    Layout = struct TrainerCard (0x60) with the structurally-meaningful fields set + wonder-card u16
    at offset 96 (CreateTrainerCardInBuffer's setWonderCard write) + 2 bytes residue."""
    card = bytearray(TRAINER_CARD_BLOCK_SIZE)
    card[TC_OFF_GENDER] = link_player.gender & 0xFF
    # trainerId on the card is the public (low 16 bits) of the 32-bit OT id [trainer_card.c
    # TrainerCard_GenerateCardForLinkPlayer reads GetTrainerId() low half].
    card[TC_OFF_TRAINER_ID:TC_OFF_TRAINER_ID + 2] = \
        (link_player.trainer_id & 0xFFFF).to_bytes(2, "little")
    card[TC_OFF_PLAYER_NAME:TC_OFF_PLAYER_NAME + 8] = \
        charmap.encode(link_player.name, width=8, pad=name_pad)
    # TrainerCard.version is a u8 = gGameVersion (VERSION_FIRE_RED/LEAF_GREEN low byte), NOT the
    # 0x4000-tagged LinkPlayer.version field [trainer_card.c sets card->version = gameVersion].
    card[TC_OFF_VERSION] = link_player.version & 0xFF
    if mon_species:
        for i, sp in enumerate(mon_species[:PARTY_SIZE]):
            o = TC_OFF_MON_SPECIES + i * 2
            card[o:o + 2] = (sp & 0xFFFF).to_bytes(2, "little")
    card[TC_OFF_WONDER_CARD:TC_OFF_WONDER_CARD + 2] = (wonder_card_id & 0xFFFF).to_bytes(2, "little")
    return bytes(card)


def parse_block(b):
    """60+ bytes -> (LinkPlayer, magics_ok). Validates both GameFreak magics like the host."""
    magic1 = b[0:16]
    struct = b[16:44]
    magic2 = b[44:60]
    ok = (magic1[:14] == b"GameFreak inc." and magic2[:14] == b"GameFreak inc.")
    return LinkPlayer.unpack(struct), ok
