"""Gen-3 mon (.pk3) I/O for the trade.

The on-wire 100-byte party `struct Pokemon` (encrypted + shuffled) IS the canonical PKHeX
.pk3 layout, so injecting a chosen mon is essentially a memcpy - no re-encryption. `decode_mon`
below is the checksum oracle (the only validity gate that matters: the 16-bit checksum over the
48-byte secure region; party stats are NOT covered, so they are cosmetic for the trade). It was
originally from a separate sniffing/analysis tool; it lives here so frlgsim has no external dependency.

struct Pokemon (include/pokemon.h, 100B) = BoxPokemon(80B) + party tail:
    [80] status u32  [84] level u8  [85] mail u8  [86] hp u16  [88] maxHP u16
    [90] attack u16  [92] defense u16  [94] speed u16  [96] spAttack u16  [98] spDefense u16

A party block (trade.c BufferTradeParties) = 2 consecutive party mons = 200 bytes; the whole
gPlayerParty is 6 slots (600B) sent as three 200B blocks, empty slots = zeroed struct.
"""

# ── Gen-3 mon decode oracle (checksum + species/text), inlined from a separate
#    traffic-sniffing tool so frlgsim stands alone. ────────────────────────────────
from . import stats

# Substructure order by (personality % 24); each string = logical struct in physical
# slots 0..3.  G=Growth(0) A=Attacks(1) E=EVs(2) M=Misc(3).
SUBSTRUCT_ORDER = [
    "GAEM", "GAME", "GEAM", "GEMA", "GMAE", "GMEA",
    "AGEM", "AGME", "AEGM", "AEMG", "AMGE", "AMEG",
    "EGAM", "EGMA", "EAGM", "EAMG", "EMGA", "EMAG",
    "MGAE", "MGEA", "MAGE", "MAEG", "MEGA", "MEAG",
]

# Gen-3 English charmap (enough for names): space, digits, A-Z, a-z, punctuation, terminator.
_CHARS = {0x00: " ", 0xAB: "!", 0xAC: "?", 0xAD: ".", 0xAE: "-", 0xAF: "·", 0xB0: "…",
          0xB1: "“", 0xB2: "”", 0xB3: "‘", 0xB4: "’", 0xB5: "♂", 0xB6: "♀", 0xB7: "¥",
          0xB8: ",", 0xB9: "×", 0xBA: "/", 0xFF: ""}
for _i in range(10):
    _CHARS[0xA1 + _i] = "0123456789"[_i]
for _i in range(26):
    _CHARS[0xBB + _i] = chr(ord("A") + _i)
    _CHARS[0xD5 + _i] = chr(ord("a") + _i)


def gba_str(b):
    """Decode a Gen-3 name field (0xFF terminator) to display text."""
    out = []
    for x in b:
        if x == 0xFF:
            break
        out.append(_CHARS.get(x, "."))
    return "".join(out)


def load_species(decomp="~/Git/pokefirered"):
    """Map INTERNAL species index -> name from the decomp's species.h. NOTE: the internal
    index is NOT the National Dex number in general -- they coincide only for #1-251
    (...SPECIES_CELEBI=251); 252-276 are the OLD_UNOWN gap and Hoenn starts at
    SPECIES_TREECKO=277 (= National Dex #252). PKHeX maps the internal index itself, so for
    identifying a carved mon we want this name map, not a dex number. Absent the decomp, a
    tiny fallback keeps species_name useful for the common trade mons."""
    import os
    import re
    path = os.path.expanduser(os.path.join(decomp, "include/constants/species.h"))
    m = {}
    try:
        for line in open(path):
            g = re.match(r"#define SPECIES_(\w+)\s+(\d+)", line.strip())
            if g:
                m.setdefault(int(g.group(2)), g.group(1))
    except OSError:
        m = {4: "CHARMANDER", 5: "CHARMELEON", 16: "PIDGEY", 19: "RATTATA"}  # fallback
    return m


SPECIES = load_species()


def decode_mon(mon):
    """mon = >=80 bytes. Returns a decoded dict, or None if too short."""
    if len(mon) < 80:
        return None
    pid = int.from_bytes(mon[0:4], "little")
    otid = int.from_bytes(mon[4:8], "little")
    key = pid ^ otid
    sec = bytearray(mon[32:80])
    for i in range(12):
        v = (int.from_bytes(sec[i * 4:i * 4 + 4], "little") ^ key) & 0xFFFFFFFF
        sec[i * 4:i * 4 + 4] = v.to_bytes(4, "little")
    calc = sum(int.from_bytes(sec[i * 2:i * 2 + 2], "little") for i in range(24)) & 0xFFFF
    stored = int.from_bytes(mon[28:30], "little")
    order = SUBSTRUCT_ORDER[pid % 24]
    growth = sec[order.index("G") * 12:][:12]
    attacks = sec[order.index("A") * 12:][:12]
    species = int.from_bytes(growth[0:2], "little")
    return {
        "pid": pid, "otid": otid,
        "nickname": gba_str(mon[8:18]),
        "otName": gba_str(mon[20:27]),
        "language": mon[18],
        "checksum_ok": calc == stored,
        "stored": stored, "calc": calc,
        "species": species, "species_name": SPECIES.get(species, f"#{species}"),
        "heldItem": int.from_bytes(growth[2:4], "little"),
        "exp": int.from_bytes(growth[4:8], "little"),
        "moves": [int.from_bytes(attacks[i * 2:i * 2 + 2], "little") for i in range(4)],
        "level": mon[84] if len(mon) >= 100 else None,
    }

BOX_SIZE = 80
PARTY_MON_SIZE = 100
PARTY_SIZE = 6
PARTY_BLOCK_SIZE = 200          # 2 mons; BLOCK_REQ_200, count=17
SECURE_OFF = 32                 # 48-byte encrypted+shuffled substruct region
SECURE_END = 80


# --- Gen-3 mon encryption (the difference between a PKHeX .pk3 and .ek3) ---------------------
# .ek3 (encrypted) = the raw save/link/wire format: 48-byte secure region XOR'd by PID^OTID and
# the four substructs SHUFFLED by PID%24. .pk3 (decrypted) = secure region XOR-removed and
# substructs UN-shuffled to canonical G,A,E,M order. Header (incl. checksum) + party tail are
# plaintext in both. The trade tunnels the .ek3 form; we convert so either file works.
def _xor_secure(buf, key):
    out = bytearray(buf)
    for i in range(12):
        o = SECURE_OFF + i * 4
        v = (int.from_bytes(out[o:o + 4], "little") ^ key) & 0xFFFFFFFF
        out[o:o + 4] = v.to_bytes(4, "little")
    return out


def to_decrypted(wire):
    """encrypted+shuffled (.ek3 / wire) -> decrypted canonical (.pk3)."""
    pid = int.from_bytes(wire[0:4], "little")
    key = pid ^ int.from_bytes(wire[4:8], "little")
    dec = _xor_secure(wire, key)                       # XOR-decrypt the secure region
    order = SUBSTRUCT_ORDER[pid % 24]
    sec = dec[SECURE_OFF:SECURE_END]
    canon = bytearray(48)
    for ci, letter in enumerate("GAEM"):               # un-shuffle to canonical order
        p = order.index(letter)
        canon[ci * 12:ci * 12 + 12] = sec[p * 12:p * 12 + 12]
    dec[SECURE_OFF:SECURE_END] = canon
    return bytes(dec)


def to_encrypted(pk3):
    """decrypted canonical (.pk3) -> encrypted+shuffled (.ek3 / wire)."""
    pid = int.from_bytes(pk3[0:4], "little")
    key = pid ^ int.from_bytes(pk3[4:8], "little")
    order = SUBSTRUCT_ORDER[pid % 24]
    canon = pk3[SECURE_OFF:SECURE_END]
    shuf = bytearray(48)
    for p in range(4):                                 # shuffle into PID%24 physical order
        ci = "GAEM".index(order[p])
        shuf[p * 12:p * 12 + 12] = canon[ci * 12:ci * 12 + 12]
    out = bytearray(pk3)
    out[SECURE_OFF:SECURE_END] = shuf
    return bytes(_xor_secure(out, key))                # XOR-encrypt the secure region


def _wire_valid(b):
    d = decode_mon(b)
    return bool(d and d["checksum_ok"])


class Mon:
    """One Pokémon, held as its 100-byte party struct (the .pk3 wire form)."""

    def __init__(self, party100):
        if len(party100) != PARTY_MON_SIZE:
            raise ValueError(f"party mon must be {PARTY_MON_SIZE} bytes, got {len(party100)}")
        self.raw = bytes(party100)

    # ---- construction -------------------------------------------------------
    @classmethod
    def from_pk3(cls, data):
        """Accept a PKHeX mon in EITHER form - .ek3 (encrypted, the raw save/wire format) or
        .pk3 (decrypted) - in 80-byte box or 100-byte party size. Auto-detects: if the bytes
        already checksum-validate they are the encrypted wire form; otherwise they are decrypted
        and we encrypt+shuffle them. A box export carries no party tail (level/stats), so we derive
        it from the box data - both an 80-byte box widened to 100B and a 100-byte export with a
        zeroed tail otherwise show as level 0 on the receiver. Internally a Mon always holds the
        wire form."""
        data = bytes(data)
        if len(data) not in (BOX_SIZE, PARTY_MON_SIZE):
            raise ValueError(f".pk3/.ek3 must be {BOX_SIZE} or {PARTY_MON_SIZE} bytes, "
                             f"got {len(data)}")
        # key = personality ^ otId; when 0 (PID==OTID) the XOR is identity, so the .pk3 (decrypted,
        # canonical substruct order) and .ek3 (shuffled by PID%24) are INDISTINGUISHABLE by checksum -
        # _wire_valid passes for BOTH, and trusting it ships an UN-shuffled mon the host rejects.
        # Assume the common INJECTION case (a decrypted PKHeX .pk3) and (re)build the wire form;
        # for a key==0 .ek3 pass a key!=0 mon or use the .ek3 path explicitly.
        key = int.from_bytes(data[0:4], "little") ^ int.from_bytes(data[4:8], "little")
        if _wire_valid(data) and key != 0:
            wire = data                                # already .ek3 (encrypted)
        else:
            enc = to_encrypted(data)                   # treat as .pk3 (decrypted) -> shuffle + encrypt
            wire = enc if _wire_valid(enc) else data   # fall back to as-is (e.g. bad egg)
        if len(wire) == BOX_SIZE:
            # Widen an 80B box to 100B party. Default mail = MAIL_NONE (0xFF): a zeroed mail byte
            # reads as mail slot 0, which the host treats as real mail on the OFFERED mon. The tail
            # recompute below overwrites this with the full tail when stats are derivable.
            wire = bytearray(wire) + b"\x00" * (PARTY_MON_SIZE - BOX_SIZE)
            wire[85] = 0xFF                            # struct Pokemon.mail = MAIL_NONE
            wire = bytes(wire)
        # A missing party tail (box export / widened box) reads as level 0 with zero stats on the
        # receiver. Derive level + stats from the box data when, and only when, the tail is absent
        # (level byte 0); a valid party export keeps its own tail. The tail is not checksummed.
        if _wire_valid(wire) and wire[84] == 0:
            tail = stats.build_party_tail(to_decrypted(wire))
            if tail is not None:
                wire = wire[:BOX_SIZE] + tail
        return cls(wire)

    @classmethod
    def from_file(cls, path):
        with open(path, "rb") as f:
            return cls.from_pk3(f.read())

    @classmethod
    def empty(cls):
        """A zeroed struct Pokemon (SPECIES_NONE) - an empty party slot."""
        return cls(b"\x00" * PARTY_MON_SIZE)

    # ---- bytes --------------------------------------------------------------
    def party_bytes(self):
        return self.raw

    def box_bytes(self):
        return self.raw[:BOX_SIZE]

    # ---- decode / validate (checksum oracle) --------------------------------
    def decode(self):
        return decode_mon(self.raw)

    @property
    def is_empty(self):
        return int.from_bytes(self.raw[0:8], "little") == 0

    @property
    def checksum_ok(self):
        d = self.decode()
        return bool(d and d["checksum_ok"])

    @property
    def species(self):
        d = self.decode()
        return d["species"] if d else None

    @property
    def species_name(self):
        d = self.decode()
        return d["species_name"] if d else "?"

    @property
    def pid(self):
        return int.from_bytes(self.raw[0:4], "little")

    @property
    def otid(self):
        return int.from_bytes(self.raw[4:8], "little")

    @property
    def nickname(self):
        d = self.decode()
        return d["nickname"] if d else ""

    @property
    def ot_name(self):
        d = self.decode()
        return d["otName"] if d else ""

    def describe(self):
        d = self.decode()
        if not d:
            return "<undecodable>"
        ck = "OK" if d["checksum_ok"] else f"BAD({d['calc']:04x}!={d['stored']:04x})"
        return (f"{d['species_name']} (#{d['species']}) nick={d['nickname']!r} "
                f"OT={d['otName']!r} PID={d['pid']:08x} lv={d['level']} checksum={ck}")

    # ---- save ---------------------------------------------------------------
    def save_pk3(self, path, size=PARTY_MON_SIZE):
        """Write the DECRYPTED .pk3 (opens directly in PKHeX)."""
        if size not in (BOX_SIZE, PARTY_MON_SIZE):
            raise ValueError("size must be 80 (box) or 100 (party)")
        with open(path, "wb") as f:
            f.write(to_decrypted(self.raw)[:size])
        return path

    def save_ek3(self, path, size=PARTY_MON_SIZE):
        """Write the ENCRYPTED .ek3 (raw save/wire bytes)."""
        if size not in (BOX_SIZE, PARTY_MON_SIZE):
            raise ValueError("size must be 80 (box) or 100 (party)")
        with open(path, "wb") as f:
            f.write(self.raw[:size])
        return path


def build_player_party(mons):
    """List[Mon] -> the 600-byte gPlayerParty buffer (6 slots, empties zeroed)."""
    if len(mons) > PARTY_SIZE:
        raise ValueError(f"party holds at most {PARTY_SIZE} mons")
    buf = bytearray(PARTY_MON_SIZE * PARTY_SIZE)
    for i, m in enumerate(mons):
        buf[i * PARTY_MON_SIZE:(i + 1) * PARTY_MON_SIZE] = m.party_bytes()
    return bytes(buf)


def party_blocks(party600):
    """The three 200-byte party blocks the trade FSM streams (gPlayerParty[0..1]/[2..3]/[4..5])."""
    return [party600[i:i + PARTY_BLOCK_SIZE] for i in range(0, 600, PARTY_BLOCK_SIZE)]
