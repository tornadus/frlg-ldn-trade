"""Gen-3 (FRLG) level and stat calculation.

A boxed mon stores only experience and IVs/EVs; its level and the six battle stats are derived when
it enters a party. `build_party_tail` reconstructs that 20-byte party tail (level + stats) from a
mon's box data so a box-sourced .pk3 trades with the correct shown level/stats instead of level 0.
"""

from . import basestats

MAX_LEVEL = 100

# Two species whose stats are not the plain formula.
SHEDINJA = 303          # HP is always 1.
DEOXYS = 410            # Form-dependent bases; FRLG uses the Attack forme for the five non-HP stats.
DEOXYS_FORME = {"atk": 180, "def": 20, "spe": 150, "spa": 180, "spd": 20}


def _build_exp_tables():
    """EXP_TABLES[growthRate][level] = total experience required to be that level (level 0..100).
    growthRate: 0=MediumFast 1=Erratic 2=Fluctuating 3=MediumSlow 4=Fast 5=Slow."""
    def medium_fast(n):
        return n ** 3

    def erratic(n):
        if n <= 50:
            return (100 - n) * n ** 3 // 50
        if n <= 68:
            return (150 - n) * n ** 3 // 100
        if n <= 98:
            return ((1911 - 10 * n) // 3) * n ** 3 // 500
        return (160 - n) * n ** 3 // 100

    def fluctuating(n):
        if n <= 15:
            return ((n + 1) // 3 + 24) * n ** 3 // 50
        if n <= 36:
            return (n + 14) * n ** 3 // 50
        return ((n // 2) + 32) * n ** 3 // 50

    def medium_slow(n):
        return 6 * n ** 3 // 5 - 15 * n ** 2 + 100 * n - 140

    def fast(n):
        return 4 * n ** 3 // 5

    def slow(n):
        return 5 * n ** 3 // 4

    curves = [medium_fast, erratic, fluctuating, medium_slow, fast, slow]
    tables = []
    for curve in curves:
        # Levels 0 and 1 are fixed at 0 and 1; the curve gives levels 2..100.
        tables.append([0, 1] + [curve(n) for n in range(2, MAX_LEVEL + 1)])
    return tables


EXP_TABLES = _build_exp_tables()

# Per-nature stat modifiers over (Attack, Defense, Speed, Sp.Atk, Sp.Def): +1 = x1.1, -1 = x0.9.
# Nature = personality % 25. HP is never affected.
NATURE_STAT_TABLE = [
    [0, 0, 0, 0, 0], [1, -1, 0, 0, 0], [1, 0, -1, 0, 0], [1, 0, 0, -1, 0], [1, 0, 0, 0, -1],
    [-1, 1, 0, 0, 0], [0, 0, 0, 0, 0], [0, 1, -1, 0, 0], [0, 1, 0, -1, 0], [0, 1, 0, 0, -1],
    [-1, 0, 1, 0, 0], [0, -1, 1, 0, 0], [0, 0, 0, 0, 0], [0, 0, 1, -1, 0], [0, 0, 1, 0, -1],
    [-1, 0, 0, 1, 0], [0, -1, 0, 1, 0], [0, 0, -1, 1, 0], [0, 0, 0, 0, 0], [0, 0, 0, 1, -1],
    [-1, 0, 0, 0, 1], [0, -1, 0, 0, 1], [0, 0, -1, 0, 1], [0, 0, 0, -1, 1], [0, 0, 0, 0, 0],
]


def level_from_exp(species, exp):
    """The level a mon of this species has at the given total experience."""
    growth = basestats.BASE_STATS[species][6]
    table = EXP_TABLES[growth]
    level = 1
    while level <= MAX_LEVEL and table[level] <= exp:
        level += 1
    return level - 1


def modify_stat_by_nature(nature, value, stat_index):
    """Apply a nature's +10%/-10%/none modifier. stat_index 0..4 = Atk,Def,Speed,Sp.Atk,Sp.Def."""
    mod = NATURE_STAT_TABLE[nature][stat_index]
    if mod == 1:
        return value * 110 // 100
    if mod == -1:
        return value * 90 // 100
    return value


def _stat(base, iv, ev, level):
    return ((2 * base + iv + ev // 4) * level) // 100 + 5


def build_party_tail(canon):
    """Build the 20-byte party tail (status, level, mail, hp, maxHP, atk, def, speed, spAtk, spDef)
    from the DECRYPTED canonical 100-byte mon. Returns None if the species has no base-stat entry
    (e.g. an invalid index), so the caller can leave the existing tail untouched."""
    pid = int.from_bytes(canon[0:4], "little")
    sec = canon[32:80]                                  # canonical substruct order G, A, E, M
    growth, evs, misc = sec[0:12], sec[24:36], sec[36:48]
    species = int.from_bytes(growth[0:2], "little")
    if species not in basestats.BASE_STATS:
        return None
    exp = int.from_bytes(growth[4:8], "little")
    ev = list(evs[0:6])                                 # HP, Atk, Def, Speed, Sp.Atk, Sp.Def
    iv_word = int.from_bytes(misc[4:8], "little")
    iv = [(iv_word >> (5 * i)) & 0x1F for i in range(6)]
    nature = pid % 25
    level = level_from_exp(species, exp)
    base = basestats.BASE_STATS[species]                # (hp, atk, def, spe, spa, spd, growth)

    if species == SHEDINJA:
        hp = 1
    else:
        hp = ((2 * base[0] + iv[0] + ev[0] // 4) * level) // 100 + level + 10

    nonhp = dict(zip(("atk", "def", "spe", "spa", "spd"), base[1:6]))
    if species == DEOXYS:
        nonhp.update(DEOXYS_FORME)
    atk = modify_stat_by_nature(nature, _stat(nonhp["atk"], iv[1], ev[1], level), 0)
    dfn = modify_stat_by_nature(nature, _stat(nonhp["def"], iv[2], ev[2], level), 1)
    spe = modify_stat_by_nature(nature, _stat(nonhp["spe"], iv[3], ev[3], level), 2)
    spa = modify_stat_by_nature(nature, _stat(nonhp["spa"], iv[4], ev[4], level), 3)
    spd = modify_stat_by_nature(nature, _stat(nonhp["spd"], iv[5], ev[5], level), 4)

    tail = bytearray(20)                                # [0:4] status = 0
    tail[4] = level
    tail[5] = 0xFF                                      # mail = MAIL_NONE
    for off, val in ((6, hp), (8, hp), (10, atk), (12, dfn), (14, spe), (16, spa), (18, spd)):
        tail[off:off + 2] = int(val).to_bytes(2, "little")
    return bytes(tail)
