"""FRLG AgbRfu command slot - the 14-byte (7x u16 LE) unit the child emits once per VBlank.

Implements ChildBuildSendCmd [src/link_rfu_2.c:944-962] and the OUT opcode set.
The rolling tag (childSendCmdId, 0..7) lives in bits 5-7 of word0's low byte and advances +1
mod 8 on every NON-idle slot; the host hard-errors after >4 bad ids [link_rfu_2.c:884-888].
Idle = 14 zero bytes and does NOT advance the tag.
"""

COMM_SLOT_LENGTH = 14
RFUCMD_MASK = 0xFF00
FRAG_INDEX_MASK = 0x1F          # SEND_BLOCK index = low 5 bits (tag is bits 5-7)

# OUT opcodes the sim emits (high byte of word0).
IDLE = 0x0000
SEND_BLOCK_INIT = 0x8800
SEND_BLOCK = 0x8900
SEND_HELD_KEYS = 0xBE00
READY_EXIT_STANDBY = 0x6600
READY_CLOSE_LINK = 0x5F00
# IN-only (we react, never emit):
SEND_BLOCK_REQ = 0xA100
SEND_PLAYER_IDS = 0x7700      # host broadcasts playerCount + ids[] right after the NI handshake
DISCONNECT = 0xED00

RFUCMD_NAMES = {
    0x0000: "IDLE", 0x2F00: "SEND_PACKET", 0x5F00: "READY_CLOSE_LINK",
    0x6600: "READY_EXIT_STANDBY", 0x7700: "SEND_PLAYER_IDS", 0x7800: "SEND_PLAYER_IDS_NEW",
    0x8800: "SEND_BLOCK_INIT", 0x8900: "SEND_BLOCK", 0xA100: "SEND_BLOCK_REQ",
    0xBE00: "SEND_HELD_KEYS", 0xED00: "DISCONNECT", 0xEE00: "DISCONNECT_PARENT",
}

OWNER_FLAG = 0x80               # owner word2 = mpId | 0x80  (joiner owner=1 -> 0x81)

# librfu Link-Layer Sub-Frame (LLSF) command states [include/librfu.h:249-253].
LCOM_NULL, LCOM_NI_START, LCOM_NI, LCOM_NI_END, LCOM_UNI = 0, 1, 2, 3, 4
# CHILD LLSF shifts [llsf_struct[MODE_CHILD], librfu_rfu.c:79-94]: frameSize=2 (the LLSF header is a
# 2-byte LE word) state<<10 ack<<9 n<<7 phase<<5 | size.
CHILD_LLSF_STATE_SHIFT, CHILD_LLSF_ACK_SHIFT = 10, 9
CHILD_LLSF_N_SHIFT, CHILD_LLSF_PHASE_SHIFT = 7, 5
# PARENT LLSF [MODE_PARENT]: frameSize=3 state<<14 bmSlot<<18 ack<<13 n<<11 phase<<9 | size.
PARENT_LLSF_STATE_SHIFT = 14


def uni_slot(cmd14):
    """Wrap a 14-byte gSendCmd in a CHILD UNI link-layer sub-frame: a 2-byte LLSF word
    (LCOM_UNI<<10 | payloadSize) then the command [rfu_STC_UNI_constructLLSF, librfu_rfu.c:1872].
    For a 14-byte cmd: (4<<10)|14 = 0x100e -> bytes `0e 10`, total slot 16 bytes (matches the reference capture)."""
    cmd = bytes(cmd14)
    llsf = (LCOM_UNI << CHILD_LLSF_STATE_SHIFT) | len(cmd)
    return llsf.to_bytes(2, "little") + cmd


# PARENT LLSF field shifts/masks [llsf_struct[MODE_PARENT], librfu_rfu.c:95-110]: frameSize=3 (a
# 3-byte LE header), state<<14, ack<<13, n<<11, phase<<9, connSlotFlag(bmSlot)<<18, recvFirst<<22,
# size in the low 7 bits (framesMask 0x7f).
PARENT_LLSF_ACK_SHIFT, PARENT_LLSF_N_SHIFT = 13, 11
PARENT_LLSF_PHASE_SHIFT, PARENT_LLSF_BMSLOT_SHIFT = 9, 18
PARENT_FRAME_SIZE = 3
COMM_TABLE_LENGTH = 70          # gRfu.recvCmds[5][7][2] = 5 rows x 14 bytes, the parent UNI payload


def _parent_llsf(state, size, *, ack=0, n=0, phase=0, bm_slot=1):
    """Build a 3-byte PARENT LLSF header (LE) [rfu_STC_*_constructLLSF, MODE_PARENT branch,
    librfu_rfu.c:1843-1852,1884-1890]. For UNI only state+size(+bmSlot) are set; NI adds ack/n/phase."""
    frame = ((state & 0xF) << PARENT_LLSF_STATE_SHIFT) | ((ack & 1) << PARENT_LLSF_ACK_SHIFT) \
        | ((n & 3) << PARENT_LLSF_N_SHIFT) | ((phase & 3) << PARENT_LLSF_PHASE_SHIFT) \
        | ((bm_slot & 0xF) << PARENT_LLSF_BMSLOT_SHIFT) | (size & 0x7F)
    return (frame & 0xFFFFFF).to_bytes(PARENT_FRAME_SIZE, "little")


def parent_uni_slot(recv_cmds, bm_slot=1):
    """Wrap the parent's 70-byte gRecvCmds echo table in a PARENT UNI sub-frame [InitParentSendData
    -> rfu_UNI_setSendData(acceptSlot, gRfu.recvCmds, 70), rfu_STC_UNI_constructLLSF]: a 3-byte LLSF
    (LCOM_UNI<<14 | payloadSize | bmSlot<<18) then the table. `bm_slot` = the connected-child slot
    bitmask (1 for a single child in RFU slot 0). This is broadcast every frame while linked."""
    payload = bytes(recv_cmds).ljust(COMM_TABLE_LENGTH, b"\x00")[:COMM_TABLE_LENGTH]
    return _parent_llsf(LCOM_UNI, len(payload), bm_slot=bm_slot) + payload


def parent_ni_llsf(state, n, phase, ack, size, bm_slot=1):
    """Build a PARENT NI sub-frame LLSF header (3-byte LE) — the parent's side of the NI handshake
    (delivering the 1-byte join status, rfu_NI_setSendData). Mirrors child_ni_llsf but MODE_PARENT."""
    return _parent_llsf(state, size, ack=ack, n=n, phase=phase, bm_slot=bm_slot)


def pack_recv_cmds(rows):
    """Pack up to 5 player rows (each a 14-byte gSendCmd slot, or b"" for an empty row) into the
    70-byte gRecvCmds table. Row 0 = the parent's own gSendCmd; row 1 = the child (player 1);
    rows 2-4 zero for a 2-player link [ReadAllPlayerRecvCmds, link_rfu_2.c:743]."""
    out = bytearray(COMM_TABLE_LENGTH)
    for i, row in enumerate(rows[:5]):
        r = bytes(row)[:COMM_SLOT_LENGTH]
        out[i * COMM_SLOT_LENGTH:i * COMM_SLOT_LENGTH + len(r)] = r
    return bytes(out)


def child_ni_llsf(state, n, phase, ack, size):
    """Build a CHILD NI link-layer sub-frame header (2-byte LE) [rfu_STC_NI_constructLLSF,
    librfu_rfu.c:1843]: (state&0xF)<<10 | ack<<9 | n<<7 | phase<<5 | size."""
    frame = ((state & 0xF) << CHILD_LLSF_STATE_SHIFT) | ((ack & 1) << CHILD_LLSF_ACK_SHIFT) \
        | ((n & 3) << CHILD_LLSF_N_SHIFT) | ((phase & 3) << CHILD_LLSF_PHASE_SHIFT) | (size & 0x1F)
    return frame.to_bytes(2, "little")


def parse_llsf_child(slot):
    """Decode a 2-byte CHILD LLSF header -> dict(state,ack,n,phase,size). (For parsing our own /
    a child's sub-frames.)"""
    f = int.from_bytes(slot[0:2], "little")
    return {"state": (f >> CHILD_LLSF_STATE_SHIFT) & 0xF, "ack": (f >> CHILD_LLSF_ACK_SHIFT) & 1,
            "n": (f >> CHILD_LLSF_N_SHIFT) & 3, "phase": (f >> CHILD_LLSF_PHASE_SHIFT) & 3,
            "size": f & 0x1F}


def _words_to_slot(words):
    w = list(words) + [0] * (7 - len(words))
    return b"".join((x & 0xFFFF).to_bytes(2, "little") for x in w[:7])


def idle_slot():
    return b"\x00" * COMM_SLOT_LENGTH


def serialize(words):
    """Serialize 7 gSendCmd words to a 14-byte slot WITHOUT a rolling tag (the PARENT path /
    test harness; the child uses SlotBuilder which adds the tag)."""
    return _words_to_slot(words)


def init_words(count, owner=1):
    """SEND_BLOCK_INIT slot words (pre-tag): w0=0x8800, w1=count, w2=owner|0x80."""
    return [SEND_BLOCK_INIT, count & 0xFFFF, (owner | OWNER_FLAG) & 0xFFFF, 0, 0, 0, 0]


def send_block_words(index, chunk12):
    """SEND_BLOCK slot words (pre-tag): w0=0x8900|index, w1..w6 = 12 payload bytes (6 u16 LE)."""
    c = bytes(chunk12[:12]).ljust(12, b"\x00")
    return [SEND_BLOCK | (index & FRAG_INDEX_MASK)] + \
        [int.from_bytes(c[i:i + 2], "little") for i in range(0, 12, 2)]


def held_keys_words(keycode=0):
    return [SEND_HELD_KEYS, keycode & 0xFFFF, 0, 0, 0, 0, 0]


BLOCK_REQ_SIZE_NONE = 0         # blockRequestType for the player-exchange block req [link.c BLOCK_REQ_*]


def send_player_ids_words(link_player_idx=(1, 0, 0, 0), player_count=2):
    """PARENT SEND_PLAYER_IDS (0x7700) slot words [RfuPrepareSendBuffer, link_rfu_2.c:1298-1305]:
    w0=0x7700, w1=playerCount, then buff=(u8*)&gSendCmd[2] holds linkPlayerIdx[0..3]. A single child
    in RFU slot 0 gets linkPlayerIdx=[1,0,0,0] (baseId 1, link_rfu_2.c:388), so the child reads its
    mpId=linkPlayerIdx[childSlot=0]=1 (LoadLinkPlayerIds), matching MysteryGiftClient_Init(1,0)."""
    idx = list(link_player_idx)[:4] + [0] * (4 - len(link_player_idx))
    w2 = (idx[0] & 0xFF) | ((idx[1] & 0xFF) << 8)
    w3 = (idx[2] & 0xFF) | ((idx[3] & 0xFF) << 8)
    return [SEND_PLAYER_IDS, player_count & 0xFFFF, w2, w3, 0, 0, 0]


def send_block_req_words(reqtype=BLOCK_REQ_SIZE_NONE):
    """PARENT SEND_BLOCK_REQ (0xA100) slot words [RfuPrepareSendBuffer, link_rfu_2.c:1294-1296]:
    w0=0xA100, w1=blockRequestType. reqtype NONE(0) makes both sides Rfu_InitBlockSend(...,200) so
    each block-sends its 60-byte LinkPlayerBlock during the player exchange (link_rfu_2.c:1172)."""
    return [SEND_BLOCK_REQ, reqtype & 0xFFFF, 0, 0, 0, 0, 0]


def exit_standby_words(count):
    """READY_EXIT_STANDBY slot words (pre-tag): w0=0x6600, w1=resendExitStandbyCount, rest 0
    [RfuPrepareSendBuffer link_rfu_2.c:1307-1310]. The child's reply word1 MUST equal the round
    number the host is currently broadcasting, else the host's recv gate (link_rfu_2.c:1178-1180)
    ignores it. SlotBuilder applies + advances the rolling tag (this is a NON-idle slot)."""
    return [READY_EXIT_STANDBY, count & 0xFFFF, 0, 0, 0, 0, 0]


def close_link_words(count):
    """READY_CLOSE_LINK slot words (pre-tag): w0=0x5F00, w1=resendExitStandbyCount - CONTINUES the
    standby round counter (the reference capture: CLOSE=13 right after the seat STANDBY=12), it is NOT a static tag;
    the host's recv side accepts any count (marks readyCloseLink[i]=TRUE unconditionally,
    link_rfu_2.c:1175-1176), so barrier.py mirroring the host's count is correct."""
    return [READY_CLOSE_LINK, count & 0xFFFF, 0, 0, 0, 0, 0]


class SlotBuilder:
    """Serializes gSendCmd words -> 14-byte slot, applying + advancing the rolling tag.
    One instance per outgoing link (the child's childSendCmdId)."""

    def __init__(self):
        self.tag = 0            # childSendCmdId

    def build(self, words):
        """words = 7-int gSendCmd (word0 carries opcode|args, NO tag yet). Idle (word0==0)
        emits 14 zeros and leaves the tag untouched."""
        if (words[0] & 0xFFFF) == 0:
            return idle_slot()
        w = list(words)
        w[0] = (w[0] | (self.tag << 5)) & 0xFFFF
        slot = _words_to_slot(w)
        self.tag = (self.tag + 1) & 7
        return slot


def parse_slot(slot):
    """Decode a received (IN) 14-byte slot. The PARENT applies no child-tag to its own
    blocks; reflected child blocks may carry the child tag, so we strip it for the index
    (real indices < 32). Returns a dict or None for an empty/short slot."""
    if len(slot) < 2:
        return None
    if slot[:COMM_SLOT_LENGTH] == b"\x00" * min(len(slot), COMM_SLOT_LENGTH):
        return None
    word0 = int.from_bytes(slot[0:2], "little")
    op = word0 & RFUCMD_MASK
    rec = {"word0": word0, "op": op, "name": RFUCMD_NAMES.get(op, f"0x{op:04x}"),
           "low": word0 & 0xFF}
    if op == SEND_BLOCK_INIT:
        rec["count"] = int.from_bytes(slot[2:4], "little")
        owner_raw = slot[4]
        rec["owner_raw"] = owner_raw
        rec["peer"] = owner_raw & 0x7F            # mpId: 0 host (0x80) / 1 reflected (0x81)
    elif op == SEND_BLOCK:
        rec["index"] = word0 & FRAG_INDEX_MASK
        rec["frag"] = bytes(slot[2:14]).ljust(12, b"\x00")
    elif op == SEND_BLOCK_REQ:
        # BLOCK_REQ_* selector lives in word1 (gSendCmd[1] = gRfu.blockRequestType,
        # link_rfu_2.c:1296; received as gRecvCmds[i][1], link_rfu_2.c:1173) = slot[2:4] LE,
        # NOT word0's low byte (word0 is exactly RFUCMD_SEND_BLOCK_REQ=0xA100). Verified vs the reference capture:
        # the card pull is `00 a1 02 00..`, mail `00 a1 03 00..`, ribbons `00 a1 04 00..`.
        rec["reqtype"] = int.from_bytes(slot[2:4], "little")
    elif op == SEND_HELD_KEYS:
        rec["keycode"] = int.from_bytes(slot[2:4], "little")
    elif op in (READY_EXIT_STANDBY, READY_CLOSE_LINK):
        # word1 = resendExitStandbyCount: the round number the host advertises [link_rfu_2.c:1309].
        rec["count"] = int.from_bytes(slot[2:4], "little")
    return rec
