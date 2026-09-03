"""librfu NI (reliable, acknowledged) sender state machine - the CHILD's post-'A' game-data
handshake [src/librfu_rfu.c rfu_STC_NI_constructLLSF:1808, rfu_STC_setSendData_org:1423].

After the host accepts our emulator connect ('A'), the real child runs the librfu NI sender to
deliver its RfuGameData ("connection-all-slots", rfu_NI_CreateConnectionAllSlots,
src/librfu_rfu.c:1418-1421: ni_or_uni=0x40, dataType=1, src=&my.serialNo, dataSize=26) before any
UNI trade traffic. The NI machine windows the data over WINDOW_COUNT=4 phases with per-phase n[]
sequence numbers and per-phase retransmit; since Pia Reliable already guarantees delivery + order
under us, this is a FAITHFUL SINGLE-PASS sender (each sub-frame emitted exactly once, no retransmit
window) that reproduces the same frame SEQUENCE the real child puts on the wire.

Verified byte-exact vs the reference capture (a real working trade); see the test suite. The emitted
CHILD NI sub-frame sequence for the 26-byte game data (payloadSize 12) is:

    NI_START n=1 ph=0 sz=7  pay = <7-byte NI header: dataType, payloadSize u16 LE, dataSize u32 LE>
    NI       n=1 ph=0 sz=12 pay = src[0:12]
    NI       n=1 ph=1 sz=12 pay = src[12:24]
    NI       n=1 ph=2 sz=2  pay = src[24:26]
    NI_END   n=0 ph=0 sz=0
    NULL     n=1 ph=0 sz=0

The slot = rfu.child_ni_llsf(state, n, phase, ack, size) (2-byte LE LLSF) + payload, wrapped into a
'T' frame by gbaframe.wrap_t. ack=0 (these are our OUTGOING NI data sub-frames; the ack=1 frames in
the capture are the child's RECV-side NI acking the HOST's NI - handled separately by the recv path).

The NI machine [setSendData_org]:
  * now_p[0] = &dataType; remainSize = 7   (the NI_START sends a 7-byte header first)
  * payloadSize = subFrameSize - frameSize = 14 - 2 = 12   (CHILD frameSize is 2)
  * SLOT_STATE_SEND_START -> emit NI_START with the header (size = min(remainSize, payloadSize) = 7,
    since remainSize 7 < payloadSize 12); on ack, transition to SLOT_STATE_SENDING with
    remainSize = dataSize, now_p[i] = src + payloadSize*i, n[i] = 1.
  * SLOT_STATE_SENDING -> window src over 4 phases, payloadSize bytes each, in phase order until the
    whole dataSize is sent (here: 12 @ph0, 12 @ph1, 2 @ph2); then SLOT_STATE_SEND_LAST.
  * SLOT_STATE_SEND_LAST -> emit NI_END (n=0, size=0); then SLOT_STATE_SEND_NULL.
  * SLOT_STATE_SEND_NULL -> emit NULL (n=1, size=0); done.
"""

from . import rfu, charmap, linkplayer

# librfu NI slot states [include/librfu.h SLOT_STATE_*; the LCOM_* the LLSF carries].
SLOT_STATE_SEND_START = "SEND_START"   # emits LCOM_NI_START
SLOT_STATE_SENDING = "SENDING"          # emits LCOM_NI
SLOT_STATE_SEND_LAST = "SEND_LAST"      # emits LCOM_NI_END
SLOT_STATE_SEND_NULL = "SEND_NULL"      # emits LCOM_NULL
SLOT_STATE_DONE = "DONE"

WINDOW_COUNT = 4
CHILD_FRAME_SIZE = 2                     # llsf_struct[MODE_CHILD].frameSize
RFU_SERIAL_GAME = 0x0002                 # RFU_SERIAL_GAME [include/link_rfu.h:24]
RFU_STATUS_JOIN_GROUP_OK = 5             # host accepted our join [include/link_rfu.h:40]; any other
#                                          recv-NI status byte (JOIN_GROUP_NO/CONNECTION_ERROR/...) = reject
NI_HEADER_SIZE = 7                       # dataType(1) + payloadSize(2) + dataSize(4) [remainSize=7]

# RfuGameData compatibility bit layout [include/link_rfu.h:81-93] - all in the first u16 (LE).
ACTIVITY_TRADE = 0x04                    # gRfuGameData.activity for a trade [link_rfu.h activity:7]


def build_game_data(version_low, trainer_id, ot_name, *, language=linkplayer.LANGUAGE_ENGLISH,
                    activity=ACTIVITY_TRADE, started=True, partner_info=b"\x00\x00\x00\x00"):
    """Construct the 26-byte NI game-data src for rfu_NI_CreateConnectionAllSlots
    (&gRfuLinkStatus->my.serialNo, dataSize 26) from OUR sim identity, NOT hardcoded reference-capture bytes:
        serialNo(2 LE) + gname[15] + uname[9]
    where gname[0:13] = struct RfuGameData (packed): compatibility(u16 LE: language:4 ... version:4),
    partnerInfo[4], tradeSpecies:10|tradeType:6 (u16), activity:7|startedActivity:1 (u8), gender/level
    (u8), padding(u8); gname is then 0-padded to 15. uname = the OT name charmap-encoded to 9 bytes.

    `version_low` = gGameVersion (4=FireRed, 5=LeafGreen); `trainer_id` = the 16-bit public OT id
    written into compatibility.playerTrainerId; `ot_name` = the trainer name (the uname). Verified:
    build_game_data(5, 0x2288, "EMU") == the reference capture's child 26-byte NI src byte-for-byte."""
    compat = (language & 0xF) | ((version_low & 0xF) << 10)
    rgd = bytearray(13)
    rgd[0:2] = (compat & 0xFFFF).to_bytes(2, "little")
    rgd[2:4] = (trainer_id & 0xFFFF).to_bytes(2, "little")     # compatibility.playerTrainerId[2]
    rgd[4:8] = bytes(partner_info[:4]).ljust(4, b"\x00")       # partnerInfo[RFU_CHILD_MAX]
    rgd[8:10] = (0).to_bytes(2, "little")                      # tradeSpecies:10 | tradeType:6
    rgd[10] = (activity & 0x7F) | ((1 if started else 0) << 7) # activity:7 | startedActivity:1
    rgd[11] = 0                                                # playerGender:1 | tradeLevel:7
    rgd[12] = 0                                                # padding
    gname = bytes(rgd).ljust(15, b"\x00")                      # gname[RFU_GAME_NAME_LENGTH + 2] = 15
    uname = charmap.encode(ot_name, width=9, pad=0x00)         # uname[RFU_USER_NAME_LENGTH + 1] = 9
    src = RFU_SERIAL_GAME.to_bytes(2, "little") + gname + uname
    assert len(src) == 26, len(src)
    return bytes(src)


def _ni_header(data_type, payload_size, data_size):
    """The 7-byte NI_START header (now_p[0] = &dataType, remainSize 7): dataType(u8) +
    payloadSize(u16 LE) + dataSize(u32 LE) - the in-memory layout of struct NIComm from .dataType."""
    return (bytes([data_type & 0xFF])
            + (payload_size & 0xFFFF).to_bytes(2, "little")
            + (data_size & 0xFFFFFFFF).to_bytes(4, "little"))


def _ni_send_sequence(src, data_type, payload_size):
    """Faithful single-pass of the librfu NI sender state machine [rfu_STC_setSendData_org +
    rfu_STC_NI_constructLLSF + rfu_STC_NI_receive_Sender], returning the ordered list of sub-frames
    as (state, n, phase, size, payload) tuples - LLSF-agnostic (works for CHILD or PARENT; the caller
    wraps each tuple in the mode-appropriate LLSF header). `payload_size = subFrameSize - frameSize`.

    Reproduces the SEND_START -> SENDING -> SEND_LAST -> SEND_NULL walk. The 7-byte NI header
    (dataType, payloadSize, dataSize) is chunked over one-or-more NI_START frames in `payload_size`
    units at phase 0 (n = 1,2,3,... per frame); the parent status (payloadSize 5 < 7) needs TWO
    NI_STARTs, the child game data (payloadSize 12 >= 7) needs one. Then SENDING windows `src` over
    WINDOW_COUNT phases. Verified: _ni_send_sequence(childGameData, 1, 12) reproduces the byte-exact
    child NISender output, and _ni_send_sequence(status, 0, 5) matches the recv-ack capture below."""
    src = bytes(src)
    data_size = len(src)
    header = _ni_header(data_type, payload_size, data_size)
    seq = []
    # SLOT_STATE_SEND_START: send the 7-byte header, `payload_size` bytes/frame, all at phase 0.
    # remainSize starts at 7 and is decremented by payload_size per ACK [receive_Sender:2132]; the
    # header is done once remainSize hits 0 or underflows (the C's `default`/`case 0`), then -> SENDING.
    n0, off, remain = 1, 0, NI_HEADER_SIZE
    while True:
        size = min(remain, payload_size)
        seq.append((rfu.LCOM_NI_START, n0, 0, size, header[off:off + size]))
        n0 = (n0 + 1) & 3
        off += payload_size
        remain -= payload_size
        if remain <= 0:
            break
    # SLOT_STATE_SENDING: window src over WINDOW_COUNT phases, payload_size bytes each, phase-round-robin
    # skipping phases whose window is past the end of src [constructLLSF:1818]. n resets to 1 per phase.
    now = [payload_size * i for i in range(WINDOW_COUNT)]
    n = [1] * WINDOW_COUNT
    phase, remain = 0, data_size
    while remain > 0:
        while now[phase] >= data_size:
            phase = (phase + 1) % WINDOW_COUNT
        o = now[phase]
        size = min(payload_size, data_size - o)
        seq.append((rfu.LCOM_NI, n[phase], phase, size, src[o:o + size]))
        now[phase] += payload_size << 2            # SENDING stride = payloadSize<<2 [receive_Sender:2131]
        n[phase] = (n[phase] + 1) & 3
        phase = (phase + 1) % WINDOW_COUNT
        remain -= payload_size
    seq.append((rfu.LCOM_NI_END, 0, 0, 0, b""))    # SLOT_STATE_SEND_LAST: n=0, size=0
    seq.append((rfu.LCOM_NULL, 1, 0, 0, b""))      # SLOT_STATE_SEND_NULL: n=1, size=0
    return seq


class NISender:
    """Single-pass CHILD NI sender. next_slot() returns the next NI sub-frame SLOT bytes (LLSF + the
    sub-frame payload), or None once the whole NI transfer is finished (the machine reached
    SLOT_STATE_SEND_NULL and emitted its NULL frame). One sub-frame per call; the orchestrator wraps
    each in a 'T' frame via gbaframe.wrap_t and paces them one per VBlank like the real child."""

    def __init__(self, src, sub_frame_size=14, data_type=1):
        """`src` = the user/game data (26 bytes for the connection game data). `data_type` = 1 for
        game identification info (rfu_NI_CreateConnectionAllSlots) [setSendData_org dataType]."""
        self.src = bytes(src)
        self.data_size = len(self.src)
        self.data_type = data_type & 0xFF
        self.payload_size = sub_frame_size - CHILD_FRAME_SIZE   # 12 for sub_frame_size 14
        self.state = SLOT_STATE_SEND_START
        self.phase = 0
        self.n = [1] * WINDOW_COUNT
        self.remain = NI_HEADER_SIZE                            # NI_START sends the 7-byte header
        self.now = [0] * WINDOW_COUNT                           # per-phase offset into src (SENDING)
        self._header = _ni_header(self.data_type, self.payload_size, self.data_size)

    @property
    def done(self):
        return self.state == SLOT_STATE_DONE

    def _emit(self, state_lcom, n, phase, size, payload):
        return rfu.child_ni_llsf(state_lcom, n, phase, 0, size) + bytes(payload)

    def next_slot(self):
        """Advance the NI machine one sub-frame and return its slot bytes (or None when done).
        Faithful single-pass of rfu_STC_NI_constructLLSF + the SEND_START -> SENDING -> SEND_LAST ->
        SEND_NULL transitions (no retransmit window - Pia Reliable guarantees delivery)."""
        if self.state == SLOT_STATE_SEND_START:
            # NI_START: size = min(remainSize, payloadSize). remainSize 7 < payloadSize 12 -> 7.
            size = min(self.remain, self.payload_size)
            slot = self._emit(rfu.LCOM_NI_START, self.n[0], 0, size, self._header[:size])
            # transition to SENDING: reset windows over src, remainSize = dataSize.
            self.state = SLOT_STATE_SENDING
            self.phase = 0
            for i in range(WINDOW_COUNT):
                self.n[i] = 1
                self.now[i] = self.payload_size * i
            self.remain = self.data_size
            return slot

        if self.state == SLOT_STATE_SENDING:
            # skip phases whose window is past the end of src [constructLLSF:1818-1823].
            while self.now[self.phase] >= self.data_size:
                self.phase = (self.phase + 1) % WINDOW_COUNT
            off = self.now[self.phase]
            size = min(self.payload_size, self.data_size - off)
            slot = self._emit(rfu.LCOM_NI, self.n[self.phase], self.phase, size,
                              self.src[off:off + size])
            self.remain -= size
            # advance this phase's window by payloadSize<<2 (SENDING stride) and bump n.
            self.now[self.phase] += self.payload_size << 2
            self.phase = (self.phase + 1) % WINDOW_COUNT
            if self.remain <= 0:
                self.state = SLOT_STATE_SEND_LAST
                self.phase = 0
            return slot

        if self.state == SLOT_STATE_SEND_LAST:
            # NI_END: n=0, size=0 [the SEND_LAST emit; n[0] set to 0 on the SENDING->LAST edge].
            slot = self._emit(rfu.LCOM_NI_END, 0, 0, 0, b"")
            self.state = SLOT_STATE_SEND_NULL
            return slot

        if self.state == SLOT_STATE_SEND_NULL:
            # NULL: n=1, size=0 - the terminator the child emits once before going UNI.
            slot = self._emit(rfu.LCOM_NULL, 1, 0, 0, b"")
            self.state = SLOT_STATE_DONE
            return slot

        return None


class ParentNISender:
    """Single-pass PARENT NI sender - the HOST's side of the NI handshake, delivering the 1-byte join
    STATUS to the child right after acking the child's game-data NI [SendRfuStatusToPartner ->
    rfu_NI_setSendData(1 << idx, 8, &status, 1), link_rfu_2.c:1747]. MODE_PARENT: frameSize 3,
    subFrameSize 8 => payloadSize 5; dataType 0 (rfu_STC_setSendData_org sending-path sets dataType=0).

    Because payloadSize 5 < the 7-byte NI header, SEND_START emits TWO NI_STARTs. Verified byte-exact
    vs the child's recv-ack capture in recv_ack_slot()'s docstring (the child acked NI_START n=1,
    NI_START n=2, NI n=1, NI_END n=0 - exactly the (state,n,phase) this sender emits):

        NI_START n=1 ph0 sz5  <hdr[0:5] = dataType 0, payloadSize 5, dataSize 1 (low bytes)>
        NI_START n=2 ph0 sz2  <hdr[5:7] = dataSize high bytes>
        NI       n=1 ph0 sz1  <status byte (5)>
        NI_END   n=0 ph0 sz0
        NULL     n=1 ph0 sz0

    next_slot() returns the next PARENT NI sub-frame SLOT (3-byte PARENT LLSF + payload) or None when
    finished; the orchestrator wraps each in a HOST 'T' frame via gbaframe.wrap_t_parent, one/VBlank."""

    STATUS_SUBFRAME_SIZE = 8            # rfu_NI_setSendData(1 << idx, 8, &status, 1) [link_rfu_2.c:1747]

    def __init__(self, status=RFU_STATUS_JOIN_GROUP_OK, bm_slot=1, sub_frame_size=STATUS_SUBFRAME_SIZE):
        """`status` = the 1-byte join status the child reads (RFU_STATUS_JOIN_GROUP_OK=5 accepts it;
        any other value rejects). `bm_slot` = the connected-child slot bitmask (1 for RFU slot 0)."""
        self.status = status & 0xFF
        self.bm_slot = bm_slot
        payload_size = sub_frame_size - rfu.PARENT_FRAME_SIZE       # 8 - 3 = 5
        # dataType 0 (user data): the sending path of setSendData_org sets dataType=0 [librfu_rfu.c:1477].
        self._seq = _ni_send_sequence(bytes([self.status]), data_type=0, payload_size=payload_size)
        self._i = 0

    @property
    def done(self):
        return self._i >= len(self._seq)

    def next_slot(self):
        """Advance one sub-frame; return its PARENT slot bytes (ack=0) or None when the NI send done."""
        if self.done:
            return None
        state, n, phase, size, payload = self._seq[self._i]
        self._i += 1
        return rfu.parent_ni_llsf(state, n, phase, 0, size, self.bm_slot) + bytes(payload)


def recv_ack_slot(state, n, phase):
    """Build the CHILD's RECV-side NI ACK slot for a received HOST NI sub-frame: MIRROR the host
    frame's (state, n, phase) with ack=1, size=0, NO payload [rfu_STC_NI_receive ack path].

    The host runs its own librfu NI sender right after acking ours (delivering its connection/join-
    status data); the child must ACK every host NI sub-frame so the host's NI transfer completes -
    otherwise the host faults the RFU link ("Communication error"). The host's NI data content is
    discarded (it is just the join status) - no reassembly/window needed.

    Verified byte-exact vs the reference capture (the joiner's recv-NI ack sequence): NI_START n=1 ph0 -> 8006,
    NI_START n=2 ph0 -> 0007, NI n=1 ph0 -> 800a, NI_END n=0 ph0 -> 000e."""
    return rfu.child_ni_llsf(state, n, phase, ack=1, size=0)


class NIReceiver:
    """Tracks the HOST's NI transfer so the sim knows when to stop emitting recv-NI acks and proceed
    to UNI. The host NI completes when its NI_END (state=LCOM_NI_END) arrives with ack=0; a host NULL
    (LCOM_NULL, ack=0) also terminates (defensive). on_host_ni() returns the recv-NI ACK slot bytes
    to emit for a host NI sub-frame (NI_START/NI/NI_END), or None for a host NULL / a host ack frame
    (ack=1) / a frame we should not ack.

    The reference capture's recv-NI ack sequence is exactly NI_START n=1, NI_START n=2, NI n=1, NI_END
    n=0 (all ack=1 sz=0) - the host's terminal NULL is NOT acked by the child."""

    def __init__(self):
        self.complete = False
        # The host's recv-NI carries a 1-byte join STATUS in its LCOM_NI sub-frame [doc layer 6:
        # SendRfuStatusToPartner -> data->joinRequestAnswer]. RFU_STATUS_JOIN_GROUP_OK(5) = accepted; any
        # other value (JOIN_GROUP_NO / CONNECTION_ERROR / FATAL_ERROR) = the host REJECTED us. Capturing
        # it lets the sim abort cleanly instead of acking forever and then hanging on a UNI that never
        # comes. None until the host sends its NI data sub-frame.
        self.status = None

    def on_host_ni(self, ni_rec):
        """`ni_rec` = the dict gbaframe.parse_in attaches as record['ni'] for a host NI-window frame
        ({state, ack, n, phase, size, payload}). Returns the recv-NI ack slot bytes (mirror state/n/
        phase, ack=1, sz=0) for a host NI_START/NI/NI_END sub-frame with ack=0, else None. Marks the
        host's NI complete on the host's NI_END (or NULL) with ack=0, and captures the join status."""
        if ni_rec is None or ni_rec.get("ack") != 0:
            return None                 # only the host's OUTGOING NI data (ack=0) is ack-able by us
        state = ni_rec["state"]
        if state == rfu.LCOM_NI and ni_rec.get("payload"):
            self.status = ni_rec["payload"][0]   # the 1-byte join status (5 = JOIN_GROUP_OK)
        if state == rfu.LCOM_NULL:      # host's terminator: completes the transfer, NOT acked
            self.complete = True
            return None
        if state == rfu.LCOM_NI_END:    # last host NI sub-frame: ack it AND mark complete
            self.complete = True
        if state in (rfu.LCOM_NI_START, rfu.LCOM_NI, rfu.LCOM_NI_END):
            return recv_ack_slot(state, ni_rec["n"], ni_rec["phase"])
        return None


# --- PARENT recv path: ACK the child's game-data NI and reassemble its 26-byte RfuGameData ----------
def parent_recv_ack_slot(state, n, phase, bm_slot=1):
    """The HOST's RECV-side NI ACK slot for a received CHILD NI sub-frame: MIRROR the child frame's
    (state, n, phase) with ack=1, size=0, in a 3-byte PARENT LLSF [rfu_STC_NI_constructLLSF on the
    recv NIComm, MODE_PARENT]. Parent counterpart of recv_ack_slot()."""
    return rfu.parent_ni_llsf(state, n, phase, 1, 0, bm_slot)


def decode_child_ni_slot(slot):
    """Decode a CHILD NI sub-frame SLOT (2-byte CHILD LLSF + payload) into the same dict shape
    gbaframe.parse_in attaches as record['ni'] ({state, ack, n, phase, size, payload}) - so
    ParentNIReceiver.on_child_ni() consumes the console-child's NI frames symmetrically to how the
    child's NIReceiver consumes the host's. `slot` = the child's LLSF+payload (LLSF stripped of the
    'T'-frame wrapper)."""
    llsf = rfu.parse_llsf_child(slot)
    return {"state": llsf["state"], "ack": llsf["ack"], "n": llsf["n"], "phase": llsf["phase"],
            "size": llsf["size"], "payload": bytes(slot[2:2 + llsf["size"]])}


class ParentNIReceiver:
    """The HOST's NI RECEIVER: ACKs the child's outgoing game-data NI sub-frames and reassembles the
    26-byte RfuGameData (serialNo + gname + uname) the child delivers via
    rfu_NI_CHILD_setSendGameName (dataType 1, payloadSize 12). The mirror of the child's NIReceiver.

    The child's NI send is NI_START(header) then NI frames windowed over phases (ph0=src[0:12],
    ph1=src[12:24], ph2=src[24:26]) then NI_END then NULL. on_child_ni() returns the PARENT recv-NI
    ack slot (mirror state/n/phase, ack=1, sz=0) for each NI_START/NI/NI_END with ack=0, reassembles
    the payload by phase, marks `complete` on the child's NI_END (defensively also on NULL), and
    exposes `game_data` (the raw 26 bytes), `trainer_id`, and `uname` for the Pia partner list /
    reconnect match (link_rfu_2.c:2761). The child's terminal NULL is NOT acked (symmetric with the
    child's own recv path)."""

    def __init__(self, bm_slot=1, payload_size=12):
        self.complete = False
        self.bm_slot = bm_slot
        self.payload_size = payload_size          # refined from the NI_START header when it arrives
        self.data_type = None
        self.data_size = None
        self.game_data = None
        self._hdr = bytearray()
        self._buf = bytearray()
        self._phase_count = [0] * WINDOW_COUNT

    def on_child_ni(self, ni_rec):
        """`ni_rec` = a child NI record ({state, ack, n, phase, size, payload}, from decode_child_ni_slot
        or parse_in). Returns the PARENT recv-NI ack slot for a child NI_START/NI/NI_END with ack=0,
        else None (ack=1 frames are the child acking OUR ParentNISender; a child NULL only terminates)."""
        if ni_rec is None or ni_rec.get("ack") != 0:
            return None                           # only the child's OUTGOING NI data (ack=0) is ack-able
        state = ni_rec["state"]
        if state == rfu.LCOM_NI_START:
            self._hdr += ni_rec.get("payload", b"")
            if self.data_size is None and len(self._hdr) >= NI_HEADER_SIZE:
                self.data_type = self._hdr[0]
                self.payload_size = int.from_bytes(self._hdr[1:3], "little") or self.payload_size
                self.data_size = int.from_bytes(self._hdr[3:7], "little")
        elif state == rfu.LCOM_NI:
            phase = ni_rec["phase"] & 3
            off = phase * self.payload_size + self._phase_count[phase] * WINDOW_COUNT * self.payload_size
            payload = ni_rec.get("payload", b"")
            if off + len(payload) > len(self._buf):
                self._buf.extend(b"\x00" * (off + len(payload) - len(self._buf)))
            self._buf[off:off + len(payload)] = payload
            self._phase_count[phase] += 1
        elif state == rfu.LCOM_NULL:              # child terminator: completes the transfer, NOT acked
            self.complete = True
            self._finalize()
            return None
        if state == rfu.LCOM_NI_END:              # last child NI sub-frame: ack it AND mark complete
            self.complete = True
            self._finalize()
        if state in (rfu.LCOM_NI_START, rfu.LCOM_NI, rfu.LCOM_NI_END):
            return parent_recv_ack_slot(state, ni_rec["n"], ni_rec["phase"], self.bm_slot)
        return None

    def _finalize(self):
        if self.game_data is None:
            data = bytes(self._buf)
            if self.data_size is not None:
                data = data[:self.data_size]
            self.game_data = data

    @property
    def trainer_id(self):
        """compatibility.playerTrainerId - gname[2:4] = game_data[4:6] LE [build_game_data / link_rfu.h]."""
        if not self.game_data or len(self.game_data) < 6:
            return None
        return int.from_bytes(self.game_data[4:6], "little")

    @property
    def uname(self):
        """The child's OT name (uname[9]) = game_data[17:26], game-charset, 0-padded [build_game_data]."""
        if not self.game_data or len(self.game_data) < 26:
            return None
        return bytes(self.game_data[17:26])
