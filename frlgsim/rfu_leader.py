"""Leader/parent side of the emulator RFU protocol.

This module owns the *inner* payload carried by Pia Reliable protocol 10.  It is
deliberately independent of sockets, Pia crypto, packet ids, and the Reliable
window so it can be driven by both the live host and deterministic simulations.

The two integration calls are::

    leader.receive(inner)       # once for each in-order, unique Reliable payload
    inner = leader.tick(words)  # once per VBlank; queue as Reliable FLAGSA_GBA

``words`` is the leader's seven-word gSendCmd for the next UNI poll.  Before
UNI it is ignored.  ``tick`` emits at most one frame and gives C/A and NI
control traffic priority over UNI.

Single-child sequence implemented here:

    child C -> parent A
    child game-data NI -> parent mirrored NI ACKs
    parent join-status NI -> child mirrored NI ACKs
    continuous parent UNI table (row 0 parent, row 1 reflected child)

The surrounding Reliable layer MUST deduplicate retransmitted DATA before
calling :meth:`receive`.  The engine is nevertheless defensive about duplicate
C and NI frames because the live console retransmits aggressively until its
Reliable opening window is acknowledged.
"""

from collections import deque
import secrets

from . import gbaframe, ni, rfu


WAIT_CONNECT = "WAIT_CONNECT"
CHILD_NI = "CHILD_NI"
PARENT_NI = "PARENT_NI"
UNI = "UNI"
DISCONNECTED = "DISCONNECTED"


def _control_frame(frame):
    """Decode the common ``57 type len body`` envelope from a child frame."""
    frame = bytes(frame)
    if len(frame) < 4 or frame[0] != gbaframe.GBA_MARKER:
        return None
    size = int.from_bytes(frame[2:4], "little")
    if len(frame) < 4 + size:
        return None
    return frame[1], frame[4:4 + size]


def _parent_ni_fields(slot):
    """Return the fields that a child's recv-NI ACK mirrors."""
    value = int.from_bytes(slot[:3], "little")
    return ((value >> rfu.PARENT_LLSF_STATE_SHIFT) & 0xF,
            (value >> rfu.PARENT_LLSF_N_SHIFT) & 3,
            (value >> rfu.PARENT_LLSF_PHASE_SHIFT) & 3)


class RFULeader:
    """One-child RFU leader state machine.

    ``host_session_id`` is the two-byte value echoed in the emulator ``A``
    frame.  ``bm_slot=1`` seats the child in RFU slot zero / multiplayer id 1.
    The public counters and state are intended for milestone logging.
    """

    def __init__(self, host_session_id=None, *, bm_slot=1,
                 join_status=ni.RFU_STATUS_JOIN_GROUP_OK, start_ts=1):
        if host_session_id is None:
            # Three independent native leaders used 0xf17b, 0xf189 and
            # 0xf1a4. The low byte varies; the parent-id high byte is 0xf1.
            # Both the beacon and A store that u16 little-endian.
            host_session_id = secrets.token_bytes(1) + b"\xf1"
        self.host_session_id = bytes(host_session_id)[:2].ljust(2, b"\x00")
        self.bm_slot = bm_slot & 0xF
        self.join_status = join_status & 0xFF
        self.ts = start_ts & 0xFFFFFFFF
        self.state = WAIT_CONNECT
        self.connect_id = None
        self.child_cmd = rfu.idle_slot()
        self.child_game_data = None
        self.k_acks = 0
        self.uni_in = 0
        self.uni_out = 0

        self._pending = deque()
        self._child_ni = None
        self._parent_ni = None
        self._parent_waiting = None
        self._parent_current_slot = None
        self._seen_child_ni = set()

    @property
    def connected(self):
        return self.connect_id is not None and self.state != DISCONNECTED

    @property
    def ni_complete(self):
        return self.state == UNI

    @property
    def child_trainer_id(self):
        return None if self._child_ni is None else self._child_ni.trainer_id

    @property
    def child_uname(self):
        return None if self._child_ni is None else self._child_ni.uname

    def _wrap_parent_t(self, slot):
        frame = gbaframe.wrap_t_parent(slot, self.ts)
        self.ts = (self.ts + 1) & 0xFFFFFFFF
        return frame

    def receive(self, inner):
        """Consume one unique, in-order child Reliable inner payload.

        Output is queued and returned later by :meth:`tick`; this preserves the
        one-parent-frame-per-VBlank cadence used by the native implementation.
        Returns a short event name for logging, or ``None``.
        """
        ctl = _control_frame(inner)
        if ctl is None:
            return None
        typ, body = ctl

        if typ == gbaframe.TYPE_C:
            if len(body) < 2:
                return None
            cid = bytes(body[:2])
            if self.connect_id is None:
                self.connect_id = cid
                self.state = CHILD_NI
                self._child_ni = ni.ParentNIReceiver(self.bm_slot)
                self._pending.append(gbaframe.build_accept(self.host_session_id, cid))
                return "connect"
            if cid == self.connect_id and self.state != DISCONNECTED:
                # The child emits C as NEW Reliable frames every VBlank until
                # it sees A (host_2.3: fff1, fff2, ...).  A is the leader's
                # single stream-opening fff0 frame; Reliable owns retransmits
                # of that same sequence. Allocating a fresh A for every C
                # floods the send window and does not match the native leader.
                return "connect_duplicate"
            return "connect_rejected"

        if typ == gbaframe.TYPE_D:
            self.state = DISCONNECTED
            self._pending.clear()
            return "disconnect"

        if typ == gbaframe.TYPE_K:
            self.k_acks += 1
            return "k_ack"

        if typ != gbaframe.TYPE_T or not self.connected:
            return None

        rec = gbaframe.parse_out(inner)
        if rec is None or rec.get("llsf") is None:
            return None
        llsf = rec["llsf"]

        # Child recv-side NI ACK of the parent's current stop-and-wait frame.
        if llsf["ack"] == 1:
            got = (llsf["state"], llsf["n"], llsf["phase"])
            if self.state == PARENT_NI and got == self._parent_waiting:
                self._parent_waiting = None
                self._parent_current_slot = None
                return "parent_ni_ack"
            return "ni_ack_ignored"

        if llsf["state"] != rfu.LCOM_UNI:
            if self.state not in (CHILD_NI, PARENT_NI):
                return "ni_out_of_phase"
            slot = rec["slot"]
            key = (llsf["state"], llsf["n"], llsf["phase"], bytes(slot[2:]))
            if key in self._seen_child_ni:
                # Reliable normally deduplicates this.  If an integration layer
                # does not, ACK it again but never append its payload twice.
                if llsf["state"] in (rfu.LCOM_NI_START, rfu.LCOM_NI, rfu.LCOM_NI_END):
                    ack = ni.parent_recv_ack_slot(llsf["state"], llsf["n"],
                                                  llsf["phase"], self.bm_slot)
                    self._pending.append(self._wrap_parent_t(ack))
                return "child_ni_duplicate"
            self._seen_child_ni.add(key)
            ack = self._child_ni.on_child_ni(ni.decode_child_ni_slot(slot))
            if ack is not None:
                self._pending.append(self._wrap_parent_t(ack))
            # NI_END is ACKed, but the child transfer does not hand over to
            # the parent's NI sender until its unacknowledged terminal NULL.
            # The native completed-trade order is END -> NULL -> parent NI.
            if (llsf["state"] == rfu.LCOM_NULL
                    and self._child_ni.complete and self.state == CHILD_NI):
                self.child_game_data = self._child_ni.game_data
                self._parent_ni = ni.ParentNISender(self.join_status, self.bm_slot)
                self.state = PARENT_NI
                return "child_ni_complete"
            return "child_ni"

        # UNI is accepted only once both halves of NI have completed.  Save the
        # child's gSendCmd so every parent UNI table can reflect it in row 1.
        if self.state != UNI or rec.get("cmd") is None:
            return "uni_early"
        self.child_cmd = bytes(rec["cmd"][:rfu.COMM_SLOT_LENGTH]).ljust(rfu.COMM_SLOT_LENGTH, b"\x00")
        self.uni_in += 1
        return "uni"

    def tick(self, parent_words=None):
        """Return the next parent emulator frame, or ``None`` before C arrives.

        Call once per VBlank. Queued A/NI ACKs come first. Parent NI is
        stop-and-wait on the child's mirrored ACK. In UNI a parent ``T`` is
        emitted every call, including when both command rows are idle.
        """
        if self._pending:
            return self._pending.popleft()

        if self.state == PARENT_NI:
            # RFU NI is its own stop-and-wait layer above Pia Reliable.  The
            # native leader presents the current NI subframe on every VBlank
            # (as a new T/timestamp) until the child mirrors its fields with
            # ack=1. Reliable retransmission alone is insufficient because a
            # delivered poll may still be missed by the child's RFU callback.
            if self._parent_waiting is not None:
                return self._wrap_parent_t(self._parent_current_slot)

            slot = self._parent_ni.next_slot()
            if slot is not None:
                fields = _parent_ni_fields(slot)
                frame = self._wrap_parent_t(slot)
                if fields[0] == rfu.LCOM_NULL:
                    # The terminal NULL is not ACKed by the child.
                    self.state = UNI
                else:
                    self._parent_waiting = fields
                    self._parent_current_slot = slot
                return frame

        if self.state == UNI:
            if parent_words is None:
                parent_cmd = rfu.idle_slot()
            elif isinstance(parent_words, (bytes, bytearray)):
                parent_cmd = bytes(parent_words)[:rfu.COMM_SLOT_LENGTH].ljust(
                    rfu.COMM_SLOT_LENGTH, b"\x00")
            else:
                parent_cmd = rfu.serialize(parent_words)
            table = rfu.pack_recv_cmds([parent_cmd, self.child_cmd])
            self.uni_out += 1
            return self._wrap_parent_t(rfu.parent_uni_slot(table, self.bm_slot))
        return None

    def disconnect_frame(self):
        """Return the leader ``D`` frame and move to DISCONNECTED."""
        if self.connect_id is None:
            return None
        self.state = DISCONNECTED
        self._pending.clear()
        return gbaframe.build_disconnect(self.connect_id)

    def on_ldn_leave(self):
        """Abort immediately when the LDN station disappears.

        A LeaveEvent is below Pia/RFU, so there is no peer left to receive a
        ``D``.  Clear queued NI/UNI work and make all future ticks silent.  A
        graceful in-protocol shutdown should use :meth:`disconnect_frame`.
        """
        self.state = DISCONNECTED
        self._pending.clear()
