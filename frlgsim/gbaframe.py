"""emulator 0x54 frame - the Switch adapter's wrapper around the RFU command slot.

A gba frame = `57 <type:1> <len:u16 LE> <body>`. types: C=0x43 A=0x41 T=0x54 K=0x4b. (The session
metadata/config-game-data is NOT a 0x57 frame - it is a Reliable INIT payload owned by
reliable.METADATA_FRAME whose leading byte happens to be 0x4a; do not treat it as a 'J' 0x57 type.)

CHILD/joiner 'T' (we emit, OUT) body = <ts:u32 LE><00><slot_len:u8 @body[5]><00 00><slot, pad mult-4>.
HOST/parent 'T' (we parse, IN)  body = <ts:u32 LE><slot_len:u8 @body[4]><00 00 00><slot> (off-by-one;
slot_len<=1 = host idle keepalive, still K-acked). The SLOT = a librfu LLSF header + payload (see
rfu.uni_slot / ni.NISender); the parent UNI slot coalesces 5x14-byte gRecvCmds by mpId after its
3-byte LLSF. `ts` is a per-NEW-frame u32 counter (reused on a Pia retransmit), NOT a per-datagram seq.

'K' (we emit, OUT) = `57 4b 0c 00 <k_seq:u32><mid:u32><acked_host_ts:u32>` - one per UNIQUE host 'T'
ts; the host sends us NO K. Builders: wrap_t/build_k (OUT), parse_in (IN host), parse_out (our OUT).
"""

GBA_MARKER = 0x57
TYPE_T = 0x54           # RFU command-slot carrier
TYPE_K = 0x4B           # emulator ack of a received host 'T'
SLOT_LEN = 14


# emulator RFU control frame types (ASCII mnemonics): 'J'=join/metadata(configGameData),
# 'C'=connect request (rfu_REQ_startConnectParent), 'A'=host accept, 'K'=data ack, 'T'=slot data.
TYPE_J, TYPE_C, TYPE_A = 0x4A, 0x43, 0x41
TYPE_D = 0x44           # host emulator DISCONNECT ('D' = 57 44 02 00 <connect_id>)


def build_gba_frame(ftype, data):
    """emulator control frame = 57 <type> <len:u16 LE> <data> (the J/C connect frames; the
    'T'/'K' data frames use the dedicated wrap_t/build_k builders)."""
    return bytes([GBA_MARKER, ftype]) + len(data).to_bytes(2, "little") + bytes(data)


def build_connect(connect_id):
    """The joiner's emulator RFU connect request (e.g. 57 43 02 00 67 79). `connect_id` is the joiner's
    OWN 2-byte RFU connection id, self-chosen. Any nonzero value works - the host does not match it
    against anything, it just seats our slot. The host echoes it back in its accept
    (0x41: <host_session_id> <connect_id> 0000) and repeats it in the 'D' disconnect, so the same value
    is reused for the whole session."""
    return build_gba_frame(TYPE_C, connect_id)


def _roundup4(n):
    return (n + 3) & ~3


def wrap_t(slot, ts):
    """Build a CHILD/joiner 'T' (0x54) frame for a complete slot (slot ALREADY includes its LLSF
    header, e.g. rfu.uni_slot(cmd14) or an NI sub-frame). Verified format [reference capture, 3620/3620]:
        57 54 <body_len:u16 LE> | <ts:u32 LE> 00 <slot_len:u8> 00 00 | <slot, zero-padded to mult-4>
    `ts` is the child's per-frame counter (must increase per NEW frame; reuse on retransmit)."""
    slot = bytes(slot)
    padded = slot + b"\x00" * (_roundup4(len(slot)) - len(slot))
    body = (ts & 0xFFFFFFFF).to_bytes(4, "little") + bytes([0, len(slot) & 0xFF, 0, 0]) + padded
    return bytes([GBA_MARKER, TYPE_T]) + len(body).to_bytes(2, "little") + body


def build_k(k_seq, mid, acked_ts):
    """Build a 'K' (0x4b) emulator ack frame [reference capture, verified]: 57 4b 0c 00 <k_seq:u32><mid:u32>
    <acked_host_ts:u32> (all LE). One per UNIQUE host 'T' ts; k_seq is joiner-global (+1 from 1);
    mid = 1-based position within the OUT Pia datagram; acked_ts = the host 'T's ts verbatim."""
    body = ((k_seq & 0xFFFFFFFF).to_bytes(4, "little")
            + (mid & 0xFFFFFFFF).to_bytes(4, "little")
            + (acked_ts & 0xFFFFFFFF).to_bytes(4, "little"))
    return bytes([GBA_MARKER, TYPE_K]) + len(body).to_bytes(2, "little") + body


def parse_in(payload):
    """Parse a HOST/parent gba frame from a Reliable payload: 57 <type> <len:u16 LE> <body>.
    Returns a dict by type:
      'T': {ts, slot_len, llsf_state, slots:[(mpId, 14-byte gRecvCmd)...], positional:<same>, payload}
           (slot_len<=1 => host idle keepalive: ts set, slots/positional empty - still K-ack it)
      'A': {host_session_id, connect_id}    'K': {k_seq, acked_ts}    else {type}
           (accept fields: body[0:2]=host session id, body[2:4]=our echoed connect id)
    HOST 'T' body = <ts:u32> <slot_len:u8 @body[4]> 00 00 00 <slot>; the slot is a 3-byte PARENT
    LLSF then, for UNI, N x 14-byte gRecvCmds (chunk0=host's own, chunk1=our reflected slot).

    `positional` is an alias of `slots` (the [(mpId, 14-byte slot)] list) so the trade
    engine (BlockReceiver.feed_frame / TradeEngine.feed_in_frame / _host_barrier_in_frame, which read
    `positional`) consumes a parse_in record directly - the migration off the old unwrap() touches no
    engine code."""
    if len(payload) < 4 or payload[0] != GBA_MARKER:
        return None
    typ = payload[1]
    ln = int.from_bytes(payload[2:4], "little")
    body = payload[4:4 + ln]
    if typ == TYPE_T:
        if len(body) < 5:
            return {"type": "T", "ts": None, "slot_len": 0, "slots": [], "positional": []}
        ts = int.from_bytes(body[0:4], "little")
        slot_len = body[4]                          # HOST slot_len is at body[4] (joiner is body[5])
        rec = {"type": "T", "ts": ts, "slot_len": slot_len, "llsf_state": None,
               "slots": [], "positional": [], "payload": b""}
        if slot_len <= 1:                           # host idle keepalive (still must be K-acked)
            return rec
        slot = body[8:8 + slot_len]
        llsf = int.from_bytes(slot[0:3], "little")  # 3-byte PARENT LLSF
        rec["llsf_state"] = (llsf >> 14) & 0xF      # PARENT slotStateShift = 14
        rec["payload"] = slot[3:]
        if rec["llsf_state"] == 4:                  # LCOM_UNI: payload = N x 14 gRecvCmds by mpId
            for mpid, off in enumerate(range(0, len(rec["payload"]) - 13, SLOT_LEN)):
                rec["slots"].append((mpid, bytes(rec["payload"][off:off + SLOT_LEN])))
        else:                                       # NI window (NI_START/NI/NI_END/NULL): decode the
            # 3-byte PARENT NI LLSF [MODE_PARENT shifts: state<<14 ack<<13 n<<11 phase<<9 | size&0x7f].
            # The host runs its OWN librfu NI sender right after acking ours; the CHILD must ACK every
            # host NI sub-frame (ack=1, size=0, mirroring state/n/phase). The host's NI data content
            # (join status) is discarded - no reassembly needed [recv-NI ack, sim._on_gba_in].
            rec["ni"] = {
                "state": rec["llsf_state"],
                "ack": (llsf >> 13) & 1,
                "n": (llsf >> 11) & 3,
                "phase": (llsf >> 9) & 3,
                "size": llsf & 0x7F,
                "payload": bytes(rec["payload"]),
            }
        rec["positional"] = rec["slots"]            # alias: the engine reads `positional`
        return rec
    if typ == TYPE_A:
        return {"type": "A", "host_session_id": body[0:2], "connect_id": body[2:4]}
    if typ == TYPE_K:
        return {"type": "K", "k_seq": int.from_bytes(body[0:4], "little"),
                "acked_ts": int.from_bytes(body[8:12], "little") if len(body) >= 12 else None}
    return {"type": typ}


def parse_out(payload):
    """Parse a CHILD/joiner 'T' (0x54) frame WE emit (the inverse of wrap_t) back into its slot +
    decoded LLSF - for tests / OUT-stream verification. CHILD body =
        <ts:u32 LE> <00> <slot_len:u8 @body[5]> <00 00> <slot, zero-padded to mult-4>
    Returns {ts, slot_len, slot, llsf:{state,ack,n,phase,size}, cmd} where `cmd` is the 14-byte
    gSendCmd for a UNI slot (slot[2:16], LLSF stripped) or None for an NI sub-frame."""
    from . import rfu as _rfu
    if len(payload) < 4 or payload[0] != GBA_MARKER or payload[1] != TYPE_T:
        return None
    ln = int.from_bytes(payload[2:4], "little")
    body = payload[4:4 + ln]
    if len(body) < 8:
        return None
    ts = int.from_bytes(body[0:4], "little")
    slot_len = body[5]                              # CHILD slot_len is at body[5]
    slot = bytes(body[8:8 + slot_len])
    rec = {"type": "T", "ts": ts, "slot_len": slot_len, "slot": slot,
           "llsf": None, "cmd": None}
    if slot_len >= 2:
        rec["llsf"] = _rfu.parse_llsf_child(slot)
        if rec["llsf"]["state"] == _rfu.LCOM_UNI:   # UNI slot = 2-byte LLSF + 14-byte gSendCmd
            rec["cmd"] = slot[2:2 + SLOT_LEN]
    return rec
