"""Deterministic child/parent simulation for RFU leader milestones 3.1-3.3."""

from frlgsim import gbaframe, ni, rfu
from frlgsim.rfu_leader import CHILD_NI, PARENT_NI, UNI, RFULeader


def _child_t(slot, ts):
    return gbaframe.wrap_t(slot, ts)


def test_31_connect_accept_matches_native_completed_trade():
    # switch_complete_trade: child C=8084, host A owns b7f1 and echoes 8084.
    leader = RFULeader(host_session_id=b"\xb7\xf1")
    assert leader.receive(bytes.fromhex("574302008084")) == "connect"
    assert leader.state == CHILD_NI and leader.connect_id == b"\x80\x84"
    accept = leader.tick()
    assert accept == bytes.fromhex("57410600b7f180840000")
    assert gbaframe.parse_in(accept) == {
        "type": "A", "host_session_id": b"\xb7\xf1", "connect_id": b"\x80\x84"
    }
    # host_2.3 shows each retry C uses a new Reliable seq.  The leader must
    # not allocate another A; Reliable retransmits the original opening A.
    assert leader.receive(bytes.fromhex("574302008084")) == "connect_duplicate"
    assert leader.tick() is None


def test_default_parent_id_has_native_f1_high_byte():
    leader = RFULeader()
    assert len(leader.host_session_id) == 2
    assert leader.host_session_id[1] == 0xF1


def test_32_bidirectional_ni_is_ack_gated_and_recovers_identity():
    leader = RFULeader()
    leader.receive(gbaframe.build_connect(b"\xc5\xf1"))
    leader.tick()                                      # A

    source = ni.build_game_data(5, 0x2288, "EMU")
    child = ni.NISender(source)
    ts = 1
    parent_acks = []
    saw_end = False
    while not child.done:
        slot = child.next_slot()
        event = leader.receive(_child_t(slot, ts))
        ts += 1
        # Child NULL is not ACKed.  Leave the next tick for the parent's first
        # join-status NI frame instead of consuming it in this half-loop.
        child_llsf = rfu.parse_llsf_child(slot)
        if child_llsf["state"] == rfu.LCOM_NI_END:
            saw_end = True
            assert leader.state == CHILD_NI       # wait for terminal NULL
        out = None if child_llsf["state"] == rfu.LCOM_NULL else leader.tick()
        if out is not None:
            rec = gbaframe.parse_in(out)
            if rec.get("ni", {}).get("ack") == 1:
                parent_acks.append(rec["ni"])
    assert event in ("child_ni_complete", "child_ni")
    assert saw_end
    assert leader.state == PARENT_NI
    assert leader.child_game_data == source
    assert leader.child_trainer_id == 0x2288
    assert len(parent_acks) == 5                       # NULL is not ACKed

    # Parent sends one status sub-frame, then waits until the child ACKs it.
    child_recv = ni.NIReceiver()
    seen_parent = []
    while leader.state != UNI:
        frame = leader.tick()
        assert frame is not None
        rec = gbaframe.parse_in(frame)
        seen_parent.append(rec["ni"])
        ack = child_recv.on_host_ni(rec["ni"])
        if ack is not None:
            repeat = leader.tick()                    # repeat every VBlank until ACK
            repeat_rec = gbaframe.parse_in(repeat)
            assert repeat_rec["ni"] == rec["ni"]
            assert repeat_rec["ts"] == rec["ts"] + 1
            assert leader.receive(_child_t(ack, ts)) == "parent_ni_ack"
            ts += 1
    assert [x["state"] for x in seen_parent] == [1, 1, 2, 3, 0]
    assert child_recv.status == ni.RFU_STATUS_JOIN_GROUP_OK
    assert child_recv.complete and leader.ni_complete


def test_33_uni_continuously_reflects_child_and_carries_parent_row():
    leader = _complete_ni_handshake()
    child_cmd = rfu.SlotBuilder().build(rfu.held_keys_words(0x1234))
    assert leader.receive(_child_t(rfu.uni_slot(child_cmd), 100)) == "uni"

    parent_cmd = rfu.serialize(rfu.send_player_ids_words())
    first = gbaframe.parse_in(leader.tick(parent_cmd))
    second = gbaframe.parse_in(leader.tick())
    assert first["ts"] + 1 == second["ts"]
    assert first["llsf_state"] == second["llsf_state"] == rfu.LCOM_UNI
    rows1, rows2 = dict(first["slots"]), dict(second["slots"])
    assert rows1[0] == parent_cmd and rows1[1] == child_cmd
    assert rows2[0] == rfu.idle_slot() and rows2[1] == child_cmd
    assert leader.uni_in == 1 and leader.uni_out == 2


def test_duplicate_child_ni_is_reacked_without_corrupting_reassembly():
    leader = RFULeader()
    leader.receive(gbaframe.build_connect(b"\x67\x79"))
    leader.tick()
    slot = ni.NISender(ni.build_game_data(5, 0x2288, "EMU")).next_slot()
    frame = _child_t(slot, 1)
    assert leader.receive(frame) == "child_ni"
    ack1 = leader.tick()
    assert leader.receive(frame) == "child_ni_duplicate"
    ack2 = leader.tick()
    assert gbaframe.parse_in(ack1)["ni"] == gbaframe.parse_in(ack2)["ni"]


def test_ldn_leave_immediately_silences_queued_output():
    leader = RFULeader()
    leader.receive(gbaframe.build_connect(b"\x67\x79"))
    leader.on_ldn_leave()
    assert leader.tick() is None
    assert not leader.connected


def _complete_ni_handshake():
    leader = RFULeader()
    leader.receive(gbaframe.build_connect(b"\x67\x79"))
    leader.tick()
    child = ni.NISender(ni.build_game_data(5, 0x2288, "EMU"))
    ts = 1
    while not child.done:
        slot = child.next_slot()
        leader.receive(_child_t(slot, ts))
        ts += 1
        if rfu.parse_llsf_child(slot)["state"] != rfu.LCOM_NULL:
            leader.tick()                             # parent ACK
    child_recv = ni.NIReceiver()
    while leader.state != UNI:
        out = leader.tick()
        ack = child_recv.on_host_ni(gbaframe.parse_in(out)["ni"])
        if ack is not None:
            leader.receive(_child_t(ack, ts))
            ts += 1
    return leader


if __name__ == "__main__":
    for name, func in sorted(globals().copy().items()):
        if name.startswith("test_") and callable(func):
            func()
            print(f"PASS {name}")
